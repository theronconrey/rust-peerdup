// SPDX-License-Identifier: MIT
use crate::auth::{self, AuthRole, AuthState, MemberId, SignedOp};
use crate::clock::{ClockOrdering, VectorClock};
use crate::crypto::{self, InstallOutcome, KeyRing};
use crate::rotation::{self, SignedRotation, VerifyOutcome};
use crate::share::{ShareConfig, ShareRole};
use crate::share_state::{self, PersistedState};
use crate::ticket::{self, Ticket, TICKET_VERSION};
use crate::transfer::{self, BlobCache, FileHash, Transfer, PEERDUP_DIR_NAME};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use p2panda_core::{SigningKey, Topic};
use p2panda_net::addrs::NodeInfo;
use p2panda_net::gossip::GossipHandle;
use p2panda_net::iroh_endpoint::RelayUrl;
use p2panda_net::iroh_mdns::MdnsDiscoveryMode;
use p2panda_net::{AddressBook, Discovery, Endpoint, Gossip, MdnsDiscovery};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{self, UnboundedReceiver};
use tokio::sync::{oneshot, Mutex, RwLock};
use tokio::task::JoinSet;

/// Cap the in-memory buffer of out-of-order key rotations per share. 64 epochs
/// is far more than expected; we evict the oldest if we somehow run past it.
const ROTATION_BUFFER_CAP: usize = 64;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "kind")]
enum ShareMsg {
    /// A version of the share. v2 (iroh-blobs): `manifest` is the hash of
    /// the encrypted manifest blob and `provider` the node id (= identity
    /// public key, hex) to fetch it from. v1 announces (librqbit info-hash
    /// plus BitTorrent endpoints) carried a different tag and are ignored.
    #[serde(rename = "share_announce_v2")]
    Announce {
        manifest: String,
        provider: String,
        /// Deterministic hash over the share's file contents, sorted by
        /// path. Same content gives the same hash on every peer; sync
        /// compares versions with it, and receivers check the fetched
        /// manifest against it before applying anything.
        #[serde(default)]
        version_hash: Option<String>,
        /// Vector clock identifying the version. Required by Sync receivers
        /// to compare versions; absent means a Phase 2 announce, which Sync
        /// peers ignore.
        #[serde(default)]
        clock: Option<VectorClock>,
        /// Wall-clock time when this version was created. Used as the
        /// tiebreaker for LWW resolution when clocks are concurrent.
        /// Optional for back-compat with pre-3.4 announces.
        #[serde(default)]
        timestamp: Option<DateTime<Utc>>,
    },
    /// Phase 5c: full snapshot of this peer's known auth ops for the share.
    /// Receivers verify each, dedupe by op id, and apply via
    /// `AuthState::apply_remote`. Periodic re-broadcasts ensure late joiners
    /// catch up; receivers ignore ops they already hold so reflood is cheap.
    /// `bincode`-encoded `SignedOp`s are inlined as `Vec<u8>` so a peer can
    /// decode the envelope (`serde_json` here) without depending on the
    /// inner schema.
    #[serde(rename = "share_auth_ops")]
    AuthOps { ops: Vec<Vec<u8>> },
    /// Phase 5d: a freshly-rotated epoch key, sealed once per remaining
    /// member (sealed-box-style envelope). Rebroadcast on every announce
    /// tick until the manager either confirms membership has stabilised or
    /// removes the file from `pending_rotations/`. Receivers verify the
    /// outer signature against `rotator_pubkey`, check that pubkey is a
    /// current Owner in their local auth state, then decrypt the envelope
    /// addressed to them and `install_epoch_key` the result.
    #[serde(rename = "share_key_rotation")]
    KeyRotation(SignedRotation),
}

/// Command sent from an IPC handler into the running share task. Each variant
/// pairs a request with a `oneshot::Sender` for the reply, so per-share state
/// (auth log, keyring, pending rotations) only mutates inside the share loop's
/// own stack — no cross-task locking on the per-share data.
pub enum ShareCommand {
    Invite {
        invitee: MemberId,
        auth_role: AuthRole,
        suggested_role: ShareRole,
        reply: oneshot::Sender<Result<String /* base64 ticket */>>,
    },
    Revoke {
        target: MemberId,
        reply: oneshot::Sender<Result<u64 /* new_epoch */>>,
    },
    RotateKey {
        reply: oneshot::Sender<Result<u64 /* new_epoch */>>,
    },
    Members {
        reply: oneshot::Sender<Result<Vec<(MemberId, AuthRole)>>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

fn auth_announce_bytes(state: &AuthState) -> Result<Vec<u8>> {
    let ops: Result<Vec<Vec<u8>>> = state.ops().iter().map(SignedOp::encode).collect();
    let msg = ShareMsg::AuthOps { ops: ops? };
    Ok(serde_json::to_vec(&msg)?)
}

/// Apply an incoming `AuthOps` payload to the share's auth state. Persists
/// the log on disk if any op was newly applied. The `payload` is the parsed
/// `ShareMsg::AuthOps.ops` vector.
fn apply_auth_ops(
    state: &mut AuthState,
    payload: Vec<Vec<u8>>,
    data_dir: &Path,
    share_id: &str,
) -> Result<usize> {
    let mut applied = 0usize;
    for raw in payload {
        let op = match SignedOp::decode(&raw) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, share_id = %share_id, "discarding malformed auth op");
                continue;
            }
        };
        match state.apply_remote(op) {
            Ok(true) => applied += 1,
            Ok(false) => {} // duplicate or pending — fine
            Err(e) => {
                tracing::warn!(error = %e, share_id = %share_id, "auth op rejected");
            }
        }
    }
    if applied > 0 {
        auth::save(data_dir, share_id, state)
            .with_context(|| format!("persisting auth.log for share {share_id}"))?;
    }
    Ok(applied)
}

/// Process-wide handle on the running daemon's shared state. Constructed once
/// in `serve()` and handed to both the share-task spawner and the D-Bus IPC
/// surface. Per-share mutation runs inside the share loops; this struct only
/// holds enough plumbing to spawn new ones and look up running ones.
pub struct DaemonRuntime {
    pub data_dir: PathBuf,
    pub identity: SigningKey,
    /// Blob store and fetcher (iroh-blobs on the p2panda endpoint).
    pub transfer: Arc<Transfer>,
    pub gossip: Gossip,
    /// Where p2panda-net looks up peers' addresses; seeded per share from
    /// its bootstrap and member list (`seed_address_book`).
    pub address_book: AddressBook,
    /// `share_id -> mpsc tx for ShareCommand`. Populated when a share task is
    /// spawned, removed on shutdown / `share-remove`.
    pub shares: Arc<Mutex<HashMap<String, mpsc::Sender<ShareCommand>>>>,
    /// All share tasks. The select loop in `serve()` polls this for
    /// unexpected exits; the IPC layer pushes new tasks here on
    /// `ShareAdd`/`ShareJoin`.
    pub tasks: Arc<Mutex<JoinSet<Result<()>>>>,
}

/// Bring up the panda layer, the blob store, and an empty runtime.
/// No share tasks have been spawned yet — the caller (typically `serve()`)
/// loads the on-disk share configs and calls `spawn_share_task` for each.
pub async fn start_runtime(
    data_dir: PathBuf,
    identity: SigningKey,
    relays: Vec<RelayUrl>,
) -> Result<DaemonRuntime> {
    let address_book = AddressBook::builder().spawn().await?;
    let mut builder = Endpoint::builder(address_book.clone()).signing_key(identity.clone());
    if relays.is_empty() {
        tracing::info!("no relay configured; peers on other networks need a routable address");
    }
    for url in relays {
        builder = builder.relay_url(url);
    }
    let endpoint = builder.spawn().await?;
    spawn_own_addr_writer(endpoint.clone(), data_dir.clone());
    // _mdns and _discovery are kept alive for the daemon's lifetime by being
    // borrowed inside long-lived tasks they spawn. We currently don't need to
    // address them explicitly; on a future shutdown path we'd hold them on
    // the runtime to drop in order. For Phase 7 the JoinSet shutdown is the
    // single source of "stop everything."
    let _mdns = MdnsDiscovery::builder(address_book.clone(), endpoint.clone())
        .mode(MdnsDiscoveryMode::Active)
        .spawn()
        .await?;
    let _discovery = Discovery::builder(address_book.clone(), endpoint.clone())
        .spawn()
        .await?;
    let gossip = Gossip::builder(address_book.clone(), endpoint.clone())
        .spawn()
        .await?;
    // Leak the discovery handles into a background task so they live for the
    // process lifetime — same shape as the pre-Phase-7 `_mdns` / `_discovery`
    // bindings on `serve`'s stack.
    tokio::spawn(async move {
        let _hold = (_mdns, _discovery);
        std::future::pending::<()>().await;
    });

    let transfer = Arc::new(
        Transfer::start(&data_dir, endpoint.clone())
            .await
            .context("starting the blob store")?,
    );

    Ok(DaemonRuntime {
        data_dir,
        identity,
        transfer,
        gossip,
        address_book,
        shares: Arc::new(Mutex::new(HashMap::new())),
        tasks: Arc::new(Mutex::new(JoinSet::new())),
    })
}

/// Once the endpoint is online (or after 30 s), write its address to
/// `<data_dir>/endpoint.json` for invites to carry, and refresh it every
/// minute as direct addresses and the home relay change.
fn spawn_own_addr_writer(endpoint: Endpoint, data_dir: PathBuf) {
    tokio::spawn(async move {
        let iroh_ep = match endpoint.endpoint().await {
            Ok(ep) => ep,
            Err(e) => {
                tracing::warn!(error = ?e, "no iroh endpoint; invites won't carry our address");
                return;
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(30), iroh_ep.online()).await;
        loop {
            let addr = iroh_ep.addr();
            if let Err(e) = crate::bootstrap::save_own_addr(&data_dir, &addr) {
                tracing::warn!(error = ?e, "could not save our address");
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

/// Tell p2panda-net where this share's peers are: the inviter's address
/// from the ticket (as a bootstrap node) and every member's interest in
/// the share's topic. Failures are logged; same-LAN peers still find each
/// other over mDNS.
async fn seed_address_book(
    address_book: &AddressBook,
    data_dir: &Path,
    share_id: &str,
    topic: Topic,
    auth_state: &AuthState,
    group_id: MemberId,
    me_hex: &str,
) {
    if let Some(addr) = crate::bootstrap::load_share_bootstrap(data_dir, share_id) {
        if let Err(e) = address_book
            .insert_node_info(NodeInfo::from(addr).bootstrap())
            .await
        {
            tracing::warn!(error = ?e, share_id, "could not add the bootstrap peer");
        }
    }
    for (member, _) in auth_state.members(group_id) {
        if member.to_hex() == me_hex {
            continue;
        }
        let Ok(node_id) = p2panda_core::VerifyingKey::from_bytes(&member.0) else {
            continue;
        };
        if let Err(e) = address_book.add_topic(node_id, topic).await {
            tracing::warn!(error = ?e, share_id, "could not register a member's topic");
        }
    }
}

/// Spawn a share task for `config` and return the `mpsc::Sender<ShareCommand>`
/// the IPC layer uses to drive it. The caller already holds the runtime's
/// `tasks` lock (passed in to make the "check the shares map and spawn"
/// pattern atomic without taking the lock twice).
pub async fn spawn_share_task(
    rt: &DaemonRuntime,
    tasks_guard: &mut JoinSet<Result<()>>,
    config: ShareConfig,
) -> Result<mpsc::Sender<ShareCommand>> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<ShareCommand>(32);
    let key = match crypto::load_or_create_keyring(&rt.data_dir, &config.id) {
        Ok(k) => Arc::new(RwLock::new(k)),
        Err(e) => return Err(e.context("loading share keyring")),
    };
    let auth_state = match auth::load(&rt.data_dir, &config.id) {
        Ok(s) => s,
        Err(e) => return Err(e.context("loading auth log")),
    };
    let pending_rotations = match rotation::load_pending(&rt.data_dir, &config.id) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = ?e, share_id = %config.id,
                "could not load pending rotations; continuing with empty queue");
            Vec::new()
        }
    };
    let transfer = rt.transfer.clone();
    let gossip = rt.gossip.clone();
    let address_book = rt.address_book.clone();
    let identity = rt.identity.clone();
    let data_dir = rt.data_dir.clone();
    let peer_id_hex = identity.verifying_key().to_hex();
    let share_id_for_ctx = config.id.clone();

    tasks_guard.spawn(async move {
        run_share(
            config,
            transfer,
            gossip,
            address_book,
            data_dir,
            peer_id_hex,
            identity,
            key,
            auth_state,
            pending_rotations,
            cmd_rx,
        )
        .await
        .with_context(|| format!("share {share_id_for_ctx} failed"))
    });
    Ok(cmd_tx)
}

/// Configure the daemon's runtime, spawn share tasks for every config on
/// disk, and wait for shutdown. The IPC registration (Phase 7) is layered
/// on top by the caller in `cmd_serve`.
pub async fn serve(
    data_dir: PathBuf,
    identity: SigningKey,
    configs: Vec<ShareConfig>,
    register_dbus: bool,
    relays: Vec<RelayUrl>,
) -> Result<()> {
    let peer_id_hex = identity.verifying_key().to_hex();
    tracing::info!(peer_id = %peer_id_hex, share_count = configs.len(), "daemon starting");

    let rt = Arc::new(start_runtime(data_dir, identity, relays).await?);
    let no_shares_at_start = configs.is_empty();
    if no_shares_at_start {
        tracing::warn!("no shares configured; daemon will idle. Add some with `peerdup share-add` (or via D-Bus).");
    }

    {
        let mut shares = rt.shares.lock().await;
        let mut tasks = rt.tasks.lock().await;
        for config in configs {
            let share_id = config.id.clone();
            match spawn_share_task(&rt, &mut tasks, config).await {
                Ok(tx) => {
                    shares.insert(share_id, tx);
                }
                Err(e) => {
                    tracing::error!(error = ?e, share_id = %share_id,
                        "could not spawn share task; skipping");
                }
            }
        }
    }

    // Optionally register on the session bus. We hold the connection so the
    // bus name stays claimed for the daemon's lifetime; dropping it would
    // un-register us.
    let _dbus_conn: Option<zbus::Connection> = if register_dbus {
        if crate::ipc::session_bus_likely_available() {
            match crate::ipc::register(rt.clone()).await {
                Ok(conn) => Some(conn),
                Err(e) => {
                    tracing::error!(error = ?e,
                        "could not register on session bus; continuing without IPC");
                    None
                }
            }
        } else {
            tracing::info!(
                "no session bus detected (DBUS_SESSION_BUS_ADDRESS unset and \
                 $XDG_RUNTIME_DIR/bus missing); running without D-Bus IPC"
            );
            None
        }
    } else {
        None
    };

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<&'static str>();
    spawn_shutdown_watcher(shutdown_tx);

    // The tasks lock is also held briefly by IPC handlers spawning new
    // share tasks. To avoid blocking the IPC handler while we sit awaiting
    // `join_next()`, we poll the JoinSet on a short timer and release the
    // lock between polls. 250ms is fast enough that a freshly-started share
    // task is observed almost immediately on its (rare) early exit, and
    // long enough that the lock is not the bottleneck.
    loop {
        let join_outcome = {
            let mut tasks = rt.tasks.lock().await;
            if tasks.is_empty() {
                None
            } else {
                // Try to drain at most one finished task non-blockingly.
                let outcome = tokio::select! {
                    biased;
                    sig = &mut shutdown_rx => {
                        match sig {
                            Ok(name) => tracing::info!(signal = name, "shutdown signal received"),
                            Err(_) => tracing::warn!("shutdown watcher dropped without firing"),
                        }
                        // Release the tasks lock before finish_shutdown
                        // re-acquires it, otherwise we self-deadlock on
                        // the async Mutex.
                        drop(tasks);
                        return finish_shutdown(rt.clone()).await;
                    }
                    joined = tasks.join_next() => Some(joined),
                    _ = tokio::time::sleep(Duration::from_millis(250)) => None,
                };
                outcome
            }
        };
        match join_outcome {
            Some(Some(Ok(Ok(())))) => tracing::info!("share task exited cleanly"),
            Some(Some(Ok(Err(e)))) => tracing::error!(error = ?e, "share task returned error"),
            Some(Some(Err(e))) => tracing::error!(error = ?e, "share task join error"),
            Some(None) | None => {
                // No-op tick; either nothing was waiting or the JoinSet was
                // empty. Briefly yield so the IPC handlers can grab locks.
                tokio::select! {
                    biased;
                    sig = &mut shutdown_rx => {
                        match sig {
                            Ok(name) => tracing::info!(signal = name, "shutdown signal received"),
                            Err(_) => tracing::warn!("shutdown watcher dropped without firing"),
                        }
                        return finish_shutdown(rt.clone()).await;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
            }
        }

        // If we started with shares but they've all exited (and no IPC
        // registered any new ones), call it a day.
        let shares_active = !rt.shares.lock().await.is_empty();
        if !shares_active && !no_shares_at_start && !register_dbus {
            tracing::info!("all share tasks have finished");
            return finish_shutdown(rt.clone()).await;
        }
    }
}

async fn finish_shutdown(rt: Arc<DaemonRuntime>) -> Result<()> {
    tracing::info!("aborting remaining tasks");
    let mut tasks = rt.tasks.lock().await;
    tasks.shutdown().await;
    rt.transfer.shutdown().await;
    Ok(())
}

fn spawn_shutdown_watcher(tx: tokio::sync::oneshot::Sender<&'static str>) {
    tokio::spawn(async move {
        let name = wait_for_shutdown_signal().await;
        let _ = tx.send(name);
    });
}

async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let term = signal(SignalKind::terminate());
        let int = signal(SignalKind::interrupt());
        match (term, int) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    _ = term.recv() => "SIGTERM",
                    _ = int.recv() => "SIGINT",
                }
            }
            _ => {
                tracing::warn!("falling back to ctrl_c handler");
                let _ = tokio::signal::ctrl_c().await;
                "ctrl_c"
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "ctrl_c"
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_share(
    config: ShareConfig,
    transfer: Arc<Transfer>,
    gossip: Gossip,
    address_book: AddressBook,
    data_dir: PathBuf,
    peer_id_hex: String,
    identity: SigningKey,
    key: Arc<RwLock<KeyRing>>,
    auth_state: AuthState,
    pending_rotations: Vec<SignedRotation>,
    cmd_rx: mpsc::Receiver<ShareCommand>,
) -> Result<()> {
    // BLAKE3 of the topic string, the same id p2panda-core 0.5's Hash::new gave.
    let topic = Topic::from(*blake3::hash(config.topic.as_bytes()).as_bytes());
    tracing::info!(
        share_id = %config.id,
        topic = %config.topic,
        role = ?config.role,
        auth_ops = auth_state.ops().len(),
        pending_rotations = pending_rotations.len(),
        "starting share"
    );
    config.role.ensure_encrypted()?;
    match config.role {
        ShareRole::Seed | ShareRole::Leech => {
            Err(anyhow!("role {:?} is not supported", config.role))
        }
        ShareRole::Sync => {
            sync_loop(
                config,
                transfer,
                gossip,
                address_book,
                topic,
                data_dir,
                peer_id_hex,
                identity,
                key,
                auth_state,
                pending_rotations,
                cmd_rx,
            )
            .await
        }
    }
}

/// Bidirectional sync. Both peers run this for the same share.
///
/// 3.3: vector clocks decide which announces dominate. Sequential edits in
/// either direction converge. Concurrent edits (each peer ahead on a
/// different counter) are detected and logged but not resolved — that's 3.4.
/// File deletions don't propagate yet — also 3.4.
#[allow(clippy::too_many_arguments)]
async fn sync_loop(
    config: ShareConfig,
    transfer: Arc<Transfer>,
    gossip: Gossip,
    address_book: AddressBook,
    topic: Topic,
    data_dir: PathBuf,
    peer_id_hex: String,
    identity: SigningKey,
    key: Arc<RwLock<KeyRing>>,
    mut auth_state: AuthState,
    mut pending_rotations: Vec<SignedRotation>,
    mut cmd_rx: mpsc::Receiver<ShareCommand>,
) -> Result<()> {
    let root = config.root_path.clone();
    tokio::fs::create_dir_all(&root)
        .await
        .with_context(|| format!("create_dir_all {root:?}"))?;
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalize {root:?}"))?;

    let group_id = auth::group_id_for(&config.id);
    let mut rotation_buffer: Vec<SignedRotation> = Vec::new();

    seed_address_book(
        &address_book,
        &data_dir,
        &config.id,
        topic,
        &auth_state,
        group_id,
        &peer_id_hex,
    )
    .await;
    let topic_handle = gossip.stream(topic).await?;
    let mut sub = topic_handle.subscribe();
    tracing::info!(share_id = %config.id, root = %root.display(), "sync started");

    let mut cache = BlobCache::load(&data_dir, &config.id);
    let mut state = {
        let k = key.read().await;
        reconcile_on_start(
            &config,
            &transfer,
            &root,
            &data_dir,
            &peer_id_hex,
            &k,
            &mut cache,
        )
        .await?
    };
    if let Some(s) = &state {
        publish_sync_announce(&topic_handle, s, &peer_id_hex).await;
    }

    let (_watcher, mut watch_rx) =
        spawn_fs_watcher(&root).with_context(|| format!("watching {root:?}"))?;
    let mut announce_tick = tokio::time::interval(Duration::from_secs(10));
    announce_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    announce_tick.tick().await;

    loop {
        tokio::select! {
            Some(()) = debounce(&mut watch_rx, Duration::from_millis(500)) => {
                let outcome = {
                    let k = key.read().await;
                    handle_local_change(&config, &transfer, &root, &data_dir, &peer_id_hex, &k, state.as_ref(), &mut cache).await
                };
                match outcome {
                    Ok(Some(new_state)) => {
                        tracing::info!(
                            share_id = %config.id,
                            version_hash = %new_state.version_hash,
                            clock = ?new_state.clock.0,
                            "local change detected"
                        );
                        publish_sync_announce(&topic_handle, &new_state, &peer_id_hex).await;
                        state = Some(new_state);
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(error = ?e, share_id = %config.id, "local change check failed"),
                }
            }
            _ = announce_tick.tick() => {
                if let Some(s) = &state {
                    publish_sync_announce(&topic_handle, s, &peer_id_hex).await;
                }
                publish_auth_ops(&topic_handle, &auth_state, &config.id).await;
                publish_pending_rotations(&topic_handle, &pending_rotations, &config.id).await;
            }
            Some(cmd) = cmd_rx.recv() => {
                if handle_share_command(
                    cmd,
                    &config,
                    &data_dir,
                    &identity,
                    &key,
                    &mut auth_state,
                    &mut pending_rotations,
                ).await {
                    return Ok(());
                }
            }
            item = sub.next() => {
                let Some(item) = item else { break Ok(()) };
                let payload = match item {
                    Ok(p) => p,
                    Err(e) => { tracing::debug!(error = %e, "gossip lag"); continue; }
                };
                let msg = match serde_json::from_slice::<ShareMsg>(&payload) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let (manifest, provider, version_hash, clock, timestamp) = match msg {
                    ShareMsg::Announce { manifest, provider, version_hash, clock, timestamp } =>
                        (manifest, provider, version_hash, clock, timestamp),
                    ShareMsg::AuthOps { ops } => {
                        if let Err(e) = apply_auth_ops(&mut auth_state, ops, &data_dir, &config.id) {
                            tracing::warn!(error = ?e, share_id = %config.id, "auth apply failed");
                        }
                        continue;
                    }
                    ShareMsg::KeyRotation(rot) => {
                        if let Err(e) = apply_key_rotation(
                            rot,
                            &auth_state,
                            group_id,
                            &identity,
                            &key,
                            &mut rotation_buffer,
                            &data_dir,
                            &config.id,
                        ).await {
                            tracing::warn!(error = ?e, share_id = %config.id, "key rotation handler failed");
                        }
                        continue;
                    }
                };

                let (Some(remote_vhash), Some(remote_clock), Some(remote_ts)) = (version_hash, clock, timestamp) else {
                    tracing::debug!(share_id = %config.id, "ignoring legacy announce missing required fields");
                    continue;
                };

                let cmp = state.as_ref().map(|s| s.clock.compare(&remote_clock));
                match cmp {
                    Some(ClockOrdering::Equal) => continue,
                    Some(ClockOrdering::SelfDominates) => {
                        tracing::debug!(share_id = %config.id, "ignoring older remote announce");
                        continue;
                    }
                    Some(ClockOrdering::Concurrent) => {
                        let local = state.as_ref().unwrap();
                        let we_win = lww_we_win(local.timestamp, &local.version_hash, remote_ts, &remote_vhash);
                        if we_win {
                            // Local wins. Merge remote's clock into ours (so future
                            // announces dominate), persist, re-announce. No fetch.
                            let mut clock = local.clock.clone();
                            clock.merge(&remote_clock);
                            let new_state = ShareState { clock, ..local.clone() };
                            tracing::warn!(
                                share_id = %config.id,
                                local_ts = %new_state.timestamp,
                                remote_ts = %remote_ts,
                                "concurrent edits; LWW: local wins"
                            );
                            if let Err(e) = persist(&data_dir, &config.id, &new_state) {
                                tracing::warn!(error = ?e, "could not persist state");
                            }
                            publish_sync_announce(&topic_handle, &new_state, &peer_id_hex).await;
                            state = Some(new_state);
                            continue;
                        }
                        tracing::warn!(
                            share_id = %config.id,
                            local_ts = %local.timestamp,
                            remote_ts = %remote_ts,
                            "concurrent edits; LWW: remote wins, fetching"
                        );
                        // fall through to apply remote
                    }
                    Some(ClockOrdering::OtherDominates) | None => {}
                }

                tracing::info!(
                    share_id = %config.id,
                    %remote_vhash,
                    %manifest,
                    %provider,
                    remote_clock = ?remote_clock.0,
                    "received remote announce; applying"
                );
                let apply_outcome = {
                    let k = key.read().await;
                    apply_remote_sync(&transfer, &root, &provider, &manifest, &remote_vhash, &remote_clock, remote_ts, &k, state.as_ref(), &mut cache).await
                };
                match apply_outcome {
                    Ok(new_state) => {
                        if let Err(e) = persist(&data_dir, &config.id, &new_state) {
                            tracing::warn!(error = ?e, "could not persist state");
                        }
                        if let Err(e) = cache.save(&data_dir, &config.id) {
                            tracing::warn!(error = ?e, "could not save blob cache");
                        }
                        publish_sync_announce(&topic_handle, &new_state, &peer_id_hex).await;
                        state = Some(new_state);
                    }
                    Err(e) => tracing::warn!(error = ?e, share_id = %config.id, "apply_remote failed"),
                }
            }
        }
    }
}

/// Dispatch a `ShareCommand` against the share-loop's owned state. Returns
/// `true` iff the loop should exit (Shutdown).
async fn handle_share_command(
    cmd: ShareCommand,
    config: &ShareConfig,
    data_dir: &Path,
    identity: &SigningKey,
    key: &Arc<RwLock<KeyRing>>,
    auth_state: &mut AuthState,
    pending_rotations: &mut Vec<SignedRotation>,
) -> bool {
    match cmd {
        ShareCommand::Invite {
            invitee,
            auth_role,
            suggested_role,
            reply,
        } => {
            let result = handle_invite(
                config,
                data_dir,
                identity,
                key,
                auth_state,
                invitee,
                auth_role,
                suggested_role,
            )
            .await;
            let _ = reply.send(result);
            false
        }
        ShareCommand::Revoke { target, reply } => {
            let result = handle_revoke(
                config,
                data_dir,
                identity,
                key,
                auth_state,
                pending_rotations,
                target,
            )
            .await;
            let _ = reply.send(result);
            false
        }
        ShareCommand::RotateKey { reply } => {
            let result = handle_rotate_key(config, data_dir, key).await;
            let _ = reply.send(result);
            false
        }
        ShareCommand::Members { reply } => {
            let group_id = auth::group_id_for(&config.id);
            let mut members = auth_state.members(group_id);
            members.sort_by_key(|(m, _)| m.0);
            let _ = reply.send(Ok(members));
            false
        }
        ShareCommand::Shutdown { reply } => {
            let _ = reply.send(());
            true
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_invite(
    config: &ShareConfig,
    data_dir: &Path,
    identity: &SigningKey,
    key: &Arc<RwLock<KeyRing>>,
    auth_state: &mut AuthState,
    invitee: MemberId,
    auth_role: AuthRole,
    suggested_role: ShareRole,
) -> Result<String> {
    suggested_role.ensure_encrypted()?;
    let group_id = auth::group_id_for(&config.id);
    if auth_state.is_empty() {
        return Err(anyhow!(
            "share {} has no auth state on disk; can only invite from the creator's machine",
            config.id
        ));
    }
    auth_state.require_owner(group_id, identity)?;
    if auth_state.is_member(group_id, invitee) {
        return Err(anyhow!(
            "{} is already a member of share {}",
            invitee.to_hex(),
            config.id
        ));
    }
    auth_state.add_member(identity, group_id, invitee, auth_role)?;
    auth::save(data_dir, &config.id, auth_state)?;

    let exported = {
        let k = key.read().await;
        k.export_keys()
    };
    let ticket = Ticket {
        version: TICKET_VERSION,
        share_id: config.id.clone(),
        topic: config.topic.clone(),
        keys: exported,
        auth_log: auth_state.ops().to_vec(),
        invitee_pubkey: invitee.0,
        role: suggested_role,
        inviter_addr: crate::bootstrap::load_own_addr(data_dir),
    };
    let _ = ticket::TICKET_VERSION; // touch to keep the import live
    ticket.encode()
}

async fn handle_revoke(
    config: &ShareConfig,
    data_dir: &Path,
    identity: &SigningKey,
    key: &Arc<RwLock<KeyRing>>,
    auth_state: &mut AuthState,
    pending_rotations: &mut Vec<SignedRotation>,
    target: MemberId,
) -> Result<u64> {
    let group_id = auth::group_id_for(&config.id);
    if auth_state.is_empty() {
        return Err(anyhow!("share {} has no auth state on disk", config.id));
    }
    auth_state.require_owner(group_id, identity)?;
    if !auth_state.is_member(group_id, target) {
        return Err(anyhow!(
            "{} is not a current member of share {}",
            target.to_hex(),
            config.id
        ));
    }
    auth_state.remove_member(identity, group_id, target)?;
    auth::save(data_dir, &config.id, auth_state)?;

    let mut remaining: Vec<MemberId> = auth_state
        .members(group_id)
        .into_iter()
        .map(|(m, _role)| m)
        .filter(|m| *m != target)
        .collect();
    remaining.sort_by_key(|m| m.0);

    let new_epoch = crypto::rotate_keyring(data_dir, &config.id)?;
    let new_key_bytes = {
        let ring = crypto::load_or_create_keyring(data_dir, &config.id)?;
        *ring
            .key_for_epoch(new_epoch)
            .ok_or_else(|| anyhow!("rotated keyring missing epoch {new_epoch}"))?
    };
    // Reload the in-memory keyring so encrypt/decrypt sees the new epoch.
    {
        let fresh = crypto::load_or_create_keyring(data_dir, &config.id)?;
        *key.write().await = fresh;
    }

    let rotation_msg =
        rotation::build_signed_rotation(identity, group_id, new_epoch, &new_key_bytes, &remaining)?;
    rotation::save_pending(data_dir, &config.id, &rotation_msg)?;
    // Live broadcasting: append to the in-memory queue so the next announce
    // tick picks it up (no daemon restart needed).
    pending_rotations.push(rotation_msg);

    Ok(new_epoch)
}

async fn handle_rotate_key(
    config: &ShareConfig,
    data_dir: &Path,
    key: &Arc<RwLock<KeyRing>>,
) -> Result<u64> {
    let new_epoch = crypto::rotate_keyring(data_dir, &config.id)?;
    let fresh = crypto::load_or_create_keyring(data_dir, &config.id)?;
    *key.write().await = fresh;
    Ok(new_epoch)
}

#[derive(Debug, Clone)]
struct ShareState {
    /// Deterministic, content-derived. Same content → same hash on every peer.
    version_hash: String,
    /// Hash of this version's encrypted manifest blob in our store; what we
    /// announce. Peers that fetched the version announce the same one.
    manifest_hash: String,
    /// Per-peer counters. Identifies the logical version across peers.
    clock: VectorClock,
    /// When this version was created. Tiebreaker for LWW conflict resolution.
    timestamp: DateTime<Utc>,
    /// Files in this version, relative to the share root. Used for orphan
    /// deletion on apply: files in old manifest but not in new are removed.
    manifest: BTreeSet<PathBuf>,
}

fn persist(data_dir: &Path, share_id: &str, s: &ShareState) -> Result<()> {
    share_state::save(
        data_dir,
        share_id,
        &PersistedState {
            version_hash: s.version_hash.clone(),
            clock: s.clock.clone(),
            timestamp: s.timestamp,
            manifest: s.manifest.clone(),
        },
    )
}

/// Decide initial state at daemon start. Four cases over (persisted, on-disk):
/// - empty share, no persisted state → None (waits for content)
/// - content present, no persisted state → first run; clock = {our_peer: 1}
/// - content matches persisted vhash → resume cleanly at persisted clock
/// - content differs from persisted vhash → out-of-band edit; bump our counter
///
/// Every case with content (re)publishes it to the blob store, which is a
/// cache and may have been wiped.
async fn reconcile_on_start(
    config: &ShareConfig,
    transfer: &Transfer,
    root: &Path,
    data_dir: &Path,
    peer_id_hex: &str,
    key: &KeyRing,
    cache: &mut BlobCache,
) -> Result<Option<ShareState>> {
    let persisted = share_state::load(data_dir, &config.id)?;
    if !has_content(root)? {
        if persisted.is_some() {
            tracing::warn!(
                share_id = %config.id,
                "persisted state exists but share root is empty; waiting for content"
            );
        }
        return Ok(None);
    }

    let (disk_vh, manifest, files) = snapshot_content(root)?;
    let manifest_hash = transfer.publish(root, &files, key, cache).await?;
    cache.save(data_dir, &config.id)?;

    let state = match persisted {
        Some(p) if p.version_hash == disk_vh => {
            tracing::info!(
                share_id = %config.id,
                clock = ?p.clock.0,
                version_hash = %disk_vh,
                "resumed at persisted clock"
            );
            return Ok(Some(ShareState {
                version_hash: disk_vh,
                manifest_hash,
                clock: p.clock,
                timestamp: p.timestamp,
                manifest,
            }));
        }
        Some(p) => {
            let mut clock = p.clock.clone();
            clock.increment(peer_id_hex);
            tracing::info!(share_id = %config.id, clock = ?clock.0, "out-of-band edit detected; bumped clock");
            ShareState {
                version_hash: disk_vh,
                manifest_hash,
                clock,
                timestamp: Utc::now(),
                manifest,
            }
        }
        None => {
            let mut clock = VectorClock::new();
            clock.increment(peer_id_hex);
            tracing::info!(share_id = %config.id, version_hash = %disk_vh, "first run: adopted local content");
            ShareState {
                version_hash: disk_vh,
                manifest_hash,
                clock,
                timestamp: Utc::now(),
                manifest,
            }
        }
    };
    persist(data_dir, &config.id, &state)?;
    Ok(Some(state))
}

#[allow(clippy::too_many_arguments)]
async fn handle_local_change(
    config: &ShareConfig,
    transfer: &Transfer,
    root: &Path,
    data_dir: &Path,
    peer_id_hex: &str,
    key: &KeyRing,
    current: Option<&ShareState>,
    cache: &mut BlobCache,
) -> Result<Option<ShareState>> {
    if !has_content(root)? {
        return Ok(None);
    }
    let (new_vhash, new_manifest, files) = snapshot_content(root)?;
    if current
        .map(|s| s.version_hash == new_vhash)
        .unwrap_or(false)
    {
        return Ok(None);
    }
    let manifest_hash = transfer.publish(root, &files, key, cache).await?;
    cache.save(data_dir, &config.id)?;
    let mut clock = current.map(|s| s.clock.clone()).unwrap_or_default();
    clock.increment(peer_id_hex);
    let new_state = ShareState {
        version_hash: new_vhash,
        manifest_hash,
        clock,
        timestamp: Utc::now(),
        manifest: new_manifest,
    };
    persist(data_dir, &config.id, &new_state)?;
    Ok(Some(new_state))
}

/// Snapshot a share's content: the version hash, the set of relative
/// paths, and each file's plaintext blake3. Every peer computes the same
/// values for the same content.
fn snapshot_content(root: &Path) -> Result<(String, BTreeSet<PathBuf>, Vec<FileHash>)> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    paths.sort();

    let mut files = Vec::with_capacity(paths.len());
    for rel in &paths {
        let abs = root.join(rel);
        let mut file = std::fs::File::open(&abs).with_context(|| format!("opening {abs:?}"))?;
        let mut content_hasher = blake3::Hasher::new();
        std::io::copy(&mut file, &mut content_hasher)
            .with_context(|| format!("hashing {abs:?}"))?;
        files.push((rel.clone(), *content_hasher.finalize().as_bytes()));
    }
    let manifest = paths.into_iter().collect();
    Ok((transfer::version_hash_of(&files), manifest, files))
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir {dir:?}"))? {
        let entry = entry?;
        let name = entry.file_name();
        if name == PEERDUP_DIR_NAME {
            // peerdup's own state, never user content (the watcher ignores
            // it at any depth too).
            continue;
        }
        if name.to_string_lossy().ends_with(".peerdup-tmp") {
            // A fetched file still being staged.
            continue;
        }
        let ft = entry.file_type()?;
        let path = entry.path();
        if ft.is_dir() {
            collect_files(root, &path, out)?;
        } else if ft.is_file() {
            out.push(path.strip_prefix(root)?.to_path_buf());
        }
    }
    Ok(())
}

fn has_content(root: &Path) -> Result<bool> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    Ok(!paths.is_empty())
}

/// Fetch a remote version, verify it, and apply it to the share root.
/// Nothing in the root changes until every file has been fetched,
/// decrypted and checked against the manifest, and the manifest against
/// the announced version hash.
#[allow(clippy::too_many_arguments)]
async fn apply_remote_sync(
    transfer: &Transfer,
    root: &Path,
    provider: &str,
    manifest_hash: &str,
    remote_vhash: &str,
    remote_clock: &VectorClock,
    remote_timestamp: DateTime<Utc>,
    key: &KeyRing,
    current: Option<&ShareState>,
    cache: &mut BlobCache,
) -> Result<ShareState> {
    let staged = transfer
        .fetch(provider, manifest_hash, remote_vhash, root, key, cache)
        .await?;
    let new_manifest: BTreeSet<PathBuf> = staged.files.iter().map(|(p, _)| p.clone()).collect();
    staged.commit(root)?;

    if let Some(s) = current {
        delete_orphans(root, &s.manifest, &new_manifest);
    }

    let mut clock = current.map(|s| s.clock.clone()).unwrap_or_default();
    clock.merge(remote_clock);

    Ok(ShareState {
        version_hash: remote_vhash.to_string(),
        manifest_hash: manifest_hash.to_string(),
        clock,
        timestamp: remote_timestamp,
        manifest: new_manifest,
    })
}

/// LWW tiebreak: later timestamp wins; on tie, lexicographically larger
/// version_hash wins (deterministic — both peers compute the same answer).
fn lww_we_win(
    local_ts: DateTime<Utc>,
    local_vhash: &str,
    remote_ts: DateTime<Utc>,
    remote_vhash: &str,
) -> bool {
    match local_ts.cmp(&remote_ts) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => local_vhash > remote_vhash,
    }
}

fn delete_orphans(root: &Path, old: &BTreeSet<PathBuf>, new: &BTreeSet<PathBuf>) {
    for rel in old.difference(new) {
        let abs = root.join(rel);
        match std::fs::remove_file(&abs) {
            Ok(()) => tracing::info!(path = %rel.display(), "removed orphan"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(error = %e, path = %rel.display(), "failed to remove orphan"),
        }
    }
}

/// Watch the share root recursively. Returns the watcher (which must be kept
/// alive for events to flow) and an unbounded receiver of "something changed"
/// notifications. We don't care about event details — any change just means
/// "recompute the version hash."
fn spawn_fs_watcher(root: &Path) -> Result<(notify::RecommendedWatcher, UnboundedReceiver<()>)> {
    use notify::{RecommendedWatcher, RecursiveMode, Watcher};
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(ev) => {
                // Skip events fully inside the shadow dir — those are our
                // own writes; reacting would make us recompute and re-encrypt
                // forever.
                let all_in_shadow = !ev.paths.is_empty()
                    && ev
                        .paths
                        .iter()
                        .all(|p| p.components().any(|c| c.as_os_str() == PEERDUP_DIR_NAME));
                if !all_in_shadow {
                    let _ = tx.send(());
                }
            }
            Err(e) => tracing::warn!(error = %e, "filesystem watch error"),
        })
        .context("creating notify watcher")?;
    watcher
        .watch(root, RecursiveMode::Recursive)
        .with_context(|| format!("watching {root:?}"))?;
    Ok((watcher, rx))
}

/// Read one event, then keep reading until `settle` elapses without another
/// event, then resolve. Collapses bursts (like an editor's atomic save:
/// unlink + rename + write) into a single "change happened" signal.
///
/// Returns `Some(())` when a debounced change is ready, `None` when the
/// watcher channel has closed.
async fn debounce(rx: &mut UnboundedReceiver<()>, settle: Duration) -> Option<()> {
    rx.recv().await?;
    loop {
        match tokio::time::timeout(settle, rx.recv()).await {
            Ok(Some(())) => continue,
            Ok(None) => return Some(()), // channel closed mid-debounce; deliver what we have
            Err(_) => return Some(()),   // settled
        }
    }
}

async fn publish_sync_announce(handle: &GossipHandle, state: &ShareState, provider: &str) {
    let announce = ShareMsg::Announce {
        manifest: state.manifest_hash.clone(),
        provider: provider.to_string(),
        version_hash: Some(state.version_hash.clone()),
        clock: Some(state.clock.clone()),
        timestamp: Some(state.timestamp),
    };
    if let Ok(bytes) = serde_json::to_vec(&announce) {
        if let Err(e) = handle.publish(bytes).await {
            tracing::warn!(error = %e, "gossip publish failed");
        }
    }
}

async fn publish_auth_ops(handle: &GossipHandle, auth_state: &AuthState, share_id: &str) {
    if auth_state.is_empty() {
        return;
    }
    let bytes = match auth_announce_bytes(auth_state) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, share_id = %share_id, "encoding auth ops failed");
            return;
        }
    };
    if let Err(e) = handle.publish(bytes).await {
        tracing::warn!(error = %e, share_id = %share_id, "gossip publish (auth ops) failed");
    }
}

/// Re-broadcast all queued sealed-box rotations once per announce tick. Keeps
/// peers that joined late (or were offline at revoke time) able to catch up.
async fn publish_pending_rotations(
    handle: &GossipHandle,
    pending: &[SignedRotation],
    share_id: &str,
) {
    for rot in pending {
        let msg = ShareMsg::KeyRotation(rot.clone());
        let bytes = match serde_json::to_vec(&msg) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, share_id = %share_id, epoch = rot.epoch,
                    "encoding rotation failed");
                continue;
            }
        };
        if let Err(e) = handle.publish(bytes).await {
            tracing::warn!(error = %e, share_id = %share_id, epoch = rot.epoch,
                "gossip publish (rotation) failed");
        }
    }
}

/// Receive-side handler for `ShareMsg::KeyRotation`. Verifies, decrypts,
/// installs the new epoch key, then drains any buffered out-of-order
/// rotations whose dependencies are now satisfied.
// Each argument is a separate piece of per-share state owned by the share
// loop; bundling them into a struct would only move the list.
#[allow(clippy::too_many_arguments)]
async fn apply_key_rotation(
    rotation: SignedRotation,
    auth_state: &AuthState,
    group_id: MemberId,
    identity: &SigningKey,
    key: &Arc<RwLock<KeyRing>>,
    rotation_buffer: &mut Vec<SignedRotation>,
    data_dir: &Path,
    share_id: &str,
) -> Result<()> {
    match try_install_rotation(
        &rotation, auth_state, group_id, identity, key, data_dir, share_id,
    )
    .await?
    {
        AppliedOrBuffered::Applied => {
            // Drain buffered rotations whose epochs are now installable.
            drain_rotation_buffer(
                auth_state,
                group_id,
                identity,
                key,
                rotation_buffer,
                data_dir,
                share_id,
            )
            .await;
        }
        AppliedOrBuffered::Idempotent | AppliedOrBuffered::Stale => {}
        AppliedOrBuffered::Buffered => {
            buffer_push(rotation_buffer, rotation);
        }
    }
    Ok(())
}

enum AppliedOrBuffered {
    Applied,
    Idempotent,
    Stale,
    Buffered,
}

async fn try_install_rotation(
    rotation: &SignedRotation,
    auth_state: &AuthState,
    group_id: MemberId,
    identity: &SigningKey,
    key: &Arc<RwLock<KeyRing>>,
    data_dir: &Path,
    share_id: &str,
) -> Result<AppliedOrBuffered> {
    match rotation::verify_and_decrypt(rotation, auth_state, group_id, identity) {
        VerifyOutcome::OkForUs(new_key) => {
            let outcome = crypto::install_epoch_key(data_dir, share_id, rotation.epoch, &new_key)
                .with_context(|| {
                format!(
                    "installing rotation key for share {share_id} at epoch {}",
                    rotation.epoch
                )
            })?;
            match outcome {
                InstallOutcome::Installed => {
                    // Reload the on-disk keyring into the in-memory Arc so
                    // subsequent encrypt/decrypt calls see the new epoch.
                    let fresh =
                        crypto::load_or_create_keyring(data_dir, share_id).with_context(|| {
                            format!("reloading keyring for share {share_id} after install")
                        })?;
                    *key.write().await = fresh;
                    tracing::info!(
                        share_id = %share_id,
                        epoch = rotation.epoch,
                        "installed rotated key"
                    );
                    Ok(AppliedOrBuffered::Applied)
                }
                InstallOutcome::Idempotent => {
                    tracing::debug!(share_id = %share_id, epoch = rotation.epoch,
                        "rotation already installed; ignoring");
                    Ok(AppliedOrBuffered::Idempotent)
                }
                InstallOutcome::Stale => {
                    tracing::debug!(share_id = %share_id, epoch = rotation.epoch,
                        "rotation older than current epoch; ignoring");
                    Ok(AppliedOrBuffered::Stale)
                }
                InstallOutcome::Gap { have, got } => {
                    tracing::info!(share_id = %share_id, have, got,
                        "rotation epoch ahead of local keyring; buffering");
                    Ok(AppliedOrBuffered::Buffered)
                }
            }
        }
        VerifyOutcome::NotForUs => {
            tracing::debug!(share_id = %share_id, epoch = rotation.epoch,
                "rotation has no envelope for us; ignoring");
            Ok(AppliedOrBuffered::Idempotent)
        }
        VerifyOutcome::NotAManager => {
            tracing::warn!(share_id = %share_id, epoch = rotation.epoch,
                rotator = %rotation.rotator_pubkey.to_hex(),
                "rotation rejected: rotator is not a current manager");
            Ok(AppliedOrBuffered::Idempotent)
        }
        VerifyOutcome::BadSignature => {
            tracing::warn!(share_id = %share_id, epoch = rotation.epoch,
                "rotation rejected: bad signature");
            Ok(AppliedOrBuffered::Idempotent)
        }
        VerifyOutcome::DecryptFailed => {
            tracing::warn!(share_id = %share_id, epoch = rotation.epoch,
                "rotation rejected: decrypt failed");
            Ok(AppliedOrBuffered::Idempotent)
        }
    }
}

async fn drain_rotation_buffer(
    auth_state: &AuthState,
    group_id: MemberId,
    identity: &SigningKey,
    key: &Arc<RwLock<KeyRing>>,
    rotation_buffer: &mut Vec<SignedRotation>,
    data_dir: &Path,
    share_id: &str,
) {
    loop {
        if rotation_buffer.is_empty() {
            return;
        }
        // Try installing the smallest-epoch buffered rotation. If it slots in,
        // remove it and try the next; if it gaps again, leave it and stop.
        rotation_buffer.sort_by_key(|r| r.epoch);
        let candidate = rotation_buffer.remove(0);
        match try_install_rotation(
            &candidate, auth_state, group_id, identity, key, data_dir, share_id,
        )
        .await
        {
            Ok(AppliedOrBuffered::Applied)
            | Ok(AppliedOrBuffered::Idempotent)
            | Ok(AppliedOrBuffered::Stale) => continue,
            Ok(AppliedOrBuffered::Buffered) => {
                // Still gapped; put it back and stop draining.
                buffer_push(rotation_buffer, candidate);
                return;
            }
            Err(e) => {
                tracing::warn!(error = ?e, share_id = %share_id,
                    "buffered rotation install errored; dropping");
                continue;
            }
        }
    }
}

/// Bounded push: drop the oldest (lowest-epoch) entry once the buffer fills.
fn buffer_push(buf: &mut Vec<SignedRotation>, rot: SignedRotation) {
    if buf.iter().any(|r| r.epoch == rot.epoch) {
        return;
    }
    if buf.len() >= ROTATION_BUFFER_CAP {
        buf.sort_by_key(|r| r.epoch);
        buf.remove(0);
    }
    buf.push(rot);
}

#[cfg(test)]
mod tests {
    //! Per-share IPC handler tests. Each test builds a tempdir, creates a
    //! fresh share with this peer as Owner, then exercises the
    //! `handle_invite`/`handle_revoke`/`handle_rotate_key` functions
    //! directly (no D-Bus, no JoinSet) so we can assert on the on-disk
    //! and in-memory side-effects.

    use super::*;
    use crate::auth::{group_id_for, AuthRole, AuthState, MemberId};
    use crate::crypto;
    use crate::share::{ShareConfig, ShareRole};

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(label: &str) -> Self {
            let nonce: u64 = rand::random();
            let p = std::env::temp_dir().join(format!("peerdup-ipc-{label}-{nonce:016x}"));
            std::fs::create_dir_all(&p).unwrap();
            TmpDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn me_of(k: &SigningKey) -> MemberId {
        MemberId(*k.verifying_key().as_bytes())
    }

    fn bootstrap(
        label: &str,
    ) -> (
        TmpDir,
        ShareConfig,
        SigningKey,
        AuthState,
        Arc<RwLock<KeyRing>>,
    ) {
        let td = TmpDir::new(label);
        let identity = SigningKey::generate();
        let topic = format!("topic-{label}");
        let config = ShareConfig::new(topic, td.path().join("share-root"), ShareRole::Sync);
        config.save(td.path()).unwrap();
        let group = group_id_for(&config.id);
        let mut auth_state = AuthState::empty();
        auth_state.create_group(&identity, group).unwrap();
        auth::save(td.path(), &config.id, &auth_state).unwrap();
        let ring = crypto::load_or_create_keyring(td.path(), &config.id).unwrap();
        (
            td,
            config,
            identity,
            auth_state,
            Arc::new(RwLock::new(ring)),
        )
    }

    #[tokio::test]
    async fn invite_handler_appends_op_and_returns_ticket() {
        let (td, config, identity, mut auth_state, key) = bootstrap("invite-1");
        let bob = SigningKey::generate();
        let ticket = handle_invite(
            &config,
            td.path(),
            &identity,
            &key,
            &mut auth_state,
            me_of(&bob),
            AuthRole::Writer,
            ShareRole::Sync,
        )
        .await
        .unwrap();
        assert!(!ticket.is_empty(), "ticket must not be empty");

        // Auth log on disk should now contain Create + Add.
        let reloaded = auth::load(td.path(), &config.id).unwrap();
        assert_eq!(reloaded.ops().len(), 2);
        let group = group_id_for(&config.id);
        assert!(reloaded.is_member(group, me_of(&bob)));
    }

    #[tokio::test]
    async fn revoke_handler_rotates_keyring_and_writes_pending() {
        let (td, config, identity, mut auth_state, key) = bootstrap("revoke-1");
        let bob = SigningKey::generate();
        // First add bob.
        handle_invite(
            &config,
            td.path(),
            &identity,
            &key,
            &mut auth_state,
            me_of(&bob),
            AuthRole::Writer,
            ShareRole::Sync,
        )
        .await
        .unwrap();

        let mut pending = Vec::new();
        let new_epoch = handle_revoke(
            &config,
            td.path(),
            &identity,
            &key,
            &mut auth_state,
            &mut pending,
            me_of(&bob),
        )
        .await
        .unwrap();
        assert_eq!(new_epoch, 2);

        // Pending in-memory queue should have one entry; on disk too.
        assert_eq!(pending.len(), 1);
        let on_disk = rotation::load_pending(td.path(), &config.id).unwrap();
        assert_eq!(on_disk.len(), 1);
        assert_eq!(on_disk[0].epoch, 2);

        // Keyring on disk must have grown.
        let ring = crypto::load_or_create_keyring(td.path(), &config.id).unwrap();
        assert_eq!(ring.current_epoch(), 2);

        // The in-memory keyring (held via Arc<RwLock<...>>) must have the
        // new epoch too.
        assert_eq!(key.read().await.current_epoch(), 2);
    }

    #[tokio::test]
    async fn rotate_key_handler_appends_epoch() {
        let (td, config, _identity, _auth_state, key) = bootstrap("rotate-1");
        assert_eq!(key.read().await.current_epoch(), 1);
        let new_epoch = handle_rotate_key(&config, td.path(), &key).await.unwrap();
        assert_eq!(new_epoch, 2);
        assert_eq!(key.read().await.current_epoch(), 2);
    }
}
