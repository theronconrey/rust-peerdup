// SPDX-License-Identifier: MIT
use crate::access::Access;
use crate::announce::{self, Announce};
use crate::auth::{self, AuthRole, AuthState, MemberId, SignedOp};
use crate::clock::{ClockOrdering, VectorClock};
use crate::crypto::{self, InstallOutcome, KeyRing};
use crate::epochs;
use crate::rotation::{self, SignedRotation, VerifyOutcome};
use crate::share::{ShareConfig, ShareRole};
use crate::share_state::{self, PersistedState};
use crate::ticket::{self, Ticket, TICKET_VERSION};
use crate::transfer::{self, BlobCache, FileHash, Transfer, PEERDUP_DIR_NAME};
use crate::wire::{self, ShareMsg};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use p2panda_core::{SigningKey, Topic};
use p2panda_net::addrs::NodeInfo;
use p2panda_net::gossip::{GossipConfig, GossipHandle};
use p2panda_net::iroh_endpoint::RelayUrl;
use p2panda_net::iroh_mdns::MdnsDiscoveryMode;
use p2panda_net::{AddressBook, Discovery, Endpoint, Gossip, MdnsDiscovery};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, Mutex, RwLock};
use tokio::task::JoinSet;

/// Overall limit on fetching one remote version. Each blob also has its
/// own limit (`transfer.rs`); this bounds a version with many files from a
/// provider that is slow but never quite stalls.
const VERSION_FETCH_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Cap the in-memory buffer of out-of-order key rotations per share. 64 epochs
/// is far more than expected; we evict the oldest if we somehow run past it.
const ROTATION_BUFFER_CAP: usize = 64;

/// Manifests refused for their key epochs (`transfer::EpochRefused`) are
/// remembered so their re-announces (every 10 s) aren't fetched again. The
/// memo is cleared when the required epoch changes and when it fills.
const REFUSED_MEMO_CAP: usize = 256;

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

/// Apply an incoming `AuthOps` payload to the share's auth state. Persists
/// the log on disk if any op was newly applied. The `payload` is the parsed
/// `wire::ShareMsg::AuthOps.ops` vector (one chunk of the sender's log).
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
    /// Members-only connection gate on the endpoint (`access.rs`).
    pub access: Arc<Access>,
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
    let access = Arc::new(Access::new(*identity.verifying_key().as_bytes()));
    let mut builder = Endpoint::builder(address_book.clone())
        .signing_key(identity.clone())
        .hooks(access.hook());
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
    // p2panda-net's default limit is 4 KiB, too small for the auth log
    // and key rotations of any real share. Every peer must use the same
    // limit (wire.rs).
    let gossip = Gossip::builder(address_book.clone(), endpoint.clone())
        .config(GossipConfig {
            max_message_size: wire::MAX_GOSSIP_MESSAGE,
            ..Default::default()
        })
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
        access,
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

fn member_ids(auth_state: &AuthState, group_id: MemberId) -> Vec<MemberId> {
    auth_state
        .members(group_id)
        .into_iter()
        .map(|(m, _)| m)
        .collect()
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
    if auth_state.is_empty() {
        // Without its Create op nobody is a member, and the first op that
        // arrived over gossip would define the group. A share gets its log
        // from share-add or from a ticket; anything else is damage.
        return Err(anyhow!(
            "share {} has no auth log ({}); remove it and join again from a fresh ticket",
            config.id,
            auth::auth_log_path(&rt.data_dir, &config.id).display()
        ));
    }
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
    let access = rt.access.clone();
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
            access,
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
    access: Arc<Access>,
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
                access,
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
    access: Arc<Access>,
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
    access
        .set_members(&config.id, member_ids(&auth_state, group_id))
        .await;
    let topic_handle = gossip.stream(topic).await?;
    let mut sub = topic_handle.subscribe();
    tracing::info!(share_id = %config.id, root = %root.display(), "sync started");

    let mut cache = BlobCache::load(&data_dir, &config.id);
    // The required epoch (`epochs`) is recomputed from the auth state and
    // the floor wherever it's used; both only change on this loop.
    let mut epoch_floor = crypto::load_epoch_floor(&data_dir, &config.id);
    let required_now =
        |auth: &AuthState, floor: u64| epochs::required(auth.required_epoch(), floor);
    let mut state = {
        let k = key.read().await;
        reconcile_on_start(
            &config,
            &transfer,
            &root,
            &data_dir,
            &peer_id_hex,
            &k,
            required_now(&auth_state, epoch_floor),
            &mut cache,
        )
        .await?
    };
    if let Some(s) = &state {
        publish_sync_announce(
            &topic_handle,
            s,
            &identity,
            group_id,
            &auth_state,
            required_now(&auth_state, epoch_floor),
        )
        .await;
    }

    let (_watcher, watch_tx, mut watch_rx) =
        spawn_fs_watcher(&root).with_context(|| format!("watching {root:?}"))?;
    let mut announce_tick = tokio::time::interval(Duration::from_secs(10));
    announce_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    announce_tick.tick().await;

    // Remote versions are fetched and staged off this loop, so a slow
    // provider can't hold up IPC commands, auth ops, rotations or local
    // changes. At most one fetch runs per share; the newest announce that
    // arrives meanwhile waits in `next`. Dropping `fetch` aborts the task,
    // and its staged files are removed.
    let (fetch_tx, mut fetch_rx) = mpsc::channel::<FetchDone>(1);
    const SETTLE: Duration = Duration::from_millis(500);
    let mut change_due: Option<tokio::time::Instant> = None;
    let mut fetch: Option<FetchTask> = None;
    let mut next: Option<RemoteVersion> = None;
    let mut generation: u64 = 0;
    // A local change (or the first run's content) waits for the rotated
    // key: set when `publish_current` held something back.
    let mut held_back = state.is_none();
    // The keyring epoch we last re-encrypted under (or tried to), so a
    // republish is attempted once per epoch, not on every message.
    let mut republished_at: u64 = state.as_ref().map_or(0, |s| s.epoch);
    // Manifests refused for their key epochs, and the required epoch the
    // memo was built under.
    let mut refused: HashSet<String> = HashSet::new();
    let mut refused_under = required_now(&auth_state, epoch_floor);

    loop {
        // Whenever the keyring has advanced past the version we publish
        // (a revocation or rotation here, or a rotated key installed from
        // gossip), or a change waited for the key, publish now: the same
        // version re-encrypted with the same clock, or a new one. Readers
        // record their own changes but have nothing to re-announce.
        let required = required_now(&auth_state, epoch_floor);
        if required != refused_under {
            refused.clear();
            refused_under = required;
        }
        let have = key.read().await.current_epoch();
        let stale = state.as_ref().is_some_and(|s| {
            epochs::needs_republish(s.epoch, have, required)
                && announce::may_publish(&auth_state, group_id, &identity)
        });
        if epochs::may_encrypt(have, required) && (held_back || (stale && have > republished_at)) {
            held_back = false;
            republished_at = have;
            let outcome = {
                let k = key.read().await;
                publish_current(
                    &config,
                    &transfer,
                    &root,
                    &data_dir,
                    &peer_id_hex,
                    &k,
                    required,
                    state.as_ref(),
                    &mut cache,
                )
                .await
            };
            if let Some(s) = handle_published(
                outcome,
                &config.id,
                &topic_handle,
                &identity,
                group_id,
                &auth_state,
                required,
                &mut held_back,
            )
            .await
            {
                state = Some(s);
            }
        }

        tokio::select! {
            // Debounce: every event pushes the deadline back; the check runs
            // once things have been quiet for SETTLE. Both arms are
            // cancel-safe, so an event is never lost when another arm wins
            // the select (the old `debounce()` future consumed the first
            // event and dropped it whenever that happened).
            Some(()) = watch_rx.recv() => {
                change_due = Some(tokio::time::Instant::now() + SETTLE);
            }
            _ = sleep_until_due(change_due) => {
                change_due = None;
                tracing::debug!(share_id = %config.id, "filesystem changed; checking for a new version");
                let outcome = {
                    let k = key.read().await;
                    publish_current(&config, &transfer, &root, &data_dir, &peer_id_hex, &k, required, state.as_ref(), &mut cache).await
                };
                if let Some(s) = handle_published(outcome, &config.id, &topic_handle, &identity, group_id, &auth_state, required, &mut held_back).await {
                    state = Some(s);
                }
            }
            _ = announce_tick.tick() => {
                if let Some(s) = &state {
                    publish_sync_announce(&topic_handle, s, &identity, group_id, &auth_state, required).await;
                }
                publish_auth_ops(&topic_handle, &auth_state, &config.id).await;
                publish_pending_rotations(&topic_handle, &pending_rotations, &config.id).await;
            }
            Some(cmd) = cmd_rx.recv() => {
                let exit = handle_share_command(
                    cmd,
                    &config,
                    &data_dir,
                    &identity,
                    &key,
                    &mut auth_state,
                    &mut pending_rotations,
                    epoch_floor,
                ).await;
                if exit {
                    access.remove_share(&config.id).await;
                    return Ok(());
                }
                // An invite or a revocation may have changed who's in.
                access.set_members(&config.id, member_ids(&auth_state, group_id)).await;
            }
            item = sub.next() => {
                let Some(item) = item else { break Ok(()) };
                let payload = match item {
                    Ok(p) => p,
                    Err(e) => { tracing::debug!(error = %e, "gossip lag"); continue; }
                };
                let Some(msg) = wire::decode(&payload) else {
                    tracing::debug!(share_id = %config.id, len = payload.len(), "ignoring a message that isn't wire v4");
                    continue;
                };
                let ann = match msg {
                    ShareMsg::Announce(ann) => ann,
                    ShareMsg::AuthOps { ops } => {
                        match apply_auth_ops(&mut auth_state, ops, &data_dir, &config.id) {
                            Ok(0) => {}
                            Ok(_) => access.set_members(&config.id, member_ids(&auth_state, group_id)).await,
                            Err(e) => tracing::warn!(error = ?e, share_id = %config.id, "auth apply failed"),
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
                            &mut epoch_floor,
                        ).await {
                            tracing::warn!(error = ?e, share_id = %config.id, "key rotation handler failed");
                        }
                        continue;
                    }
                };

                if ann.provider == peer_id_hex {
                    continue; // our own, echoed back
                }
                if let Err(e) = ann.verify(&auth_state, group_id) {
                    tracing::warn!(error = %e, share_id = %config.id, provider = %ann.provider, "ignoring announce");
                    continue;
                }
                if refused.contains(&ann.manifest) {
                    tracing::debug!(share_id = %config.id, manifest = %ann.manifest,
                        "ignoring a re-announce of a version refused for its key epoch");
                    continue;
                }
                let Announce {
                    manifest,
                    provider,
                    version_hash: remote_vhash,
                    clock: remote_clock,
                    timestamp: remote_ts,
                    ..
                } = ann;

                let remote = RemoteVersion {
                    manifest,
                    provider,
                    version_hash: remote_vhash,
                    clock: remote_clock,
                    timestamp: remote_ts,
                };
                // A peer announcing our exact version has it: it becomes
                // the base later concurrent edits are measured against.
                if let Some(s) = state.as_mut() {
                    if s.clock == remote.clock && s.version_hash == remote.version_hash && s.base != s.manifest {
                        s.base = s.manifest.clone();
                        if let Err(e) = persist(&data_dir, &config.id, s) {
                            tracing::warn!(error = ?e, "could not persist state");
                        }
                    }
                }
                match judge(&config.id, state.as_ref(), &remote) {
                    Verdict::Ignore | Verdict::LocalWins => {}
                    Verdict::Fetch { .. } if fetch.is_some() => {
                        // One fetch per share at a time; keep the newest
                        // version that isn't older than the one waiting.
                        let older = next
                            .as_ref()
                            .is_some_and(|n| n.clock.compare(&remote.clock) == ClockOrdering::SelfDominates);
                        if !older {
                            tracing::debug!(share_id = %config.id, "a fetch is running; queued the announce");
                            next = Some(remote);
                        }
                    }
                    Verdict::Fetch { .. } => {
                        fetch = Some(start_fetch(&mut generation, remote, &config.id, &transfer, &root, &key, required, &fetch_tx).await);
                    }
                }
            }
            Some(done) = fetch_rx.recv() => {
                if fetch.as_ref().map(|f| f.generation) != Some(done.generation) {
                    tracing::debug!(share_id = %config.id, "discarding the result of a superseded fetch");
                    continue;
                }
                fetch = None;
                let FetchDone { remote, result, .. } = done;
                // Check the key epoch again against the required epoch as
                // it is *now*: a revocation may have arrived mid-fetch.
                let result = result.and_then(|staged| {
                    transfer::check_version_epochs(staged.epoch, std::iter::empty::<u64>(), required)?;
                    Ok(staged)
                });
                match result {
                    Err(e) => match e.downcast_ref::<transfer::EpochRefused>() {
                        Some(refusal) => {
                            tracing::warn!(share_id = %config.id, provider = %remote.provider,
                                manifest = %remote.manifest, version_hash = %remote.version_hash,
                                "refused a remote version: {refusal}");
                            if refused.len() >= REFUSED_MEMO_CAP {
                                refused.clear();
                            }
                            refused.insert(remote.manifest.clone());
                        }
                        None => tracing::warn!(error = ?e, share_id = %config.id, "apply_remote failed"),
                    },
                    // The share may have moved on while the fetch ran (a
                    // local edit, or a version applied in between), so
                    // decide again before touching the root.
                    Ok(staged) => match judge(&config.id, state.as_ref(), &remote) {
                        Verdict::Ignore => {
                            tracing::info!(share_id = %config.id, version_hash = %remote.version_hash,
                                "fetched version is no longer newer; discarding");
                        }
                        Verdict::LocalWins => drop(staged),
                        Verdict::Fetch { concurrent } => match commit_remote(&root, staged, &remote, state.as_ref(), &mut cache, concurrent, &peer_id_hex[..8]) {
                            Ok((new_state, rescan)) => {
                                if rescan {
                                    // Conflict copies or files kept from our
                                    // side: publish them as a newer version.
                                    let _ = watch_tx.send(());
                                }
                                tracing::info!(share_id = %config.id, version_hash = %new_state.version_hash,
                                    epoch = new_state.epoch, "applied remote version");
                                if let Err(e) = persist(&data_dir, &config.id, &new_state) {
                                    tracing::warn!(error = ?e, "could not persist state");
                                }
                                if let Err(e) = cache.save(&data_dir, &config.id) {
                                    tracing::warn!(error = ?e, "could not save blob cache");
                                }
                                publish_sync_announce(&topic_handle, &new_state, &identity, group_id, &auth_state, required).await;
                                state = Some(new_state);
                            }
                            Err(e) => tracing::warn!(error = ?e, share_id = %config.id, "apply_remote failed"),
                        },
                    },
                }
                if let Some(queued) = next.take() {
                    match judge(&config.id, state.as_ref(), &queued) {
                        Verdict::Fetch { .. } if refused.contains(&queued.manifest) => {}
                        Verdict::Fetch { .. } => {
                            fetch = Some(start_fetch(&mut generation, queued, &config.id, &transfer, &root, &key, required, &fetch_tx).await);
                        }
                        Verdict::Ignore | Verdict::LocalWins => {}
                    }
                }
            }
        }
    }
}

/// Log and announce what `publish_current` did, and return the new state
/// if there is one. A held-back change sets `held_back`, so the loop
/// publishes it once the rotated key arrives.
#[allow(clippy::too_many_arguments)]
async fn handle_published(
    outcome: Result<Published>,
    share_id: &str,
    topic_handle: &GossipHandle,
    identity: &SigningKey,
    group_id: MemberId,
    auth_state: &AuthState,
    required: u64,
    held_back: &mut bool,
) -> Option<ShareState> {
    let new_state = match outcome {
        Ok(Published::Unchanged) => return None,
        Ok(Published::Held { have, required }) => {
            *held_back = true;
            tracing::info!(
                share_id,
                have,
                required,
                "local change waits for the rotated key from a revocation; \
                 it is published once the key arrives"
            );
            return None;
        }
        Ok(Published::New(s)) => {
            tracing::info!(
                share_id,
                version_hash = %s.version_hash,
                clock = ?s.clock.0,
                epoch = s.epoch,
                "local change detected"
            );
            if !announce::may_publish(auth_state, group_id, identity) {
                tracing::warn!(
                    share_id,
                    "you are a Reader of this share; local changes are not shared"
                );
            }
            s
        }
        Ok(Published::Republished(s)) => {
            tracing::info!(
                share_id,
                version_hash = %s.version_hash,
                manifest = %s.manifest_hash,
                "republished under epoch {}",
                s.epoch
            );
            s
        }
        Err(e) => {
            tracing::warn!(error = ?e, share_id, "publishing the current version failed");
            return None;
        }
    };
    publish_sync_announce(
        topic_handle,
        &new_state,
        identity,
        group_id,
        auth_state,
        required,
    )
    .await;
    Some(new_state)
}

/// Dispatch a `ShareCommand` against the share-loop's owned state. Returns
/// `true` iff the loop should exit (Shutdown).
#[allow(clippy::too_many_arguments)]
async fn handle_share_command(
    cmd: ShareCommand,
    config: &ShareConfig,
    data_dir: &Path,
    identity: &SigningKey,
    key: &Arc<RwLock<KeyRing>>,
    auth_state: &mut AuthState,
    pending_rotations: &mut Vec<SignedRotation>,
    epoch_floor: u64,
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
                epoch_floor,
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
                epoch_floor,
            )
            .await;
            let _ = reply.send(result);
            false
        }
        ShareCommand::RotateKey { reply } => {
            let result = handle_rotate_key(
                config,
                data_dir,
                identity,
                key,
                auth_state,
                pending_rotations,
                epoch_floor,
            )
            .await;
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
    epoch_floor: u64,
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
    epochs::check_invite(
        key.read().await.current_epoch(),
        epochs::required(auth_state.required_epoch(), epoch_floor),
    )?;
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

#[allow(clippy::too_many_arguments)]
async fn handle_revoke(
    config: &ShareConfig,
    data_dir: &Path,
    identity: &SigningKey,
    key: &Arc<RwLock<KeyRing>>,
    auth_state: &mut AuthState,
    pending_rotations: &mut Vec<SignedRotation>,
    target: MemberId,
    epoch_floor: u64,
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
    // The key minted below must satisfy the required epoch after this
    // removal; checked before the Remove is authored, so a refusal leaves
    // no removal without its rotation.
    epochs::check_mint(
        key.read().await.current_epoch(),
        epochs::required(auth_state.required_epoch() + 1, epoch_floor),
    )?;
    auth_state.remove_member(identity, group_id, target)?;
    auth::save(data_dir, &config.id, auth_state)?;

    let mut remaining: Vec<MemberId> = auth_state
        .members(group_id)
        .into_iter()
        .map(|(m, _role)| m)
        .filter(|m| *m != target)
        .collect();
    remaining.sort_by_key(|m| m.0);

    let (new_epoch, chunks) =
        rotation::mint_and_queue(data_dir, &config.id, identity, group_id, &remaining)?;
    // Reload the in-memory keyring so encrypt/decrypt sees the new epoch.
    {
        let fresh = crypto::load_or_create_keyring(data_dir, &config.id)?;
        *key.write().await = fresh;
    }
    // Live broadcasting: append to the in-memory queue so the next announce
    // tick picks it up (no daemon restart needed).
    pending_rotations.extend(chunks);

    Ok(new_epoch)
}

/// Rotate the share key without revoking anyone. Owners only, and the new
/// key is sent to every other member, like a revocation's: before, the
/// key stayed on this machine, so after the share loop re-encrypted its
/// current version under it (it does that whenever the keyring advances)
/// no other member could read the share.
async fn handle_rotate_key(
    config: &ShareConfig,
    data_dir: &Path,
    identity: &SigningKey,
    key: &Arc<RwLock<KeyRing>>,
    auth_state: &AuthState,
    pending_rotations: &mut Vec<SignedRotation>,
    epoch_floor: u64,
) -> Result<u64> {
    let group_id = auth::group_id_for(&config.id);
    auth_state.require_owner(group_id, identity)?;
    epochs::check_mint(
        key.read().await.current_epoch(),
        epochs::required(auth_state.required_epoch(), epoch_floor),
    )?;
    let me = MemberId(*identity.verifying_key().as_bytes());
    let mut others = member_ids(auth_state, group_id);
    others.retain(|m| *m != me);
    others.sort_by_key(|m| m.0);
    let (new_epoch, chunks) =
        rotation::mint_and_queue(data_dir, &config.id, identity, group_id, &others)?;
    let fresh = crypto::load_or_create_keyring(data_dir, &config.id)?;
    *key.write().await = fresh;
    pending_rotations.extend(chunks);
    Ok(new_epoch)
}

#[derive(Debug, Clone)]
struct ShareState {
    /// Deterministic, content-derived. Same content → same hash on every peer.
    version_hash: String,
    /// Hash of this version's encrypted manifest blob in our store; what we
    /// announce. Peers that fetched the version announce the same one.
    /// Empty while nothing is published (`epoch` 0).
    manifest_hash: String,
    /// Key epoch the manifest (and every file blob) is encrypted under; 0
    /// if not published, which happens when the daemon starts while it
    /// waits for a revocation's rotated key. Only a version at or above
    /// the required epoch is announced (`epochs::announceable`).
    epoch: u64,
    /// Per-peer counters. Identifies the logical version across peers.
    clock: VectorClock,
    /// When this version was created. Tiebreaker for LWW conflict resolution.
    timestamp: DateTime<Utc>,
    /// Files in this version, relative to the share root, with the
    /// plaintext hash we published or applied. Orphan deletion and
    /// conflict copies compare the disk against it.
    manifest: FileMap,
    /// Files of the last version known to be shared with a peer: one we
    /// applied, or ours when a peer announced it back. A concurrent apply
    /// counts a file as changed by us if it differs from this.
    base: FileMap,
}

/// Path (relative to the share root) to the blake3 of its plaintext.
type FileMap = BTreeMap<PathBuf, [u8; 32]>;

fn to_hex_map(m: &FileMap) -> BTreeMap<PathBuf, String> {
    m.iter()
        .map(|(p, h)| (p.clone(), blake3::Hash::from_bytes(*h).to_hex().to_string()))
        .collect()
}

fn from_hex_map(m: &BTreeMap<PathBuf, String>) -> FileMap {
    m.iter()
        .filter_map(|(p, h)| Some((p.clone(), *blake3::Hash::from_hex(h).ok()?.as_bytes())))
        .collect()
}

fn persist(data_dir: &Path, share_id: &str, s: &ShareState) -> Result<()> {
    share_state::save(
        data_dir,
        share_id,
        &PersistedState {
            format: share_state::STATE_FORMAT,
            version_hash: s.version_hash.clone(),
            clock: s.clock.clone(),
            timestamp: s.timestamp,
            manifest: s.manifest.keys().cloned().collect(),
            files: to_hex_map(&s.manifest),
            base: to_hex_map(&s.base),
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
/// cache and may have been wiped, under the current key epoch.
///
/// While the keyring is below the required epoch (a revocation's rotated
/// key hasn't arrived), nothing is encrypted: the persisted version comes
/// back unpublished (`epoch` 0) and the share loop publishes it, and any
/// out-of-band edit, once the key is here (`epochs::needs_republish`).
#[allow(clippy::too_many_arguments)]
async fn reconcile_on_start(
    config: &ShareConfig,
    transfer: &Transfer,
    root: &Path,
    data_dir: &Path,
    peer_id_hex: &str,
    key: &KeyRing,
    required: u64,
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

    let epoch = key.current_epoch();
    if !epochs::may_encrypt(epoch, required) {
        tracing::info!(
            share_id = %config.id,
            have = epoch,
            required,
            "this share had a revocation and its rotated key hasn't arrived; \
             nothing is published until it does"
        );
        return Ok(persisted.map(|p| ShareState {
            version_hash: p.version_hash,
            manifest_hash: String::new(),
            epoch: 0,
            clock: p.clock,
            timestamp: p.timestamp,
            manifest: from_hex_map(&p.files),
            base: from_hex_map(&p.base),
        }));
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
                epoch,
                "resumed at persisted clock"
            );
            return Ok(Some(ShareState {
                version_hash: disk_vh,
                manifest_hash,
                epoch,
                clock: p.clock,
                timestamp: p.timestamp,
                manifest,
                base: from_hex_map(&p.base),
            }));
        }
        Some(p) => {
            let mut clock = p.clock.clone();
            clock.increment(peer_id_hex);
            tracing::info!(share_id = %config.id, clock = ?clock.0, epoch,
                "out-of-band edit detected; bumped clock");
            ShareState {
                version_hash: disk_vh,
                manifest_hash,
                epoch,
                clock,
                timestamp: Utc::now(),
                manifest,
                base: from_hex_map(&p.base),
            }
        }
        None => {
            let mut clock = VectorClock::new();
            clock.increment(peer_id_hex);
            tracing::info!(share_id = %config.id, version_hash = %disk_vh, epoch,
                "first run: adopted local content");
            ShareState {
                version_hash: disk_vh,
                manifest_hash,
                epoch,
                clock,
                timestamp: Utc::now(),
                manifest,
                base: FileMap::new(),
            }
        }
    };
    persist(data_dir, &config.id, &state)?;
    Ok(Some(state))
}

/// What `publish_current` did.
#[derive(Debug)]
enum Published {
    /// Nothing to do: no content, or the current version is on disk and
    /// already published under the current key.
    Unchanged,
    /// There is something to publish, but the keyring is below the
    /// required epoch: nothing was encrypted. The share loop tries again
    /// once the key arrives.
    Held { have: u64, required: u64 },
    /// A new version (local change): the clock was bumped.
    New(ShareState),
    /// The same version (same version hash, clock and timestamp)
    /// re-encrypted under the current key: a new manifest hash only.
    Republished(ShareState),
}

/// Publish what is on disk: a new version if the content changed, or the
/// current version again if it is encrypted under an older key epoch than
/// the keyring's (after a rotation). Nothing is encrypted while the
/// keyring is below `required`.
#[allow(clippy::too_many_arguments)]
async fn publish_current(
    config: &ShareConfig,
    transfer: &Transfer,
    root: &Path,
    data_dir: &Path,
    peer_id_hex: &str,
    key: &KeyRing,
    required: u64,
    current: Option<&ShareState>,
    cache: &mut BlobCache,
) -> Result<Published> {
    if !has_content(root)? {
        return Ok(Published::Unchanged);
    }
    let (new_vhash, new_manifest, files) = snapshot_content(root)?;
    tracing::debug!(share_id = %config.id, files = files.len(), "snapshot taken");
    let epoch = key.current_epoch();
    let changed = current.is_none_or(|s| s.version_hash != new_vhash);
    let stale = current.is_some_and(|s| s.epoch < epoch);
    if !changed && !stale {
        return Ok(Published::Unchanged);
    }
    if !epochs::may_encrypt(epoch, required) {
        return Ok(Published::Held {
            have: epoch,
            required,
        });
    }
    let manifest_hash = transfer.publish(root, &files, key, cache).await?;
    tracing::debug!(share_id = %config.id, epoch, "published to the blob store");
    cache.save(data_dir, &config.id)?;
    let next = next_state(
        current,
        new_vhash,
        new_manifest,
        manifest_hash,
        epoch,
        peer_id_hex,
        Utc::now(),
    );
    persist(data_dir, &config.id, &next)?;
    Ok(if changed {
        Published::New(next)
    } else {
        Published::Republished(next)
    })
}

/// The state after publishing `version_hash` as `manifest_hash` under
/// `epoch`. Only a content change is a new version and bumps our clock
/// counter; re-encrypting the same content keeps the clock and the
/// timestamp, so peers that have it compare `Equal` and fetch nothing.
fn next_state(
    current: Option<&ShareState>,
    version_hash: String,
    manifest: FileMap,
    manifest_hash: String,
    epoch: u64,
    peer_id_hex: &str,
    now: DateTime<Utc>,
) -> ShareState {
    match current {
        Some(s) if s.version_hash == version_hash => ShareState {
            manifest_hash,
            epoch,
            manifest,
            ..s.clone()
        },
        _ => {
            let mut clock = current.map(|s| s.clock.clone()).unwrap_or_default();
            clock.increment(peer_id_hex);
            ShareState {
                version_hash,
                manifest_hash,
                epoch,
                clock,
                timestamp: now,
                manifest,
                base: current.map(|s| s.base.clone()).unwrap_or_default(),
            }
        }
    }
}

/// Snapshot a share's content: the version hash, the set of relative
/// paths, and each file's plaintext blake3. Every peer computes the same
/// values for the same content.
fn snapshot_content(root: &Path) -> Result<(String, FileMap, Vec<FileHash>)> {
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
    let manifest = files.iter().cloned().collect();
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

/// A verified remote version that may be fetched.
#[derive(Clone, Debug)]
struct RemoteVersion {
    manifest: String,
    provider: String,
    version_hash: String,
    clock: VectorClock,
    timestamp: DateTime<Utc>,
}

/// What to do with a remote version, given where the share is now.
enum Verdict {
    /// Older than or equal to ours.
    Ignore,
    /// Concurrent, and ours wins last-writer-wins: keep our version as it
    /// is. Our clock is deliberately *not* merged with theirs: that would
    /// make our version dominate theirs without containing their changes,
    /// and the other side would then apply it as a fast-forward and lose
    /// those changes without a conflict copy. Instead the other side, which
    /// loses the same comparison, applies ours as a concurrent version
    /// (keeping conflict copies) and its merged result dominates both.
    LocalWins,
    /// Newer (`concurrent: false`), or concurrent and it wins: fetch and
    /// apply it.
    Fetch { concurrent: bool },
}

fn judge(share_id: &str, state: Option<&ShareState>, remote: &RemoteVersion) -> Verdict {
    let Some(local) = state else {
        return Verdict::Fetch { concurrent: false };
    };
    match local.clock.compare(&remote.clock) {
        ClockOrdering::Equal => Verdict::Ignore,
        ClockOrdering::SelfDominates => {
            tracing::debug!(share_id, "ignoring older remote announce");
            Verdict::Ignore
        }
        ClockOrdering::OtherDominates => Verdict::Fetch { concurrent: false },
        ClockOrdering::Concurrent => {
            if lww_we_win(
                local.timestamp,
                &local.version_hash,
                remote.timestamp,
                &remote.version_hash,
            ) {
                tracing::warn!(
                    share_id,
                    local_ts = %local.timestamp,
                    remote_ts = %remote.timestamp,
                    "concurrent edits; LWW: local wins"
                );
                Verdict::LocalWins
            } else {
                tracing::warn!(
                    share_id,
                    local_ts = %local.timestamp,
                    remote_ts = %remote.timestamp,
                    "concurrent edits; LWW: remote wins, fetching"
                );
                Verdict::Fetch { concurrent: true }
            }
        }
    }
}

/// A fetch running in its own task. Dropping this aborts it.
struct FetchTask {
    generation: u64,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for FetchTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

struct FetchDone {
    generation: u64,
    remote: RemoteVersion,
    result: Result<transfer::StagedVersion>,
}

/// Fetch, verify and stage `remote` in a task of its own, with a copy of
/// the keyring (a read lock held across the fetch would block a rotation
/// from installing). The result comes back on `tx`, tagged with a fresh
/// generation.
/// `min_epoch` is the required epoch when the fetch starts; the loop
/// checks the staged version again at commit time against the required
/// epoch then.
#[allow(clippy::too_many_arguments)]
async fn start_fetch(
    generation: &mut u64,
    remote: RemoteVersion,
    share_id: &str,
    transfer: &Arc<Transfer>,
    root: &Path,
    key: &Arc<RwLock<KeyRing>>,
    min_epoch: u64,
    tx: &mpsc::Sender<FetchDone>,
) -> FetchTask {
    *generation += 1;
    let generation = *generation;
    tracing::info!(
        share_id,
        remote_vhash = %remote.version_hash,
        manifest = %remote.manifest,
        provider = %remote.provider,
        remote_clock = ?remote.clock.0,
        "received remote announce; applying"
    );
    let transfer = transfer.clone();
    let root = root.to_path_buf();
    let key = key.read().await.clone();
    let tx = tx.clone();
    let handle = tokio::spawn(async move {
        let result = tokio::time::timeout(
            VERSION_FETCH_TIMEOUT,
            transfer.fetch(
                &remote.provider,
                &remote.manifest,
                &remote.version_hash,
                &root,
                &key,
                min_epoch,
            ),
        )
        .await
        .unwrap_or_else(|_| {
            Err(anyhow!(
                "fetching the version took longer than {VERSION_FETCH_TIMEOUT:?}"
            ))
        });
        // If the share loop is gone, the staged files are removed when the
        // unsent result drops.
        let _ = tx
            .send(FetchDone {
                generation,
                remote,
                result,
            })
            .await;
    });
    FetchTask { generation, handle }
}

/// Apply a fetched, verified version to the share root and return the new
/// state, plus whether files of ours were kept (so the caller publishes
/// them as a newer version). Runs on the share loop, after `judge` said
/// the version still wins.
///
/// Local content is never silently lost. A file the new version would
/// overwrite or remove is moved to a conflict copy
/// (`name (conflict from <our id> <date>).ext`) when it holds changes the
/// other side hasn't seen:
/// - `concurrent: false` (the version descends from ours): the file
///   differs from what we last published or applied (`manifest`), i.e. an
///   edit not yet announced;
/// - `concurrent: true` (both sides changed; theirs won last-writer-wins):
///   the file differs from the last version both sides had (`base`). A
///   file we added that the other side never had is kept under its own
///   name; one unchanged since the base that they removed is removed.
///
/// Conflict copies and kept files are new local files: the watcher
/// publishes them as a version that dominates, so both sides converge
/// with one copy. Last-writer-wins only decides which content keeps the
/// original name.
fn commit_remote(
    root: &Path,
    staged: transfer::StagedVersion,
    remote: &RemoteVersion,
    current: Option<&ShareState>,
    cache: &mut BlobCache,
    concurrent: bool,
    me_short: &str,
) -> Result<(ShareState, bool)> {
    let incoming: FileMap = staged.files.iter().cloned().collect();
    let epoch = staged.epoch;
    let empty = FileMap::new();
    let (recorded, base) = current
        .map(|s| (&s.manifest, &s.base))
        .unwrap_or((&empty, &empty));
    // Did we change this file, as far as the other side knows?
    let ours = |rel: &Path, disk: &[u8; 32]| {
        let known = if concurrent { base } else { recorded };
        known.get(rel) != Some(disk)
    };
    let now = Utc::now();
    let mut kept = false;

    for (rel, theirs) in &incoming {
        let Some(disk) = hash_existing_file(&root.join(rel))? else {
            continue;
        };
        if disk != *theirs && ours(rel.as_path(), &disk) {
            keep_as_conflict_copy(root, rel, me_short, now)?;
            kept = true;
        }
    }

    staged.apply_to_cache(cache);
    staged.commit(root)?;

    for rel in recorded.keys().filter(|p| !incoming.contains_key(*p)) {
        let disk = match hash_existing_file(&root.join(rel)) {
            Ok(Some(h)) => h,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(error = ?e, path = %rel.display(), "could not check a removed file; keeping it");
                kept = true;
                continue;
            }
        };
        if concurrent && !base.contains_key(rel) {
            tracing::info!(path = %rel.display(), "kept a file the other side doesn't have");
            kept = true;
        } else if ours(rel.as_path(), &disk) {
            if let Err(e) = keep_as_conflict_copy(root, rel, me_short, now) {
                tracing::warn!(error = ?e, path = %rel.display(), "could not keep a conflict copy; leaving the file");
            }
            kept = true;
        } else {
            match std::fs::remove_file(root.join(rel)) {
                Ok(()) => tracing::info!(path = %rel.display(), "removed orphan"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!(error = %e, path = %rel.display(), "failed to remove orphan")
                }
            }
        }
    }

    let mut clock = current.map(|s| s.clock.clone()).unwrap_or_default();
    clock.merge(&remote.clock);

    Ok((
        ShareState {
            version_hash: remote.version_hash.clone(),
            manifest_hash: remote.manifest.clone(),
            epoch,
            clock,
            timestamp: remote.timestamp,
            base: incoming.clone(),
            manifest: incoming,
        },
        kept,
    ))
}

/// blake3 of a regular file's contents, or `None` if nothing (or not a
/// regular file) is there.
fn hash_existing_file(path: &Path) -> Result<Option<[u8; 32]>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("checking {path:?}: {e}")),
    }
    let mut file = std::fs::File::open(path).with_context(|| format!("opening {path:?}"))?;
    let mut h = blake3::Hasher::new();
    std::io::copy(&mut file, &mut h).with_context(|| format!("hashing {path:?}"))?;
    Ok(Some(*h.finalize().as_bytes()))
}

/// Move `rel` to a free conflict-copy name beside it.
fn keep_as_conflict_copy(
    root: &Path,
    rel: &Path,
    me_short: &str,
    when: DateTime<Utc>,
) -> Result<PathBuf> {
    let copy = conflict_copy_name(rel, me_short, when, |p| {
        std::fs::symlink_metadata(root.join(p)).is_ok()
    });
    let (from, to) = (root.join(rel), root.join(&copy));
    std::fs::rename(&from, &to).with_context(|| format!("renaming {from:?} -> {to:?}"))?;
    tracing::warn!(path = %rel.display(), copy = %copy.display(),
        "concurrent change: kept our version as a conflict copy");
    Ok(copy)
}

/// `dir/name (conflict from <peer> <YYYY-MM-DD HHMMSS> UTC).ext`, with
/// `-2`, `-3`, ... before the extension if that is `taken`. The suffix goes
/// before the last extension; a dotfile (`.bashrc`) keeps its whole name
/// as the stem.
fn conflict_copy_name(
    rel: &Path,
    me_short: &str,
    when: DateTime<Utc>,
    taken: impl Fn(&Path) -> bool,
) -> PathBuf {
    let name = rel
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name.as_str(), ""),
    };
    let tag = format!(
        "{stem} (conflict from {me_short} {})",
        when.format("%Y-%m-%d %H%M%S UTC")
    );
    let parent = rel.parent().unwrap_or(Path::new(""));
    let mut n = 1;
    loop {
        let candidate = if n == 1 {
            parent.join(format!("{tag}{ext}"))
        } else {
            parent.join(format!("{tag}-{n}{ext}"))
        };
        if !taken(&candidate) {
            return candidate;
        }
        n += 1;
    }
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

/// Watch the share root recursively. Returns the watcher (which must be kept
/// alive for events to flow) and an unbounded receiver of "something changed"
/// notifications. We don't care about event details — any change just means
/// "recompute the version hash."
/// The sender is handed back too, so the share loop can ask for a re-check
/// itself (after an apply that kept local files).
fn spawn_fs_watcher(
    root: &Path,
) -> Result<(
    notify::RecommendedWatcher,
    UnboundedSender<()>,
    UnboundedReceiver<()>,
)> {
    use notify::{RecommendedWatcher, RecursiveMode, Watcher};
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let tx_loop = tx.clone();
    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(ev) => {
                // Skip events fully inside the shadow dir — those are our
                // own writes; reacting would make us recompute and re-encrypt
                // forever.
                // Staged downloads (`*.peerdup-tmp`) are ours too; their
                // rename into place still counts, since it names the
                // destination as well.
                let all_in_shadow = !ev.paths.is_empty()
                    && ev.paths.iter().all(|p| {
                        p.components().any(|c| c.as_os_str() == PEERDUP_DIR_NAME)
                            || p.to_string_lossy().ends_with(".peerdup-tmp")
                    });
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
    Ok((watcher, tx_loop, rx))
}

/// Resolves at `due`, or never if there is no change waiting.
async fn sleep_until_due(due: Option<tokio::time::Instant>) {
    match due {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// Announce `state`, signed, if we may: Readers' changes stay local, and
/// so does a version under a key epoch below `required` (it waits to be
/// re-encrypted once the rotated key arrives).
async fn publish_sync_announce(
    handle: &GossipHandle,
    state: &ShareState,
    identity: &SigningKey,
    group_id: MemberId,
    auth_state: &AuthState,
    required: u64,
) {
    if !announce::may_publish(auth_state, group_id, identity) {
        tracing::debug!("not a Writer or Owner of this share; not announcing");
        return;
    }
    if !epochs::announceable(state.epoch, required) {
        tracing::debug!(
            epoch = state.epoch,
            required,
            "current version is under an old key epoch; not announcing"
        );
        return;
    }
    let ann = Announce::sign(
        identity,
        group_id,
        state.manifest_hash.clone(),
        state.version_hash.clone(),
        state.clock.clone(),
        state.timestamp,
    );
    match wire::encode(ShareMsg::Announce(ann)) {
        Ok(bytes) => {
            if let Err(e) = handle.publish(bytes).await {
                tracing::warn!(error = %e, "gossip publish failed");
            }
        }
        Err(e) => tracing::warn!(error = %e, "encoding announce failed"),
    }
}

async fn publish_auth_ops(handle: &GossipHandle, auth_state: &AuthState, share_id: &str) {
    if auth_state.is_empty() {
        return;
    }
    let messages = match wire::auth_ops_messages(auth_state) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, share_id = %share_id, "encoding auth ops failed");
            return;
        }
    };
    for bytes in messages {
        if let Err(e) = handle.publish(bytes).await {
            tracing::warn!(error = %e, share_id = %share_id, "gossip publish (auth ops) failed");
        }
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
        let bytes = match wire::encode(ShareMsg::KeyRotation(rot.clone())) {
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
    epoch_floor: &mut u64,
) -> Result<()> {
    match try_install_rotation(
        &rotation,
        auth_state,
        group_id,
        identity,
        key,
        data_dir,
        share_id,
        epoch_floor,
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
                epoch_floor,
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

#[allow(clippy::too_many_arguments)]
async fn try_install_rotation(
    rotation: &SignedRotation,
    auth_state: &AuthState,
    group_id: MemberId,
    identity: &SigningKey,
    key: &Arc<RwLock<KeyRing>>,
    data_dir: &Path,
    share_id: &str,
    epoch_floor: &mut u64,
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
                InstallOutcome::Conflict { epoch } => {
                    // Two Owners minted different keys for one epoch (a
                    // concurrent revocation or rotation). One of them may
                    // have gone to a member the other was revoking, so
                    // neither is trusted for new content: the next epoch
                    // is required. Fail closed until an Owner rotates.
                    *epoch_floor = crypto::raise_epoch_floor(data_dir, share_id, epoch + 1)
                        .with_context(|| format!("raising the epoch floor of share {share_id}"))?;
                    tracing::error!(
                        share_id = %share_id,
                        epoch,
                        rotator = %rotation.rotator_pubkey.to_hex(),
                        floor = *epoch_floor,
                        "two different keys for one epoch (concurrent rotations by Owners); \
                         new content waits for a newer key: an Owner should run share-rotate-key"
                    );
                    Ok(AppliedOrBuffered::Idempotent)
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

#[allow(clippy::too_many_arguments)]
async fn drain_rotation_buffer(
    auth_state: &AuthState,
    group_id: MemberId,
    identity: &SigningKey,
    key: &Arc<RwLock<KeyRing>>,
    rotation_buffer: &mut Vec<SignedRotation>,
    data_dir: &Path,
    share_id: &str,
    epoch_floor: &mut u64,
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
            &candidate,
            auth_state,
            group_id,
            identity,
            key,
            data_dir,
            share_id,
            epoch_floor,
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
/// Only a chunk that carries our envelope is ever buffered, and an epoch
/// has one such chunk per rotator, so this dedups by signature.
fn buffer_push(buf: &mut Vec<SignedRotation>, rot: SignedRotation) {
    if buf.iter().any(|r| r.signature == rot.signature) {
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
        let mut auth_state = AuthState::empty_for(group);
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
            0,
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
            0,
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
            0,
        )
        .await
        .unwrap();
        assert_eq!(new_epoch, 2);

        // Pending in-memory queue should have one chunk; on disk too.
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

    const ME: &str = "abcd1234";

    fn at() -> DateTime<Utc> {
        "2026-11-26T01:38:00Z".parse().unwrap()
    }

    #[test]
    fn the_lww_winner_keeps_its_clock_so_the_loser_applies_concurrently() {
        let (a, b) = ("aa".repeat(32), "bb".repeat(32));
        let mut base = VectorClock::new();
        base.increment(&a);
        let mut ours = base.clone();
        ours.increment(&b);
        let mut theirs = base.clone();
        theirs.increment(&a);
        let mut local = state(FileMap::new(), FileMap::new());
        local.clock = ours.clone();
        local.timestamp = at() + chrono::TimeDelta::seconds(1);
        let theirs_remote = RemoteVersion {
            clock: theirs.clone(),
            ..remote()
        };
        // We are later: we win and change nothing.
        assert!(matches!(
            judge("s", Some(&local), &theirs_remote),
            Verdict::LocalWins
        ));
        // The other side, earlier, sees our version as concurrent (not
        // dominating), so its apply keeps conflict copies.
        let mut other = state(FileMap::new(), FileMap::new());
        other.clock = theirs;
        let ours_remote = RemoteVersion {
            clock: ours,
            timestamp: local.timestamp,
            ..remote()
        };
        assert!(matches!(
            judge("s", Some(&other), &ours_remote),
            Verdict::Fetch { concurrent: true }
        ));
    }

    #[test]
    fn conflict_copy_names() {
        let free = |_: &Path| false;
        let name = |p: &str| conflict_copy_name(Path::new(p), ME, at(), free);
        let tag = "(conflict from abcd1234 2026-11-26 013800 UTC)";
        assert_eq!(name("notes.txt"), PathBuf::from(format!("notes {tag}.txt")));
        assert_eq!(name("Makefile"), PathBuf::from(format!("Makefile {tag}")));
        assert_eq!(name(".bashrc"), PathBuf::from(format!(".bashrc {tag}")));
        assert_eq!(
            name("dir/archive.tar.gz"),
            PathBuf::from(format!("dir/archive.tar {tag}.gz"))
        );
        // Taken names get a counter before the extension.
        let first = PathBuf::from(format!("notes {tag}.txt"));
        let second = PathBuf::from(format!("notes {tag}-2.txt"));
        let taken = |p: &Path| p == first.as_path() || p == second.as_path();
        assert_eq!(
            conflict_copy_name(Path::new("notes.txt"), ME, at(), taken),
            PathBuf::from(format!("notes {tag}-3.txt"))
        );
        // Every generated name is a valid manifest path.
        for p in [
            "notes.txt",
            "Makefile",
            ".bashrc",
            "dir/archive.tar.gz",
            "a/b/.env",
        ] {
            let copy = name(p);
            let s = copy.to_str().unwrap();
            assert_eq!(transfer::manifest_path_to_rel(s).unwrap(), copy, "{s}");
        }
    }

    fn h(b: &[u8]) -> [u8; 32] {
        *blake3::hash(b).as_bytes()
    }

    fn files(entries: &[(&str, &[u8])]) -> FileMap {
        entries
            .iter()
            .map(|(p, b)| (PathBuf::from(p), h(b)))
            .collect()
    }

    fn remote() -> RemoteVersion {
        let mut clock = VectorClock::new();
        clock.increment(&"ee".repeat(32));
        RemoteVersion {
            manifest: "aa".repeat(32),
            provider: "ee".repeat(32),
            version_hash: "bb".repeat(32),
            clock,
            timestamp: at(),
        }
    }

    fn state(manifest: FileMap, base: FileMap) -> ShareState {
        ShareState {
            version_hash: "cc".repeat(32),
            manifest_hash: "dd".repeat(32),
            epoch: 1,
            clock: VectorClock::new(),
            timestamp: at(),
            manifest,
            base,
        }
    }

    fn write(root: &Path, rel: &str, b: &[u8]) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b).unwrap();
    }

    fn copies(root: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out: Vec<_> = std::fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_name().to_string_lossy().contains("(conflict from "))
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn fast_forward_keeps_unannounced_edits_as_conflict_copies() {
        let td = TmpDir::new("ff");
        let root = td.path();
        // We last had a=v1, b=v1, c=v1; a and c were edited since,
        // without being announced.
        write(root, "a.txt", b"local edit");
        write(root, "b.txt", b"v1");
        write(root, "c.txt", b"local edit of c");
        let current = state(
            files(&[("a.txt", b"v1"), ("b.txt", b"v1"), ("c.txt", b"v1")]),
            FileMap::new(),
        );
        // Their newer version changes a and drops b and c.
        let staged = transfer::staged_for_test(root, &[("a.txt", b"theirs")]);
        let mut cache = BlobCache::default();
        let (next, kept) = commit_remote(
            root,
            staged,
            &remote(),
            Some(&current),
            &mut cache,
            false,
            ME,
        )
        .unwrap();
        assert!(kept);
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"theirs");
        assert!(!root.join("b.txt").exists(), "unchanged orphan is removed");
        assert!(!root.join("c.txt").exists());
        let c = copies(root);
        assert_eq!(c.len(), 2, "{c:?}");
        assert!(c
            .iter()
            .any(|(n, b)| n.starts_with("a ") && b == b"local edit"));
        assert!(c
            .iter()
            .any(|(n, b)| n.starts_with("c ") && b == b"local edit of c"));
        assert_eq!(next.manifest, files(&[("a.txt", b"theirs")]));
        assert_eq!(next.base, next.manifest);
    }

    #[test]
    fn fast_forward_overwrites_files_we_did_not_change() {
        let td = TmpDir::new("ff-clean");
        let root = td.path();
        write(root, "a.txt", b"v1");
        let current = state(files(&[("a.txt", b"v1")]), FileMap::new());
        let staged = transfer::staged_for_test(root, &[("a.txt", b"v2")]);
        let (_, kept) = commit_remote(
            root,
            staged,
            &remote(),
            Some(&current),
            &mut BlobCache::default(),
            false,
            ME,
        )
        .unwrap();
        assert!(!kept);
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"v2");
        assert!(copies(root).is_empty());
    }

    #[test]
    fn concurrent_apply_measures_against_the_shared_base() {
        let td = TmpDir::new("concurrent");
        let root = td.path();
        // Both sides had a=v0, b=v0, gone=v0. We changed a and added
        // new; they changed b, and removed gone. Their version won.
        write(root, "a.txt", b"ours");
        write(root, "b.txt", b"v0");
        write(root, "gone.txt", b"v0");
        write(root, "new.txt", b"added by us");
        let base = files(&[("a.txt", b"v0"), ("b.txt", b"v0"), ("gone.txt", b"v0")]);
        let current = state(
            files(&[
                ("a.txt", b"ours"),
                ("b.txt", b"v0"),
                ("gone.txt", b"v0"),
                ("new.txt", b"added by us"),
            ]),
            base,
        );
        let staged = transfer::staged_for_test(root, &[("a.txt", b"v0"), ("b.txt", b"theirs")]);
        let (_, kept) = commit_remote(
            root,
            staged,
            &remote(),
            Some(&current),
            &mut BlobCache::default(),
            true,
            ME,
        )
        .unwrap();
        assert!(kept);
        // Our edit to a survives as a copy; theirs keeps the name.
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"v0");
        let c = copies(root);
        assert_eq!(c.len(), 1, "{c:?}");
        assert!(c[0].0.starts_with("a (conflict from abcd1234 ") && c[0].1 == b"ours");
        // Only they changed b: no copy, their content.
        assert_eq!(std::fs::read(root.join("b.txt")).unwrap(), b"theirs");
        // Unchanged since the base and dropped by them: removed.
        assert!(!root.join("gone.txt").exists());
        // Added by us, unknown to them: kept under its own name.
        assert_eq!(std::fs::read(root.join("new.txt")).unwrap(), b"added by us");
    }

    #[tokio::test]
    async fn rotate_key_handler_appends_epoch_and_sends_it_to_the_members() {
        let (td, config, identity, mut auth_state, key) = bootstrap("rotate-1");
        let bob = SigningKey::generate();
        handle_invite(
            &config,
            td.path(),
            &identity,
            &key,
            &mut auth_state,
            me_of(&bob),
            AuthRole::Reader,
            ShareRole::Sync,
            0,
        )
        .await
        .unwrap();
        assert_eq!(key.read().await.current_epoch(), 1);
        let mut pending = Vec::new();
        let new_epoch = handle_rotate_key(
            &config,
            td.path(),
            &identity,
            &key,
            &auth_state,
            &mut pending,
            0,
        )
        .await
        .unwrap();
        assert_eq!(new_epoch, 2);
        assert_eq!(key.read().await.current_epoch(), 2);
        // Bob gets the new key; it is queued on disk and in memory.
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].epoch, 2);
        let group = group_id_for(&config.id);
        match rotation::verify_and_decrypt(&pending[0], &auth_state, group, &bob) {
            VerifyOutcome::OkForUs(k) => {
                assert_eq!(&k, key.read().await.key_for_epoch(2).unwrap())
            }
            other => panic!("expected OkForUs, got {other:?}"),
        }
        assert_eq!(
            rotation::load_pending(td.path(), &config.id).unwrap().len(),
            1
        );
        // A rotation is not a removal.
        assert_eq!(auth_state.required_epoch(), 1);
    }

    #[tokio::test]
    async fn only_owners_rotate() {
        let (td, config, identity, mut auth_state, key) = bootstrap("rotate-owner");
        let bob = SigningKey::generate();
        let group = group_id_for(&config.id);
        auth_state
            .add_member(&identity, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        let err = handle_rotate_key(
            &config,
            td.path(),
            &bob,
            &key,
            &auth_state,
            &mut Vec::new(),
            0,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("Owner"), "{err}");
        assert_eq!(key.read().await.current_epoch(), 1);
    }

    /// An Owner that knows of a removal but hasn't got its rotated key
    /// must not revoke, rotate or invite: a revocation would mint a second
    /// epoch-2 key, and nothing may be authored without its rotation.
    #[tokio::test]
    async fn an_owner_behind_on_keys_refuses_to_mint_or_invite() {
        let (td, config, identity, mut auth_state, key) = bootstrap("behind");
        let group = group_id_for(&config.id);
        let (bob, carol, dave) = (
            SigningKey::generate(),
            SigningKey::generate(),
            SigningKey::generate(),
        );
        for m in [&bob, &carol] {
            auth_state
                .add_member(&identity, group, me_of(m), AuthRole::Writer)
                .unwrap();
        }
        // Another Owner's removal arrived; its key (epoch 2) didn't.
        auth_state
            .remove_member(&identity, group, me_of(&bob))
            .unwrap();
        assert_eq!(auth_state.required_epoch(), 2);
        let ops_before = auth_state.ops().len();

        let err = handle_revoke(
            &config,
            td.path(),
            &identity,
            &key,
            &mut auth_state,
            &mut Vec::new(),
            me_of(&carol),
            0,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("fork"), "{err}");
        assert_eq!(
            auth_state.ops().len(),
            ops_before,
            "no Remove without a rotation"
        );
        assert!(auth_state.is_member(group, me_of(&carol)));
        assert_eq!(key.read().await.current_epoch(), 1);

        let err = handle_invite(
            &config,
            td.path(),
            &identity,
            &key,
            &mut auth_state,
            me_of(&dave),
            AuthRole::Writer,
            ShareRole::Sync,
            0,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("epoch 2"), "{err}");
        assert!(!auth_state.is_member(group, me_of(&dave)));

        // A rotation to epoch 2 is allowed: it is what heals a fork, and
        // here it gives this node the epoch the removal requires.
        let epoch = handle_rotate_key(
            &config,
            td.path(),
            &identity,
            &key,
            &auth_state,
            &mut Vec::new(),
            0,
        )
        .await
        .unwrap();
        assert_eq!(epoch, 2);
        // A fork floor of 4 still refuses a revocation from epoch 2.
        assert!(handle_revoke(
            &config,
            td.path(),
            &identity,
            &key,
            &mut auth_state,
            &mut Vec::new(),
            me_of(&carol),
            4,
        )
        .await
        .is_err());
    }

    fn shared_state(epoch: u64) -> ShareState {
        let mut s = state(files(&[("a.txt", b"v1")]), FileMap::new());
        s.clock.increment(&"aa".repeat(32));
        s.epoch = epoch;
        s
    }

    #[test]
    fn republishing_unchanged_content_keeps_the_clock() {
        let current = shared_state(1);
        let later = at() + chrono::TimeDelta::hours(1);
        let next = next_state(
            Some(&current),
            current.version_hash.clone(),
            current.manifest.clone(),
            "ee".repeat(32),
            2,
            &"bb".repeat(32),
            later,
        );
        assert_eq!(next.clock, current.clock, "no clock bump");
        assert_eq!(
            next.timestamp, current.timestamp,
            "same version, same timestamp"
        );
        assert_eq!(next.version_hash, current.version_hash);
        assert_eq!(next.base, current.base);
        assert_eq!(next.epoch, 2);
        assert_eq!(next.manifest_hash, "ee".repeat(32));
        // Peers that have the version compare it Equal: nothing to fetch.
        let as_remote = RemoteVersion {
            manifest: next.manifest_hash.clone(),
            provider: "bb".repeat(32),
            version_hash: next.version_hash.clone(),
            clock: next.clock.clone(),
            timestamp: next.timestamp,
        };
        assert!(matches!(
            judge("s", Some(&current), &as_remote),
            Verdict::Ignore
        ));
    }

    #[test]
    fn a_content_change_is_a_new_version() {
        let current = shared_state(1);
        let me = "bb".repeat(32);
        let later = at() + chrono::TimeDelta::hours(1);
        let next = next_state(
            Some(&current),
            "ff".repeat(32),
            files(&[("a.txt", b"v2")]),
            "ee".repeat(32),
            2,
            &me,
            later,
        );
        assert_eq!(next.clock.0.get(&me), Some(&1));
        assert_eq!(
            current.clock.compare(&next.clock),
            ClockOrdering::OtherDominates
        );
        assert_eq!(next.timestamp, later);
        // First publish ever.
        let first = next_state(
            None,
            "ff".repeat(32),
            FileMap::new(),
            "ee".repeat(32),
            1,
            &me,
            later,
        );
        assert_eq!(first.clock.0.get(&me), Some(&1));
    }
}
