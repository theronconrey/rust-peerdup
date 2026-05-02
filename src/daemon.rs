use crate::auth::{self, AuthState, MemberId, SignedOp};
use crate::clock::{ClockOrdering, VectorClock};
use crate::crypto::{self, InstallOutcome, KeyRing};
use crate::rotation::{self, SignedRotation, VerifyOutcome};
use crate::share::{ShareConfig, ShareRole};
use crate::share_state::{self, PersistedState};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use librqbit::api::TorrentIdOrHash;
use librqbit::{
    create_torrent, AddTorrent, AddTorrentOptions, CreateTorrentOptions, Session, SessionOptions,
};
use p2panda_core::{Hash, PrivateKey};
use p2panda_net::gossip::GossipHandle;
use p2panda_net::iroh_mdns::MdnsDiscoveryMode;
use p2panda_net::{AddressBook, Discovery, Endpoint, Gossip, MdnsDiscovery, TopicId};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::RwLock;
use tokio::task::JoinSet;

/// Cap the in-memory buffer of out-of-order key rotations per share. 64 epochs
/// is far more than expected; we evict the oldest if we somehow run past it.
const ROTATION_BUFFER_CAP: usize = 64;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "kind")]
enum ShareMsg {
    #[serde(rename = "share_announce")]
    Announce {
        info_hash: String,
        bt_endpoints: Vec<(String, u16)>,
        /// Deterministic hash over the share's file contents, sorted by path.
        /// Two peers with the same content compute the same `version_hash`,
        /// even though their librqbit `info_hash` will differ (librqbit's
        /// `create_torrent` walks dirs in filesystem order, which is
        /// host-specific). Sync uses `version_hash` for "is this the same
        /// content as we have?" comparisons; `info_hash` is used only as the
        /// BitTorrent magnet for fetching the bytes. Optional for back-compat
        /// with the Phase 2 leech path.
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

pub async fn serve(
    data_dir: PathBuf,
    bt_port: u16,
    identity: PrivateKey,
    configs: Vec<ShareConfig>,
) -> Result<()> {
    let peer_id_hex = identity.public_key().to_hex();
    tracing::info!(peer_id = %peer_id_hex, share_count = configs.len(), "daemon starting");

    let address_book = AddressBook::builder().spawn().await?;
    // We need the identity for both the endpoint and per-share key-rotation
    // verification. Endpoint::builder takes by value; clone first.
    let endpoint = Endpoint::builder(address_book.clone())
        .private_key(identity.clone())
        .spawn()
        .await?;
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

    let session = Session::new_with_opts(
        data_dir.clone(),
        SessionOptions {
            listen_port_range: Some(bt_port..bt_port + 1),
            disable_dht: true,
            ..Default::default()
        },
    )
    .await
    .context("creating librqbit session")?;

    let no_shares_at_start = configs.is_empty();
    if no_shares_at_start {
        tracing::warn!("no shares configured; daemon will idle. Add some with `peerdup share-add`.");
    }

    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    for config in configs {
        let share_id = config.id.clone();
        let session = session.clone();
        let gossip = gossip.clone();
        let data_dir = data_dir.clone();
        let peer_id_hex = peer_id_hex.clone();
        let identity = identity.clone();
        let key = match crypto::load_or_create_keyring(&data_dir, &share_id) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = ?e, share_id = %share_id, "could not load share key");
                continue;
            }
        };
        let key = Arc::new(RwLock::new(key));
        let auth_state = match auth::load(&data_dir, &share_id) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, share_id = %share_id, "could not load auth log");
                continue;
            }
        };
        let pending_rotations = match rotation::load_pending(&data_dir, &share_id) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = ?e, share_id = %share_id,
                    "could not load pending rotations; continuing with empty queue");
                Vec::new()
            }
        };
        tasks.spawn(async move {
            run_share(
                config,
                session,
                gossip,
                bt_port,
                data_dir,
                peer_id_hex,
                identity,
                key,
                auth_state,
                pending_rotations,
            )
            .await
            .with_context(|| format!("share {share_id} failed"))
        });
    }

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<&'static str>();
    spawn_shutdown_watcher(shutdown_tx);

    loop {
        tokio::select! {
            biased;
            sig = &mut shutdown_rx => {
                match sig {
                    Ok(name) => tracing::info!(signal = name, "shutdown signal received"),
                    Err(_) => tracing::warn!("shutdown watcher dropped without firing"),
                }
                break;
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok(Ok(()))) => tracing::info!("share task exited cleanly"),
                    Some(Ok(Err(e))) => tracing::error!(error = ?e, "share task returned error"),
                    Some(Err(e)) => tracing::error!(error = ?e, "share task join error"),
                    // join_next() with !is_empty() guard means None is unreachable, but keep
                    // the arm for type completeness.
                    None => {}
                }
                if tasks.is_empty() && !no_shares_at_start {
                    tracing::info!("all share tasks have finished");
                    break;
                }
            }
        }
    }

    tracing::info!("aborting remaining tasks");
    tasks.shutdown().await;
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

async fn run_share(
    config: ShareConfig,
    session: Arc<Session>,
    gossip: Gossip,
    bt_port: u16,
    data_dir: PathBuf,
    peer_id_hex: String,
    identity: PrivateKey,
    key: Arc<RwLock<KeyRing>>,
    auth_state: AuthState,
    pending_rotations: Vec<SignedRotation>,
) -> Result<()> {
    let topic = TopicId::from(Hash::new(config.topic.as_bytes()));
    tracing::info!(
        share_id = %config.id,
        topic = %config.topic,
        role = ?config.role,
        auth_ops = auth_state.ops().len(),
        pending_rotations = pending_rotations.len(),
        "starting share"
    );
    match config.role {
        ShareRole::Seed => {
            seed_loop(
                config,
                session,
                gossip,
                topic,
                bt_port,
                data_dir,
                identity,
                key,
                auth_state,
                pending_rotations,
            )
            .await
        }
        ShareRole::Leech => {
            leech_loop(
                config,
                session,
                gossip,
                topic,
                data_dir,
                identity,
                key,
                auth_state,
                pending_rotations,
            )
            .await
        }
        ShareRole::Sync => {
            sync_loop(
                config,
                session,
                gossip,
                topic,
                bt_port,
                data_dir,
                peer_id_hex,
                identity,
                key,
                auth_state,
                pending_rotations,
            )
            .await
        }
    }
}

async fn seed_loop(
    config: ShareConfig,
    session: Arc<Session>,
    gossip: Gossip,
    topic: TopicId,
    bt_port: u16,
    data_dir: PathBuf,
    identity: PrivateKey,
    key: Arc<RwLock<KeyRing>>,
    mut auth_state: AuthState,
    pending_rotations: Vec<SignedRotation>,
) -> Result<()> {
    let root = config
        .root_path
        .canonicalize()
        .with_context(|| format!("canonicalize {:?}", config.root_path))?;
    let result = create_torrent(root.as_path(), Default::default())
        .await
        .context("create_torrent")?;
    let info_hash = result.info_hash();
    let torrent_bytes = result.as_bytes()?;
    tracing::info!(
        share_id = %config.id,
        root = %root.display(),
        info_hash = %info_hash.as_string(),
        "created torrent"
    );

    let add = AddTorrent::from_bytes(torrent_bytes);
    let opts = AddTorrentOptions {
        output_folder: Some(root.to_string_lossy().into_owned()),
        overwrite: true,
        paused: false,
        ..Default::default()
    };
    let _handle = session
        .add_torrent(add, Some(opts))
        .await?
        .into_handle()
        .ok_or_else(|| anyhow!("add_torrent returned no handle"))?;
    tracing::info!(share_id = %config.id, port = bt_port, "seeding");

    let bt_endpoints = vec![("127.0.0.1".to_string(), bt_port)];
    let announce = ShareMsg::Announce {
        info_hash: info_hash.as_string(),
        bt_endpoints,
        version_hash: None,
        clock: None,
        timestamp: None,
    };
    let announce_bytes = serde_json::to_vec(&announce)?;

    let group_id = auth::group_id_for(&config.id);
    let mut rotation_buffer: Vec<SignedRotation> = Vec::new();

    let handle = gossip.stream(topic).await?;
    let mut sub = handle.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Err(e) = handle.publish(announce_bytes.clone()).await {
                    tracing::warn!(share_id = %config.id, error = %e, "gossip publish failed");
                }
                publish_auth_ops(&handle, &auth_state, &config.id).await;
                publish_pending_rotations(&handle, &pending_rotations, &config.id).await;
            }
            item = sub.next() => {
                let Some(item) = item else { break };
                let payload = match item {
                    Ok(p) => p,
                    Err(e) => { tracing::debug!(error = %e, "gossip lag"); continue; }
                };
                match serde_json::from_slice::<ShareMsg>(&payload) {
                    Ok(ShareMsg::AuthOps { ops }) => {
                        if let Err(e) = apply_auth_ops(&mut auth_state, ops, &data_dir, &config.id) {
                            tracing::warn!(error = ?e, share_id = %config.id, "auth apply failed");
                        }
                    }
                    Ok(ShareMsg::KeyRotation(rot)) => {
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
                    }
                    Ok(ShareMsg::Announce { .. }) => {} // seeds ignore other peers' announces
                    Err(_) => {} // unknown payload, drop
                }
            }
        }
    }
    let _ = pending_rotations; // currently never mutated by seed loop, but plumbed for symmetry
    Err(anyhow!("seed gossip subscription ended"))
}

async fn leech_loop(
    config: ShareConfig,
    session: Arc<Session>,
    gossip: Gossip,
    topic: TopicId,
    data_dir: PathBuf,
    identity: PrivateKey,
    key: Arc<RwLock<KeyRing>>,
    mut auth_state: AuthState,
    pending_rotations: Vec<SignedRotation>,
) -> Result<()> {
    let root = config.root_path.clone();
    tokio::fs::create_dir_all(&root)
        .await
        .with_context(|| format!("create_dir_all {root:?}"))?;
    let root_string = root
        .canonicalize()
        .with_context(|| format!("canonicalize {root:?}"))?
        .to_string_lossy()
        .into_owned();

    let group_id = auth::group_id_for(&config.id);
    let mut rotation_buffer: Vec<SignedRotation> = Vec::new();

    let handle = gossip.stream(topic).await?;
    let mut sub = handle.subscribe();
    tracing::info!(share_id = %config.id, "subscribed; waiting for announce");

    // Drain any pending rotations queued by the CLI on this peer (rare for a
    // pure leech, but keep symmetry with sync_loop / seed_loop).
    publish_pending_rotations(&handle, &pending_rotations, &config.id).await;

    while let Some(item) = sub.next().await {
        let payload = match item {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(error = %e, "gossip subscription lag");
                continue;
            }
        };
        let msg = match serde_json::from_slice::<ShareMsg>(&payload) {
            Ok(m) => m,
            Err(_) => {
                tracing::debug!("ignoring non-ShareMsg payload");
                continue;
            }
        };
        let (info_hash, bt_endpoints) = match msg {
            ShareMsg::Announce {
                info_hash,
                bt_endpoints,
                ..
            } => (info_hash, bt_endpoints),
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
        tracing::info!(
            share_id = %config.id,
            %info_hash,
            peers = ?bt_endpoints,
            "received announce"
        );

        let initial_peers: Vec<SocketAddr> = bt_endpoints
            .iter()
            .filter_map(|(host, port)| {
                format!("{}:{}", host, port)
                    .parse::<SocketAddr>()
                    .map_err(|e| {
                        tracing::warn!(host, port, error = %e, "skipping unparseable peer")
                    })
                    .ok()
            })
            .collect();
        if initial_peers.is_empty() {
            tracing::warn!("announce had no usable peers");
            continue;
        }

        let magnet = format!("magnet:?xt=urn:btih:{}", info_hash);
        let opts = AddTorrentOptions {
            output_folder: Some(root_string.clone()),
            initial_peers: Some(initial_peers),
            overwrite: true,
            ..Default::default()
        };
        let add = AddTorrent::from_url(magnet);
        let torrent_handle = session
            .add_torrent(add, Some(opts))
            .await?
            .into_handle()
            .ok_or_else(|| anyhow!("add_torrent returned no handle"))?;
        tracing::info!(share_id = %config.id, "added torrent, waiting for completion");

        torrent_handle
            .wait_until_completed()
            .await
            .context("wait_until_completed failed")?;
        tracing::info!(share_id = %config.id, "download completed");
        return Ok(());
    }
    Err(anyhow!("gossip subscription ended before any announce was seen"))
}

/// Bidirectional sync. Both peers run this for the same share.
///
/// 3.3: vector clocks decide which announces dominate. Sequential edits in
/// either direction converge. Concurrent edits (each peer ahead on a
/// different counter) are detected and logged but not resolved — that's 3.4.
/// File deletions don't propagate yet — also 3.4.
async fn sync_loop(
    config: ShareConfig,
    session: Arc<Session>,
    gossip: Gossip,
    topic: TopicId,
    bt_port: u16,
    data_dir: PathBuf,
    peer_id_hex: String,
    identity: PrivateKey,
    key: Arc<RwLock<KeyRing>>,
    mut auth_state: AuthState,
    pending_rotations: Vec<SignedRotation>,
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

    let topic_handle = gossip.stream(topic).await?;
    let mut sub = topic_handle.subscribe();
    tracing::info!(share_id = %config.id, root = %root.display(), "sync started");

    let mut state = {
        let k = key.read().await;
        reconcile_on_start(&config, &session, &root, &data_dir, &peer_id_hex, &*k).await?
    };
    if let Some(s) = &state {
        publish_sync_announce(&topic_handle, s, bt_port).await;
    }

    let (_watcher, mut watch_rx) = spawn_fs_watcher(&root)
        .with_context(|| format!("watching {root:?}"))?;
    let mut announce_tick = tokio::time::interval(Duration::from_secs(10));
    announce_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    announce_tick.tick().await;

    loop {
        tokio::select! {
            Some(()) = debounce(&mut watch_rx, Duration::from_millis(500)) => {
                let outcome = {
                    let k = key.read().await;
                    handle_local_change(&config, &session, &root, &data_dir, &peer_id_hex, &*k, state.as_ref()).await
                };
                match outcome {
                    Ok(Some(new_state)) => {
                        tracing::info!(
                            share_id = %config.id,
                            version_hash = %new_state.version_hash,
                            clock = ?new_state.clock.0,
                            "local change detected"
                        );
                        publish_sync_announce(&topic_handle, &new_state, bt_port).await;
                        state = Some(new_state);
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(error = ?e, share_id = %config.id, "local change check failed"),
                }
            }
            _ = announce_tick.tick() => {
                if let Some(s) = &state {
                    publish_sync_announce(&topic_handle, s, bt_port).await;
                }
                publish_auth_ops(&topic_handle, &auth_state, &config.id).await;
                publish_pending_rotations(&topic_handle, &pending_rotations, &config.id).await;
            }
            item = sub.next() => {
                let Some(item) = item else { break };
                let payload = match item {
                    Ok(p) => p,
                    Err(e) => { tracing::debug!(error = %e, "gossip lag"); continue; }
                };
                let msg = match serde_json::from_slice::<ShareMsg>(&payload) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let (info_hash, bt_endpoints, version_hash, clock, timestamp) = match msg {
                    ShareMsg::Announce { info_hash, bt_endpoints, version_hash, clock, timestamp } =>
                        (info_hash, bt_endpoints, version_hash, clock, timestamp),
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
                            publish_sync_announce(&topic_handle, &new_state, bt_port).await;
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
                    %info_hash,
                    remote_clock = ?remote_clock.0,
                    peers = ?bt_endpoints,
                    "received remote announce; applying"
                );
                let apply_outcome = {
                    let k = key.read().await;
                    apply_remote_sync(&session, &root, &info_hash, &remote_vhash, &remote_clock, remote_ts, &bt_endpoints, &*k, state.as_ref()).await
                };
                match apply_outcome {
                    Ok(new_state) => {
                        if let Err(e) = persist(&data_dir, &config.id, &new_state) {
                            tracing::warn!(error = ?e, "could not persist state");
                        }
                        publish_sync_announce(&topic_handle, &new_state, bt_port).await;
                        state = Some(new_state);
                    }
                    Err(e) => tracing::warn!(error = ?e, share_id = %config.id, "apply_remote failed"),
                }
            }
        }
    }
    Err(anyhow!("gossip subscription ended"))
}

#[derive(Debug, Clone)]
struct ShareState {
    /// Deterministic, content-derived. Same content → same hash on every peer.
    version_hash: String,
    /// librqbit's hash for our local copy of this content. Differs across
    /// peers even for identical content (librqbit's `create_torrent` walks
    /// dirs in filesystem order). Used only as the BT magnet for fetches.
    info_hash: String,
    /// librqbit's internal id; needed to remove the previous torrent when
    /// we replace it.
    torrent_id: usize,
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
async fn reconcile_on_start(
    config: &ShareConfig,
    session: &Arc<Session>,
    root: &Path,
    data_dir: &Path,
    peer_id_hex: &str,
    key: &KeyRing,
) -> Result<Option<ShareState>> {
    let persisted = share_state::load(data_dir, &config.id)?;

    match persisted {
        None if !has_content(root)? => Ok(None),
        None => {
            let (disk_vh, manifest) = snapshot_content(root)?;
            let mut clock = VectorClock::new();
            clock.increment(peer_id_hex);
            sync_plaintext_to_shadow(root, key, &manifest)?;
            let (info_hash, torrent_id) =
                create_and_add_shadow_torrent(config, session, root).await?;
            let state = ShareState {
                version_hash: disk_vh,
                info_hash,
                torrent_id,
                clock,
                timestamp: Utc::now(),
                manifest,
            };
            persist(data_dir, &config.id, &state)?;
            tracing::info!(
                share_id = %config.id,
                clock = ?state.clock.0,
                version_hash = %state.version_hash,
                "first run: adopted local content"
            );
            Ok(Some(state))
        }
        Some(p) if !has_content(root)? => {
            tracing::warn!(
                share_id = %config.id,
                "persisted state exists but share root is empty; waiting for content"
            );
            let _ = p;
            Ok(None)
        }
        Some(p) => {
            let (disk_vh, manifest) = snapshot_content(root)?;
            if p.version_hash == disk_vh {
                sync_plaintext_to_shadow(root, key, &manifest)?;
            let (info_hash, torrent_id) =
                create_and_add_shadow_torrent(config, session, root).await?;
                tracing::info!(
                    share_id = %config.id,
                    clock = ?p.clock.0,
                    version_hash = %disk_vh,
                    "resumed at persisted clock"
                );
                Ok(Some(ShareState {
                    version_hash: disk_vh,
                    info_hash,
                    torrent_id,
                    clock: p.clock,
                    timestamp: p.timestamp,
                    manifest,
                }))
            } else {
                let mut clock = p.clock.clone();
                clock.increment(peer_id_hex);
                sync_plaintext_to_shadow(root, key, &manifest)?;
            let (info_hash, torrent_id) =
                create_and_add_shadow_torrent(config, session, root).await?;
                let state = ShareState {
                    version_hash: disk_vh,
                    info_hash,
                    torrent_id,
                    clock,
                    timestamp: Utc::now(),
                    manifest,
                };
                persist(data_dir, &config.id, &state)?;
                tracing::info!(
                    share_id = %config.id,
                    clock = ?state.clock.0,
                    "out-of-band edit detected; bumped clock"
                );
                Ok(Some(state))
            }
        }
    }
}

async fn handle_local_change(
    config: &ShareConfig,
    session: &Arc<Session>,
    root: &Path,
    data_dir: &Path,
    peer_id_hex: &str,
    key: &KeyRing,
    current: Option<&ShareState>,
) -> Result<Option<ShareState>> {
    if !has_content(root)? {
        return Ok(None);
    }
    let (new_vhash, new_manifest) = snapshot_content(root)?;
    if current.map(|s| s.version_hash == new_vhash).unwrap_or(false) {
        return Ok(None);
    }
    if let Some(s) = current {
        let _ = session
            .delete(TorrentIdOrHash::Id(s.torrent_id), false)
            .await;
    }
    sync_plaintext_to_shadow(root, key, &new_manifest)?;
    let (info_hash, torrent_id) =
        create_and_add_shadow_torrent(config, session, root).await?;
    let mut clock = current.map(|s| s.clock.clone()).unwrap_or_default();
    clock.increment(peer_id_hex);
    let new_state = ShareState {
        version_hash: new_vhash,
        info_hash,
        torrent_id,
        clock,
        timestamp: Utc::now(),
        manifest: new_manifest,
    };
    persist(data_dir, &config.id, &new_state)?;
    Ok(Some(new_state))
}

/// Snapshot a share's content. Returns a deterministic version hash and a
/// manifest (set of relative paths). Both peers compute the same values for
/// the same content. The hash is blake3 over sorted (rel_path, blake3(content))
/// triples; the manifest is the same sorted path set.
fn snapshot_content(root: &Path) -> Result<(String, BTreeSet<PathBuf>)> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    paths.sort();

    let mut top = blake3::Hasher::new();
    let mut manifest = BTreeSet::new();
    for rel in &paths {
        let abs = root.join(rel);
        let mut file = std::fs::File::open(&abs)
            .with_context(|| format!("opening {abs:?}"))?;
        let mut content_hasher = blake3::Hasher::new();
        std::io::copy(&mut file, &mut content_hasher)
            .with_context(|| format!("hashing {abs:?}"))?;
        let path_bytes = rel.to_string_lossy();
        top.update(&(path_bytes.len() as u64).to_le_bytes());
        top.update(path_bytes.as_bytes());
        top.update(content_hasher.finalize().as_bytes());
        manifest.insert(rel.clone());
    }
    Ok((top.finalize().to_hex().to_string(), manifest))
}


fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir {dir:?}"))? {
        let entry = entry?;
        if entry.file_name() == PEERDUP_DIR_NAME {
            // Don't recurse into peerdup's hidden state dir; that's the
            // ciphertext shadow, not user content.
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

const PEERDUP_DIR_NAME: &str = ".peerdup";

fn shadow_root(root: &Path) -> PathBuf {
    root.join(PEERDUP_DIR_NAME).join("encrypted")
}

/// Map a plaintext relative path to its ciphertext path inside the shadow.
/// Adds a `.bin` suffix to the leaf filename so plaintext and shadow can
/// coexist if anything ever pulls the shadow into the plaintext tree.
fn shadow_file_for(root: &Path, plaintext_rel: &Path) -> PathBuf {
    let mut p = shadow_root(root).join(plaintext_rel);
    if let Some(name) = p.file_name() {
        let mut n = name.to_os_string();
        n.push(".bin");
        p.set_file_name(n);
    }
    p
}

/// Inverse of `shadow_file_for`: given a path relative to the shadow root,
/// recover the plaintext relative path. Returns None if the path doesn't
/// have the `.bin` suffix.
fn plaintext_rel_from_shadow_rel(shadow_rel: &Path) -> Option<PathBuf> {
    let name = shadow_rel.file_name()?.to_str()?;
    let stripped = name.strip_suffix(".bin")?;
    let mut out = shadow_rel.to_path_buf();
    out.set_file_name(stripped);
    Some(out)
}

fn has_content(root: &Path) -> Result<bool> {
    let mut entries = std::fs::read_dir(root)
        .with_context(|| format!("read_dir {root:?}"))?;
    Ok(entries.next().is_some())
}

/// Encrypt the plaintext working copy into the ciphertext shadow.
/// Walks `manifest`, encrypts each file with `key`, writes to the matching
/// shadow path. Then walks the shadow and removes any ciphertext file
/// without a corresponding plaintext entry (handles user file deletions).
fn sync_plaintext_to_shadow(
    root: &Path,
    key: &KeyRing,
    plaintext_manifest: &BTreeSet<PathBuf>,
) -> Result<()> {
    let shadow = shadow_root(root);
    std::fs::create_dir_all(&shadow)
        .with_context(|| format!("create_dir_all {shadow:?}"))?;

    for rel in plaintext_manifest {
        let pt_path = root.join(rel);
        let shadow_path = shadow_file_for(root, rel);
        if let Some(parent) = shadow_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create_dir_all {parent:?}"))?;
        }
        let pt_bytes = std::fs::read(&pt_path)
            .with_context(|| format!("reading plaintext {pt_path:?}"))?;
        let ct_bytes = crypto::encrypt(key, &pt_bytes)
            .with_context(|| format!("encrypting {rel:?}"))?;
        std::fs::write(&shadow_path, ct_bytes)
            .with_context(|| format!("writing ciphertext {shadow_path:?}"))?;
    }

    // Shadow-side orphan deletion.
    let mut shadow_files = Vec::new();
    if shadow.exists() {
        collect_files(&shadow, &shadow, &mut shadow_files)?;
    }
    for shadow_rel in &shadow_files {
        let Some(pt_rel) = plaintext_rel_from_shadow_rel(shadow_rel) else {
            continue;
        };
        if !plaintext_manifest.contains(&pt_rel) {
            let abs = shadow.join(shadow_rel);
            let _ = std::fs::remove_file(&abs);
        }
    }
    Ok(())
}

/// Decrypt every ciphertext file in the shadow and write plaintext to the
/// share root. Returns the resulting plaintext manifest. Plaintext writes
/// use a temp-file + rename for atomicity.
fn sync_shadow_to_plaintext(root: &Path, key: &KeyRing) -> Result<BTreeSet<PathBuf>> {
    let shadow = shadow_root(root);
    if !shadow.exists() {
        return Ok(BTreeSet::new());
    }
    let mut shadow_files = Vec::new();
    collect_files(&shadow, &shadow, &mut shadow_files)?;
    let mut manifest = BTreeSet::new();
    for shadow_rel in &shadow_files {
        let Some(pt_rel) = plaintext_rel_from_shadow_rel(shadow_rel) else {
            tracing::warn!(
                path = %shadow_rel.display(),
                "shadow file without .bin suffix; skipping"
            );
            continue;
        };
        let shadow_path = shadow.join(shadow_rel);
        let pt_path = root.join(&pt_rel);
        let ct_bytes = std::fs::read(&shadow_path)
            .with_context(|| format!("reading ciphertext {shadow_path:?}"))?;
        let pt_bytes = crypto::decrypt(key, &ct_bytes)
            .with_context(|| format!("decrypting {shadow_rel:?}"))?;
        if let Some(parent) = pt_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create_dir_all {parent:?}"))?;
        }
        let mut tmp_name = pt_path
            .file_name()
            .ok_or_else(|| anyhow!("plaintext path has no filename: {pt_path:?}"))?
            .to_os_string();
        tmp_name.push(".peerdup-tmp");
        let tmp = pt_path.with_file_name(tmp_name);
        std::fs::write(&tmp, &pt_bytes)
            .with_context(|| format!("writing plaintext {tmp:?}"))?;
        std::fs::rename(&tmp, &pt_path)
            .with_context(|| format!("renaming {tmp:?} -> {pt_path:?}"))?;
        manifest.insert(pt_rel);
    }
    Ok(manifest)
}

/// Run create_torrent over the shadow directory and add to librqbit, with
/// the share id as the torrent name (so the same plaintext + same key on
/// two peers — even though their ciphertext nonces differ — produces the
/// same torrent name; the info-hash will still differ per peer because
/// ciphertext bytes differ, but that's fine since `version_hash` is what
/// peerdup compares).
async fn create_and_add_shadow_torrent(
    config: &ShareConfig,
    session: &Arc<Session>,
    root: &Path,
) -> Result<(String, usize)> {
    let shadow = shadow_root(root);
    let result = create_torrent(
        &shadow,
        CreateTorrentOptions {
            name: Some(&config.id),
            piece_length: None,
        },
    )
    .await
    .context("create_torrent")?;
    let info_hash = result.info_hash().as_string();
    let opts = AddTorrentOptions {
        output_folder: Some(shadow.to_string_lossy().into_owned()),
        overwrite: true,
        paused: false,
        ..Default::default()
    };
    let resp = session
        .add_torrent(AddTorrent::from_bytes(result.as_bytes()?), Some(opts))
        .await?;
    let handle = resp.into_handle().ok_or_else(|| anyhow!("no handle"))?;
    Ok((info_hash, handle.id()))
}

async fn apply_remote_sync(
    session: &Arc<Session>,
    root: &Path,
    info_hash: &str,
    remote_vhash: &str,
    remote_clock: &VectorClock,
    remote_timestamp: DateTime<Utc>,
    bt_endpoints: &[(String, u16)],
    key: &KeyRing,
    current: Option<&ShareState>,
) -> Result<ShareState> {
    let initial_peers: Vec<SocketAddr> = bt_endpoints
        .iter()
        .filter_map(|(host, port)| format!("{}:{}", host, port).parse().ok())
        .collect();
    if initial_peers.is_empty() {
        return Err(anyhow!("announce had no usable peers"));
    }

    if let Some(s) = current {
        let _ = session
            .delete(TorrentIdOrHash::Id(s.torrent_id), false)
            .await;
    }

    // librqbit fetches ciphertext into the shadow.
    let shadow = shadow_root(root);
    std::fs::create_dir_all(&shadow)
        .with_context(|| format!("create_dir_all {shadow:?}"))?;
    let magnet = format!("magnet:?xt=urn:btih:{}", info_hash);
    let opts = AddTorrentOptions {
        output_folder: Some(shadow.to_string_lossy().into_owned()),
        initial_peers: Some(initial_peers),
        overwrite: true,
        ..Default::default()
    };
    let resp = session
        .add_torrent(AddTorrent::from_url(magnet), Some(opts))
        .await?;
    let handle = resp.into_handle().ok_or_else(|| anyhow!("no handle"))?;
    let torrent_id = handle.id();
    handle.wait_until_completed().await.context("wait_until_completed")?;

    // Decrypt every shadow file into plaintext. If decryption fails (wrong
    // key, tampered blob), bail out — this is the "fetched ciphertext but
    // can't read it" failure mode that's expected for unauthorized peers.
    let new_manifest = sync_shadow_to_plaintext(root, key)
        .context("decrypting shadow to plaintext after fetch")?;

    // Verify the decrypted plaintext matches the announced version_hash.
    // If not, peers disagree about content — likely a key mismatch silently
    // producing junk that AEAD would have caught (defense in depth) or a
    // peerdup bug.
    let (computed_vhash, _) = snapshot_content(root)?;
    if computed_vhash != remote_vhash {
        return Err(anyhow!(
            "decrypted plaintext version_hash {} != announced {}",
            computed_vhash,
            remote_vhash
        ));
    }

    // Orphan deletion in the plaintext root, using the plaintext manifest.
    if let Some(s) = current {
        delete_orphans(root, &s.manifest, &new_manifest);
    }

    let mut clock = current.map(|s| s.clock.clone()).unwrap_or_default();
    clock.merge(remote_clock);

    Ok(ShareState {
        version_hash: remote_vhash.to_string(),
        info_hash: info_hash.to_string(),
        torrent_id,
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
fn spawn_fs_watcher(
    root: &Path,
) -> Result<(notify::RecommendedWatcher, UnboundedReceiver<()>)> {
    use notify::{RecommendedWatcher, RecursiveMode, Watcher};
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(ev) => {
                // Skip events fully inside the shadow dir — those are our
                // own writes; reacting would make us recompute and re-encrypt
                // forever.
                let all_in_shadow = !ev.paths.is_empty()
                    && ev.paths.iter().all(|p| {
                        p.components()
                            .any(|c| c.as_os_str() == PEERDUP_DIR_NAME)
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

async fn publish_sync_announce(handle: &GossipHandle, state: &ShareState, bt_port: u16) {
    let bt_endpoints = vec![("127.0.0.1".to_string(), bt_port)];
    let announce = ShareMsg::Announce {
        info_hash: state.info_hash.clone(),
        bt_endpoints,
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
async fn apply_key_rotation(
    rotation: SignedRotation,
    auth_state: &AuthState,
    group_id: MemberId,
    identity: &PrivateKey,
    key: &Arc<RwLock<KeyRing>>,
    rotation_buffer: &mut Vec<SignedRotation>,
    data_dir: &Path,
    share_id: &str,
) -> Result<()> {
    match try_install_rotation(&rotation, auth_state, group_id, identity, key, data_dir, share_id)
        .await?
    {
        AppliedOrBuffered::Applied => {
            // Drain buffered rotations whose epochs are now installable.
            drain_rotation_buffer(
                auth_state, group_id, identity, key, rotation_buffer, data_dir, share_id,
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
    identity: &PrivateKey,
    key: &Arc<RwLock<KeyRing>>,
    data_dir: &Path,
    share_id: &str,
) -> Result<AppliedOrBuffered> {
    match rotation::verify_and_decrypt(rotation, auth_state, group_id, identity) {
        VerifyOutcome::OkForUs(new_key) => {
            let outcome =
                crypto::install_epoch_key(data_dir, share_id, rotation.epoch, &new_key)
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
                    let fresh = crypto::load_or_create_keyring(data_dir, share_id)
                        .with_context(|| {
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
    identity: &PrivateKey,
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
