//! Phase 7: D-Bus IPC surface.
//!
//! Exposes `org.peerdup.Daemon1` on the user session bus. Other processes
//! (CLI, GNOME extension, etc.) drive share lifecycle and inspection live,
//! replacing the Phase 2 "edit files on disk and restart the daemon"
//! pattern. Modeled on Fedora conventions: thin CLI, D-Bus activation,
//! session bus.
//!
//! The interface name is `org.peerdup.Daemon1` and the object path is
//! `/org/peerdup/Daemon1`. zbus exposes `snake_case` Rust method names
//! as `PascalCase` on the wire (matching `nmcli`/`firewall-cmd`).
//!
//! Auth gate: none. Session bus is already user-scoped, and this matches
//! the pre-existing data-dir threat model.

use crate::auth::{self, MemberId};
use crate::daemon::{spawn_share_task, DaemonRuntime, ShareCommand};
use crate::share::{self, ShareConfig, ShareRole};
use crate::{crypto, identity, share_state};
use anyhow::Context;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::oneshot;
use zbus::interface;

pub const BUS_NAME: &str = "org.peerdup.Daemon1";
pub const OBJECT_PATH: &str = "/org/peerdup/Daemon1";

/// The D-Bus-exposed object. Holds an `Arc<DaemonRuntime>` so each method
/// dispatch can look at shared state (the per-share command channels, the
/// data dir, etc.) without serializing on a single mutex.
pub struct Daemon1Iface {
    rt: Arc<DaemonRuntime>,
}

impl Daemon1Iface {
    pub fn new(rt: Arc<DaemonRuntime>) -> Self {
        Self { rt }
    }
}

/// Map an `anyhow::Error` to `zbus::fdo::Error::Failed`. The full chain is
/// preserved in the message so callers see the underlying cause.
fn fdo_err(e: anyhow::Error) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(format!("{e:#}"))
}

#[interface(name = "org.peerdup.Daemon1")]
impl Daemon1Iface {
    /// Return the daemon's identity public key as 64-char hex.
    async fn whoami(&self) -> zbus::fdo::Result<String> {
        Ok(self.rt.identity.public_key().to_hex())
    }

    /// Return all configured shares as `(id, topic, root_path, role,
    /// created_at_rfc3339)` tuples. Reads from disk (single source of
    /// truth for share configs); the running daemon's spawned-task map
    /// is a subset of this list (shares may exist on disk but not yet be
    /// running, e.g. immediately after `share-add` before the spawn task
    /// has registered).
    async fn share_list(
        &self,
    ) -> zbus::fdo::Result<Vec<(String, String, String, String, String)>> {
        let configs = share::load_all(&self.rt.data_dir).map_err(fdo_err)?;
        let mut out = Vec::with_capacity(configs.len());
        for c in configs {
            let role = match c.role {
                ShareRole::Seed => "seed",
                ShareRole::Leech => "leech",
                ShareRole::Sync => "sync",
            };
            out.push((
                c.id,
                c.topic,
                c.root_path.display().to_string(),
                role.to_string(),
                c.created_at.to_rfc3339(),
            ));
        }
        Ok(out)
    }

    /// Add a new share to disk and spawn its share task. Returns the
    /// allocated share id. The share is bootstrapped with this daemon as
    /// auth-group Owner, mirroring the Phase 5c CLI's `share-add` body.
    async fn share_add(
        &self,
        topic: &str,
        path: &str,
        role: &str,
    ) -> zbus::fdo::Result<String> {
        let role = ShareRole::from_str(role)
            .map_err(|e| fdo_err(anyhow::anyhow!("invalid role {role:?}: {e}")))?;
        let path = PathBuf::from(path);
        if matches!(role, ShareRole::Seed) && !path.exists() {
            return Err(fdo_err(anyhow::anyhow!(
                "seed path does not exist: {path:?}"
            )));
        }

        // Hold both runtime locks together while we check for an existing
        // share with the same id and spawn the new task. This avoids the
        // race where two concurrent ShareAdd calls with the same topic
        // both pass the existence check.
        let mut shares_guard = self.rt.shares.lock().await;
        let mut tasks_guard = self.rt.tasks.lock().await;

        let config = ShareConfig::new(topic.to_string(), path, role);
        let share_id = config.id.clone();

        if shares_guard.contains_key(&share_id) {
            return Err(fdo_err(anyhow::anyhow!(
                "share {share_id} is already running"
            )));
        }

        // Bootstrap auth group with us as Owner.
        let group_id = auth::group_id_for(&config.id);
        let mut auth_state = auth::AuthState::empty();
        auth_state
            .create_group(&self.rt.identity, group_id)
            .map_err(fdo_err)?;

        config.save(&self.rt.data_dir).map_err(fdo_err)?;
        auth::save(&self.rt.data_dir, &config.id, &auth_state).map_err(fdo_err)?;

        // Spawn the share task and register the sender.
        let cmd_tx = spawn_share_task(&self.rt, &mut tasks_guard, config.clone())
            .await
            .map_err(fdo_err)?;
        shares_guard.insert(share_id.clone(), cmd_tx);

        Ok(share_id)
    }

    /// Consume an invitation ticket: register the share locally, import
    /// its keyring and auth log, spawn the share task. Returns the share
    /// id from the ticket.
    async fn share_join(&self, ticket: &str, path: &str) -> zbus::fdo::Result<String> {
        use crate::ticket;
        let t = ticket::Ticket::decode(ticket).map_err(fdo_err)?;

        let path = PathBuf::from(path);
        let path = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()
                .context("resolving cwd for relative join path")
                .map_err(fdo_err)?
                .join(path)
        };

        let me = *self.rt.identity.public_key().as_bytes();
        if t.invitee_pubkey != me {
            return Err(fdo_err(anyhow::anyhow!(
                "ticket was issued for a different public key (expected {}, this daemon is {})",
                MemberId(t.invitee_pubkey).to_hex(),
                self.rt.identity.public_key().to_hex()
            )));
        }

        let mut shares_guard = self.rt.shares.lock().await;
        let mut tasks_guard = self.rt.tasks.lock().await;

        // Reject duplicate joins.
        if shares_guard.contains_key(&t.share_id) {
            return Err(fdo_err(anyhow::anyhow!(
                "share {} is already running",
                t.share_id
            )));
        }
        let configs = share::load_all(&self.rt.data_dir).map_err(fdo_err)?;
        if configs.iter().any(|c| c.id == t.share_id) {
            return Err(fdo_err(anyhow::anyhow!(
                "share {} is already configured locally",
                t.share_id
            )));
        }

        std::fs::create_dir_all(&path).map_err(|e| fdo_err(anyhow::Error::new(e)))?;

        let cfg = ShareConfig {
            id: t.share_id.clone(),
            topic: t.topic.clone(),
            root_path: path,
            role: t.role,
            created_at: chrono::Utc::now(),
        };
        cfg.save(&self.rt.data_dir).map_err(fdo_err)?;
        crypto::install_keyring(&self.rt.data_dir, &t.share_id, &t.keys).map_err(fdo_err)?;

        // Replay the auth log. Each op is signature-verified via apply_remote.
        let mut auth_state = auth::AuthState::empty();
        for op in &t.auth_log {
            auth_state
                .apply_remote(op.clone())
                .with_context(|| format!("applying auth op while joining {}", t.share_id))
                .map_err(fdo_err)?;
        }
        let group_id = auth::group_id_for(&t.share_id);
        if !auth_state.is_member(group_id, MemberId(me)) {
            return Err(fdo_err(anyhow::anyhow!(
                "ticket's auth log does not list us as a member"
            )));
        }
        auth::save(&self.rt.data_dir, &t.share_id, &auth_state).map_err(fdo_err)?;

        let cmd_tx = spawn_share_task(&self.rt, &mut tasks_guard, cfg.clone())
            .await
            .map_err(fdo_err)?;
        shares_guard.insert(t.share_id.clone(), cmd_tx);

        Ok(t.share_id)
    }

    /// Author a signed `Add` op for `invitee_pubkey`, append to the local
    /// auth log, and return a base64 ticket containing the keyring + log
    /// snapshot so the receiver can join.
    async fn share_invite(
        &self,
        id: &str,
        invitee_pubkey: &str,
        role: &str,
        auth_role: &str,
    ) -> zbus::fdo::Result<String> {
        let role = ShareRole::from_str(role)
            .map_err(|e| fdo_err(anyhow::anyhow!("invalid role {role:?}: {e}")))?;
        let auth_role = parse_auth_role(auth_role).map_err(fdo_err)?;
        let invitee = MemberId::from_hex(invitee_pubkey)
            .context("parsing invitee public key")
            .map_err(fdo_err)?;

        // Run via the share's command channel so per-share auth/keyring
        // mutations stay serialised on the share loop's stack.
        let tx = self.share_sender(id).await?;
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ShareCommand::Invite {
            invitee,
            auth_role,
            suggested_role: role,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            zbus::fdo::Error::Failed("share task no longer running".to_string())
        })?;
        let ticket = reply_rx
            .await
            .map_err(|_| zbus::fdo::Error::Failed("share task dropped reply".to_string()))?
            .map_err(fdo_err)?;
        Ok(ticket)
    }

    /// Revoke a member: append `Remove`, rotate keyring, queue per-member
    /// rotation envelopes. Returns the new epoch.
    async fn share_revoke(&self, id: &str, peer_pubkey: &str) -> zbus::fdo::Result<u64> {
        let target = MemberId::from_hex(peer_pubkey)
            .context("parsing peer public key")
            .map_err(fdo_err)?;
        let tx = self.share_sender(id).await?;
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ShareCommand::Revoke {
            target,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            zbus::fdo::Error::Failed("share task no longer running".to_string())
        })?;
        let new_epoch = reply_rx
            .await
            .map_err(|_| zbus::fdo::Error::Failed("share task dropped reply".to_string()))?
            .map_err(fdo_err)?;
        Ok(new_epoch)
    }

    /// Current ACL members: `(hex_pubkey, role)`. Reads the local replay
    /// of the share's auth log via the share task.
    async fn share_members(
        &self,
        id: &str,
    ) -> zbus::fdo::Result<Vec<(String, String)>> {
        let tx = self.share_sender(id).await?;
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ShareCommand::Members { reply: reply_tx })
            .await
            .map_err(|_| {
                zbus::fdo::Error::Failed("share task no longer running".to_string())
            })?;
        let members = reply_rx
            .await
            .map_err(|_| zbus::fdo::Error::Failed("share task dropped reply".to_string()))?
            .map_err(fdo_err)?;
        Ok(members
            .into_iter()
            .map(|(m, r)| (m.to_hex(), r.to_string()))
            .collect())
    }

    /// Activity-based peer list (vector clock entries): `(hex_pubkey,
    /// version_count)`. This is the same data shown by `share-peers` in
    /// the CLI, served from the share task so a running daemon's freshly
    /// observed peer counts are reflected without the CLI needing to poke
    /// at on-disk state.
    async fn share_peers(&self, id: &str) -> zbus::fdo::Result<Vec<(String, u64)>> {
        // share_peers is a read; we can serve it from disk rather than
        // round-tripping through the share task. The share loop only
        // mutates state.json on its own ticks, and that file is what the
        // CLI used to read pre-Phase-7. Disk-side keeps this method
        // consistent across "share is running" and "share is paused".
        let configs = share::load_all(&self.rt.data_dir).map_err(fdo_err)?;
        if !configs.iter().any(|c| c.id == id) {
            return Err(fdo_err(anyhow::anyhow!("share {id} not found")));
        }
        let state = share_state::load(&self.rt.data_dir, id).map_err(fdo_err)?;
        let Some(state) = state else {
            return Ok(Vec::new());
        };
        let mut peers: Vec<(String, u64)> = state
            .clock
            .0
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        peers.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        Ok(peers)
    }

    /// Append a fresh epoch key to the keyring. Returns the new epoch.
    async fn share_rotate_key(&self, id: &str) -> zbus::fdo::Result<u64> {
        let tx = self.share_sender(id).await?;
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ShareCommand::RotateKey { reply: reply_tx })
            .await
            .map_err(|_| {
                zbus::fdo::Error::Failed("share task no longer running".to_string())
            })?;
        let new_epoch = reply_rx
            .await
            .map_err(|_| zbus::fdo::Error::Failed("share task dropped reply".to_string()))?
            .map_err(fdo_err)?;
        Ok(new_epoch)
    }

    /// Stop the share task and remove the share's directory + shadow.
    async fn share_remove(&self, id: &str) -> zbus::fdo::Result<()> {
        // Look up the share root before tearing down state, so we can clean
        // the .peerdup shadow afterwards.
        let configs = share::load_all(&self.rt.data_dir).map_err(fdo_err)?;
        let root = configs
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.root_path.clone());

        // Remove the sender + ask the share task to shut down. We hold the
        // shares lock briefly so a concurrent share_add for the same id
        // can't interleave.
        let maybe_tx = {
            let mut shares = self.rt.shares.lock().await;
            shares.remove(id)
        };
        if let Some(tx) = maybe_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            // If the task already exited, send may fail — treat as a
            // successful early shutdown.
            if tx.send(ShareCommand::Shutdown { reply: reply_tx }).await.is_ok() {
                let _ = reply_rx.await;
            }
        }

        share::remove(&self.rt.data_dir, id).map_err(fdo_err)?;

        if let Some(root) = root {
            let shadow_parent = root.join(".peerdup");
            if shadow_parent.exists() {
                if let Err(e) = std::fs::remove_dir_all(&shadow_parent) {
                    tracing::warn!(error = %e, path = %shadow_parent.display(),
                        "could not remove shadow dir during share_remove");
                }
            }
        }
        Ok(())
    }
}

impl Daemon1Iface {
    /// Look up the per-share command sender. Returns a `not found` fdo
    /// error if the share isn't currently running.
    async fn share_sender(
        &self,
        id: &str,
    ) -> zbus::fdo::Result<tokio::sync::mpsc::Sender<ShareCommand>> {
        let shares = self.rt.shares.lock().await;
        shares
            .get(id)
            .cloned()
            .ok_or_else(|| zbus::fdo::Error::Failed(format!("share {id} not running")))
    }
}

fn parse_auth_role(s: &str) -> anyhow::Result<auth::AuthRole> {
    match s.to_lowercase().as_str() {
        "owner" => Ok(auth::AuthRole::Owner),
        "writer" => Ok(auth::AuthRole::Writer),
        "reader" => Ok(auth::AuthRole::Reader),
        other => Err(anyhow::anyhow!("unknown auth role {other:?}")),
    }
}

impl FromStr for ShareRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "seed" => Ok(ShareRole::Seed),
            "leech" => Ok(ShareRole::Leech),
            "sync" => Ok(ShareRole::Sync),
            other => Err(format!("unknown role {other:?}")),
        }
    }
}

/// Build a session-bus connection, register `Daemon1Iface` at
/// `/org/peerdup/Daemon1`, and request the bus name. Holds the connection
/// alive by returning it; the caller must keep it in scope for the
/// daemon's lifetime.
pub async fn register(rt: Arc<DaemonRuntime>) -> anyhow::Result<zbus::Connection> {
    let iface = Daemon1Iface::new(rt);
    let conn = zbus::connection::Builder::session()
        .context("opening session bus connection")?
        .name(BUS_NAME)
        .context("requesting bus name")?
        .serve_at(OBJECT_PATH, iface)
        .context("registering object at OBJECT_PATH")?
        .build()
        .await
        .context("building zbus connection")?;
    tracing::info!(bus_name = BUS_NAME, object_path = OBJECT_PATH,
        "registered on session bus");
    Ok(conn)
}

/// Quick auto-detect: is there a session bus we can plausibly use? Used by
/// the daemon to skip IPC registration when running in a headless container
/// (no Containerfile churn needed).
pub fn session_bus_likely_available() -> bool {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        return true;
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        if std::path::Path::new(&runtime).join("bus").exists() {
            return true;
        }
    }
    false
}

// We deliberately keep `identity::*` and `share_state::*` imports referenced
// even when most paths flow through the per-share loop, so future
// refactorings don't drop them by accident.
#[allow(dead_code)]
fn _keep_imports(_: &dyn Fn(&std::path::Path) -> anyhow::Result<()>) {
    let _ = identity::load_or_create;
    let _ = share_state::load;
}
