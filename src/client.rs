//! Phase 7 CLI-side D-Bus client.
//!
//! Each CLI subcommand opens a session-bus `DaemonClient` and forwards
//! arguments to the running daemon's `org.peerdup.Daemon1` interface.
//! Pretty-printing stays in `main.rs`; this module is just method-call
//! plumbing and friendly error mapping for "daemon not registered" cases.
//!
//! The daemon is auto-started on first call by `dbus-broker` if the
//! activation `.service` file is installed under
//! `~/.local/share/dbus-1/services/`. Without that file, every method
//! call fails with `org.freedesktop.DBus.Error.ServiceUnknown` and we
//! map it back to a clear "run install.sh" message.

use crate::ipc::{BUS_NAME, OBJECT_PATH};
use anyhow::{anyhow, Context, Result};
use std::path::Path;

/// Thin handle over a `zbus::Proxy` for `org.peerdup.Daemon1`. Each method
/// awaits the proxy call and returns `anyhow::Result<T>` so the CLI can
/// keep using `?` and `with_context`.
pub struct DaemonClient {
    proxy: zbus::Proxy<'static>,
}

impl DaemonClient {
    /// Open a session-bus connection and build the proxy. Returns a
    /// human-readable error if no session bus is reachable.
    pub async fn connect() -> Result<Self> {
        let conn = zbus::Connection::session().await.map_err(|e| {
            // The most common failure here is "no DBUS_SESSION_BUS_ADDRESS
            // and no $XDG_RUNTIME_DIR/bus" — log the underlying detail
            // unchanged and add an actionable hint.
            anyhow!(
                "no D-Bus session bus available ({e}). Are you running outside a \
                 desktop session? On a server, wrap commands in `dbus-run-session` \
                 or run the daemon with `rust-peerdup serve --no-dbus`."
            )
        })?;
        let proxy = zbus::Proxy::new(&conn, BUS_NAME, OBJECT_PATH, BUS_NAME)
            .await
            .context("creating Daemon1 proxy")?;
        Ok(Self { proxy })
    }

    pub async fn whoami(&self) -> Result<String> {
        self.call_no_args("Whoami").await
    }

    pub async fn share_list(&self) -> Result<Vec<(String, String, String, String, String)>> {
        self.call_no_args("ShareList").await
    }

    pub async fn share_add(
        &self,
        topic: &str,
        path: &Path,
        role: &str,
    ) -> Result<String> {
        let path_str = path.to_string_lossy().into_owned();
        self.proxy
            .call("ShareAdd", &(topic, path_str.as_str(), role))
            .await
            .map_err(map_call_err)
    }

    pub async fn share_join(&self, ticket: &str, path: &Path) -> Result<String> {
        let path_str = path.to_string_lossy().into_owned();
        self.proxy
            .call("ShareJoin", &(ticket, path_str.as_str()))
            .await
            .map_err(map_call_err)
    }

    pub async fn share_invite(
        &self,
        id: &str,
        invitee_pubkey: &str,
        role: &str,
        auth_role: &str,
    ) -> Result<String> {
        self.proxy
            .call("ShareInvite", &(id, invitee_pubkey, role, auth_role))
            .await
            .map_err(map_call_err)
    }

    pub async fn share_revoke(&self, id: &str, peer_pubkey: &str) -> Result<u64> {
        self.proxy
            .call("ShareRevoke", &(id, peer_pubkey))
            .await
            .map_err(map_call_err)
    }

    pub async fn share_members(&self, id: &str) -> Result<Vec<(String, String)>> {
        self.proxy
            .call("ShareMembers", &(id,))
            .await
            .map_err(map_call_err)
    }

    pub async fn share_peers(&self, id: &str) -> Result<Vec<(String, u64)>> {
        self.proxy
            .call("SharePeers", &(id,))
            .await
            .map_err(map_call_err)
    }

    pub async fn share_rotate_key(&self, id: &str) -> Result<u64> {
        self.proxy
            .call("ShareRotateKey", &(id,))
            .await
            .map_err(map_call_err)
    }

    pub async fn share_remove(&self, id: &str) -> Result<()> {
        self.proxy
            .call("ShareRemove", &(id,))
            .await
            .map_err(map_call_err)
    }

    async fn call_no_args<R>(&self, method: &'static str) -> Result<R>
    where
        R: for<'de> zbus::zvariant::Type
            + for<'de> serde::Deserialize<'de>
            + std::fmt::Debug,
    {
        self.proxy.call(method, &()).await.map_err(map_call_err)
    }
}

/// Map zbus call errors to actionable CLI messages. `ServiceUnknown` is
/// the load-bearing case: it signals the activation `.service` file isn't
/// installed (or has a typo), so the bus cannot start the daemon.
fn map_call_err(e: zbus::Error) -> anyhow::Error {
    if let zbus::Error::FDO(boxed) = &e {
        if let zbus::fdo::Error::ServiceUnknown(_) = boxed.as_ref() {
            return anyhow!(
                "rust-peerdup daemon is not registered with the session bus. \
                 Run ./install.sh to set up D-Bus activation, or start the \
                 daemon manually with `rust-peerdup serve --bt-port 41000`."
            );
        }
        if let zbus::fdo::Error::SpawnFailed(msg) = boxed.as_ref() {
            return anyhow!(
                "session bus tried to activate rust-peerdup but the unit \
                 failed: {msg}. Check `journalctl --user -u rust-peerdup -n 50`."
            );
        }
    }
    anyhow::Error::new(e).context("D-Bus call failed")
}
