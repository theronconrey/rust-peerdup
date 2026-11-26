// SPDX-License-Identifier: MIT
use crate::auth::{group_id_for, AuthState, MemberId, SignedOp};
use crate::crypto::KEY_LEN;
use crate::share::{ShareConfig, ShareRole};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Largest decoded ticket. A ticket holds the keyring and the whole auth
/// log (about 200 bytes an op), so this is thousands of members.
pub const MAX_TICKET_BYTES: usize = 1024 * 1024;

/// Current ticket schema version. 2 added the auth-log snapshot (Phase 5c);
/// 3 added the inviter's network address. Older tickets are refused.
pub const TICKET_VERSION: u8 = 3;

/// A share invitation. Contains everything a receiving peer needs to join
/// the share locally: the topic (so gossip lines up), the per-share keyring
/// (so the receiver can decrypt content), the auth-log snapshot (so the
/// receiver can replay group membership and recognise themselves as a
/// member), and a suggested role.
///
/// **Warning:** the ticket carries the encryption key in plaintext.
/// Only send tickets over secure channels (Signal, encrypted mail, etc.).
/// Anyone who sees a ticket gains access to the share's content for as long
/// as those keys are valid; rotating the key invalidates older tickets but
/// does not retroactively shut anyone out who already received content
/// under an old epoch.
#[derive(Serialize, Deserialize, Debug)]
pub struct Ticket {
    /// Schema version of the ticket format itself. Current: 2.
    pub version: u8,
    /// Logical share id (`hex(blake3(topic))[..16]`). Receivers use this
    /// directly as the share id; it doesn't need to be recomputed.
    pub share_id: String,
    /// Topic string. Receivers will hash it to derive the gossip topic.
    pub topic: String,
    /// Concatenated 32-byte keys, epoch N's key at index N-1. Same wire
    /// format as `keys.bin` on disk.
    pub keys: Vec<[u8; KEY_LEN]>,
    /// Snapshot of the inviter's auth log at the moment of invitation,
    /// already containing the `Add` op for `invitee_pubkey`. The receiver
    /// replays these to construct their local `AuthState`.
    pub auth_log: Vec<SignedOp>,
    /// Raw 32-byte Ed25519 public key the inviter expects the receiver to
    /// use. Must match the receiver's local `identity.key`; otherwise the
    /// receiver isn't actually a member according to the embedded auth log.
    pub invitee_pubkey: [u8; 32],
    /// Transport role the inviter suggests for this peer (Seed/Leech/Sync).
    /// Distinct from the auth-level role inside `auth_log`.
    pub role: ShareRole,
    /// The inviter's iroh address (node id, home relay, direct addresses)
    /// when its daemon has run, so the joiner can reach it on another
    /// network. Kept as the share's bootstrap peer (`bootstrap.rs`).
    pub inviter_addr: Option<p2panda_net::iroh_endpoint::EndpointAddr>,
}

impl Ticket {
    pub fn encode(&self) -> Result<String> {
        let bytes = bincode::serde::encode_to_vec(self, bincode::config::standard())
            .context("encoding ticket")?;
        Ok(URL_SAFE_NO_PAD.encode(&bytes))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let s = s.trim();
        // base64 is 4 characters per 3 bytes.
        if s.len() / 4 * 3 > MAX_TICKET_BYTES {
            return Err(anyhow!("ticket is over {MAX_TICKET_BYTES} bytes"));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .context("ticket is not valid base64")?;
        let (ticket, _read): (Ticket, _) = bincode::serde::decode_from_slice(
            &bytes,
            bincode::config::standard().with_limit::<MAX_TICKET_BYTES>(),
        )
        .context("ticket payload is malformed")?;
        if ticket.version != TICKET_VERSION {
            return Err(anyhow!(
                "unsupported ticket version: {} (this build expects v{TICKET_VERSION})",
                ticket.version
            ));
        }
        if ticket.keys.is_empty() {
            return Err(anyhow!("ticket has no keys"));
        }
        if ticket.auth_log.is_empty() {
            return Err(anyhow!("ticket has no auth log"));
        }
        // share_id becomes a directory name; it must be the one the topic
        // derives, which also makes it 16 hex characters.
        if ticket.share_id != crate::share::id_from_topic(&ticket.topic) {
            return Err(anyhow!(
                "ticket share id {:?} does not match its topic",
                ticket.share_id
            ));
        }
        ticket.role.ensure_encrypted()?;
        Ok(ticket)
    }

    /// Replay and verify the ticket's auth log for `me`, before anything
    /// is written to disk: every op's signature, the group (the first op
    /// must be this share's `Create`), no op left waiting for a missing
    /// dependency, and `me` a member at the end.
    pub fn verified_auth_state(&self, me: MemberId) -> Result<AuthState> {
        if self.invitee_pubkey != me.0 {
            return Err(anyhow!(
                "ticket was issued for a different public key (expected {}, this peer is {}); \
                 ask the inviter to re-run `share invite` with the correct key",
                MemberId(self.invitee_pubkey).to_hex(),
                me.to_hex()
            ));
        }
        let group = group_id_for(&self.share_id);
        let mut state = AuthState::empty_for(group);
        for op in &self.auth_log {
            state.apply_remote(op.clone()).with_context(|| {
                format!("applying auth log op while joining share {}", self.share_id)
            })?;
        }
        if state.pending_len() > 0 {
            return Err(anyhow!(
                "ticket's auth log has {} op(s) with missing dependencies",
                state.pending_len()
            ));
        }
        if !state.is_member(state.group_id(), me) {
            return Err(anyhow!(
                "ticket's auth log does not list us as a member; refusing to join"
            ));
        }
        Ok(state)
    }
}

/// Write a joined share to disk, after `Ticket::verified_auth_state`
/// passed: keyring, auth log and bootstrap address first, `share.json`
/// last, so the daemon never sees a configured share whose keys or
/// membership are missing. A share directory without `share.json` is the
/// leftover of an interrupted join and is replaced; if any write fails,
/// the directory is removed again.
pub fn install_join(
    data_dir: &std::path::Path,
    ticket: &Ticket,
    auth_state: &AuthState,
    root_path: std::path::PathBuf,
) -> Result<ShareConfig> {
    crate::share::validate_id(&ticket.share_id)?;
    let dir = crate::data_dir::shares_dir(data_dir).join(&ticket.share_id);
    if dir.join("share.json").exists() {
        return Err(anyhow!(
            "share {} is already configured locally; remove it first if you want to re-join",
            ticket.share_id
        ));
    }
    if dir.exists() {
        tracing::warn!(share_id = %ticket.share_id, "replacing the leftovers of an interrupted join");
        std::fs::remove_dir_all(&dir).with_context(|| format!("removing {dir:?}"))?;
    }
    let cfg = ShareConfig {
        id: ticket.share_id.clone(),
        topic: ticket.topic.clone(),
        root_path,
        role: ticket.role,
        created_at: chrono::Utc::now(),
    };
    let written = (|| -> Result<()> {
        crate::crypto::install_keyring(data_dir, &ticket.share_id, &ticket.keys)?;
        crate::auth::save(data_dir, &ticket.share_id, auth_state)?;
        if let Some(addr) = &ticket.inviter_addr {
            crate::bootstrap::save_share_bootstrap(data_dir, &ticket.share_id, addr)?;
        }
        cfg.save(data_dir)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e.context(format!("writing share {}", ticket.share_id)));
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{group_id_for, AuthRole, AuthState, MemberId};
    use p2panda_core::SigningKey;

    fn make_log() -> (SigningKey, SigningKey, Vec<SignedOp>) {
        make_log_for("demo")
    }

    fn make_log_for(topic: &str) -> (SigningKey, SigningKey, Vec<SignedOp>) {
        let alice = SigningKey::generate();
        let bob = SigningKey::generate();
        let group = group_id_for(&crate::share::id_from_topic(topic));
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(
                &alice,
                group,
                MemberId(*bob.verifying_key().as_bytes()),
                AuthRole::Writer,
            )
            .unwrap();
        (alice, bob, state.ops().to_vec())
    }

    #[test]
    fn round_trip() {
        let (_alice, bob, log) = make_log();
        let t = Ticket {
            version: TICKET_VERSION,
            share_id: crate::share::id_from_topic("demo"),
            topic: "demo".into(),
            keys: vec![[1u8; KEY_LEN], [2u8; KEY_LEN]],
            auth_log: log.clone(),
            invitee_pubkey: *bob.verifying_key().as_bytes(),
            role: ShareRole::Sync,
            inviter_addr: None,
        };
        let s = t.encode().unwrap();
        let back = Ticket::decode(&s).unwrap();
        assert_eq!(back.share_id, t.share_id);
        assert_eq!(back.topic, t.topic);
        assert_eq!(back.keys, t.keys);
        assert_eq!(back.role, t.role);
        assert_eq!(back.invitee_pubkey, t.invitee_pubkey);
        assert_eq!(back.auth_log.len(), log.len());
        // Signatures survive the round-trip.
        for op in &back.auth_log {
            op.verify().unwrap();
        }
    }

    fn ticket_with(log: Vec<SignedOp>, invitee: &SigningKey) -> Ticket {
        Ticket {
            version: TICKET_VERSION,
            share_id: crate::share::id_from_topic("demo"),
            topic: "demo".into(),
            keys: vec![[1u8; KEY_LEN]],
            auth_log: log,
            invitee_pubkey: *invitee.verifying_key().as_bytes(),
            role: ShareRole::Sync,
            inviter_addr: None,
        }
    }

    fn me(k: &SigningKey) -> MemberId {
        MemberId(*k.verifying_key().as_bytes())
    }

    #[test]
    fn join_verifies_the_auth_log_for_us() {
        let (alice, bob, log) = make_log();
        let state = ticket_with(log.clone(), &bob)
            .verified_auth_state(me(&bob))
            .unwrap();
        assert!(state.is_member(state.group_id(), me(&alice)));
        assert!(state.is_member(state.group_id(), me(&bob)));

        // Issued for someone else.
        let carol = SigningKey::generate();
        let err = ticket_with(log.clone(), &bob)
            .verified_auth_state(me(&carol))
            .err()
            .expect("refused")
            .to_string();
        assert!(err.contains("different public key"), "{err}");

        // A log for another share's group.
        let (_, other_bob, other_log) = make_log_for("another-share");
        assert!(ticket_with(other_log, &other_bob)
            .verified_auth_state(me(&other_bob))
            .is_err());

        // A log that never adds us.
        let err = ticket_with(log[..1].to_vec(), &bob)
            .verified_auth_state(me(&bob))
            .err()
            .expect("refused")
            .to_string();
        assert!(err.contains("not list us"), "{err}");

        // A log missing its Create: the Add waits forever.
        let err = ticket_with(log[1..].to_vec(), &bob)
            .verified_auth_state(me(&bob))
            .err()
            .expect("refused")
            .to_string();
        assert!(err.contains("missing dependencies"), "{err}");
    }

    #[test]
    fn rejects_oversize_tickets() {
        let huge = "A".repeat(MAX_TICKET_BYTES / 3 * 4 + 8);
        let err = Ticket::decode(&huge).unwrap_err().to_string();
        assert!(err.contains("over"), "{err}");
    }

    #[test]
    fn rejects_bad_base64() {
        assert!(Ticket::decode("!!!not base64!!!").is_err());
    }

    #[test]
    fn rejects_old_version() {
        // Construct a malformed payload that claims version 1.
        let (_alice, bob, log) = make_log();
        let mut t = Ticket {
            version: 1,
            share_id: crate::share::id_from_topic("demo"),
            topic: "demo".into(),
            keys: vec![[1u8; KEY_LEN]],
            auth_log: log,
            invitee_pubkey: *bob.verifying_key().as_bytes(),
            role: ShareRole::Sync,
            inviter_addr: None,
        };
        let s = t.encode().unwrap();
        let err = Ticket::decode(&s).unwrap_err().to_string();
        assert!(err.contains("unsupported ticket version"), "got: {err}");
        // Sanity: bumping to current version makes it accept.
        t.version = TICKET_VERSION;
        assert!(Ticket::decode(&t.encode().unwrap()).is_ok());
    }

    #[test]
    fn rejects_share_id_that_does_not_match_topic() {
        let (_alice, bob, log) = make_log();
        let t = Ticket {
            version: TICKET_VERSION,
            share_id: "../../../../tmp/evil".into(),
            topic: "demo".into(),
            keys: vec![[7u8; KEY_LEN]],
            auth_log: log,
            invitee_pubkey: *bob.verifying_key().as_bytes(),
            role: ShareRole::Sync,
            inviter_addr: None,
        };
        let err = Ticket::decode(&t.encode().unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match its topic"), "{err}");
    }

    #[test]
    fn inviter_address_survives_the_round_trip() {
        let (_alice, bob, log) = make_log();
        let id = iroh::PublicKey::from_bytes(bob.verifying_key().as_bytes()).unwrap();
        let addr = p2panda_net::iroh_endpoint::EndpointAddr::new(id)
            .with_relay_url(crate::bootstrap::default_relay_urls()[0].clone());
        let t = Ticket {
            version: TICKET_VERSION,
            share_id: crate::share::id_from_topic("demo"),
            topic: "demo".into(),
            keys: vec![[3u8; KEY_LEN]],
            auth_log: log,
            invitee_pubkey: *bob.verifying_key().as_bytes(),
            role: ShareRole::Sync,
            inviter_addr: Some(addr.clone()),
        };
        let back = Ticket::decode(&t.encode().unwrap()).unwrap();
        assert_eq!(back.inviter_addr, Some(addr));
    }
}
