use crate::auth::SignedOp;
use crate::crypto::KEY_LEN;
use crate::share::ShareRole;
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Current ticket schema version. Bumped to 2 in Phase 5c when the auth-log
/// snapshot was added; v1 tickets are no longer accepted.
pub const TICKET_VERSION: u8 = 2;

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
}

impl Ticket {
    pub fn encode(&self) -> Result<String> {
        let bytes = bincode::serde::encode_to_vec(self, bincode::config::standard())
            .context("encoding ticket")?;
        Ok(URL_SAFE_NO_PAD.encode(&bytes))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s.trim())
            .context("ticket is not valid base64")?;
        let (ticket, _read): (Ticket, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
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
        Ok(ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{group_id_for, AuthRole, AuthState, MemberId};
    use p2panda_core::PrivateKey;

    fn make_log() -> (PrivateKey, PrivateKey, Vec<SignedOp>) {
        let alice = PrivateKey::new();
        let bob = PrivateKey::new();
        let group = group_id_for("ticket-test");
        let mut state = AuthState::empty();
        state.create_group(&alice, group).unwrap();
        state
            .add_member(
                &alice,
                group,
                MemberId(*bob.public_key().as_bytes()),
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
            share_id: "abcd1234".into(),
            topic: "demo".into(),
            keys: vec![[1u8; KEY_LEN], [2u8; KEY_LEN]],
            auth_log: log.clone(),
            invitee_pubkey: *bob.public_key().as_bytes(),
            role: ShareRole::Sync,
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
            share_id: "abcd1234".into(),
            topic: "demo".into(),
            keys: vec![[1u8; KEY_LEN]],
            auth_log: log,
            invitee_pubkey: *bob.public_key().as_bytes(),
            role: ShareRole::Sync,
        };
        let s = t.encode().unwrap();
        let err = Ticket::decode(&s).unwrap_err().to_string();
        assert!(err.contains("unsupported ticket version"), "got: {err}");
        // Sanity: bumping to current version makes it accept.
        t.version = TICKET_VERSION;
        assert!(Ticket::decode(&t.encode().unwrap()).is_ok());
    }
}
