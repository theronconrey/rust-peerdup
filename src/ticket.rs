use crate::crypto::KEY_LEN;
use crate::share::ShareRole;
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// A share invitation. Contains everything a receiving peer needs to join
/// the share locally: the topic (so gossip lines up), the per-share keyring
/// (so the receiver can decrypt content), and a suggested role.
///
/// **Warning:** the ticket carries the encryption key in plaintext.
/// Only send tickets over secure channels (Signal, encrypted mail, etc.).
/// Anyone who sees a ticket gains access to the share's content for as long
/// as those keys are valid; rotating the key (Phase 4.2) invalidates older
/// tickets but does not retroactively shut anyone out who already received
/// content under an old epoch.
#[derive(Serialize, Deserialize, Debug)]
pub struct Ticket {
    /// Schema version of the ticket format itself. Current: 1.
    pub version: u8,
    /// Logical share id (`hex(blake3(topic))[..16]`). Receivers use this
    /// directly as the share id; it doesn't need to be recomputed.
    pub share_id: String,
    /// Topic string. Receivers will hash it to derive the gossip topic.
    pub topic: String,
    /// Concatenated 32-byte keys, epoch N's key at index N-1. Same wire
    /// format as `keys.bin` on disk.
    pub keys: Vec<[u8; KEY_LEN]>,
    /// Role the inviter suggests for this peer. Not enforced in Phase 5a;
    /// 5c+ will turn this into an actual capability.
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
        if ticket.version != 1 {
            return Err(anyhow!(
                "unsupported ticket version: {} (this build expects v1)",
                ticket.version
            ));
        }
        if ticket.keys.is_empty() {
            return Err(anyhow!("ticket has no keys"));
        }
        Ok(ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let t = Ticket {
            version: 1,
            share_id: "abcd1234".into(),
            topic: "demo".into(),
            keys: vec![[1u8; KEY_LEN], [2u8; KEY_LEN]],
            role: ShareRole::Sync,
        };
        let s = t.encode().unwrap();
        let back = Ticket::decode(&s).unwrap();
        assert_eq!(back.share_id, t.share_id);
        assert_eq!(back.topic, t.topic);
        assert_eq!(back.keys, t.keys);
        assert_eq!(back.role, t.role);
    }

    #[test]
    fn rejects_bad_base64() {
        assert!(Ticket::decode("!!!not base64!!!").is_err());
    }
}
