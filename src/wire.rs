// SPDX-License-Identifier: MIT
//! Gossip wire format v4.
//!
//! Every message on a share's gossip topic is
//! `bincode((v = 4, nonce, ShareMsg))` with `bincode::config::standard()`
//! and a decode limit of `MAX_GOSSIP_MESSAGE`. Before v4 the envelope was
//! JSON, which wrote each bincode-encoded auth op as an array of numbers
//! (about 700 bytes an op), and p2panda-net 0.8.1 refuses to publish
//! anything over its default 4,096 bytes (`GossipPublishError::
//! MessageTooLarge`). So past about five auth ops, or seven members in a
//! key rotation, those messages were never sent (INTEGRATION_NOTES.md,
//! "Gossip message size and wire format v4").
//!
//! Now:
//! - the daemon's gossip runs with `max_message_size = MAX_GOSSIP_MESSAGE`
//!   (64 KiB); every peer on a topic must use the same value;
//! - auth ops travel as raw bytes and are split into messages of at most
//!   `CHUNK_BUDGET` (48 KiB);
//! - key rotations are split into separately signed chunks
//!   (`rotation::build_signed_rotation`).
//!
//! The first byte is the version, so a v4 peer drops anything else
//! (including the old JSON, which starts with `{`), and an older peer fails
//! to parse v4 as JSON and drops it.

use crate::announce::Announce;
use crate::auth::{AuthState, SignedOp};
use crate::rotation::SignedRotation;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Version byte at the start of every message.
pub const WIRE_VERSION: u8 = 4;

/// The gossip layer's maximum message size, set on `GossipConfig`. All
/// peers must agree on it: a peer with a smaller limit can't receive
/// larger messages.
pub const MAX_GOSSIP_MESSAGE: usize = 64 * 1024;

/// What we aim to fill a chunked message up to, leaving room under
/// `MAX_GOSSIP_MESSAGE` for the envelope and any estimate error.
pub const CHUNK_BUDGET: usize = 48 * 1024;

#[derive(Serialize, Deserialize, Debug)]
pub enum ShareMsg {
    /// A version of the share, signed by a Writer or Owner (`announce.rs`).
    Announce(Announce),
    /// Some of the sender's auth ops, each a `SignedOp::encode`d op.
    /// Receivers verify each on its own and buffer the ones whose
    /// dependencies haven't arrived, so chunks can come in any order.
    AuthOps { ops: Vec<Vec<u8>> },
    /// One signed chunk of a key rotation's envelopes.
    KeyRotation(SignedRotation),
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u8,
    /// Random per send. Gossip drops repeated messages, and the periodic
    /// re-broadcasts of auth ops and rotations would otherwise be
    /// byte-identical (see "Signed announces" in INTEGRATION_NOTES.md).
    nonce: u64,
    msg: ShareMsg,
}

fn config() -> impl bincode::config::Config {
    bincode::config::standard().with_limit::<{ MAX_GOSSIP_MESSAGE }>()
}

pub fn encode(msg: ShareMsg) -> Result<Vec<u8>> {
    let env = Envelope {
        v: WIRE_VERSION,
        nonce: rand::random(),
        msg,
    };
    let bytes = bincode::serde::encode_to_vec(&env, config()).context("encoding gossip message")?;
    if bytes.len() > MAX_GOSSIP_MESSAGE {
        return Err(anyhow!(
            "gossip message is {} bytes, over the {MAX_GOSSIP_MESSAGE}-byte limit",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// `None` for anything that isn't a well-formed v4 message.
pub fn decode(bytes: &[u8]) -> Option<ShareMsg> {
    if bytes.len() > MAX_GOSSIP_MESSAGE || bytes.first() != Some(&WIRE_VERSION) {
        return None;
    }
    let (env, _): (Envelope, _) = bincode::serde::decode_from_slice(bytes, config()).ok()?;
    (env.v == WIRE_VERSION).then_some(env.msg)
}

/// Split `items` into runs whose summed `size` (plus a small per-item
/// overhead) stays within `budget`. An item bigger than the budget gets a
/// run of its own.
fn chunk_by_size<T>(items: Vec<T>, budget: usize, size: impl Fn(&T) -> usize) -> Vec<Vec<T>> {
    // Upper bound on bincode's varint length prefix per item.
    const PER_ITEM: usize = 9;
    let mut out: Vec<Vec<T>> = Vec::new();
    let mut cur: Vec<T> = Vec::new();
    let mut used = 0usize;
    for item in items {
        let n = size(&item) + PER_ITEM;
        if !cur.is_empty() && used + n > budget {
            out.push(std::mem::take(&mut cur));
            used = 0;
        }
        used += n;
        cur.push(item);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Every auth op we hold, as encoded gossip messages of at most
/// `CHUNK_BUDGET` of ops each.
pub fn auth_ops_messages(state: &AuthState) -> Result<Vec<Vec<u8>>> {
    let ops: Vec<Vec<u8>> = state
        .ops()
        .iter()
        .map(SignedOp::encode)
        .collect::<Result<_>>()?;
    chunk_by_size(ops, CHUNK_BUDGET, Vec::len)
        .into_iter()
        .map(|ops| encode(ShareMsg::AuthOps { ops }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{group_id_for, AuthRole, MemberId};
    use crate::rotation::{self, VerifyOutcome};
    use p2panda_core::SigningKey;

    fn me(k: &SigningKey) -> MemberId {
        MemberId(*k.verifying_key().as_bytes())
    }

    #[test]
    fn three_hundred_ops_fit_and_every_chunk_decodes_and_verifies() {
        let owner = SigningKey::generate();
        let group = group_id_for("wire-300");
        let mut state = AuthState::empty_for(group);
        state.create_group(&owner, group).unwrap();
        for _ in 0..299 {
            let m = me(&SigningKey::generate());
            state
                .add_member(&owner, group, m, AuthRole::Reader)
                .unwrap();
        }
        assert_eq!(state.ops().len(), 300);

        let msgs = auth_ops_messages(&state).unwrap();
        assert!(msgs.len() > 1, "300 ops should need more than one message");
        let mut receiver = AuthState::empty_for(group);
        let mut seen = 0;
        // Deliver the chunks last-first: order must not matter.
        for bytes in msgs.iter().rev() {
            assert!(bytes.len() <= MAX_GOSSIP_MESSAGE, "{} bytes", bytes.len());
            let Some(ShareMsg::AuthOps { ops }) = decode(bytes) else {
                panic!("chunk did not decode as auth ops");
            };
            for raw in ops {
                let op = SignedOp::decode(&raw).unwrap();
                op.verify().unwrap();
                receiver.apply_remote(op).unwrap();
                seen += 1;
            }
        }
        assert_eq!(seen, 300);
        assert_eq!(receiver.ops().len(), 300);
        assert_eq!(receiver.pending_len(), 0);
        assert_eq!(receiver.members(group).len(), 300);
    }

    #[test]
    fn two_hundred_envelopes_fit_and_each_chunk_verifies() {
        let owner = SigningKey::generate();
        let group = group_id_for("wire-200");
        let mut state = AuthState::empty_for(group);
        state.create_group(&owner, group).unwrap();
        let recipients: Vec<SigningKey> = (0..200).map(|_| SigningKey::generate()).collect();
        let ids: Vec<MemberId> = recipients.iter().map(me).collect();
        let key = [0x5au8; crate::crypto::KEY_LEN];

        for per_chunk in [rotation::ENVELOPES_PER_CHUNK, 64] {
            let chunks = rotation::build_chunks(&owner, group, 2, &key, &ids, per_chunk).unwrap();
            assert_eq!(chunks.len(), 200usize.div_ceil(per_chunk));
            let mut covered = 0;
            for chunk in &chunks {
                covered += chunk.envelopes.len();
                let bytes = encode(ShareMsg::KeyRotation(chunk.clone())).unwrap();
                assert!(bytes.len() <= MAX_GOSSIP_MESSAGE, "{} bytes", bytes.len());
                let Some(ShareMsg::KeyRotation(back)) = decode(&bytes) else {
                    panic!("chunk did not decode as a rotation");
                };
                // Every recipient in this chunk gets the key; one outside
                // it is told the chunk isn't for it.
                for env in &back.envelopes {
                    let k =
                        &recipients[ids.iter().position(|m| *m == env.recipient_pubkey).unwrap()];
                    match rotation::verify_and_decrypt(&back, &state, group, k) {
                        VerifyOutcome::OkForUs(got) => assert_eq!(got, key),
                        other => panic!("expected OkForUs, got {other:?}"),
                    }
                }
                let outsider = recipients
                    .iter()
                    .find(|k| !back.envelopes.iter().any(|e| e.recipient_pubkey == me(k)));
                if let Some(k) = outsider {
                    assert!(matches!(
                        rotation::verify_and_decrypt(&back, &state, group, k),
                        VerifyOutcome::NotForUs
                    ));
                }
            }
            assert_eq!(covered, 200);
        }
    }

    #[test]
    fn other_versions_and_garbage_are_ignored() {
        let owner = SigningKey::generate();
        let group = group_id_for("wire-ver");
        let ann = Announce::sign(
            &owner,
            group,
            "aa".repeat(32),
            "bb".repeat(32),
            crate::clock::VectorClock::new(),
            chrono::Utc::now(),
        );
        let mut bytes = encode(ShareMsg::Announce(ann)).unwrap();
        assert!(matches!(decode(&bytes), Some(ShareMsg::Announce(_))));
        bytes[0] = 3;
        assert!(decode(&bytes).is_none());
        // The pre-v4 JSON envelope.
        assert!(decode(br#"{"kind":"share_auth_ops","ops":[]}"#).is_none());
        assert!(decode(&[]).is_none());
        assert!(decode(&[WIRE_VERSION, 0xff, 0xff]).is_none());
        // Two sends of the same message differ (the nonce).
        let a = encode(ShareMsg::AuthOps { ops: vec![] }).unwrap();
        let b = encode(ShareMsg::AuthOps { ops: vec![] }).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn chunking_keeps_order_and_respects_the_budget() {
        let items: Vec<Vec<u8>> = (0..100).map(|i| vec![i as u8; 1000]).collect();
        let chunks = chunk_by_size(items.clone(), 10_000, Vec::len);
        assert!(chunks
            .iter()
            .all(|c| c.iter().map(|i| i.len() + 9).sum::<usize>() <= 10_000));
        assert_eq!(chunks.concat(), items);
        // An item over budget travels alone.
        let big = chunk_by_size(vec![vec![0u8; 20_000], vec![1u8; 10]], 10_000, Vec::len);
        assert_eq!(big.len(), 2);
    }
}
