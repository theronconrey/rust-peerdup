// SPDX-License-Identifier: MIT
//! Signed version announces.
//!
//! An announce tells the share "this is the current version, fetch it from
//! me". Before, anyone on the gossip topic could send one and every peer
//! applied it, so a Reader, or a revoked member until it was cut off, could
//! push changes (review finding 2). Now each announce is signed with the
//! sender's identity key over the share's group id and every field, and a
//! receiver applies it only if the signer is currently a Writer or Owner in
//! its own view of the membership. A Reader's daemon doesn't announce its
//! local edits at all.

use crate::auth::{AuthRole, AuthState, MemberId};
use crate::clock::VectorClock;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use p2panda_core::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Domain tag of the signed bytes; bump it if their layout changes.
const DOMAIN: &[u8] = b"peerdup-announce-v1";

/// A vector clock has one entry per peer that ever edited the share. Far
/// more than any real share, small enough that a peer can't bloat ours.
const MAX_CLOCK_ENTRIES: usize = 1024;

/// Largest clock counter accepted from a peer: one edit a millisecond for
/// 34 years. Without a bound a Writer could send `u64::MAX`; `increment`
/// saturates there, so every later version compares `Equal` and the share
/// is frozen for good.
pub const MAX_CLOCK_VALUE: u64 = 1 << 40;

/// How far in the future an announce's timestamp may be. A later
/// timestamp always wins last-writer-wins, so an unbounded one would win
/// every conflict.
pub const MAX_CLOCK_SKEW_MINUTES: i64 = 10;

/// Clock keys are peer ids: 64 lowercase hex characters.
fn is_peer_id_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Announce {
    /// Hash of the encrypted manifest blob (hex).
    pub manifest: String,
    /// Signer and blob provider: node id = identity public key (hex).
    pub provider: String,
    /// `transfer::version_hash_of` the version's files.
    pub version_hash: String,
    pub clock: VectorClock,
    pub timestamp: DateTime<Utc>,
    /// Ed25519 signature (hex) by `provider` over `signed_bytes`.
    pub signature: String,
    /// Random per send, outside the signature. Ed25519 signatures are
    /// deterministic, so without it every 10-second re-announce of the same
    /// version is byte-identical and gossip, which drops repeats, delivers
    /// only the first. A receiver whose fetch failed (say, before a rotated
    /// key arrived) would then never get another chance.
    #[serde(default)]
    pub nonce: u64,
}

fn signed_bytes(
    group_id: &MemberId,
    manifest: &str,
    provider: &str,
    version_hash: &str,
    clock: &VectorClock,
    timestamp: &DateTime<Utc>,
) -> Vec<u8> {
    bincode::serde::encode_to_vec(
        (
            DOMAIN,
            group_id,
            manifest,
            provider,
            version_hash,
            clock,
            timestamp.timestamp_micros(),
        ),
        bincode::config::standard(),
    )
    .expect("encoding an in-memory announce never fails")
}

impl Announce {
    pub fn sign(
        identity: &SigningKey,
        group_id: MemberId,
        manifest: String,
        version_hash: String,
        clock: VectorClock,
        timestamp: DateTime<Utc>,
    ) -> Self {
        let provider = identity.verifying_key().to_hex();
        let bytes = signed_bytes(
            &group_id,
            &manifest,
            &provider,
            &version_hash,
            &clock,
            &timestamp,
        );
        let signature = identity.sign(&bytes).to_hex();
        Announce {
            manifest,
            provider,
            version_hash,
            clock,
            timestamp,
            signature,
            nonce: rand::random(),
        }
    }

    /// Accept only a well-formed announce, signed for this share by a
    /// current Writer or Owner.
    pub fn verify(&self, auth_state: &AuthState, group_id: MemberId) -> Result<()> {
        if self.clock.0.len() > MAX_CLOCK_ENTRIES {
            return Err(anyhow!(
                "clock has {} entries (limit {MAX_CLOCK_ENTRIES})",
                self.clock.0.len()
            ));
        }
        for (peer, &value) in &self.clock.0 {
            if !is_peer_id_hex(peer) {
                return Err(anyhow!("clock key {peer:?} is not a peer id"));
            }
            if value > MAX_CLOCK_VALUE {
                return Err(anyhow!(
                    "clock value {value} is above the limit {MAX_CLOCK_VALUE}"
                ));
            }
        }
        if self.timestamp > Utc::now() + chrono::TimeDelta::minutes(MAX_CLOCK_SKEW_MINUTES) {
            return Err(anyhow!(
                "timestamp {} is more than {MAX_CLOCK_SKEW_MINUTES} minutes in the future",
                self.timestamp
            ));
        }
        let key = VerifyingKey::from_str(&self.provider)
            .map_err(|e| anyhow!("bad provider key: {e:?}"))?;
        let signature =
            Signature::from_str(&self.signature).map_err(|e| anyhow!("bad signature: {e:?}"))?;
        let bytes = signed_bytes(
            &group_id,
            &self.manifest,
            &self.provider,
            &self.version_hash,
            &self.clock,
            &self.timestamp,
        );
        if !key.verify(&bytes, &signature) {
            return Err(anyhow!("signature does not verify"));
        }
        match auth_state.role_of(group_id, MemberId(*key.as_bytes())) {
            Some(AuthRole::Owner) | Some(AuthRole::Writer) => Ok(()),
            Some(AuthRole::Reader) => Err(anyhow!("announce from a Reader")),
            None => Err(anyhow!("announce from a non-member")),
        }
    }
}

/// Whether our own changes may be announced: only Writers and Owners.
pub fn may_publish(auth_state: &AuthState, group_id: MemberId, identity: &SigningKey) -> bool {
    matches!(
        auth_state.role_of(group_id, MemberId(*identity.verifying_key().as_bytes())),
        Some(AuthRole::Owner) | Some(AuthRole::Writer)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::group_id_for;

    fn me(k: &SigningKey) -> MemberId {
        MemberId(*k.verifying_key().as_bytes())
    }

    fn setup() -> (MemberId, AuthState, SigningKey, SigningKey, SigningKey) {
        let owner = SigningKey::generate();
        let writer = SigningKey::generate();
        let reader = SigningKey::generate();
        let group = group_id_for("announce-test");
        let mut state = AuthState::empty_for(group);
        state.create_group(&owner, group).unwrap();
        state
            .add_member(&owner, group, me(&writer), AuthRole::Writer)
            .unwrap();
        state
            .add_member(&owner, group, me(&reader), AuthRole::Reader)
            .unwrap();
        (group, state, owner, writer, reader)
    }

    fn announce(k: &SigningKey, group: MemberId) -> Announce {
        let mut clock = VectorClock::new();
        clock.increment(&k.verifying_key().to_hex());
        Announce::sign(
            k,
            group,
            "aa".repeat(32),
            "bb".repeat(32),
            clock,
            Utc::now(),
        )
    }

    #[test]
    fn owners_and_writers_are_accepted() {
        let (group, state, owner, writer, _) = setup();
        announce(&owner, group).verify(&state, group).unwrap();
        announce(&writer, group).verify(&state, group).unwrap();
        assert!(may_publish(&state, group, &owner));
        assert!(may_publish(&state, group, &writer));
    }

    #[test]
    fn readers_and_strangers_are_refused() {
        let (group, state, _, _, reader) = setup();
        let stranger = SigningKey::generate();
        assert!(announce(&reader, group).verify(&state, group).is_err());
        assert!(announce(&stranger, group).verify(&state, group).is_err());
        assert!(!may_publish(&state, group, &reader));
        assert!(!may_publish(&state, group, &stranger));
    }

    #[test]
    fn tampering_or_another_share_breaks_the_signature() {
        let (group, state, owner, _, _) = setup();
        let mut a = announce(&owner, group);
        a.manifest = "cc".repeat(32);
        assert!(a.verify(&state, group).is_err());

        let other = group_id_for("another-share");
        let b = announce(&owner, other);
        assert!(b.verify(&state, group).is_err());
    }

    #[test]
    fn oversized_clocks_are_refused() {
        let (group, state, owner, _, _) = setup();
        let mut clock = VectorClock::new();
        for i in 0..=MAX_CLOCK_ENTRIES {
            clock.increment(&format!("{i:064x}"));
        }
        let a = Announce::sign(&owner, group, "aa".into(), "bb".into(), clock, Utc::now());
        assert!(a.verify(&state, group).is_err());
    }

    fn signed_with(
        owner: &SigningKey,
        group: MemberId,
        clock: VectorClock,
        ts: DateTime<Utc>,
    ) -> Announce {
        Announce::sign(owner, group, "aa".repeat(32), "bb".repeat(32), clock, ts)
    }

    #[test]
    fn clock_values_above_the_limit_are_refused() {
        let (group, state, owner, _, _) = setup();
        let me = owner.verifying_key().to_hex();
        let mut clock = VectorClock::new();
        clock.0.insert(me.clone(), MAX_CLOCK_VALUE);
        signed_with(&owner, group, clock.clone(), Utc::now())
            .verify(&state, group)
            .unwrap();
        clock.0.insert(me, MAX_CLOCK_VALUE + 1);
        let err = signed_with(&owner, group, clock, Utc::now())
            .verify(&state, group)
            .unwrap_err()
            .to_string();
        assert!(err.contains("above the limit"), "{err}");
        let mut max = VectorClock::new();
        max.0.insert("ab".repeat(32), u64::MAX);
        assert!(signed_with(&owner, group, max, Utc::now())
            .verify(&state, group)
            .is_err());
    }

    #[test]
    fn clock_keys_must_be_peer_ids() {
        let (group, state, owner, _, _) = setup();
        let upper = owner.verifying_key().to_hex().to_uppercase();
        for bad in [
            "peer-1".to_string(),
            "ab".repeat(31),
            "ab".repeat(33),
            upper,
        ] {
            let mut clock = VectorClock::new();
            clock.0.insert(bad.clone(), 1);
            let err = signed_with(&owner, group, clock, Utc::now())
                .verify(&state, group)
                .unwrap_err()
                .to_string();
            assert!(err.contains("not a peer id"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn timestamps_far_in_the_future_are_refused() {
        let (group, state, owner, _, _) = setup();
        let soon = Utc::now() + chrono::TimeDelta::minutes(5);
        signed_with(&owner, group, VectorClock::new(), soon)
            .verify(&state, group)
            .unwrap();
        let later = Utc::now() + chrono::TimeDelta::minutes(MAX_CLOCK_SKEW_MINUTES + 1);
        let err = signed_with(&owner, group, VectorClock::new(), later)
            .verify(&state, group)
            .unwrap_err()
            .to_string();
        assert!(err.contains("in the future"), "{err}");
    }

    #[test]
    fn each_send_differs_but_still_verifies() {
        let (group, state, owner, _, _) = setup();
        let ts = Utc::now();
        let a = Announce::sign(
            &owner,
            group,
            "aa".into(),
            "bb".into(),
            VectorClock::new(),
            ts,
        );
        let b = Announce::sign(
            &owner,
            group,
            "aa".into(),
            "bb".into(),
            VectorClock::new(),
            ts,
        );
        assert_eq!(a.signature, b.signature);
        assert_ne!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap(),
            "re-announces must not be byte-identical"
        );
        b.verify(&state, group).unwrap();
    }
}
