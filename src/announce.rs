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
        let mut state = AuthState::empty();
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
            clock.increment(&format!("peer-{i}"));
        }
        let a = Announce::sign(&owner, group, "aa".into(), "bb".into(), clock, Utc::now());
        assert!(a.verify(&state, group).is_err());
    }
}
