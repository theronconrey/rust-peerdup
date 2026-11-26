// SPDX-License-Identifier: MIT
//! Phase 5d: signed sealed-box envelopes that distribute a freshly-rotated
//! per-share encryption key to remaining members after a revocation.
//!
//! Workflow:
//!   1. Manager runs `share-revoke <id> <peer>`. After authoring the
//!      `Remove` op, they rotate the local `KeyRing` (append a fresh 32-byte
//!      key) and call [`build_signed_rotation`] to produce one envelope per
//!      remaining member, signed end-to-end with the manager's Ed25519
//!      identity.
//!   2. The CLI persists the rotation as a "pending" file under
//!      `<share_dir>/pending_rotations/<epoch>.bin`. The daemon picks it up
//!      on next start and re-broadcasts on each gossip announce tick.
//!   3. Each receiver runs [`verify_and_decrypt`]: signature check, member
//!      role lookup (rotator must be Owner/manager in the receiver's local
//!      auth state), pick out our envelope, derive an X25519 secret from
//!      our Ed25519 identity, decrypt. The 32-byte payload is then handed
//!      to [`crate::crypto::install_epoch_key`] which appends it to the
//!      local keyring.
//!
//! The KEM is `crypto_box`'s X25519 + XSalsa20Poly1305 construction (NaCl
//! "box"), with a fresh ephemeral X25519 keypair per envelope. We reuse the
//! Ed25519 identity for the static recipient key via the well-known
//! `to_scalar_bytes` / `to_montgomery` Ed25519 → X25519 conversion (see
//! INTEGRATION_NOTES.md "Phase 5d key distribution" for the tradeoff).

use crate::auth::SIGNATURE_LEN;
use crate::auth::{self, AuthRole, AuthState, MemberId};
use crate::crypto::{Key, KEY_LEN};
use crate::data_dir;
use anyhow::{anyhow, Context, Result};
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey as BoxPublic, SalsaBox, SecretKey as BoxSecret};
use ed25519_dalek::{SigningKey as DalekSigningKey, VerifyingKey as DalekVerifyingKey};
use p2panda_core::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// One sealed envelope addressed to a single recipient. Bytes layout
/// (nominally; bincode-encoded inside `SignedRotation`):
///   recipient_pubkey:   raw 32-byte Ed25519 public key (same as MemberId)
///   ephemeral_pubkey:   one-shot X25519 public key (32 bytes)
///   nonce:              24-byte XSalsa20 nonce
///   ciphertext:         32-byte AEAD-encrypted key payload + 16-byte tag
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyEnvelope {
    pub recipient_pubkey: MemberId,
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// A key-rotation broadcast, or one chunk of it: an epoch + author + some
/// of the envelopes, signed by the rotator over exactly the envelopes it
/// carries. A rotation for many members is split into several of these
/// (`build_signed_rotation`), so each fits in one gossip message; the
/// daemon wraps each in `wire::ShareMsg::KeyRotation`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedRotation {
    pub epoch: u64,
    pub rotator_pubkey: MemberId,
    #[serde(with = "auth::serde_bytes_64")]
    pub signature: [u8; SIGNATURE_LEN],
    pub envelopes: Vec<KeyEnvelope>,
}

/// Outcome of a receiver-side check + decrypt of an incoming rotation.
#[derive(Debug)]
pub enum VerifyOutcome {
    /// Signature, role check, and our envelope all decrypted; here is the
    /// 32-byte epoch key.
    OkForUs([u8; KEY_LEN]),
    /// Rotation was valid but no envelope is addressed to us (we may have
    /// just been revoked, or this is for a different share fork).
    NotForUs,
    /// Signature verified but the rotator isn't a current Owner/manager
    /// according to our local auth state. Reject.
    NotAManager,
    /// Outer Ed25519 signature failed to verify against `rotator_pubkey`.
    BadSignature,
    /// Signature + role were ok and our envelope was present, but the
    /// AEAD decrypt failed (wrong key derivation, tampered ciphertext).
    DecryptFailed,
}

/// Domain tag for rotation signatures. v2 added the group id, so a
/// rotation signed for one share can't be replayed into another share
/// that has the same Owner and recipient. The layout is unchanged by
/// chunking: a chunk is signed exactly like a whole rotation, over the
/// envelopes it carries, so the tag stays v2.
const ROTATION_SIG_DOMAIN: &[u8] = b"peerdup-rotation-v2";

/// Canonical bytes signed by the rotator. Order is part of the wire
/// protocol — don't shuffle these fields.
fn canonical_bytes(
    group_id: &MemberId,
    epoch: u64,
    rotator_pubkey: &MemberId,
    envelopes: &[KeyEnvelope],
) -> Vec<u8> {
    bincode::serde::encode_to_vec(
        (
            ROTATION_SIG_DOMAIN,
            group_id,
            &epoch,
            rotator_pubkey,
            envelopes,
        ),
        bincode::config::standard(),
    )
    .expect("canonical encoding of in-memory rotation never fails")
}

/// Convert an Ed25519 public key (raw 32 bytes) to an X25519 public key
/// suitable for `crypto_box::PublicKey`. Errors only on malformed Ed25519
/// pubkeys (not on a valid curve point).
fn ed25519_pub_to_box_pub(raw: &[u8; 32]) -> Result<BoxPublic> {
    let vk =
        DalekVerifyingKey::from_bytes(raw).map_err(|e| anyhow!("invalid Ed25519 pubkey: {e}"))?;
    Ok(BoxPublic::from(vk.to_montgomery().to_bytes()))
}

/// Convert a `p2panda_core::SigningKey` (Ed25519) to a `crypto_box::SecretKey`
/// (X25519). Reuses the static identity key for KEM; see module docs for the
/// tradeoff.
fn ed25519_priv_to_box_priv(identity: &SigningKey) -> BoxSecret {
    let sk_bytes: [u8; 32] = *identity.as_bytes();
    let signing = DalekSigningKey::from_bytes(&sk_bytes);
    let scalar_bytes = signing.to_scalar_bytes();
    BoxSecret::from(scalar_bytes)
}

/// Envelopes per signed chunk. An envelope is about 137 bytes encoded, so
/// a chunk stays near 35 KiB, under `wire::CHUNK_BUDGET`.
pub const ENVELOPES_PER_CHUNK: usize = 256;

/// Build the signed chunks of a rotation for `recipients`, at most
/// `ENVELOPES_PER_CHUNK` envelopes each. Every chunk verifies on its own;
/// a recipient needs only the one that carries its envelope.
pub fn build_signed_rotation(
    rotator: &SigningKey,
    group_id: MemberId,
    epoch: u64,
    new_key: &Key,
    recipients: &[MemberId],
) -> Result<Vec<SignedRotation>> {
    build_chunks(
        rotator,
        group_id,
        epoch,
        new_key,
        recipients,
        ENVELOPES_PER_CHUNK,
    )
}

pub(crate) fn build_chunks(
    rotator: &SigningKey,
    group_id: MemberId,
    epoch: u64,
    new_key: &Key,
    recipients: &[MemberId],
    per_chunk: usize,
) -> Result<Vec<SignedRotation>> {
    let whole = build_one(rotator, group_id, epoch, new_key, recipients)?;
    if whole.envelopes.len() <= per_chunk {
        return Ok(vec![whole]);
    }
    let rotator_pubkey = whole.rotator_pubkey;
    Ok(whole
        .envelopes
        .chunks(per_chunk.max(1))
        .map(|envelopes| {
            let canonical = canonical_bytes(&group_id, epoch, &rotator_pubkey, envelopes);
            SignedRotation {
                epoch,
                rotator_pubkey,
                signature: rotator.sign(&canonical).to_bytes(),
                envelopes: envelopes.to_vec(),
            }
        })
        .collect())
}

/// Build a fully-signed rotation envelope set for `recipients` (which should
/// be the post-revocation membership minus the rotator themselves —
/// `verify_and_decrypt` happily handles a self-envelope being absent).
///
/// Recipients are sorted by raw pubkey bytes for determinism (so two managers
/// rotating concurrently with the same input set produce envelope vectors in
/// the same order).
fn build_one(
    rotator: &SigningKey,
    group_id: MemberId,
    epoch: u64,
    new_key: &Key,
    recipients: &[MemberId],
) -> Result<SignedRotation> {
    let mut sorted = recipients.to_vec();
    sorted.sort_by_key(|m| m.0);
    sorted.dedup_by_key(|m| m.0);

    let rotator_pubkey = MemberId(*rotator.verifying_key().as_bytes());
    let mut envelopes = Vec::with_capacity(sorted.len());
    for recipient in &sorted {
        let recipient_box_pub = ed25519_pub_to_box_pub(&recipient.0).with_context(|| {
            format!(
                "deriving X25519 pubkey for recipient {}",
                recipient.to_hex()
            )
        })?;
        let ephemeral_secret = BoxSecret::generate(&mut OsRng);
        let ephemeral_pub = ephemeral_secret.public_key();
        let bx = SalsaBox::new(&recipient_box_pub, &ephemeral_secret);
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let ciphertext = bx
            .encrypt(&nonce, new_key.as_slice())
            .map_err(|_| anyhow!("crypto_box encrypt failed"))?;
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes.copy_from_slice(nonce.as_slice());
        envelopes.push(KeyEnvelope {
            recipient_pubkey: *recipient,
            ephemeral_pubkey: *ephemeral_pub.as_bytes(),
            nonce: nonce_bytes,
            ciphertext,
        });
    }
    let canonical = canonical_bytes(&group_id, epoch, &rotator_pubkey, &envelopes);
    let sig = rotator.sign(&canonical);
    Ok(SignedRotation {
        epoch,
        rotator_pubkey,
        signature: sig.to_bytes(),
        envelopes,
    })
}

/// Receiver-side verification + decrypt. See [`VerifyOutcome`].
pub fn verify_and_decrypt(
    rotation: &SignedRotation,
    auth_state: &AuthState,
    group_id: MemberId,
    me_identity: &SigningKey,
) -> VerifyOutcome {
    // 1. Outer signature.
    let pubkey = match VerifyingKey::from_bytes(&rotation.rotator_pubkey.0) {
        Ok(p) => p,
        Err(_) => return VerifyOutcome::BadSignature,
    };
    let sig = Signature::from_bytes(&rotation.signature);
    let canonical = canonical_bytes(
        &group_id,
        rotation.epoch,
        &rotation.rotator_pubkey,
        &rotation.envelopes,
    );
    if !pubkey.verify(&canonical, &sig) {
        return VerifyOutcome::BadSignature;
    }

    // 2. Rotator must currently hold Owner/manager access.
    let is_manager = auth_state
        .members(group_id)
        .into_iter()
        .any(|(m, role)| m == rotation.rotator_pubkey && role == AuthRole::Owner);
    if !is_manager {
        return VerifyOutcome::NotAManager;
    }

    // 3. Find our envelope.
    let me = MemberId(*me_identity.verifying_key().as_bytes());
    let envelope = match rotation.envelopes.iter().find(|e| e.recipient_pubkey == me) {
        Some(e) => e,
        None => return VerifyOutcome::NotForUs,
    };

    // 4. Derive our box secret + decrypt.
    let my_secret = ed25519_priv_to_box_priv(me_identity);
    let ephemeral_pub = BoxPublic::from(envelope.ephemeral_pubkey);
    let bx = SalsaBox::new(&ephemeral_pub, &my_secret);
    let nonce = crypto_box::Nonce::from_slice(&envelope.nonce);
    let plaintext = match bx.decrypt(nonce, envelope.ciphertext.as_slice()) {
        Ok(p) => p,
        Err(_) => return VerifyOutcome::DecryptFailed,
    };
    if plaintext.len() != KEY_LEN {
        return VerifyOutcome::DecryptFailed;
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&plaintext);
    VerifyOutcome::OkForUs(out)
}

/// Largest pending-rotation file we read; a chunk is about 35 KiB.
pub const MAX_PENDING_ROTATION_BYTES: usize = 1024 * 1024;

/// Per-share directory for queued rotations the daemon hasn't broadcast yet.
pub fn pending_dir(data_dir: &Path, share_id: &str) -> PathBuf {
    data_dir::shares_dir(data_dir)
        .join(share_id)
        .join("pending_rotations")
}

/// Persist a rotation's chunks to `pending_rotations/<epoch>-<n>.bin`, one
/// `SignedRotation` per file (the format a whole rotation had before
/// chunking, so older `<epoch>.bin` files still load). Atomic via tmp +
/// rename; 0600 on Unix.
pub fn save_pending(data_dir: &Path, share_id: &str, chunks: &[SignedRotation]) -> Result<()> {
    let dir = pending_dir(data_dir, share_id);
    fs::create_dir_all(&dir).with_context(|| format!("create_dir_all {dir:?}"))?;
    for (n, rotation) in chunks.iter().enumerate() {
        let bytes = bincode::serde::encode_to_vec(rotation, bincode::config::standard())
            .context("encoding rotation")?;
        let path = dir.join(format!("{}-{n}.bin", rotation.epoch));
        crate::data_dir::write_private_atomic(&path, &bytes)
            .with_context(|| format!("writing {path:?}"))?;
    }
    Ok(())
}

/// Load all pending rotations from disk, sorted by epoch ascending. Returns
/// an empty vector if the directory doesn't exist.
pub fn load_pending(data_dir: &Path, share_id: &str) -> Result<Vec<SignedRotation>> {
    let dir = pending_dir(data_dir, share_id);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read_dir {dir:?}"))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("bin") {
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
        if bytes.len() > MAX_PENDING_ROTATION_BYTES {
            return Err(anyhow!(
                "{path:?} is {} bytes, over the {MAX_PENDING_ROTATION_BYTES}-byte limit",
                bytes.len()
            ));
        }
        let (rot, _): (SignedRotation, _) = bincode::serde::decode_from_slice(
            &bytes,
            bincode::config::standard().with_limit::<MAX_PENDING_ROTATION_BYTES>(),
        )
        .with_context(|| format!("decoding {path:?}"))?;
        out.push(rot);
    }
    out.sort_by_key(|r| r.epoch);
    Ok(out)
}

/// Mint the share's next key epoch, persist it to `keys.bin`, sign its
/// rotation for `recipients` and queue the chunks in `pending_rotations/`.
/// Shared by `share-revoke` and `share-rotate-key`, in the daemon and in
/// direct mode; the caller checks `epochs::check_mint` and that it is an
/// Owner first. Returns the new epoch and the chunks (empty when there is
/// nobody to send the key to).
pub fn mint_and_queue(
    data_dir: &Path,
    share_id: &str,
    identity: &SigningKey,
    group_id: MemberId,
    recipients: &[MemberId],
) -> Result<(u64, Vec<SignedRotation>)> {
    let new_epoch = crate::crypto::rotate_keyring(data_dir, share_id)?;
    let ring = crate::crypto::load_or_create_keyring(data_dir, share_id)?;
    let new_key = *ring
        .key_for_epoch(new_epoch)
        .ok_or_else(|| anyhow!("rotated keyring missing epoch {new_epoch}"))?;
    if recipients.is_empty() {
        return Ok((new_epoch, Vec::new()));
    }
    let chunks = build_signed_rotation(identity, group_id, new_epoch, &new_key, recipients)?;
    save_pending(data_dir, share_id, &chunks)?;
    Ok((new_epoch, chunks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{group_id_for, AuthRole, AuthState, MemberId};

    fn fresh() -> SigningKey {
        SigningKey::generate()
    }

    fn me_of(k: &SigningKey) -> MemberId {
        MemberId(*k.verifying_key().as_bytes())
    }

    fn one(r: Result<Vec<SignedRotation>>) -> SignedRotation {
        let mut chunks = r.unwrap();
        assert_eq!(chunks.len(), 1);
        chunks.remove(0)
    }

    #[test]
    fn chunks_persist_and_reload() {
        let dir = std::env::temp_dir().join(format!("peerdup-rot-{:016x}", rand::random::<u64>()));
        let alice = fresh();
        let group = group_id_for("rot-persist");
        let ids: Vec<MemberId> = (0..10).map(|_| me_of(&fresh())).collect();
        let chunks = build_chunks(&alice, group, 2, &[1u8; KEY_LEN], &ids, 4).unwrap();
        assert_eq!(chunks.len(), 3);
        save_pending(&dir, "0123456789abcdef", &chunks).unwrap();
        let back = load_pending(&dir, "0123456789abcdef").unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back.iter().map(|r| r.envelopes.len()).sum::<usize>(), 10);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn round_trip_envelope_seal_open() {
        let alice = fresh();
        let group = group_id_for("rot-roundtrip");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();

        let new_key: Key = [0xCDu8; KEY_LEN];
        // Address an envelope to alice herself (round trip).
        let rot = one(build_signed_rotation(
            &alice,
            group,
            2,
            &new_key,
            &[me_of(&alice)],
        ));
        match verify_and_decrypt(&rot, &state, group, &alice) {
            VerifyOutcome::OkForUs(k) => assert_eq!(k, new_key),
            other => panic!("expected OkForUs, got {other:?}"),
        }
    }

    #[test]
    fn signature_verifies_when_rotator_is_manager() {
        let alice = fresh();
        let bob = fresh();
        let group = group_id_for("rot-mgr");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();

        let new_key: Key = [0x42u8; KEY_LEN];
        let rot = one(build_signed_rotation(
            &alice,
            group,
            2,
            &new_key,
            &[me_of(&bob)],
        ));

        // Bob's local replay of the auth log:
        let mut bob_state = AuthState::empty_for(group);
        for op in state.ops() {
            bob_state.apply_remote(op.clone()).unwrap();
        }
        match verify_and_decrypt(&rot, &bob_state, group, &bob) {
            VerifyOutcome::OkForUs(k) => assert_eq!(k, new_key),
            other => panic!("expected OkForUs, got {other:?}"),
        }
    }

    #[test]
    fn signature_rejected_when_rotator_is_not_a_manager() {
        let alice = fresh();
        let bob = fresh();
        let mallory = fresh();
        let group = group_id_for("rot-nomgr");

        // alice creates group with bob as a member; mallory is *not* in.
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();

        let new_key: Key = [0x99u8; KEY_LEN];
        // Mallory signs a rotation envelope for bob.
        let rot = one(build_signed_rotation(
            &mallory,
            group,
            2,
            &new_key,
            &[me_of(&bob)],
        ));

        // Bob applies the auth log and checks: rotator (mallory) is not a
        // manager, so reject.
        let mut bob_state = AuthState::empty_for(group);
        for op in state.ops() {
            bob_state.apply_remote(op.clone()).unwrap();
        }
        match verify_and_decrypt(&rot, &bob_state, group, &bob) {
            VerifyOutcome::NotAManager => {}
            other => panic!("expected NotAManager, got {other:?}"),
        }
    }

    #[test]
    fn signature_rejected_when_tampered() {
        let alice = fresh();
        let bob = fresh();
        let group = group_id_for("rot-tamper");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();

        let new_key: Key = [0xAAu8; KEY_LEN];
        let mut rot = one(build_signed_rotation(
            &alice,
            group,
            2,
            &new_key,
            &[me_of(&bob)],
        ));
        // Flip a bit inside an envelope's ciphertext. The outer signature
        // covers the envelope, so verification should fail.
        rot.envelopes[0].ciphertext[0] ^= 0x01;

        let mut bob_state = AuthState::empty_for(group);
        for op in state.ops() {
            bob_state.apply_remote(op.clone()).unwrap();
        }
        match verify_and_decrypt(&rot, &bob_state, group, &bob) {
            VerifyOutcome::BadSignature => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn not_for_us_when_no_envelope_addressed() {
        let alice = fresh();
        let bob = fresh();
        let charlie = fresh();
        let group = group_id_for("rot-not-us");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        state
            .add_member(&alice, group, me_of(&charlie), AuthRole::Writer)
            .unwrap();

        let new_key: Key = [0x33u8; KEY_LEN];
        // Address only to charlie.
        let rot = one(build_signed_rotation(
            &alice,
            group,
            2,
            &new_key,
            &[me_of(&charlie)],
        ));

        let mut bob_state = AuthState::empty_for(group);
        for op in state.ops() {
            bob_state.apply_remote(op.clone()).unwrap();
        }
        match verify_and_decrypt(&rot, &bob_state, group, &bob) {
            VerifyOutcome::NotForUs => {}
            other => panic!("expected NotForUs, got {other:?}"),
        }
    }

    #[test]
    fn rotation_for_one_share_is_rejected_in_another() {
        // Same Owner, same recipient, two shares: a rotation signed for
        // share A must not verify as share B's.
        let alice = fresh();
        let bob = fresh();
        let group_a = group_id_for("rot-share-a");
        let group_b = group_id_for("rot-share-b");
        let mut bob_state = AuthState::empty_for(group_b);
        let mut state = AuthState::empty_for(group_b);
        state.create_group(&alice, group_b).unwrap();
        state
            .add_member(&alice, group_b, me_of(&bob), AuthRole::Writer)
            .unwrap();
        for op in state.ops() {
            bob_state.apply_remote(op.clone()).unwrap();
        }
        let new_key: Key = [0x42u8; KEY_LEN];
        let rot = one(build_signed_rotation(
            &alice,
            group_a,
            2,
            &new_key,
            &[me_of(&bob)],
        ));
        assert!(matches!(
            verify_and_decrypt(&rot, &bob_state, group_b, &bob),
            VerifyOutcome::BadSignature
        ));
    }
}
