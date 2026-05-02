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

use crate::auth::{self, AuthRole, AuthState, MemberId};
use crate::crypto::{Key, KEY_LEN};
use crate::data_dir;
use anyhow::{anyhow, Context, Result};
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey as BoxPublic, SalsaBox, SecretKey as BoxSecret};
use ed25519_dalek::{SigningKey, VerifyingKey};
use p2panda_core::identity::SIGNATURE_LEN;
use p2panda_core::{PrivateKey, PublicKey, Signature};
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

/// A full key-rotation broadcast: an epoch + author + envelopes, signed by
/// the rotator. Wire format is bincode-encoded; the daemon wraps it in
/// `ShareMsg::KeyRotation` for gossip.
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

/// Canonical bytes signed by the rotator. Order is part of the wire
/// protocol — don't shuffle these fields.
fn canonical_bytes(
    epoch: u64,
    rotator_pubkey: &MemberId,
    envelopes: &[KeyEnvelope],
) -> Vec<u8> {
    bincode::serde::encode_to_vec(
        (&epoch, rotator_pubkey, envelopes),
        bincode::config::standard(),
    )
    .expect("canonical encoding of in-memory rotation never fails")
}

/// Convert an Ed25519 public key (raw 32 bytes) to an X25519 public key
/// suitable for `crypto_box::PublicKey`. Errors only on malformed Ed25519
/// pubkeys (not on a valid curve point).
fn ed25519_pub_to_box_pub(raw: &[u8; 32]) -> Result<BoxPublic> {
    let vk = VerifyingKey::from_bytes(raw)
        .map_err(|e| anyhow!("invalid Ed25519 pubkey: {e}"))?;
    Ok(BoxPublic::from(vk.to_montgomery().to_bytes()))
}

/// Convert a `p2panda_core::PrivateKey` (Ed25519) to a `crypto_box::SecretKey`
/// (X25519). Reuses the static identity key for KEM; see module docs for the
/// tradeoff.
fn ed25519_priv_to_box_priv(identity: &PrivateKey) -> BoxSecret {
    let sk_bytes: [u8; 32] = *identity.as_bytes();
    let signing = SigningKey::from_bytes(&sk_bytes);
    let scalar_bytes = signing.to_scalar_bytes();
    BoxSecret::from(scalar_bytes)
}

/// Build a fully-signed rotation envelope set for `recipients` (which should
/// be the post-revocation membership minus the rotator themselves —
/// `verify_and_decrypt` happily handles a self-envelope being absent).
///
/// Recipients are sorted by raw pubkey bytes for determinism (so two managers
/// rotating concurrently with the same input set produce envelope vectors in
/// the same order).
pub fn build_signed_rotation(
    rotator: &PrivateKey,
    epoch: u64,
    new_key: &Key,
    recipients: &[MemberId],
) -> Result<SignedRotation> {
    let mut sorted = recipients.to_vec();
    sorted.sort_by_key(|m| m.0);
    sorted.dedup_by_key(|m| m.0);

    let rotator_pubkey = MemberId(*rotator.public_key().as_bytes());
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
    let canonical = canonical_bytes(epoch, &rotator_pubkey, &envelopes);
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
    me_identity: &PrivateKey,
) -> VerifyOutcome {
    // 1. Outer signature.
    let pubkey = match PublicKey::from_bytes(&rotation.rotator_pubkey.0) {
        Ok(p) => p,
        Err(_) => return VerifyOutcome::BadSignature,
    };
    let sig = Signature::from_bytes(&rotation.signature);
    let canonical = canonical_bytes(
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
    let me = MemberId(*me_identity.public_key().as_bytes());
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

/// Per-share directory for queued rotations the daemon hasn't broadcast yet.
pub fn pending_dir(data_dir: &Path, share_id: &str) -> PathBuf {
    data_dir::shares_dir(data_dir)
        .join(share_id)
        .join("pending_rotations")
}

/// Persist a rotation to `pending_rotations/<epoch>.bin`. Atomic via tmp +
/// rename; 0600 on Unix.
pub fn save_pending(data_dir: &Path, share_id: &str, rotation: &SignedRotation) -> Result<()> {
    let dir = pending_dir(data_dir, share_id);
    fs::create_dir_all(&dir).with_context(|| format!("create_dir_all {dir:?}"))?;
    let bytes = bincode::serde::encode_to_vec(rotation, bincode::config::standard())
        .context("encoding rotation")?;
    let path = dir.join(format!("{}.bin", rotation.epoch));
    let tmp = path.with_extension("bin.tmp");
    fs::write(&tmp, &bytes).with_context(|| format!("writing {tmp:?}"))?;
    fs::rename(&tmp, &path).with_context(|| format!("renaming {tmp:?} -> {path:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {path:?}"))?;
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
        let (rot, _): (SignedRotation, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .with_context(|| format!("decoding {path:?}"))?;
        out.push(rot);
    }
    out.sort_by_key(|r| r.epoch);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{group_id_for, AuthRole, AuthState, MemberId};

    fn fresh() -> PrivateKey {
        PrivateKey::new()
    }

    fn me_of(k: &PrivateKey) -> MemberId {
        MemberId(*k.public_key().as_bytes())
    }

    #[test]
    fn round_trip_envelope_seal_open() {
        let alice = fresh();
        let group = group_id_for("rot-roundtrip");
        let mut state = AuthState::empty();
        state.create_group(&alice, group).unwrap();

        let new_key: Key = [0xCDu8; KEY_LEN];
        // Address an envelope to alice herself (round trip).
        let rot = build_signed_rotation(&alice, 2, &new_key, &[me_of(&alice)]).unwrap();
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
        let mut state = AuthState::empty();
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();

        let new_key: Key = [0x42u8; KEY_LEN];
        let rot = build_signed_rotation(&alice, 2, &new_key, &[me_of(&bob)]).unwrap();

        // Bob's local replay of the auth log:
        let mut bob_state = AuthState::empty();
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
        let mut state = AuthState::empty();
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();

        let new_key: Key = [0x99u8; KEY_LEN];
        // Mallory signs a rotation envelope for bob.
        let rot = build_signed_rotation(&mallory, 2, &new_key, &[me_of(&bob)]).unwrap();

        // Bob applies the auth log and checks: rotator (mallory) is not a
        // manager, so reject.
        let mut bob_state = AuthState::empty();
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
        let mut state = AuthState::empty();
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();

        let new_key: Key = [0xAAu8; KEY_LEN];
        let mut rot = build_signed_rotation(&alice, 2, &new_key, &[me_of(&bob)]).unwrap();
        // Flip a bit inside an envelope's ciphertext. The outer signature
        // covers the envelope, so verification should fail.
        rot.envelopes[0].ciphertext[0] ^= 0x01;

        let mut bob_state = AuthState::empty();
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
        let mut state = AuthState::empty();
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        state
            .add_member(&alice, group, me_of(&charlie), AuthRole::Writer)
            .unwrap();

        let new_key: Key = [0x33u8; KEY_LEN];
        // Address only to charlie.
        let rot =
            build_signed_rotation(&alice, 2, &new_key, &[me_of(&charlie)]).unwrap();

        let mut bob_state = AuthState::empty();
        for op in state.ops() {
            bob_state.apply_remote(op.clone()).unwrap();
        }
        match verify_and_decrypt(&rot, &bob_state, group, &bob) {
            VerifyOutcome::NotForUs => {}
            other => panic!("expected NotForUs, got {other:?}"),
        }
    }
}
