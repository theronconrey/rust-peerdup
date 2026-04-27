use crate::data_dir;
use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::fs;
use std::path::{Path, PathBuf};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const EPOCH_LEN: usize = 8;
/// `epoch(8) ‖ nonce(24)` — everything before the AEAD-protected payload.
pub const HEADER_LEN: usize = EPOCH_LEN + NONCE_LEN;

pub type Key = [u8; KEY_LEN];

/// Per-share keyring: one key per epoch, epochs numbered from 1. The current
/// (most-recently-rotated) key is always last. We never delete old keys —
/// older ciphertext on disk or in flight stays decryptable as long as the
/// keyring grows monotonically.
#[derive(Clone)]
pub struct KeyRing {
    keys: Vec<Key>,
}

impl KeyRing {
    pub fn current_epoch(&self) -> u64 {
        self.keys.len() as u64
    }

    pub fn current_key(&self) -> &Key {
        self.keys.last().expect("KeyRing is never empty")
    }

    pub fn key_for_epoch(&self, epoch: u64) -> Option<&Key> {
        let idx = epoch.checked_sub(1)? as usize;
        self.keys.get(idx)
    }

    pub fn export_keys(&self) -> Vec<Key> {
        self.keys.clone()
    }
}

fn keys_path(data_dir: &Path, share_id: &str) -> PathBuf {
    data_dir::shares_dir(data_dir).join(share_id).join("keys.bin")
}

/// Load `keys.bin`, or generate epoch-1 if absent. Persists 0600 on Unix.
pub fn load_or_create_keyring(data_dir: &Path, share_id: &str) -> Result<KeyRing> {
    let path = keys_path(data_dir, share_id);
    if path.exists() {
        let raw = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
        if raw.is_empty() || raw.len() % KEY_LEN != 0 {
            return Err(anyhow!(
                "keys.bin has invalid length: {} (must be a positive multiple of {})",
                raw.len(),
                KEY_LEN
            ));
        }
        let mut keys = Vec::with_capacity(raw.len() / KEY_LEN);
        for chunk in raw.chunks_exact(KEY_LEN) {
            let mut k = [0u8; KEY_LEN];
            k.copy_from_slice(chunk);
            keys.push(k);
        }
        Ok(KeyRing { keys })
    } else {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        let ring = KeyRing { keys: vec![k] };
        save_keyring(data_dir, share_id, &ring)?;
        Ok(ring)
    }
}

fn save_keyring(data_dir: &Path, share_id: &str, ring: &KeyRing) -> Result<()> {
    let path = keys_path(data_dir, share_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create_dir_all {parent:?}"))?;
    }
    let mut bytes = Vec::with_capacity(ring.keys.len() * KEY_LEN);
    for k in &ring.keys {
        bytes.extend_from_slice(k);
    }
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

/// Install a keyring on disk from a sequence of keys (e.g. imported from a
/// ticket). Refuses to overwrite an existing `keys.bin`.
pub fn install_keyring(data_dir: &Path, share_id: &str, keys: &[Key]) -> Result<()> {
    let path = keys_path(data_dir, share_id);
    if path.exists() {
        return Err(anyhow!(
            "keys.bin already exists at {path:?}; refusing to overwrite"
        ));
    }
    if keys.is_empty() {
        return Err(anyhow!("cannot install an empty keyring"));
    }
    let ring = KeyRing { keys: keys.to_vec() };
    save_keyring(data_dir, share_id, &ring)
}

/// Append a freshly generated key to the share's keyring and persist.
/// Returns the new epoch.
pub fn rotate_keyring(data_dir: &Path, share_id: &str) -> Result<u64> {
    let mut ring = load_or_create_keyring(data_dir, share_id)?;
    let mut k = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut k);
    ring.keys.push(k);
    save_keyring(data_dir, share_id, &ring)?;
    Ok(ring.current_epoch())
}

/// Encrypt with the keyring's current key. Output: `epoch(8 LE) ‖ nonce(24) ‖ ct ‖ tag(16)`.
pub fn encrypt(ring: &KeyRing, plaintext: &[u8]) -> Result<Vec<u8>> {
    let epoch = ring.current_epoch();
    let key = ring.current_key();
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("encryption failed"))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Parse the epoch header and decrypt with the matching key from the ring.
/// Errors precisely so callers can distinguish "we don't have that epoch's
/// key" from "ciphertext doesn't authenticate".
pub fn decrypt(ring: &KeyRing, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err(anyhow!(
            "blob too short ({} bytes); need at least {}",
            blob.len(),
            HEADER_LEN + TAG_LEN
        ));
    }
    let mut epoch_bytes = [0u8; EPOCH_LEN];
    epoch_bytes.copy_from_slice(&blob[..EPOCH_LEN]);
    let epoch = u64::from_le_bytes(epoch_bytes);
    let key = ring.key_for_epoch(epoch).ok_or_else(|| {
        anyhow!(
            "no key for epoch {} (keyring has {} epoch{})",
            epoch,
            ring.current_epoch(),
            if ring.current_epoch() == 1 { "" } else { "s" }
        )
    })?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&blob[EPOCH_LEN..HEADER_LEN]);
    cipher
        .decrypt(nonce, &blob[HEADER_LEN..])
        .map_err(|_| anyhow!("AEAD authentication failed (tampered or wrong key for epoch)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_with(n: usize) -> KeyRing {
        let mut keys = Vec::new();
        for _ in 0..n {
            let mut k = [0u8; KEY_LEN];
            OsRng.fill_bytes(&mut k);
            keys.push(k);
        }
        KeyRing { keys }
    }

    #[test]
    fn round_trip_with_current_epoch() {
        let r = ring_with(1);
        let ct = encrypt(&r, b"hello").unwrap();
        let out = decrypt(&r, &ct).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn old_ciphertext_decrypts_after_rotation() {
        let mut r = ring_with(1);
        let ct = encrypt(&r, b"under epoch 1").unwrap();
        // rotate by appending
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        r.keys.push(k);
        assert_eq!(r.current_epoch(), 2);
        // encrypt produces epoch-2 blob
        let ct2 = encrypt(&r, b"under epoch 2").unwrap();
        assert_eq!(&ct[..EPOCH_LEN], &1u64.to_le_bytes());
        assert_eq!(&ct2[..EPOCH_LEN], &2u64.to_le_bytes());
        // both still decryptable
        assert_eq!(decrypt(&r, &ct).unwrap(), b"under epoch 1");
        assert_eq!(decrypt(&r, &ct2).unwrap(), b"under epoch 2");
    }

    #[test]
    fn missing_epoch_fails_loudly() {
        let r1 = ring_with(1);
        // craft a blob claiming epoch 5 (beyond what we have)
        let mut blob = encrypt(&r1, b"x").unwrap();
        blob[..EPOCH_LEN].copy_from_slice(&5u64.to_le_bytes());
        let err = decrypt(&r1, &blob).unwrap_err().to_string();
        assert!(err.contains("no key for epoch 5"), "got: {err}");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let r = ring_with(1);
        let mut ct = encrypt(&r, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(decrypt(&r, &ct).is_err());
    }

    #[test]
    fn wrong_keyring_fails() {
        let r1 = ring_with(1);
        let r2 = ring_with(1);
        let ct = encrypt(&r1, b"secret").unwrap();
        // r2's epoch 1 key is different from r1's
        assert!(decrypt(&r2, &ct).is_err());
    }
}
