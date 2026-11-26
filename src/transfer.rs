// SPDX-License-Identifier: MIT
//! File transfer over iroh-blobs, replacing librqbit.
//!
//! A version of a share is published as content-addressed blobs in a local
//! iroh-blobs store, served on the daemon's p2panda (iroh) endpoint:
//!
//! - one blob per file: the file's ciphertext (`crypto::encrypt`, so the
//!   epoch header and AEAD tag travel with it);
//! - one manifest blob: the encrypted JSON list of `(path, blake3 of the
//!   plaintext, hash of the ciphertext blob)`.
//!
//! Gossip announces only the manifest's hash and the provider's node id.
//! File names and sizes never leave the machine in the clear, and a
//! receiver fetches by node id, so iroh does the hole-punching and relaying
//! that BitTorrent's announced `127.0.0.1` endpoints never could.
//!
//! Unchanged files keep the same ciphertext (see `BlobCache`), so their
//! blobs keep the same hash and a receiver that already holds them fetches
//! nothing: `Remote::fetch` only requests what is missing locally.
//!
//! The store is a cache. The plaintext share root plus `state.json` stay the
//! source of truth; a damaged store can be deleted and is rebuilt from the
//! plaintext on the next publish.

use crate::crypto::{self, KeyRing, EPOCH_LEN};
use anyhow::{anyhow, Context, Result};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, Hash};
use p2panda_core::VerifyingKey;
use p2panda_net::Endpoint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

/// Format version of the decrypted manifest.
const MANIFEST_VERSION: u32 = 1;

/// Upper bound for fetching one blob. A provider that stalls can't hold a
/// share's loop forever (review finding 1).
const FETCH_TIMEOUT: Duration = Duration::from_secs(300);

/// Upper bound for connecting to a provider.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Directory name inside the share root that holds peerdup's own files.
/// The plaintext walk skips it, and manifest paths may never start with it.
pub const PEERDUP_DIR_NAME: &str = ".peerdup";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Path relative to the share root, `/`-separated.
    pub path: String,
    /// blake3 of the plaintext, hex.
    pub plain: String,
    /// iroh-blobs hash of the ciphertext blob, hex.
    pub blob: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Manifest {
    version: u32,
    entries: Vec<ManifestEntry>,
}

/// One file of a version: relative path plus blake3 of its plaintext.
pub type FileHash = (PathBuf, [u8; 32]);

/// A fetched, verified version, staged next to its final paths.
pub struct StagedVersion {
    /// `(final path relative to the root, temp file holding the plaintext)`.
    staged: Vec<(PathBuf, PathBuf)>,
    pub files: Vec<FileHash>,
}

impl StagedVersion {
    /// Move every staged file into place.
    pub fn commit(self, root: &Path) -> Result<()> {
        for (rel, tmp) in &self.staged {
            let dest = root.join(rel);
            std::fs::rename(tmp, &dest).with_context(|| format!("renaming {tmp:?} -> {dest:?}"))?;
        }
        Ok(())
    }

    /// Remove the staged files without applying them.
    pub fn discard(self) {
        for (_, tmp) in &self.staged {
            let _ = std::fs::remove_file(tmp);
        }
    }
}

/// Per-share record of which ciphertext blob holds each file's current
/// plaintext, so unchanged files are not re-encrypted (fresh nonces would
/// give them new hashes and every receiver would fetch them again).
/// Kept in `<data_dir>/shares/<id>/blobs.json`.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct BlobCache {
    entries: BTreeMap<String, CacheEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CacheEntry {
    plain: String,
    blob: String,
    epoch: u64,
}

impl BlobCache {
    fn path(data_dir: &Path, share_id: &str) -> PathBuf {
        crate::data_dir::shares_dir(data_dir)
            .join(share_id)
            .join("blobs.json")
    }

    pub fn load(data_dir: &Path, share_id: &str) -> BlobCache {
        let path = Self::path(data_dir, share_id);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!(error = %e, ?path, "unreadable blob cache; starting empty");
                BlobCache::default()
            }),
            Err(_) => BlobCache::default(),
        }
    }

    pub fn save(&self, data_dir: &Path, share_id: &str) -> Result<()> {
        let path = Self::path(data_dir, share_id);
        let bytes = serde_json::to_vec(self)?;
        crate::data_dir::write_private_atomic(&path, &bytes)
            .with_context(|| format!("writing {path:?}"))
    }

    fn reuse(&self, path: &str, plain: &str, epoch: u64) -> Option<Hash> {
        let e = self.entries.get(path)?;
        if e.plain == plain && e.epoch == epoch {
            Hash::from_str(&e.blob).ok()
        } else {
            None
        }
    }

    fn remember(&mut self, path: String, plain: String, blob: Hash, epoch: u64) {
        self.entries.insert(
            path,
            CacheEntry {
                plain,
                blob: blob.to_hex().to_string(),
                epoch,
            },
        );
    }

    /// Forget files that are no longer in the share.
    fn retain_paths(&mut self, keep: &[String]) {
        self.entries.retain(|p, _| keep.contains(p));
    }
}

/// The daemon's blob store, served on its endpoint under iroh-blobs' ALPN.
pub struct Transfer {
    store: FsStore,
    endpoint: Endpoint,
}

impl Transfer {
    pub async fn start(data_dir: &Path, endpoint: Endpoint) -> Result<Self> {
        let dir = data_dir.join("blobs");
        std::fs::create_dir_all(&dir).with_context(|| format!("create_dir_all {dir:?}"))?;
        let store = FsStore::load(&dir)
            .await
            .map_err(|e| anyhow!("opening blob store {dir:?}: {e:?}"))?;
        let blobs = BlobsProtocol::new(&store, None);
        endpoint
            .accept(iroh_blobs::ALPN, blobs)
            .await
            .map_err(|e| anyhow!("registering the blobs protocol: {e:?}"))?;
        Ok(Self { store, endpoint })
    }

    /// Flush and close the store. Without this the last writes can be lost.
    pub async fn shutdown(&self) {
        if let Err(e) = self.store.shutdown().await {
            tracing::warn!(error = ?e, "blob store shutdown failed");
        }
    }

    async fn add(&self, bytes: &[u8]) -> Result<Hash> {
        let tag = self
            .store
            .blobs()
            .add_slice(bytes)
            .await
            .map_err(|e| anyhow!("adding blob: {e:?}"))?;
        Ok(tag.hash)
    }

    async fn read(&self, hash: Hash) -> Result<Vec<u8>> {
        let bytes = self
            .store
            .blobs()
            .get_bytes(hash)
            .await
            .map_err(|e| anyhow!("reading blob {}: {e:?}", hash.to_hex()))?;
        Ok(bytes.to_vec())
    }

    /// Publish the share's current plaintext as a version. Returns the
    /// manifest blob's hash (hex), which is what gets announced.
    pub async fn publish(
        &self,
        root: &Path,
        files: &[FileHash],
        key: &KeyRing,
        cache: &mut BlobCache,
    ) -> Result<String> {
        let epoch = key.current_epoch();
        let mut entries = Vec::with_capacity(files.len());
        for (rel, plain) in files {
            let path = rel_to_manifest_path(rel)?;
            let plain_hex = hex32(plain);
            let blob = match cache.reuse(&path, &plain_hex, epoch) {
                Some(h) => h,
                None => {
                    let abs = root.join(rel);
                    let pt = std::fs::read(&abs).with_context(|| format!("reading {abs:?}"))?;
                    let ct =
                        crypto::encrypt(key, &pt).with_context(|| format!("encrypting {rel:?}"))?;
                    let h = self.add(&ct).await?;
                    cache.remember(path.clone(), plain_hex.clone(), h, epoch);
                    h
                }
            };
            entries.push(ManifestEntry {
                path,
                plain: plain_hex,
                blob: blob.to_hex().to_string(),
            });
        }
        let keep: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();
        cache.retain_paths(&keep);

        let manifest = Manifest {
            version: MANIFEST_VERSION,
            entries,
        };
        let ct =
            crypto::encrypt(key, &serde_json::to_vec(&manifest)?).context("encrypting manifest")?;
        Ok(self.add(&ct).await?.to_hex().to_string())
    }

    /// Fetch the version `manifest_hex` from `provider_hex`, check it
    /// against `version_hash`, decrypt and verify every file, and stage the
    /// plaintext next to its destination under `root`. Nothing in the share
    /// root changes until the caller commits the result.
    pub async fn fetch(
        &self,
        provider_hex: &str,
        manifest_hex: &str,
        version_hash: &str,
        root: &Path,
        key: &KeyRing,
        cache: &mut BlobCache,
    ) -> Result<StagedVersion> {
        let provider = VerifyingKey::from_str(provider_hex)
            .map_err(|e| anyhow!("bad provider id {provider_hex:?}: {e:?}"))?;
        let manifest_hash =
            Hash::from_str(manifest_hex).map_err(|e| anyhow!("bad manifest hash: {e:?}"))?;

        let conn = tokio::time::timeout(
            CONNECT_TIMEOUT,
            self.endpoint.connect(provider, iroh_blobs::ALPN),
        )
        .await
        .map_err(|_| anyhow!("timed out connecting to {provider_hex}"))?
        .map_err(|e| anyhow!("connecting to {provider_hex}: {e:?}"))?;

        self.fetch_blob(&conn, manifest_hash).await?;
        let manifest_ct = self.read(manifest_hash).await?;
        let manifest_pt = crypto::decrypt(key, &manifest_ct).context("decrypting manifest")?;
        let manifest: Manifest =
            serde_json::from_slice(&manifest_pt).context("parsing manifest")?;
        if manifest.version != MANIFEST_VERSION {
            return Err(anyhow!("unsupported manifest version {}", manifest.version));
        }

        // Check the manifest against the announced version hash before
        // fetching anything else.
        let mut files = Vec::with_capacity(manifest.entries.len());
        for e in &manifest.entries {
            let rel = manifest_path_to_rel(&e.path)?;
            files.push((rel, parse_hex32(&e.plain)?));
        }
        files.sort();
        let computed = version_hash_of(&files);
        if computed != version_hash {
            return Err(anyhow!(
                "manifest version hash {computed} != announced {version_hash}"
            ));
        }

        let mut staged = StagedVersion {
            staged: Vec::new(),
            files: files.clone(),
        };
        let result = async {
            for e in &manifest.entries {
                let rel = manifest_path_to_rel(&e.path)?;
                let blob =
                    Hash::from_str(&e.blob).map_err(|err| anyhow!("bad blob hash: {err:?}"))?;
                self.fetch_blob(&conn, blob).await?;
                let ct = self.read(blob).await?;
                let pt =
                    crypto::decrypt(key, &ct).with_context(|| format!("decrypting {}", e.path))?;
                if blake3::hash(&pt).to_hex().as_str() != e.plain {
                    return Err(anyhow!("{} does not match its manifest hash", e.path));
                }
                let dest = root.join(&rel);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("create_dir_all {parent:?}"))?;
                }
                let tmp = staging_path(&dest)?;
                std::fs::write(&tmp, &pt).with_context(|| format!("writing {tmp:?}"))?;
                staged.staged.push((rel, tmp));
                if ct.len() >= EPOCH_LEN {
                    let mut ep = [0u8; EPOCH_LEN];
                    ep.copy_from_slice(&ct[..EPOCH_LEN]);
                    cache.remember(
                        e.path.clone(),
                        e.plain.clone(),
                        blob,
                        u64::from_le_bytes(ep),
                    );
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        match result {
            Ok(()) => {
                let keep: Vec<String> = manifest.entries.iter().map(|e| e.path.clone()).collect();
                cache.retain_paths(&keep);
                Ok(staged)
            }
            Err(e) => {
                staged.discard();
                Err(e)
            }
        }
    }

    async fn fetch_blob(&self, conn: &iroh::endpoint::Connection, hash: Hash) -> Result<()> {
        let progress = self.store.remote().fetch(conn.clone(), hash);
        tokio::time::timeout(FETCH_TIMEOUT, async move { progress.await })
            .await
            .map_err(|_| anyhow!("timed out fetching blob {}", hash.to_hex()))?
            .map_err(|e| anyhow!("fetching blob {}: {e:?}", hash.to_hex()))?;
        Ok(())
    }
}

/// blake3 over sorted `(len(path), path, blake3(content))`, the same value
/// the daemon has always called the version hash.
pub fn version_hash_of(files: &[FileHash]) -> String {
    let mut top = blake3::Hasher::new();
    for (rel, plain) in files {
        let path_bytes = rel.to_string_lossy();
        top.update(&(path_bytes.len() as u64).to_le_bytes());
        top.update(path_bytes.as_bytes());
        top.update(plain);
    }
    top.finalize().to_hex().to_string()
}

fn hex32(b: &[u8; 32]) -> String {
    blake3::Hash::from_bytes(*b).to_hex().to_string()
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let h = blake3::Hash::from_hex(s).map_err(|e| anyhow!("bad hash {s:?}: {e}"))?;
    Ok(*h.as_bytes())
}

/// Plaintext relative path to the manifest's `/`-separated form.
fn rel_to_manifest_path(rel: &Path) -> Result<String> {
    let parts: Vec<&str> = rel
        .components()
        .map(|c| match c {
            Component::Normal(s) => s
                .to_str()
                .ok_or_else(|| anyhow!("file name is not UTF-8: {rel:?}")),
            _ => Err(anyhow!("unexpected path component in {rel:?}")),
        })
        .collect::<Result<_>>()?;
    Ok(parts.join("/"))
}

/// A manifest path from a peer becomes a path under the share root only if
/// it is relative, has no `..`, `.` or root components, and has no
/// `.peerdup` component. Anything else is refused (path traversal).
pub fn manifest_path_to_rel(path: &str) -> Result<PathBuf> {
    if path.is_empty() || path.contains('\\') || path.contains('\0') {
        return Err(anyhow!("refusing manifest path {path:?}"));
    }
    let mut out = PathBuf::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." || part == PEERDUP_DIR_NAME {
            return Err(anyhow!("refusing manifest path {path:?}"));
        }
        out.push(part);
    }
    if out.is_absolute() {
        return Err(anyhow!("refusing manifest path {path:?}"));
    }
    Ok(out)
}

fn staging_path(dest: &Path) -> Result<PathBuf> {
    let mut name = dest
        .file_name()
        .ok_or_else(|| anyhow!("no file name in {dest:?}"))?
        .to_os_string();
    name.push(".peerdup-tmp");
    Ok(dest.with_file_name(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_paths_cannot_escape_the_root() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../x",
            "a//b",
            "./a",
            ".peerdup/keys",
            "a\\b",
        ] {
            assert!(manifest_path_to_rel(bad).is_err(), "{bad:?} accepted");
        }
        assert_eq!(
            manifest_path_to_rel("docs/notes.txt").unwrap(),
            PathBuf::from("docs").join("notes.txt")
        );
        // .peerdup is peerdup's own at any depth; the walk skips it too.
        assert!(manifest_path_to_rel("a/.peerdup/x").is_err());
    }

    #[test]
    fn manifest_paths_round_trip() {
        let rel = PathBuf::from("dir").join("sub").join("f.bin");
        let s = rel_to_manifest_path(&rel).unwrap();
        assert_eq!(s, "dir/sub/f.bin");
        assert_eq!(manifest_path_to_rel(&s).unwrap(), rel);
    }

    #[test]
    fn version_hash_matches_the_original_algorithm() {
        let files = vec![
            (PathBuf::from("a.txt"), *blake3::hash(b"hello").as_bytes()),
            (PathBuf::from("b/c.txt"), *blake3::hash(b"world").as_bytes()),
        ];
        let mut top = blake3::Hasher::new();
        for (p, content) in [("a.txt", &b"hello"[..]), ("b/c.txt", &b"world"[..])] {
            top.update(&(p.len() as u64).to_le_bytes());
            top.update(p.as_bytes());
            top.update(blake3::hash(content).as_bytes());
        }
        assert_eq!(version_hash_of(&files), top.finalize().to_hex().to_string());
    }

    #[test]
    fn blob_cache_reuses_only_same_content_and_epoch() {
        let mut c = BlobCache::default();
        let h = Hash::new(b"ct");
        c.remember("a".into(), "p1".into(), h, 1);
        assert_eq!(c.reuse("a", "p1", 1), Some(h));
        assert_eq!(c.reuse("a", "p2", 1), None);
        assert_eq!(c.reuse("a", "p1", 2), None);
        c.retain_paths(&["b".to_string()]);
        assert_eq!(c.reuse("a", "p1", 1), None);
    }
}
