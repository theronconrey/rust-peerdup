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
use iroh_blobs::api::blobs::BlobStatus;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, Hash};
use p2panda_core::VerifyingKey;
use p2panda_net::Endpoint;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
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

/// Largest encrypted manifest we fetch. At about 200 bytes an entry this
/// is far above `MAX_MANIFEST_ENTRIES`.
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Largest file blob we fetch. A whole file is held in memory twice
/// (ciphertext, then plaintext) while it is decrypted and checked, and on
/// the sender while it is encrypted, until encryption is streamed. Larger
/// files are refused by the receiver.
pub const MAX_BLOB_BYTES: u64 = 1024 * 1024 * 1024;

/// Most files in one version.
pub const MAX_MANIFEST_ENTRIES: usize = 100_000;

/// Longest manifest path, in bytes (Linux's PATH_MAX).
pub const MAX_PATH_BYTES: usize = 4096;

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

/// A fetched, verified version, staged next to its final paths. Dropping
/// it removes every staged file not yet committed, so an error, a timeout
/// or an aborted fetch task leaves no `*.peerdup-tmp` behind.
pub struct StagedVersion {
    /// `(final path relative to the root, temp file holding the plaintext)`.
    staged: Vec<(PathBuf, PathBuf)>,
    pub files: Vec<FileHash>,
    /// What the fetch learned for the `BlobCache`, applied by the share
    /// loop (which owns the cache) when it commits.
    cache_updates: Vec<(String, String, Hash, u64)>,
}

impl StagedVersion {
    fn new(files: Vec<FileHash>) -> Self {
        Self {
            staged: Vec::new(),
            files,
            cache_updates: Vec::new(),
        }
    }

    /// Move every staged file into place. A file that can't be moved stays
    /// staged and is removed when `self` drops.
    pub fn commit(mut self, root: &Path) -> Result<()> {
        while let Some((rel, tmp)) = self.staged.last().cloned() {
            check_parents(root, &rel, false)?;
            let dest = root.join(&rel);
            std::fs::rename(&tmp, &dest)
                .with_context(|| format!("renaming {tmp:?} -> {dest:?}"))?;
            self.staged.pop();
        }
        Ok(())
    }

    /// Record what this version's files are encrypted as, so re-announces
    /// and our own next publish reuse the blobs.
    pub fn apply_to_cache(&self, cache: &mut BlobCache) {
        for (path, plain, blob, epoch) in &self.cache_updates {
            cache.remember(path.clone(), plain.clone(), *blob, *epoch);
        }
        let keep: Vec<String> = self
            .files
            .iter()
            .filter_map(|(rel, _)| rel_to_manifest_path(rel).ok())
            .collect();
        cache.retain_paths(&keep);
    }
}

impl Drop for StagedVersion {
    fn drop(&mut self) {
        for (_, tmp) in self.staged.drain(..) {
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
    /// root changes until the caller commits the result; if this fails or
    /// is cancelled, the staged files are removed.
    pub async fn fetch(
        &self,
        provider_hex: &str,
        manifest_hex: &str,
        version_hash: &str,
        root: &Path,
        key: &KeyRing,
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

        self.fetch_blob(&conn, manifest_hash, MAX_MANIFEST_BYTES)
            .await?;
        let manifest_ct = self.read(manifest_hash).await?;
        let manifest_pt = crypto::decrypt(key, &manifest_ct).context("decrypting manifest")?;
        let manifest: Manifest =
            serde_json::from_slice(&manifest_pt).context("parsing manifest")?;
        if manifest.version != MANIFEST_VERSION {
            return Err(anyhow!("unsupported manifest version {}", manifest.version));
        }

        // Check the manifest, and it against the announced version hash,
        // before fetching anything else.
        let mut files = validate_manifest(&manifest.entries)?;
        files.sort();
        let computed = version_hash_of(&files);
        if computed != version_hash {
            return Err(anyhow!(
                "manifest version hash {computed} != announced {version_hash}"
            ));
        }

        let mut staged = StagedVersion::new(files);
        for e in &manifest.entries {
            let rel = manifest_path_to_rel(&e.path)?;
            let blob = Hash::from_str(&e.blob).map_err(|err| anyhow!("bad blob hash: {err:?}"))?;
            self.fetch_blob(&conn, blob, MAX_BLOB_BYTES).await?;
            let ct = self.read(blob).await?;
            let pt = crypto::decrypt(key, &ct).with_context(|| format!("decrypting {}", e.path))?;
            if blake3::hash(&pt).to_hex().as_str() != e.plain {
                return Err(anyhow!("{} does not match its manifest hash", e.path));
            }
            check_parents(root, &rel, true)?;
            let dest = root.join(&rel);
            let tmp = staging_path(&dest)?;
            // Registered before it is written, so a failed write is cleaned
            // up too.
            staged.staged.push((rel, tmp.clone()));
            write_new(&tmp, &pt)?;
            if ct.len() >= EPOCH_LEN {
                let mut ep = [0u8; EPOCH_LEN];
                ep.copy_from_slice(&ct[..EPOCH_LEN]);
                staged.cache_updates.push((
                    e.path.clone(),
                    e.plain.clone(),
                    blob,
                    u64::from_le_bytes(ep),
                ));
            }
        }
        Ok(staged)
    }

    /// Fetch `hash` unless the store already has it, refusing a blob over
    /// `max` bytes before transferring it: the provider must prove the
    /// size (`get_verified_size` checks the last chunk against the hash).
    async fn fetch_blob(
        &self,
        conn: &iroh::endpoint::Connection,
        hash: Hash,
        max: u64,
    ) -> Result<()> {
        if let Ok(BlobStatus::Complete { size }) = self.store.blobs().status(hash).await {
            if size > max {
                return Err(anyhow!(
                    "blob {} is {size} bytes, over the {max}-byte limit",
                    hash.to_hex()
                ));
            }
            return Ok(());
        }
        let (size, _) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            iroh_blobs::get::request::get_verified_size(conn, &hash),
        )
        .await
        .map_err(|_| anyhow!("timed out asking for the size of blob {}", hash.to_hex()))?
        .map_err(|e| anyhow!("asking for the size of blob {}: {e:?}", hash.to_hex()))?;
        if size > max {
            return Err(anyhow!(
                "blob {} is {size} bytes, over the {max}-byte limit",
                hash.to_hex()
            ));
        }
        if size >= LARGE_BLOB_BYTES {
            tracing::info!(blob = %hash.to_hex(), size, "fetching a large file");
        }
        let progress = self.store.remote().fetch(conn.clone(), hash);
        tokio::time::timeout(FETCH_TIMEOUT, async move { progress.await })
            .await
            .map_err(|_| anyhow!("timed out fetching blob {}", hash.to_hex()))?
            .map_err(|e| anyhow!("fetching blob {}: {e:?}", hash.to_hex()))?;
        Ok(())
    }
}

/// Blobs at least this big get an info line when their fetch starts.
const LARGE_BLOB_BYTES: u64 = 16 * 1024 * 1024;

/// Check a peer's manifest entries and turn them into relative paths:
/// at most `MAX_MANIFEST_ENTRIES`, every path safe
/// (`manifest_path_to_rel`) and at most `MAX_PATH_BYTES`, no path twice,
/// and no path that is both a file and a directory of another path
/// (`a` and `a/b`), which could never be applied.
pub fn validate_manifest(entries: &[ManifestEntry]) -> Result<Vec<FileHash>> {
    if entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(anyhow!(
            "manifest has {} entries (limit {MAX_MANIFEST_ENTRIES})",
            entries.len()
        ));
    }
    let mut seen: HashSet<&str> = HashSet::with_capacity(entries.len());
    for e in entries {
        if e.path.len() > MAX_PATH_BYTES {
            return Err(anyhow!(
                "manifest path of {} bytes (limit {MAX_PATH_BYTES})",
                e.path.len()
            ));
        }
        if !seen.insert(e.path.as_str()) {
            return Err(anyhow!("manifest lists {:?} twice", e.path));
        }
    }
    let mut files = Vec::with_capacity(entries.len());
    for e in entries {
        let rel = manifest_path_to_rel(&e.path)?;
        // Every ancestor must be a directory, not another entry's file.
        let mut prefix = e.path.as_str();
        while let Some(i) = prefix.rfind('/') {
            prefix = &prefix[..i];
            if seen.contains(prefix) {
                return Err(anyhow!(
                    "manifest has {prefix:?} both as a file and as a directory of {:?}",
                    e.path
                ));
            }
        }
        files.push((rel, parse_hex32(&e.plain)?));
    }
    Ok(files)
}

/// Walk the directories between `root` and the file `rel`, refusing a
/// symlink or a non-directory on the way, so nothing is written outside
/// the root through a symlinked directory. With `create`, missing
/// directories are made.
fn check_parents(root: &Path, rel: &Path, create: bool) -> Result<()> {
    let mut dir = root.to_path_buf();
    let parents: Vec<_> = rel
        .parent()
        .into_iter()
        .flat_map(|p| p.components())
        .collect();
    for c in parents {
        dir.push(c);
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(anyhow!("refusing to write through the symlink {dir:?}"));
            }
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(anyhow!("{dir:?} is in the way: not a directory")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                std::fs::create_dir(&dir).with_context(|| format!("create_dir {dir:?}"))?;
            }
            Err(e) => return Err(anyhow!("checking {dir:?}: {e}")),
        }
    }
    Ok(())
}

/// Write `bytes` to a new file at `path`, replacing whatever was there
/// (a stale temp file) without following a symlink.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow!("removing stale {path:?}: {e}")),
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {path:?}"))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {path:?}"))?;
    Ok(())
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

    fn entry(path: &str) -> ManifestEntry {
        ManifestEntry {
            path: path.to_string(),
            plain: hex32(blake3::hash(path.as_bytes()).as_bytes()),
            blob: hex32(&[0u8; 32]),
        }
    }

    fn scratch(label: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "peerdup-transfer-{label}-{:016x}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn manifest_validation_accepts_a_normal_tree() {
        let files =
            validate_manifest(&[entry("a.txt"), entry("dir/b.txt"), entry("dir/sub/c")]).unwrap();
        assert_eq!(files.len(), 3);
        assert_eq!(files[1].0, PathBuf::from("dir").join("b.txt"));
    }

    #[test]
    fn manifest_validation_refuses_duplicates() {
        let err = validate_manifest(&[entry("a"), entry("b"), entry("a")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn manifest_validation_refuses_a_file_that_is_also_a_directory() {
        for entries in [
            vec![entry("a"), entry("a/b")],
            vec![entry("x/y/z"), entry("x/y")],
            vec![entry("d/e/f/g"), entry("d")],
        ] {
            let err = validate_manifest(&entries).unwrap_err().to_string();
            assert!(err.contains("both as a file and as a directory"), "{err}");
        }
        // Sharing a name prefix is fine.
        validate_manifest(&[entry("a"), entry("ab/c"), entry("a-b")]).unwrap();
    }

    #[test]
    fn manifest_validation_refuses_oversize_input() {
        let long = "x".repeat(MAX_PATH_BYTES + 1);
        let err = validate_manifest(&[entry(&long)]).unwrap_err().to_string();
        assert!(err.contains("limit"), "{err}");
        let many: Vec<ManifestEntry> = (0..=MAX_MANIFEST_ENTRIES)
            .map(|i| ManifestEntry {
                path: format!("f{i}"),
                plain: String::new(),
                blob: String::new(),
            })
            .collect();
        let err = validate_manifest(&many).unwrap_err().to_string();
        assert!(err.contains("entries"), "{err}");
        // Unsafe paths are still refused.
        assert!(validate_manifest(&[entry("../x")]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn writes_never_go_through_a_symlinked_directory() {
        let root = scratch("symlink");
        let outside = scratch("outside");
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let err = check_parents(&root, Path::new("link/x.txt"), true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");
        // A file where a directory should be.
        std::fs::write(root.join("file"), b"x").unwrap();
        assert!(check_parents(&root, Path::new("file/x.txt"), true).is_err());
        // Missing directories are made.
        check_parents(&root, Path::new("new/deeper/x.txt"), true).unwrap();
        assert!(root.join("new/deeper").is_dir());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn staged_files_are_removed_unless_committed() {
        let root = scratch("staged");
        let tmp = root.join("a.txt.peerdup-tmp");
        write_new(&tmp, b"hello").unwrap();
        let mut staged = StagedVersion::new(Vec::new());
        staged.staged.push((PathBuf::from("a.txt"), tmp.clone()));
        drop(staged);
        assert!(!tmp.exists(), "dropping a staged version must clean up");

        write_new(&tmp, b"hello").unwrap();
        let mut staged = StagedVersion::new(Vec::new());
        staged.staged.push((PathBuf::from("a.txt"), tmp.clone()));
        staged.commit(&root).unwrap();
        assert!(!tmp.exists());
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"hello");
        std::fs::remove_dir_all(&root).unwrap();
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
