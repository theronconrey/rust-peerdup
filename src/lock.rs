use anyhow::{anyhow, Context, Result};
use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::path::Path;

/// Acquire an exclusive lock on `daemon.lock`. The returned file must be held
/// for the daemon's lifetime; the OS releases the lock when it's dropped.
pub fn acquire(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create_dir_all {parent:?}"))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("opening {path:?}"))?;
    file.try_lock_exclusive()
        .map_err(|_| anyhow!("another peerdup daemon is already running (lock held: {path:?})"))?;
    Ok(file)
}
