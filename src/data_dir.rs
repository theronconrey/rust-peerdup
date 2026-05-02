use anyhow::{anyhow, Result};
use directories::ProjectDirs;
use std::path::{Path, PathBuf};

pub fn resolve(override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p);
    }
    // Use a distinct name from the Python `peerdup` so the two
    // implementations don't share `~/.local/share/peerdup/` and corrupt
    // each other's identity.key / daemon.lock if both are ever installed
    // on the same machine. On Linux this resolves to
    // `~/.local/share/rust-peerdup/`.
    let pd = ProjectDirs::from("", "rust-peerdup", "rust-peerdup")
        .ok_or_else(|| anyhow!("could not resolve platform project dirs"))?;
    Ok(pd.data_dir().to_path_buf())
}

pub fn identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join("identity.key")
}

pub fn lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join("daemon.lock")
}

pub fn shares_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("shares")
}
