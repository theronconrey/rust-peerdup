use anyhow::{anyhow, Result};
use directories::ProjectDirs;
use std::path::{Path, PathBuf};

pub fn resolve(override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p);
    }
    let pd = ProjectDirs::from("", "peerdup", "peerdup")
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
