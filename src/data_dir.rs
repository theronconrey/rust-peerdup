// SPDX-License-Identifier: MIT
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

/// Writes a secret (identity key, keyring, auth log, rotation envelope) so
/// that it is never readable by anyone else, even for a moment: the temp
/// file is created with mode 0600 (not chmod'ed afterwards), synced, then
/// renamed over `path`. A stale temp file from a crash is removed first, so
/// the mode always applies.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    if let Err(e) = std::fs::remove_file(&tmp) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rust-peerdup-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_private_atomic_is_0600_and_replaces() {
        let dir = scratch("private");
        let path = dir.join("secret.bin");
        write_private_atomic(&path, b"one").unwrap();
        write_private_atomic(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(!dir.join("secret.bin.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_private_atomic_ignores_stale_world_readable_tmp() {
        let dir = scratch("stale");
        let path = dir.join("secret.bin");
        std::fs::write(dir.join("secret.bin.tmp"), b"stale").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.join("secret.bin.tmp"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        write_private_atomic(&path, b"fresh").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"fresh");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
