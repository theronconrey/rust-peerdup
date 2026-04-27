use anyhow::{anyhow, Context, Result};
use p2panda_core::identity::PRIVATE_KEY_LEN;
use p2panda_core::PrivateKey;
use std::fs;
use std::path::Path;

pub fn load_or_create(path: &Path) -> Result<PrivateKey> {
    if path.exists() {
        let raw = fs::read(path).with_context(|| format!("reading {path:?}"))?;
        let bytes: [u8; PRIVATE_KEY_LEN] = raw.try_into().map_err(|v: Vec<u8>| {
            anyhow!(
                "identity.key has wrong length: got {}, want {}",
                v.len(),
                PRIVATE_KEY_LEN
            )
        })?;
        Ok(PrivateKey::from_bytes(&bytes))
    } else {
        let key = PrivateKey::new();
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("identity path has no parent: {path:?}"))?;
        fs::create_dir_all(parent).with_context(|| format!("create_dir_all {parent:?}"))?;
        fs::write(path, key.as_bytes()).with_context(|| format!("writing {path:?}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {path:?}"))?;
        }
        Ok(key)
    }
}
