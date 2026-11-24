// SPDX-License-Identifier: MIT
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
        crate::data_dir::write_private_atomic(path, key.as_bytes())
            .with_context(|| format!("writing {path:?}"))?;
        Ok(key)
    }
}
