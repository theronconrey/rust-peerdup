// SPDX-License-Identifier: MIT
use crate::data_dir;
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ShareRole {
    /// One-way publish. Disabled: serves the plaintext root (see
    /// `ensure_encrypted`).
    Seed,
    /// One-way receive. Disabled, for the same reason as `Seed`.
    Leech,
    /// Bidirectional, encrypted. The only role that runs.
    Sync,
}

impl ShareRole {
    /// Seed and Leech predate encryption: they hand librqbit the plaintext
    /// share root, so anyone who learns the gossiped info-hash can fetch
    /// the files. They stay in the enum (so existing share.json files still
    /// parse) but are refused everywhere a share is created, joined,
    /// invited to or started, until they go through the encrypted shadow
    /// the way Sync does.
    pub fn ensure_encrypted(self) -> Result<()> {
        match self {
            ShareRole::Sync => Ok(()),
            ShareRole::Seed | ShareRole::Leech => Err(anyhow!(
                "the {self:?} role is disabled: it transfers files unencrypted. Use --role sync"
            )),
        }
    }
}

/// Share ids are `hex(blake3(topic))[..16]` and become directory names
/// under the data dir. Anything else (`../x`, an absolute path, a ticket
/// from a hostile peer) is refused before it can reach a path.
pub fn validate_id(id: &str) -> Result<()> {
    let ok = id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(anyhow!(
            "invalid share id {id:?}: expected 16 lowercase hex characters"
        ))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShareConfig {
    pub id: String,
    pub topic: String,
    pub root_path: PathBuf,
    pub role: ShareRole,
    pub created_at: DateTime<Utc>,
}

impl ShareConfig {
    pub fn new(topic: String, root_path: PathBuf, role: ShareRole) -> Self {
        Self {
            id: id_from_topic(&topic),
            topic,
            root_path,
            role,
            created_at: Utc::now(),
        }
    }

    pub fn save(&self, data_dir: &Path) -> Result<()> {
        validate_id(&self.id)?;
        self.role.ensure_encrypted()?;
        let dir = data_dir::shares_dir(data_dir).join(&self.id);
        fs::create_dir_all(&dir).with_context(|| format!("create_dir_all {dir:?}"))?;
        let json = serde_json::to_string_pretty(self)?;
        fs::write(dir.join("share.json"), json)
            .with_context(|| format!("write share.json in {dir:?}"))?;
        Ok(())
    }
}

pub fn id_from_topic(topic: &str) -> String {
    let hash = blake3::hash(topic.as_bytes());
    hash.to_hex().as_str()[..16].to_string()
}

pub fn load_all(data_dir: &Path) -> Result<Vec<ShareConfig>> {
    let dir = data_dir::shares_dir(data_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read_dir {dir:?}"))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path().join("share.json");
        if !path.exists() {
            tracing::warn!(dir = %id, "skipping share dir with no share.json");
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
        let cfg: ShareConfig =
            serde_json::from_slice(&bytes).with_context(|| format!("parsing {path:?}"))?;
        if let Err(e) = validate_id(&cfg.id) {
            tracing::warn!(dir = %id, error = %e, "skipping share with an invalid id");
            continue;
        }
        if cfg.id != id {
            tracing::warn!(dir = %id, json_id = %cfg.id, "share id mismatch (using json)");
        }
        out.push(cfg);
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

pub fn remove(data_dir: &Path, id: &str) -> Result<()> {
    validate_id(id)?;
    let dir = data_dir::shares_dir(data_dir).join(id);
    if !dir.exists() {
        return Err(anyhow!("share {id} not found"));
    }
    fs::remove_dir_all(&dir).with_context(|| format!("remove_dir_all {dir:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_from_topics_are_valid() {
        validate_id(&id_from_topic("demo")).unwrap();
        validate_id(&id_from_topic("")).unwrap();
    }

    #[test]
    fn rejects_ids_that_could_escape_the_data_dir() {
        for bad in [
            "../../../../tmp/x",
            "/etc",
            "abcd1234",
            "ABCDEF0123456789",
            "0123456789abcde/",
            "0123456789abcdeg",
            "",
        ] {
            assert!(validate_id(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn remove_refuses_invalid_ids() {
        let dir = std::env::temp_dir().join(format!("rust-peerdup-share-{}", std::process::id()));
        let err = remove(&dir, "../outside").unwrap_err().to_string();
        assert!(err.contains("invalid share id"), "{err}");
    }

    #[test]
    fn only_sync_runs() {
        ShareRole::Sync.ensure_encrypted().unwrap();
        assert!(ShareRole::Seed.ensure_encrypted().is_err());
        assert!(ShareRole::Leech.ensure_encrypted().is_err());
    }
}
