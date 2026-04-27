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
    Seed,
    Leech,
    /// Bidirectional. Reserved for Phase 3; rejected at runtime in Phase 2.
    Sync,
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
        let bytes =
            fs::read(&path).with_context(|| format!("reading {path:?}"))?;
        let cfg: ShareConfig = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {path:?}"))?;
        if cfg.id != id {
            tracing::warn!(dir = %id, json_id = %cfg.id, "share id mismatch (using json)");
        }
        out.push(cfg);
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

pub fn remove(data_dir: &Path, id: &str) -> Result<()> {
    let dir = data_dir::shares_dir(data_dir).join(id);
    if !dir.exists() {
        return Err(anyhow!("share {id} not found"));
    }
    fs::remove_dir_all(&dir).with_context(|| format!("remove_dir_all {dir:?}"))?;
    Ok(())
}
