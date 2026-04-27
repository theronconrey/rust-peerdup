use crate::clock::VectorClock;
use crate::data_dir;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Per-share runtime state persisted across daemon restarts. Distinct from
/// `ShareConfig` (which is what the user configured) — this is what the
/// daemon needs to remember about its sync history.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PersistedState {
    /// blake3 over sorted (rel_path, blake3(content)) pairs. Deterministic
    /// across peers for identical content.
    pub version_hash: String,
    pub clock: VectorClock,
    /// Wall-clock time when this version was created (locally edited or
    /// applied from a remote announce). Used as the tiebreaker for LWW
    /// conflict resolution.
    #[serde(default = "Utc::now")]
    pub timestamp: DateTime<Utc>,
    /// Files in this version, relative to the share root. Used by 3.4's
    /// orphan deletion: on apply, files in the old manifest but not in the
    /// new manifest are removed. Files the user added between snapshots
    /// (not in old_manifest) are left alone.
    #[serde(default)]
    pub manifest: BTreeSet<PathBuf>,
}

fn state_path(data_dir: &Path, share_id: &str) -> std::path::PathBuf {
    data_dir::shares_dir(data_dir).join(share_id).join("state.json")
}

pub fn load(data_dir: &Path, share_id: &str) -> Result<Option<PersistedState>> {
    let path = state_path(data_dir, share_id);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
    let state: PersistedState =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {path:?}"))?;
    Ok(Some(state))
}

pub fn save(data_dir: &Path, share_id: &str, state: &PersistedState) -> Result<()> {
    let path = state_path(data_dir, share_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create_dir_all {parent:?}"))?;
    }
    let json = serde_json::to_string_pretty(state)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json).with_context(|| format!("writing {tmp:?}"))?;
    fs::rename(&tmp, &path).with_context(|| format!("renaming {tmp:?} -> {path:?}"))?;
    Ok(())
}
