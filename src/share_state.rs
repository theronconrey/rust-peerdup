// SPDX-License-Identifier: MIT
use crate::clock::VectorClock;
use crate::data_dir;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// `PersistedState::format` this build writes. 1 (no field) had only the
/// set of paths; 2 added each file's plaintext hash and the base.
pub const STATE_FORMAT: u32 = 2;

/// Per-share runtime state persisted across daemon restarts. Distinct from
/// `ShareConfig` (which is what the user configured) — this is what the
/// daemon needs to remember about its sync history.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PersistedState {
    /// Format of this file; absent (0) in format 1.
    #[serde(default)]
    pub format: u32,
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
    /// Format 2: each file of this version with the blake3 (hex) of the
    /// plaintext we published or applied. The daemon rebuilds this from
    /// the share root at start, so a format-1 file (no hashes) migrates
    /// without loss.
    #[serde(default)]
    pub files: BTreeMap<PathBuf, String>,
    /// Format 2: the files of the last version known to be shared with a
    /// peer (one we applied, or one a peer announced back to us), path to
    /// plaintext hash. Concurrent applies compare against it to tell our
    /// changes from theirs (conflict copies, `daemon::commit_remote`).
    /// Empty in format 1: every local file then counts as changed, which
    /// keeps a conflict copy rather than dropping an edit.
    #[serde(default)]
    pub base: BTreeMap<PathBuf, String>,
}

fn state_path(data_dir: &Path, share_id: &str) -> std::path::PathBuf {
    data_dir::shares_dir(data_dir)
        .join(share_id)
        .join("state.json")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_1_files_still_load() {
        let old = r#"{
            "version_hash": "ab",
            "clock": {"p": 1},
            "timestamp": "2026-01-01T00:00:00Z",
            "manifest": ["a.txt", "dir/b.txt"]
        }"#;
        let s: PersistedState = serde_json::from_str(old).unwrap();
        assert_eq!(s.format, 0);
        assert_eq!(s.manifest.len(), 2);
        assert!(s.files.is_empty());
        assert!(s.base.is_empty());
    }
}
