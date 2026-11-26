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

/// Share ids are 16 lowercase hex characters (`ShareTopic::share_id`)
/// and become directory names under the data dir. Anything else (`../x`,
/// an absolute path, a ticket from a hostile peer) is refused before it
/// can reach a path.
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

/// Longest share name, in bytes.
pub const MAX_NAME_BYTES: usize = 256;

/// A share's name is a label for people: it is shown by `share-list` and
/// carried in tickets, so it may come from another machine. Not empty, at
/// most `MAX_NAME_BYTES`, and no control characters (which could rewrite
/// the terminal that prints it).
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("a share name can't be empty"));
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(anyhow!(
            "share name is {} bytes; at most {MAX_NAME_BYTES}",
            name.len()
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(anyhow!("share name {name:?} has control characters"));
    }
    Ok(())
}

/// blake3 key-derivation contexts (`blake3::derive_key`), one per value
/// derived from a topic secret, so the share id (which is shown and
/// logged) says nothing about the gossip topic (which lets a node join
/// the share's gossip).
const SHARE_ID_CONTEXT: &str = "rust-peerdup 2026-11-26 share id v1";
const GOSSIP_TOPIC_CONTEXT: &str = "rust-peerdup 2026-11-26 gossip topic v1";

/// 32 random bytes made at `share-add`, the root of a share's id and
/// gossip topic. Whoever has it can join the share's gossip (given a
/// connection, which only members get), so it is a secret: it travels
/// only in tickets and in `share.json` (0600), and is never logged,
/// announced or returned over D-Bus. `Debug` doesn't print it.
#[derive(Clone, PartialEq, Eq)]
pub struct TopicSecret([u8; 32]);

impl TopicSecret {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        TopicSecret(b)
    }

    #[cfg(test)]
    pub fn from_bytes(b: [u8; 32]) -> Self {
        TopicSecret(b)
    }

    /// `hex(blake3::derive_key(SHARE_ID_CONTEXT, secret))[..16]`.
    pub fn share_id(&self) -> String {
        let k = blake3::derive_key(SHARE_ID_CONTEXT, &self.0);
        blake3::Hash::from_bytes(k).to_hex().as_str()[..16].to_string()
    }

    /// `blake3::derive_key(GOSSIP_TOPIC_CONTEXT, secret)`.
    pub fn gossip_topic(&self) -> [u8; 32] {
        blake3::derive_key(GOSSIP_TOPIC_CONTEXT, &self.0)
    }
}

impl std::fmt::Debug for TopicSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TopicSecret(..)")
    }
}

/// Hex in `share.json` and tickets.
impl Serialize for TopicSecret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(blake3::Hash::from_bytes(self.0).to_hex().as_str())
    }
}

impl<'de> Deserialize<'de> for TopicSecret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let h = blake3::Hash::from_hex(s.as_bytes())
            .map_err(|_| serde::de::Error::custom("topic secret is not 64 hex characters"))?;
        Ok(TopicSecret(*h.as_bytes()))
    }
}

/// Where a share's id and gossip topic come from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareTopic {
    /// Every share made since ticket v4: a random secret.
    Secret(TopicSecret),
    /// A share made before: id `hex(blake3(topic))[..16]` and gossip topic
    /// `blake3(topic)` of the user's topic string. Kept so existing shares
    /// keep working; such a topic can be guessed (INTEGRATION_NOTES.md,
    /// "Share identity and topics").
    Legacy(String),
}

impl ShareTopic {
    pub fn share_id(&self) -> String {
        match self {
            ShareTopic::Secret(s) => s.share_id(),
            ShareTopic::Legacy(t) => blake3::hash(t.as_bytes()).to_hex().as_str()[..16].to_string(),
        }
    }

    pub fn gossip_topic(&self) -> [u8; 32] {
        match self {
            ShareTopic::Secret(s) => s.gossip_topic(),
            ShareTopic::Legacy(t) => *blake3::hash(t.as_bytes()).as_bytes(),
        }
    }

    pub fn is_legacy(&self) -> bool {
        matches!(self, ShareTopic::Legacy(_))
    }
}

/// A configured share (`shares/<id>/share.json`). On disk it is
/// `ShareFile`; reading a file from before ticket v4 (with only a
/// `topic` string) gives a `ShareTopic::Legacy` share named after it.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(try_from = "ShareFile", into = "ShareFile")]
pub struct ShareConfig {
    pub id: String,
    /// Label for people (`--name`). Not secret, not unique, never hashed.
    pub name: String,
    pub topic: ShareTopic,
    pub root_path: PathBuf,
    pub role: ShareRole,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
struct ShareFile {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    topic_secret: Option<TopicSecret>,
    /// The topic string of a share made before ticket v4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_topic: Option<String>,
    /// Files written before ticket v4 have this instead of the three
    /// above; never written now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    topic: Option<String>,
    root_path: PathBuf,
    role: ShareRole,
    created_at: DateTime<Utc>,
}

impl TryFrom<ShareFile> for ShareConfig {
    type Error = String;

    fn try_from(f: ShareFile) -> std::result::Result<Self, String> {
        let (topic, name) = match (f.topic_secret, f.legacy_topic.or(f.topic)) {
            (Some(secret), None) => (ShareTopic::Secret(secret), f.name.unwrap_or_default()),
            (None, Some(t)) => {
                let name = f.name.unwrap_or_else(|| t.clone());
                (ShareTopic::Legacy(t), name)
            }
            (Some(_), Some(_)) => return Err("both a topic secret and a legacy topic".into()),
            (None, None) => return Err("no topic secret".into()),
        };
        let derived = topic.share_id();
        if f.id != derived {
            return Err(format!(
                "share id {:?} doesn't derive from its topic ({derived})",
                f.id
            ));
        }
        Ok(ShareConfig {
            id: f.id,
            name,
            topic,
            root_path: f.root_path,
            role: f.role,
            created_at: f.created_at,
        })
    }
}

impl From<ShareConfig> for ShareFile {
    fn from(c: ShareConfig) -> Self {
        let (topic_secret, legacy_topic) = match c.topic {
            ShareTopic::Secret(s) => (Some(s), None),
            ShareTopic::Legacy(t) => (None, Some(t)),
        };
        ShareFile {
            id: c.id,
            name: Some(c.name),
            topic_secret,
            legacy_topic,
            topic: None,
            root_path: c.root_path,
            role: c.role,
            created_at: c.created_at,
        }
    }
}

impl ShareConfig {
    /// A new share with a fresh random topic secret.
    pub fn create(name: String, root_path: PathBuf, role: ShareRole) -> Result<Self> {
        validate_name(&name)?;
        let topic = ShareTopic::Secret(TopicSecret::generate());
        Ok(Self {
            id: topic.share_id(),
            name,
            topic,
            root_path,
            role,
            created_at: Utc::now(),
        })
    }

    /// `share.json` holds the topic secret, so it is written like the
    /// other secrets: 0600 from creation, atomically.
    pub fn save(&self, data_dir: &Path) -> Result<()> {
        validate_id(&self.id)?;
        self.role.ensure_encrypted()?;
        let dir = data_dir::shares_dir(data_dir).join(&self.id);
        fs::create_dir_all(&dir).with_context(|| format!("create_dir_all {dir:?}"))?;
        let json = serde_json::to_vec_pretty(self)?;
        data_dir::write_private_atomic(&dir.join("share.json"), &json)
            .with_context(|| format!("write share.json in {dir:?}"))?;
        Ok(())
    }
}

/// A `share.json` from before it held a secret may be readable by others;
/// make it 0600. Its content isn't rewritten.
#[cfg(unix)]
fn tighten_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    if meta.permissions().mode() & 0o077 != 0 {
        match fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            Ok(()) => tracing::info!(?path, "made share.json private (0600)"),
            Err(e) => tracing::warn!(error = %e, ?path, "could not make share.json private"),
        }
    }
}

#[cfg(not(unix))]
fn tighten_permissions(_path: &Path) {}

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
        tighten_permissions(&path);
        let bytes = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
        let cfg: ShareConfig = match serde_json::from_slice(&bytes) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(dir = %id, error = %e, "skipping a share whose share.json can't be used");
                continue;
            }
        };
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
        validate_id(&TopicSecret::generate().share_id()).unwrap();
        validate_id(&ShareTopic::Legacy("demo".into()).share_id()).unwrap();
        validate_id(&ShareTopic::Legacy(String::new()).share_id()).unwrap();
    }

    #[test]
    fn secret_derivations_are_deterministic_and_separated() {
        let s = TopicSecret::from_bytes([7u8; 32]);
        assert_eq!(s.share_id(), TopicSecret::from_bytes([7u8; 32]).share_id());
        assert_eq!(
            s.gossip_topic(),
            TopicSecret::from_bytes([7u8; 32]).gossip_topic()
        );
        // Domain separation: the id is not a prefix of the topic, and
        // neither is a plain hash of the secret.
        let topic_hex = blake3::Hash::from_bytes(s.gossip_topic())
            .to_hex()
            .to_string();
        assert!(!topic_hex.starts_with(&s.share_id()));
        assert_ne!(s.gossip_topic(), *blake3::hash(&[7u8; 32]).as_bytes());
        assert!(!blake3::hash(&[7u8; 32])
            .to_hex()
            .as_str()
            .starts_with(&s.share_id()));
        // The context strings are part of the format: changing one would
        // split every existing share from its members.
        assert_eq!(
            s.share_id(),
            blake3::Hash::from_bytes(blake3::derive_key(
                "rust-peerdup 2026-11-26 share id v1",
                &[7u8; 32]
            ))
            .to_hex()
            .as_str()[..16]
        );
        // Different secrets, different shares, even with the same name.
        let (a, b) = (TopicSecret::generate(), TopicSecret::generate());
        assert_ne!(a.share_id(), b.share_id());
        assert_ne!(a.gossip_topic(), b.gossip_topic());
    }

    #[test]
    fn legacy_topics_keep_their_old_derivation() {
        let t = ShareTopic::Legacy("demo".into());
        assert_eq!(t.share_id(), blake3::hash(b"demo").to_hex().as_str()[..16]);
        assert_eq!(t.gossip_topic(), *blake3::hash(b"demo").as_bytes());
    }

    #[test]
    fn the_secret_is_never_printed() {
        let s = TopicSecret::from_bytes([0xab; 32]);
        let cfg = ShareConfig {
            id: s.share_id(),
            name: "photos".into(),
            topic: ShareTopic::Secret(s),
            root_path: PathBuf::from("/x"),
            role: ShareRole::Sync,
            created_at: Utc::now(),
        };
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("abababab"), "{shown}");
        assert!(!shown.contains("171, 171"), "{shown}");
        assert!(shown.contains("TopicSecret(..)"), "{shown}");
    }

    #[test]
    fn share_json_round_trips_and_migrates() {
        let cfg =
            ShareConfig::create("photos".into(), PathBuf::from("/x"), ShareRole::Sync).unwrap();
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(
            json.contains("topic_secret") && !json.contains("legacy_topic"),
            "{json}"
        );
        let back: ShareConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, cfg.id);
        assert_eq!(back.name, "photos");
        assert_eq!(back.topic, cfg.topic);

        // A share.json from before v4.
        let old = format!(
            r#"{{"id":"{}","topic":"demo","root_path":"/x","role":"sync","created_at":"2026-01-01T00:00:00Z"}}"#,
            blake3::hash(b"demo").to_hex().as_str()[..16].to_string()
        );
        let legacy: ShareConfig = serde_json::from_str(&old).unwrap();
        assert_eq!(legacy.topic, ShareTopic::Legacy("demo".into()));
        assert_eq!(legacy.name, "demo");
        // Saved again, it says what it is.
        let json = serde_json::to_string(&legacy).unwrap();
        assert!(
            json.contains("legacy_topic") && !json.contains("\"topic\""),
            "{json}"
        );
        let again: ShareConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(again.topic, legacy.topic);
    }

    #[test]
    fn share_json_with_an_id_that_does_not_derive_is_refused() {
        let old = r#"{"id":"0123456789abcdef","topic":"demo","root_path":"/x","role":"sync","created_at":"2026-01-01T00:00:00Z"}"#;
        let err = serde_json::from_str::<ShareConfig>(old)
            .unwrap_err()
            .to_string();
        assert!(err.contains("doesn't derive"), "{err}");
        let none = r#"{"id":"0123456789abcdef","root_path":"/x","role":"sync","created_at":"2026-01-01T00:00:00Z"}"#;
        assert!(serde_json::from_str::<ShareConfig>(none).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn share_json_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "rust-peerdup-sharejson-{:016x}",
            rand::random::<u64>()
        ));
        let cfg = ShareConfig::create("p".into(), dir.join("root"), ShareRole::Sync).unwrap();
        cfg.save(&dir).unwrap();
        let path = data_dir::shares_dir(&dir).join(&cfg.id).join("share.json");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // An old world-readable one is tightened when loaded.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let loaded = load_all(&dir).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn names_are_checked() {
        validate_name("photos").unwrap();
        validate_name("Fotos von Oma").unwrap();
        assert!(validate_name("").is_err());
        assert!(validate_name("a\u{1b}[2J").is_err());
        assert!(validate_name("line\nbreak").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_BYTES + 1)).is_err());
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
