// SPDX-License-Identifier: MIT
//! Finding peers on other networks.
//!
//! p2panda-net's endpoint only connects to nodes whose address is in its
//! address book (no DNS fallback), and it has no relay unless one is
//! configured. So, to sync across networks:
//!
//! - the daemon uses relays (n0's public ones unless `--relay-url` says
//!   otherwise) so peers behind NAT can reach each other;
//! - once online, it writes its own iroh address (node id, home relay,
//!   direct addresses) to `<data_dir>/endpoint.json`;
//! - an invite carries that address, and the joiner keeps it as the
//!   share's bootstrap (`shares/<id>/bootstrap.json`);
//! - when a share starts, the bootstrap goes into the address book, and
//!   every member is registered on the share's topic. p2panda's discovery
//!   then spreads the rest of the addresses.

use anyhow::{Context, Result};
use p2panda_net::iroh_endpoint::{EndpointAddr, RelayUrl};
use std::path::{Path, PathBuf};
use std::str::FromStr;

fn own_addr_path(data_dir: &Path) -> PathBuf {
    data_dir.join("endpoint.json")
}

fn share_bootstrap_path(data_dir: &Path, share_id: &str) -> PathBuf {
    crate::data_dir::shares_dir(data_dir)
        .join(share_id)
        .join("bootstrap.json")
}

fn save(path: &Path, addr: &EndpointAddr) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(addr)?;
    crate::data_dir::write_private_atomic(path, &bytes).with_context(|| format!("writing {path:?}"))
}

fn load(path: &Path) -> Option<EndpointAddr> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::warn!(error = %e, ?path, "ignoring unreadable address file");
            None
        }
    }
}

/// The daemon's own address, as last written by a running daemon.
pub fn load_own_addr(data_dir: &Path) -> Option<EndpointAddr> {
    load(&own_addr_path(data_dir))
}

pub fn save_own_addr(data_dir: &Path, addr: &EndpointAddr) -> Result<()> {
    save(&own_addr_path(data_dir), addr)
}

/// The inviter's address from the ticket a share was joined with.
pub fn load_share_bootstrap(data_dir: &Path, share_id: &str) -> Option<EndpointAddr> {
    load(&share_bootstrap_path(data_dir, share_id))
}

pub fn save_share_bootstrap(data_dir: &Path, share_id: &str, addr: &EndpointAddr) -> Result<()> {
    save(&share_bootstrap_path(data_dir, share_id), addr)
}

/// n0's public production relays, iroh's defaults. Rate-limited and meant
/// for development; `--relay-url` replaces them (README, "Relays").
pub fn default_relay_urls() -> Vec<RelayUrl> {
    use iroh::defaults::prod::{
        default_ap_relay, default_eu_relay, default_na_east_relay, default_na_west_relay,
    };
    vec![
        default_na_east_relay().url,
        default_na_west_relay().url,
        default_eu_relay().url,
        default_ap_relay().url,
    ]
}

pub fn parse_relay_url(s: &str) -> Result<RelayUrl> {
    RelayUrl::from_str(s).with_context(|| format!("invalid relay URL {s:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_are_default_relays() {
        assert!(!default_relay_urls().is_empty());
    }

    #[test]
    fn addresses_round_trip_through_their_files() {
        let dir =
            std::env::temp_dir().join(format!("rust-peerdup-bootstrap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(crate::data_dir::shares_dir(&dir).join("abc")).unwrap();
        let key = p2panda_core::SigningKey::generate();
        let id = iroh::PublicKey::from_bytes(key.verifying_key().as_bytes()).unwrap();
        let addr = EndpointAddr::new(id).with_relay_url(default_relay_urls()[0].clone());
        save_own_addr(&dir, &addr).unwrap();
        assert_eq!(load_own_addr(&dir), Some(addr.clone()));
        save_share_bootstrap(&dir, "abc", &addr).unwrap();
        assert_eq!(load_share_bootstrap(&dir, "abc"), Some(addr));
        assert_eq!(load_share_bootstrap(&dir, "missing"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
