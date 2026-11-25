// SPDX-License-Identifier: MIT
//! Who may connect: share members only.
//!
//! The daemon's endpoint runs p2panda-net's `ConnectionBlockList` in
//! restrictive mode, so every connection, incoming or outgoing and for
//! every protocol (gossip, discovery, blob transfer), is refused after the
//! TLS handshake unless the other node is allowed. The allowed set is the
//! union of the current members of every share this daemon runs. When a
//! member is revoked and isn't in any other share, it is blocked: it can no
//! longer fetch blobs (not even old ciphertext) or hear announces.
//!
//! This replaces ROADMAP phase 6 (a BitTorrent admission hook in librqbit):
//! iroh connections are authenticated by node id, and the node id is the
//! member's identity key.

use crate::auth::MemberId;
use p2panda_net::iroh_endpoint::authoriser::{BlockListMode, ConnectionBlockList};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::Mutex;

pub struct Access {
    list: ConnectionBlockList,
    shares: Mutex<BTreeMap<String, BTreeSet<[u8; 32]>>>,
    me: [u8; 32],
}

impl Access {
    pub fn new(me: [u8; 32]) -> Self {
        Self {
            list: ConnectionBlockList::with_mode(BlockListMode::Restrictive),
            shares: Mutex::new(BTreeMap::new()),
            me,
        }
    }

    /// The hook to install on the endpoint.
    pub fn hook(&self) -> ConnectionBlockList {
        self.list.clone()
    }

    /// Record `share_id`'s current members and update the allow list:
    /// nodes that became members are allowed, nodes that are no longer a
    /// member of any share are blocked.
    pub async fn set_members(&self, share_id: &str, members: impl IntoIterator<Item = MemberId>) {
        let new: BTreeSet<[u8; 32]> = members
            .into_iter()
            .map(|m| m.0)
            .filter(|m| *m != self.me)
            .collect();
        let mut shares = self.shares.lock().await;
        let before = union(&shares);
        shares.insert(share_id.to_string(), new);
        let after = union(&shares);
        drop(shares);
        self.apply(&before, &after).await;
    }

    /// Forget a share that stopped or was removed.
    pub async fn remove_share(&self, share_id: &str) {
        let mut shares = self.shares.lock().await;
        let before = union(&shares);
        shares.remove(share_id);
        let after = union(&shares);
        drop(shares);
        self.apply(&before, &after).await;
    }

    async fn apply(&self, before: &BTreeSet<[u8; 32]>, after: &BTreeSet<[u8; 32]>) {
        for added in after.difference(before) {
            if let Ok(node) = p2panda_core::VerifyingKey::from_bytes(added) {
                self.list.allow(node).await;
            }
        }
        for removed in before.difference(after) {
            if let Ok(node) = p2panda_core::VerifyingKey::from_bytes(removed) {
                tracing::info!(node = %node.to_hex(), "no longer a member of any share; blocking");
                self.list.block(node).await;
            }
        }
    }

    #[cfg(test)]
    async fn allowed(&self, m: MemberId) -> bool {
        match p2panda_core::VerifyingKey::from_bytes(&m.0) {
            Ok(node) => self.list.can_connect(node).await,
            Err(_) => false,
        }
    }
}

fn union(shares: &BTreeMap<String, BTreeSet<[u8; 32]>>) -> BTreeSet<[u8; 32]> {
    shares.values().flatten().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2panda_core::SigningKey;

    fn member() -> MemberId {
        MemberId(*SigningKey::generate().verifying_key().as_bytes())
    }

    #[tokio::test]
    async fn only_members_of_some_share_may_connect() {
        let me = member();
        let access = Access::new(me.0);
        let (a, b, stranger) = (member(), member(), member());

        assert!(!access.allowed(stranger).await, "restrictive by default");

        access.set_members("s1", [me, a, b]).await;
        assert!(access.allowed(a).await);
        assert!(access.allowed(b).await);
        assert!(!access.allowed(stranger).await);

        // b is revoked from s1 but is still in s2: stays allowed.
        access.set_members("s2", [me, b]).await;
        access.set_members("s1", [me, a]).await;
        assert!(access.allowed(b).await);

        // Removed from s2 as well: blocked.
        access.set_members("s2", [me]).await;
        assert!(!access.allowed(b).await);

        // Re-invited: allowed again.
        access.set_members("s2", [me, b]).await;
        assert!(access.allowed(b).await);

        // The share stops: its members are blocked unless elsewhere.
        access.remove_share("s1").await;
        assert!(!access.allowed(a).await);
        assert!(access.allowed(b).await);
    }
}
