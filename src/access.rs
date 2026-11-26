// SPDX-License-Identifier: MIT
//! Who may connect, and which blobs they may fetch.
//!
//! Two layers, both keyed by the node id (= the member's identity key;
//! iroh authenticates it in the TLS handshake):
//!
//! 1. **Connections** (`MembersOnly`, an iroh `EndpointHooks` on the
//!    endpoint). Every connection, incoming or outgoing and for every
//!    protocol (gossip, discovery, blob transfer), is refused after the
//!    TLS handshake unless the other node is a current member of at least
//!    one share this daemon runs (p2panda-net's `ConnectionBlockList` in
//!    restrictive mode makes that decision). Accepted connections are
//!    recorded (weak handles, so the record never keeps one alive). When a
//!    node stops being a member of every share, it is blocked *and* every
//!    connection it has open is closed with code 403, so it loses gossip
//!    and blob transfer at once instead of when the connection idles out.
//! 2. **Blobs** (`serve_blob_events`, iroh-blobs' provider events in
//!    intercept mode). A connection may carry requests for any share, so
//!    each get request is checked on its own: node N may fetch hash H only
//!    if some share S has H among the blobs of its recent versions
//!    (`ShareBlobs`) and N is a current member of S. Requests for hash
//!    sequences (children of H) and every other request type are refused.
//!
//! This replaces ROADMAP phase 6 (a BitTorrent admission hook in librqbit).

use crate::auth::MemberId;
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, VarInt,
    WeakConnectionHandle,
};
use iroh::EndpointAddr;
use iroh_blobs::provider::events::{AbortReason, ProviderMessage};
use iroh_blobs::Hash;
use p2panda_net::iroh_endpoint::authoriser::{BlockListMode, ConnectionBlockList};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

/// Versions per share whose blobs stay fetchable: the current one and the
/// few before it, so a fetch of a version that was just superseded (a
/// quick second edit, a re-encryption after a rotation) still completes.
pub const RECENT_VERSIONS: usize = 4;

/// Application close code for connections cut on revocation; the same
/// 403 p2panda-net's block list refuses new connections with.
const REVOKED_CODE: u32 = 403;
const REVOKED_REASON: &[u8] = b"membership revoked";

type NodeId = [u8; 32];

/// Members, the blob index and the endpoint hook for the whole daemon.
pub struct Access {
    hook: MembersOnly,
    me: NodeId,
    state: Mutex<State>,
    /// Serialises `set_members`/`remove_share`, so the allow and block
    /// calls (async) are applied in the order the changes were made.
    updates: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct State {
    /// Current members of each running share, without us.
    members: BTreeMap<String, BTreeSet<NodeId>>,
    /// Blobs of each running share's recent versions.
    blobs: BTreeMap<String, ShareBlobs>,
}

impl Access {
    pub fn new(me: [u8; 32]) -> Self {
        Self {
            hook: MembersOnly {
                list: ConnectionBlockList::with_mode(BlockListMode::Restrictive),
                live: Arc::new(Mutex::new(LiveConnections::default())),
            },
            me,
            state: Mutex::new(State::default()),
            updates: tokio::sync::Mutex::new(()),
        }
    }

    /// The hook to install on the endpoint.
    pub fn hook(&self) -> MembersOnly {
        self.hook.clone()
    }

    /// Record `share_id`'s current members and update the allow list:
    /// nodes that became members are allowed; nodes that are no longer a
    /// member of any share are blocked and their live connections closed.
    pub async fn set_members(&self, share_id: &str, members: impl IntoIterator<Item = MemberId>) {
        let new: BTreeSet<NodeId> = members
            .into_iter()
            .map(|m| m.0)
            .filter(|m| *m != self.me)
            .collect();
        let _serial = self.updates.lock().await;
        let (before, after) = {
            let mut st = lock(&self.state);
            let before = union(&st.members);
            st.members.insert(share_id.to_string(), new);
            (before, union(&st.members))
        };
        self.apply(&before, &after).await;
    }

    /// Forget a share that stopped or was removed: its members (unless in
    /// another share) and its blobs.
    pub async fn remove_share(&self, share_id: &str) {
        let _serial = self.updates.lock().await;
        let (before, after) = {
            let mut st = lock(&self.state);
            let before = union(&st.members);
            st.members.remove(share_id);
            st.blobs.remove(share_id);
            (before, union(&st.members))
        };
        self.apply(&before, &after).await;
    }

    /// Make the blobs of a version of `share_id` (its manifest and every
    /// file blob) fetchable by the share's members. Call it before the
    /// version is announced.
    pub fn record_version(&self, share_id: &str, hashes: impl IntoIterator<Item = Hash>) {
        lock(&self.state)
            .blobs
            .entry(share_id.to_string())
            .or_default()
            .record(hashes.into_iter().collect());
    }

    async fn apply(&self, before: &BTreeSet<NodeId>, after: &BTreeSet<NodeId>) {
        for added in after.difference(before) {
            if let Ok(node) = p2panda_core::VerifyingKey::from_bytes(added) {
                self.hook.list.allow(node).await;
            }
        }
        for removed in before.difference(after) {
            let Ok(node) = p2panda_core::VerifyingKey::from_bytes(removed) else {
                continue;
            };
            // Block first, then close: `MembersOnly::after_handshake`
            // records a connection before it asks the block list, so a
            // connection is either recorded in time to be closed here or
            // refused by the block list.
            self.hook.list.block(node).await;
            let closed = self.hook.close_all(removed);
            tracing::info!(
                node = %node.to_hex(),
                closed,
                "no longer a member of any share: blocked, live connections closed"
            );
        }
    }

    /// Answer iroh-blobs' provider events until the blob protocol stops.
    /// Connections are mapped to the node id they come from (connect
    /// events are intercepted for that), and every get request goes
    /// through `blob_verdict`. A dropped decision counts as a refusal in
    /// iroh-blobs, so request types we never enable are refused too.
    pub async fn serve_blob_events(
        self: Arc<Self>,
        mut rx: tokio::sync::mpsc::Receiver<ProviderMessage>,
    ) {
        let mut conns: HashMap<u64, NodeId> = HashMap::new();
        while let Some(msg) = rx.recv().await {
            match msg {
                ProviderMessage::ClientConnected(msg) => {
                    let result = match msg.inner.endpoint_id {
                        Some(id) => {
                            conns.insert(msg.inner.connection_id, *id.as_bytes());
                            Ok(())
                        }
                        None => Err(AbortReason::Permission),
                    };
                    msg.tx.send(result).await.ok();
                }
                ProviderMessage::ConnectionClosed(msg) => {
                    conns.remove(&msg.inner.connection_id);
                }
                ProviderMessage::GetRequestReceived(msg) => {
                    let node = conns.get(&msg.inner.connection_id).copied();
                    let req = &msg.inner.request;
                    let single = req.ranges.is_empty() || req.ranges.is_blob();
                    let result = match node {
                        Some(node) => self.blob_verdict(&node, &req.hash, single),
                        None => Err(Refusal::UnknownConnection),
                    };
                    if let Err(refusal) = &result {
                        tracing::warn!(
                            node = %node.map(hex).unwrap_or_default(),
                            blob = %req.hash.to_hex(),
                            "refused a blob request: {refusal}"
                        );
                    }
                    msg.tx
                        .send(result.map_err(|_| AbortReason::Permission))
                        .await
                        .ok();
                }
                // Push, observe and get-many are disabled in the event
                // mask; if one arrives anyway, dropping it refuses it.
                _ => {}
            }
        }
    }

    fn blob_verdict(&self, node: &NodeId, hash: &Hash, single: bool) -> Result<String, Refusal> {
        let st = lock(&self.state);
        decide_blob(&st.members, &st.blobs, node, hash, single).map(str::to_string)
    }

    #[cfg(test)]
    async fn allowed(&self, m: MemberId) -> bool {
        match p2panda_core::VerifyingKey::from_bytes(&m.0) {
            Ok(node) => self.hook.list.can_connect(node).await,
            Err(_) => false,
        }
    }
}

fn union(shares: &BTreeMap<String, BTreeSet<NodeId>>) -> BTreeSet<NodeId> {
    shares.values().flatten().copied().collect()
}

fn hex(node: NodeId) -> String {
    MemberId(node).to_hex()
}

/// A poisoned lock only means another thread panicked mid-update; the
/// maps are still usable, and refusing all access over it would be worse.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The blob hashes of a share's recent versions, newest last.
#[derive(Default, Debug)]
pub struct ShareBlobs {
    versions: VecDeque<HashSet<Hash>>,
}

impl ShareBlobs {
    fn record(&mut self, hashes: HashSet<Hash>) {
        if self.versions.back() == Some(&hashes) {
            return;
        }
        self.versions.push_back(hashes);
        while self.versions.len() > RECENT_VERSIONS {
            self.versions.pop_front();
        }
    }

    fn contains(&self, hash: &Hash) -> bool {
        self.versions.iter().any(|v| v.contains(hash))
    }
}

/// Why a blob request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A request on a connection we have no node id for.
    UnknownConnection,
    /// No running share has this blob in a recent version.
    UnknownBlob,
    /// The blob belongs only to shares the node isn't a member of.
    NotAMember,
    /// The request asks for a hash sequence (children of the hash): the
    /// children could be any blob in the store.
    NotASingleBlob,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::UnknownConnection => "no node id for the connection",
            Refusal::UnknownBlob => "not a blob of a recent version of any share",
            Refusal::NotAMember => "not a member of the share it belongs to",
            Refusal::NotASingleBlob => "asks for a hash sequence, not a single blob",
        })
    }
}

/// The blob gate: may `node` fetch `hash`? Yes if some share has `hash`
/// in a recent version and `node` is one of its members, and the request
/// is for that one blob (`single`). Returns the share that allows it.
pub fn decide_blob<'a>(
    members: &'a BTreeMap<String, BTreeSet<NodeId>>,
    blobs: &BTreeMap<String, ShareBlobs>,
    node: &NodeId,
    hash: &Hash,
    single: bool,
) -> Result<&'a str, Refusal> {
    let mut known = false;
    for (share, set) in blobs {
        if !set.contains(hash) {
            continue;
        }
        known = true;
        if let Some((id, m)) = members.get_key_value(share) {
            if m.contains(node) {
                return if single {
                    Ok(id.as_str())
                } else {
                    Err(Refusal::NotASingleBlob)
                };
            }
        }
    }
    Err(if known {
        Refusal::NotAMember
    } else {
        Refusal::UnknownBlob
    })
}

/// What the connection records need from a connection.
pub trait Live {
    fn is_closed(&self) -> bool;
    /// Close it; `true` if it was still open.
    fn close(&self) -> bool;
}

/// A connection as recorded by the hook: a weak handle, so the record
/// never keeps a connection alive (iroh's hook docs ask for exactly this).
#[derive(Debug, Clone)]
pub struct Tracked(WeakConnectionHandle);

impl Live for Tracked {
    fn is_closed(&self) -> bool {
        self.0.upgrade().is_none_or(|c| c.close_reason().is_some())
    }

    fn close(&self) -> bool {
        match self.0.upgrade() {
            Some(c) if c.close_reason().is_none() => {
                c.close(VarInt::from_u32(REVOKED_CODE), REVOKED_REASON);
                true
            }
            _ => false,
        }
    }
}

/// Live connections per remote node. Closed ones are pruned whenever the
/// node's list is touched and when a connection closes.
#[derive(Debug)]
pub struct LiveConnections<C> {
    by_node: HashMap<NodeId, Vec<C>>,
}

impl<C> Default for LiveConnections<C> {
    fn default() -> Self {
        Self {
            by_node: HashMap::new(),
        }
    }
}

impl<C: Live> LiveConnections<C> {
    pub fn insert(&mut self, node: NodeId, conn: C) {
        let list = self.by_node.entry(node).or_default();
        list.retain(|c| !c.is_closed());
        list.push(conn);
    }

    /// Drop the records of `node`'s closed connections.
    pub fn prune(&mut self, node: &NodeId) {
        if let Some(list) = self.by_node.get_mut(node) {
            list.retain(|c| !c.is_closed());
            if list.is_empty() {
                self.by_node.remove(node);
            }
        }
    }

    /// Close every connection `node` has open and forget them; returns
    /// how many were open.
    pub fn close_all(&mut self, node: &NodeId) -> usize {
        self.by_node
            .remove(node)
            .unwrap_or_default()
            .iter()
            .filter(|c| c.close())
            .count()
    }

    #[cfg(test)]
    fn count(&self, node: &NodeId) -> usize {
        self.by_node.get(node).map_or(0, Vec::len)
    }
}

/// The endpoint hook: p2panda-net's restrictive block list decides, and
/// every accepted connection is recorded so a block can close it.
#[derive(Clone, Debug)]
pub struct MembersOnly {
    list: ConnectionBlockList,
    live: Arc<Mutex<LiveConnections<Tracked>>>,
}

impl MembersOnly {
    fn close_all(&self, node: &NodeId) -> usize {
        lock(&self.live).close_all(node)
    }
}

impl EndpointHooks for MembersOnly {
    async fn before_connect(
        &self,
        remote_addr: &EndpointAddr,
        alpn: &[u8],
    ) -> BeforeConnectOutcome {
        EndpointHooks::before_connect(&self.list, remote_addr, alpn).await
    }

    async fn after_handshake(&self, conn: &Connection) -> AfterHandshakeOutcome {
        let node = *conn.remote_id().as_bytes();
        let weak = conn.weak_handle();
        // Record before deciding (see `Access::apply`).
        lock(&self.live).insert(node, Tracked(weak.clone()));
        let outcome = EndpointHooks::after_handshake(&self.list, conn).await;
        if let AfterHandshakeOutcome::Reject { .. } = outcome {
            // iroh closes it on our return; its record goes then.
            return outcome;
        }
        // Registered now, while the connection is alive, so it fires.
        let closed = weak.closed();
        let live = self.live.clone();
        tokio::spawn(async move {
            closed.await;
            lock(&live).prune(&node);
        });
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2panda_core::SigningKey;
    use std::sync::atomic::{AtomicBool, Ordering};

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

    #[derive(Clone)]
    struct Fake(Arc<AtomicBool>);

    impl Fake {
        fn open() -> Self {
            Fake(Arc::new(AtomicBool::new(false)))
        }
        fn closed(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Live for Fake {
        fn is_closed(&self) -> bool {
            self.closed()
        }
        fn close(&self) -> bool {
            !self.0.swap(true, Ordering::SeqCst)
        }
    }

    #[test]
    fn closing_a_node_closes_all_its_connections_and_only_its() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let mut live = LiveConnections::default();
        let (a1, a2, b1) = (Fake::open(), Fake::open(), Fake::open());
        live.insert(a, a1.clone());
        live.insert(a, a2.clone());
        live.insert(b, b1.clone());
        assert_eq!(live.count(&a), 2);

        assert_eq!(live.close_all(&a), 2);
        assert!(a1.closed() && a2.closed());
        assert!(!b1.closed(), "another node's connection stays");
        assert_eq!(live.count(&a), 0, "records are dropped");
        assert_eq!(live.close_all(&a), 0, "nothing left to close");
        assert_eq!(live.count(&b), 1);
    }

    #[test]
    fn closed_connections_are_pruned() {
        let a = [1u8; 32];
        let mut live = LiveConnections::default();
        let (c1, c2) = (Fake::open(), Fake::open());
        live.insert(a, c1.clone());
        live.insert(a, c2.clone());
        c1.close();
        live.prune(&a);
        assert_eq!(live.count(&a), 1);
        // Pruned on insert too.
        c2.close();
        let c3 = Fake::open();
        live.insert(a, c3.clone());
        assert_eq!(live.count(&a), 1);
        // A connection that already closed doesn't count as closed by us.
        c3.close();
        assert_eq!(live.close_all(&a), 0);
        live.prune(&a);
        assert!(live.by_node.is_empty(), "no empty entries left behind");
    }

    fn h(b: &[u8]) -> Hash {
        Hash::new(b)
    }

    fn gate() -> (
        BTreeMap<String, BTreeSet<NodeId>>,
        BTreeMap<String, ShareBlobs>,
    ) {
        let mut members = BTreeMap::new();
        members.insert("x".to_string(), BTreeSet::from([[1u8; 32], [2u8; 32]]));
        members.insert("y".to_string(), BTreeSet::from([[2u8; 32], [3u8; 32]]));
        let mut blobs: BTreeMap<String, ShareBlobs> = BTreeMap::new();
        blobs
            .entry("x".into())
            .or_default()
            .record(HashSet::from([h(b"x-manifest"), h(b"x-file")]));
        blobs
            .entry("y".into())
            .or_default()
            .record(HashSet::from([h(b"y-manifest"), h(b"shared")]));
        blobs
            .entry("x".into())
            .or_default()
            .record(HashSet::from([h(b"x-manifest-2"), h(b"shared")]));
        (members, blobs)
    }

    #[test]
    fn a_member_may_fetch_its_shares_blobs() {
        let (m, b) = gate();
        assert_eq!(decide_blob(&m, &b, &[1; 32], &h(b"x-file"), true), Ok("x"));
        assert_eq!(
            decide_blob(&m, &b, &[3; 32], &h(b"y-manifest"), true),
            Ok("y")
        );
        // A previous version of x is still fetchable.
        assert_eq!(
            decide_blob(&m, &b, &[1; 32], &h(b"x-manifest"), true),
            Ok("x")
        );
    }

    #[test]
    fn another_shares_blobs_are_refused() {
        let (m, b) = gate();
        // 1 is in x only, 3 in y only.
        assert_eq!(
            decide_blob(&m, &b, &[1; 32], &h(b"y-manifest"), true),
            Err(Refusal::NotAMember)
        );
        assert_eq!(
            decide_blob(&m, &b, &[3; 32], &h(b"x-file"), true),
            Err(Refusal::NotAMember)
        );
        // A stranger, and a hash no share has.
        assert_eq!(
            decide_blob(&m, &b, &[9; 32], &h(b"x-file"), true),
            Err(Refusal::NotAMember)
        );
        assert_eq!(
            decide_blob(&m, &b, &[1; 32], &h(b"anything else"), true),
            Err(Refusal::UnknownBlob)
        );
    }

    #[test]
    fn a_hash_in_two_shares_is_allowed_to_members_of_either() {
        let (m, b) = gate();
        assert_eq!(decide_blob(&m, &b, &[1; 32], &h(b"shared"), true), Ok("x"));
        assert_eq!(decide_blob(&m, &b, &[3; 32], &h(b"shared"), true), Ok("y"));
        assert_eq!(
            decide_blob(&m, &b, &[9; 32], &h(b"shared"), true),
            Err(Refusal::NotAMember)
        );
    }

    #[test]
    fn hash_sequence_requests_are_refused() {
        let (m, b) = gate();
        assert_eq!(
            decide_blob(&m, &b, &[1; 32], &h(b"x-file"), false),
            Err(Refusal::NotASingleBlob)
        );
    }

    #[test]
    fn only_recent_versions_stay_fetchable() {
        let mut s = ShareBlobs::default();
        for i in 0..RECENT_VERSIONS + 2 {
            s.record(HashSet::from([h(format!("v{i}").as_bytes()), h(b"kept")]));
        }
        assert_eq!(s.versions.len(), RECENT_VERSIONS);
        assert!(!s.contains(&h(b"v0")) && !s.contains(&h(b"v1")));
        assert!(s.contains(&h(b"v2")));
        assert!(s.contains(&h(format!("v{}", RECENT_VERSIONS + 1).as_bytes())));
        assert!(s.contains(&h(b"kept")));
        // Recording the newest version again doesn't push one out.
        let newest = s.versions.back().unwrap().clone();
        s.record(newest);
        assert!(s.contains(&h(b"v2")));
    }

    #[tokio::test]
    async fn revoked_members_lose_blob_access_and_stopped_shares_their_blobs() {
        let me = member();
        let access = Access::new(me.0);
        let (a, b) = (member(), member());
        access.set_members("x", [me, a, b]).await;
        access.record_version("x", [h(b"m"), h(b"f")]);
        assert_eq!(access.blob_verdict(&b.0, &h(b"f"), true), Ok("x".into()));
        access.set_members("x", [me, a]).await;
        assert_eq!(
            access.blob_verdict(&b.0, &h(b"f"), true),
            Err(Refusal::NotAMember)
        );
        access.remove_share("x").await;
        assert_eq!(
            access.blob_verdict(&a.0, &h(b"f"), true),
            Err(Refusal::UnknownBlob)
        );
    }
}
