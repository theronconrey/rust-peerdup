// SPDX-License-Identifier: MIT
//! Phase 5c: per-share membership CRDT built on `p2panda-auth`.
//!
//! Wraps `p2panda_auth::group::GroupCrdt` with peerdup-specific identity,
//! Ed25519 signatures over each operation, and an append-only on-disk log
//! (`auth.log`) that the daemon reloads on start.
//!
//! Identity types are `[u8; 32]` newtypes:
//! - `MemberId` is the raw Ed25519 public key of a peer.
//! - The group itself is identified by `group_id_for(share_id)`, a blake3
//!   hash of `"peerdup-group/" + share_id`. This keeps the group id in the
//!   same `[u8; 32]` space as individual ids without colliding with any
//!   real pubkey.
//! - `OpId` is `blake3(canonical_bytes(op) || signature)`.

use crate::data_dir;
use anyhow::{anyhow, Context, Result};
use p2panda_auth::group::resolver::StrongRemove;
use p2panda_auth::group::{GroupAction, GroupCrdt, GroupCrdtState, GroupMember};
use p2panda_auth::traits::Operation;
use p2panda_auth::{Access, AccessLevel};
use p2panda_core::{Signature, SigningKey, VerifyingKey};

/// Ed25519 signature length. p2panda-core 0.8 no longer exports it.
pub const SIGNATURE_LEN: usize = 64;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MemberId(pub [u8; 32]);

impl MemberId {
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() != 64 {
            return Err(anyhow!("member id hex must be 64 chars (got {})", s.len()));
        }
        // Slicing by byte offsets below panics on a multi-byte character, and
        // this string arrives over D-Bus and the CLI.
        if !s.is_ascii() {
            return Err(anyhow!("member id hex must be ASCII"));
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow!("invalid hex byte at {}", i * 2))?;
        }
        Ok(MemberId(out))
    }
}

impl fmt::Debug for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemberId({}…)", &self.to_hex()[..16])
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl p2panda_core::Author for MemberId {}

#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OpId(pub [u8; 32]);

impl OpId {
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

impl fmt::Debug for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpId({}…)", &self.to_hex()[..16])
    }
}

impl fmt::Display for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl p2panda_core::OperationId for OpId {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AuthRole {
    Owner,
    Writer,
    Reader,
}

impl AuthRole {
    pub fn to_access(self) -> Access<()> {
        match self {
            AuthRole::Owner => Access::manage(),
            AuthRole::Writer => Access::write(),
            AuthRole::Reader => Access::read(),
        }
    }

    pub fn from_access(a: &Access<()>) -> Self {
        match a.level {
            AccessLevel::Manage => AuthRole::Owner,
            AccessLevel::Write => AuthRole::Writer,
            AccessLevel::Read | AccessLevel::Pull => AuthRole::Reader,
        }
    }
}

impl fmt::Display for AuthRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            AuthRole::Owner => "owner",
            AuthRole::Writer => "writer",
            AuthRole::Reader => "reader",
        };
        f.write_str(s)
    }
}

/// The signed payload of an auth op. p2panda-auth 0.8 dropped its
/// `GroupControlMessage`; this is the same struct, so an op serialises to
/// the same bytes and existing `auth.log` files, signatures and op ids stay
/// valid. Don't reorder or retype its fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupControlMessage {
    pub group_id: MemberId,
    pub action: GroupAction<MemberId, ()>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedOp {
    pub author: MemberId,
    pub deps: Vec<OpId>,
    pub payload: GroupControlMessage,
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; SIGNATURE_LEN],
}

pub(crate) mod serde_bytes_64 {
    use super::SIGNATURE_LEN;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        v: &[u8; SIGNATURE_LEN],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        v.as_slice().serialize(s)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; SIGNATURE_LEN], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        if v.len() != SIGNATURE_LEN {
            return Err(serde::de::Error::custom(format!(
                "signature must be {SIGNATURE_LEN} bytes, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; SIGNATURE_LEN];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

impl SignedOp {
    fn canonical_bytes(&self) -> Vec<u8> {
        // Signed bytes cover (author, deps, payload). Excludes signature
        // itself (chicken-and-egg) and the cached id (derived).
        bincode::serde::encode_to_vec(
            (&self.author, &self.deps, &self.payload),
            bincode::config::standard(),
        )
        .expect("canonical encoding of in-memory op never fails")
    }

    fn compute_id(&self) -> OpId {
        let mut h = blake3::Hasher::new();
        h.update(&self.canonical_bytes());
        h.update(&self.signature);
        OpId(*h.finalize().as_bytes())
    }

    pub fn verify(&self) -> Result<()> {
        let pubkey = VerifyingKey::from_bytes(&self.author.0)
            .map_err(|e| anyhow!("invalid author pubkey: {e:?}"))?;
        let sig = Signature::from_bytes(&self.signature);
        if !pubkey.verify(&self.canonical_bytes(), &sig) {
            return Err(anyhow!("signature verification failed"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .context("encoding signed op")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (op, _): (Self, _) = bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard().with_limit::<MAX_OP_BYTES>(),
        )
        .context("decoding signed op")?;
        Ok(op)
    }
}

impl Operation<MemberId, OpId, ()> for SignedOp {
    fn id(&self) -> OpId {
        self.compute_id()
    }
    fn author(&self) -> MemberId {
        self.author
    }
    fn dependencies(&self) -> Vec<OpId> {
        self.deps.clone()
    }
    fn group_id(&self) -> MemberId {
        self.payload.group_id
    }
    fn action(&self) -> GroupAction<MemberId, ()> {
        self.payload.action.clone()
    }
}

/// Largest `auth.log` we read: about 80,000 ops.
pub const MAX_AUTH_LOG_BYTES: usize = 16 * 1024 * 1024;

/// Largest single encoded op: an op's deps are the heads it was authored
/// on, so this is generous.
pub const MAX_OP_BYTES: usize = 64 * 1024;

/// Cap on ops buffered while their dependencies are missing.
const MAX_PENDING_OPS: usize = 256;

type Resolver = StrongRemove<MemberId, OpId, SignedOp, ()>;
type Crdt = GroupCrdt<MemberId, OpId, SignedOp, (), Resolver>;
type CrdtState = GroupCrdtState<MemberId, OpId, SignedOp, ()>;

pub struct AuthState {
    /// The share's group. Every op must be for it, and the first one must
    /// be its `Create`.
    group: MemberId,
    crdt: CrdtState,
    /// Causally-ordered log of applied operations. Mirrors `auth.log` on disk.
    ops: Vec<SignedOp>,
    /// Operations whose deps haven't all been applied yet. Drained as deps
    /// arrive.
    pending: Vec<SignedOp>,
}

impl AuthState {
    /// An empty state for `group`. Its first op must be that group's
    /// `Create`; ops for any other group are refused.
    pub fn empty_for(group: MemberId) -> Self {
        Self {
            group,
            crdt: CrdtState::new(),
            ops: Vec::new(),
            pending: Vec::new(),
        }
    }

    pub fn ops(&self) -> &[SignedOp] {
        &self.ops
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Ops held back because a dependency hasn't arrived.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Author and apply the group's `Create` operation. Self becomes manager.
    pub fn create_group(&mut self, my_key: &SigningKey, group_id: MemberId) -> Result<SignedOp> {
        if group_id != self.group {
            return Err(anyhow!("this auth state is for another group"));
        }
        if !self.ops.is_empty() {
            return Err(anyhow!(
                "auth state already has {} operation(s); refusing to re-create group",
                self.ops.len()
            ));
        }
        let me = MemberId(*my_key.verifying_key().as_bytes());
        let action = GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(me), Access::manage())],
        };
        self.author(my_key, group_id, action)
    }

    pub fn add_member(
        &mut self,
        my_key: &SigningKey,
        group_id: MemberId,
        new_member: MemberId,
        role: AuthRole,
    ) -> Result<SignedOp> {
        let action = GroupAction::Add {
            member: GroupMember::Individual(new_member),
            access: role.to_access(),
        };
        self.author(my_key, group_id, action)
    }

    pub fn remove_member(
        &mut self,
        my_key: &SigningKey,
        group_id: MemberId,
        member: MemberId,
    ) -> Result<SignedOp> {
        let action = GroupAction::Remove {
            member: GroupMember::Individual(member),
        };
        self.author(my_key, group_id, action)
    }

    /// Leave the share: author a `Remove` of ourselves. Refused with a
    /// clear error for a non-member and for the only Owner; the same rule
    /// is enforced on every op in `check_self_remove`.
    pub fn leave(&mut self, my_key: &SigningKey, group_id: MemberId) -> Result<SignedOp> {
        let me = MemberId(*my_key.verifying_key().as_bytes());
        let members = self.members(group_id);
        let Some((_, role)) = members.iter().find(|(m, _)| *m == me) else {
            return Err(anyhow!("this node is not a member of the share"));
        };
        if *role == AuthRole::Owner
            && !members
                .iter()
                .any(|(m, r)| *m != me && *r == AuthRole::Owner)
        {
            return Err(anyhow!(
                "this node is the share's only Owner; a share without an Owner can never \
                 rotate its key again. Invite another Owner first (share-invite \
                 --auth-role owner), or drop the share on this machine only with share-remove"
            ));
        }
        self.remove_member(my_key, group_id, me)
    }

    /// Whether `member` has left: it isn't a member and the log holds a
    /// `Remove` of it that it authored itself.
    pub fn has_left(&self, group_id: MemberId, member: MemberId) -> bool {
        !self.is_member(group_id, member)
            && self.ops.iter().any(|op| {
                op.author == member
                    && matches!(
                        &op.payload.action,
                        GroupAction::Remove { member: GroupMember::Individual(m) } if *m == member
                    )
            })
    }

    /// Construct, sign, and apply a locally-authored op.
    fn author(
        &mut self,
        my_key: &SigningKey,
        group_id: MemberId,
        action: GroupAction<MemberId, ()>,
    ) -> Result<SignedOp> {
        let me = MemberId(*my_key.verifying_key().as_bytes());
        let deps: Vec<OpId> = self.crdt.inner.heads(&[self.group]).into_iter().collect();
        let payload = GroupControlMessage { group_id, action };
        let canonical =
            bincode::serde::encode_to_vec((&me, &deps, &payload), bincode::config::standard())
                .context("encoding canonical op")?;
        let sig = my_key.sign(&canonical);
        let op = SignedOp {
            author: me,
            deps,
            payload,
            signature: sig.to_bytes(),
        };
        self.process(op.clone())
            .with_context(|| "applying locally-authored auth op")?;
        Ok(op)
    }

    /// Apply an op received from a remote peer (or replayed from disk).
    /// Verifies the signature, then applies if all dependencies are present;
    /// otherwise stashes in the pending queue and tries to drain on the next
    /// arrival. Returns `true` if the op was newly applied.
    pub fn apply_remote(&mut self, op: SignedOp) -> Result<bool> {
        op.verify().context("verifying remote auth op")?;
        // One AuthState is one share's group. Ops for any other group are
        // someone else's (or an attempt to mix logs) and are refused.
        if op.payload.group_id != self.group {
            return Err(anyhow!(
                "auth op is for a different group ({:?}, this share is {:?})",
                op.payload.group_id,
                self.group
            ));
        }
        let op_id = op.id();
        if self.ops.iter().any(|o| o.id() == op_id) || self.pending.iter().any(|o| o.id() == op_id)
        {
            return Ok(false);
        }
        self.check_shape(&op)?;

        let known: HashSet<OpId> = self.ops.iter().map(|o| o.id()).collect();
        if !op.deps.iter().all(|d| known.contains(d)) {
            // Anyone with a keypair can sign ops with made-up deps; don't
            // let them grow this without bound.
            if self.pending.len() >= MAX_PENDING_OPS {
                return Err(anyhow!(
                    "too many auth ops waiting for dependencies ({MAX_PENDING_OPS}); dropping"
                ));
            }
            self.pending.push(op);
            return Ok(false);
        }

        self.process(op)?;
        self.drain_pending()?;
        Ok(true)
    }

    /// A group has exactly one `Create`, its root: it has no deps and is
    /// the first op applied. Every other op builds on earlier ones. A
    /// second `Create`, signed by anyone, would otherwise be processed by
    /// p2panda-auth as a fresh group definition (review finding 1; see
    /// INTEGRATION_NOTES.md, "p2panda-auth: a second Create resets group
    /// state").
    fn check_shape(&self, op: &SignedOp) -> Result<()> {
        match &op.payload.action {
            GroupAction::Create { .. } => {
                if !op.deps.is_empty() {
                    return Err(anyhow!("refusing a Create with dependencies"));
                }
                if !self.ops.is_empty() {
                    return Err(anyhow!(
                        "refusing a second Create for an existing group (from {})",
                        op.author.to_hex()
                    ));
                }
            }
            _ => {
                if op.deps.is_empty() {
                    return Err(anyhow!(
                        "refusing an auth op with no dependencies that is not the group's Create"
                    ));
                }
            }
        }
        Ok(())
    }

    fn process(&mut self, op: SignedOp) -> Result<()> {
        // Crdt::process takes the state by value, and GroupCrdtState isn't
        // Clone, so on failure the state it was given is gone. Rebuild it
        // from the ops already applied (they applied once, so they apply
        // again) rather than leaving an empty group behind, which would then
        // reject every rotation.
        self.check_self_remove(&op)?;
        let prev = std::mem::replace(&mut self.crdt, CrdtState::new());
        match Crdt::process(prev, &op) {
            Ok(next) => {
                self.crdt = next;
                self.ops.push(op);
                Ok(())
            }
            Err(e) => {
                self.rebuild_from_log()?;
                Err(anyhow!("auth crdt error: {e:?}"))
            }
        }
    }

    /// A member leaving: a `Remove` whose author is the removed member.
    /// p2panda-auth 0.7+ applies one from any member (upstream #1234;
    /// 0.5.2 required a manager). peerdup accepts it from anyone who was a
    /// member at the op's dependencies, except the only Owner there: a
    /// share without an Owner can never rotate its key again, and every
    /// removal raises the required epoch (`required_epoch`), so it could
    /// never publish again either. The Owners' daemons close the gap a
    /// leave opens by rotating (`daemon::auto_rotation`). Depends only on
    /// the op and its causal past, so every node decides the same.
    /// Runs with the op's dependencies applied.
    fn check_self_remove(&self, op: &SignedOp) -> Result<()> {
        let GroupAction::Remove {
            member: GroupMember::Individual(removed),
        } = &op.payload.action
        else {
            return Ok(());
        };
        if *removed != op.author {
            return Ok(());
        }
        let heads: HashSet<OpId> = op.deps.iter().copied().collect();
        let members = Crdt::members_at(&self.crdt, heads, self.group)
            .map_err(|e| anyhow!("auth crdt error: {e:?}"))?;
        let Some((_, access)) = members.iter().find(|(m, _)| *m == op.author) else {
            return Err(anyhow!(
                "refusing a self-removal by a non-member ({})",
                op.author.to_hex()
            ));
        };
        if access.level == AccessLevel::Manage {
            let other_owner = members
                .iter()
                .any(|(m, a)| *m != op.author && a.level == AccessLevel::Manage);
            if !other_owner {
                return Err(anyhow!(
                    "refusing the self-removal of the share's only Owner ({})",
                    op.author.to_hex()
                ));
            }
        }
        Ok(())
    }

    fn rebuild_from_log(&mut self) -> Result<()> {
        let mut crdt = CrdtState::new();
        for op in &self.ops {
            crdt = Crdt::process(crdt, op)
                .map_err(|e| anyhow!("rebuilding auth state from its log: {e:?}"))?;
        }
        self.crdt = crdt;
        Ok(())
    }

    fn drain_pending(&mut self) -> Result<()> {
        loop {
            let known: HashSet<OpId> = self.ops.iter().map(|o| o.id()).collect();
            let next_idx = self
                .pending
                .iter()
                .position(|p| p.deps.iter().all(|d| known.contains(d)));
            match next_idx {
                Some(idx) => {
                    let op = self.pending.remove(idx);
                    self.process(op)?;
                }
                None => return Ok(()),
            }
        }
    }

    /// The group this state belongs to.
    pub fn group_id(&self) -> MemberId {
        self.group
    }

    /// `member`'s current role in `group_id`, if it is a member.
    pub fn role_of(&self, group_id: MemberId, member: MemberId) -> Option<AuthRole> {
        self.members(group_id)
            .into_iter()
            .find(|(m, _)| *m == member)
            .map(|(_, r)| r)
    }

    /// Only Owners may invite or revoke. Checked before authoring, so a
    /// non-Owner gets a clear error rather than a CRDT rejection.
    pub fn require_owner(&self, group_id: MemberId, identity: &SigningKey) -> Result<()> {
        let me = MemberId(*identity.verifying_key().as_bytes());
        let is_owner = self
            .members(group_id)
            .into_iter()
            .any(|(m, role)| m == me && role == AuthRole::Owner);
        if is_owner {
            Ok(())
        } else {
            Err(anyhow!(
                "only an Owner of this share can invite or revoke members"
            ))
        }
    }

    /// Removals in effect: `Remove` ops in the log that p2panda-auth's
    /// strong-remove resolver didn't filter out. A filtered op (say, one a
    /// removed Owner authored concurrently with, or backdated before, its
    /// own removal) never took effect, so it isn't counted; otherwise a
    /// revoked Owner could raise the count at will and freeze the share. An
    /// op in a mutual-remove cycle is in the filter too but does take
    /// effect (everyone in the cycle is removed), so it counts.
    pub fn removals(&self) -> u64 {
        self.removals_in_effect().count() as u64
    }

    /// The `Remove` ops counted by `removals`, in the order this node
    /// applied them.
    fn removals_in_effect(&self) -> impl DoubleEndedIterator<Item = &SignedOp> {
        let inner = &self.crdt.inner;
        self.ops
            .iter()
            .filter(|op| matches!(op.payload.action, GroupAction::Remove { .. }))
            .filter(move |op| {
                let id = op.id();
                !inner.ignore.contains(&id) || inner.mutual_removes.contains(&id)
            })
    }

    /// Whether the `gap` most recently applied removals in effect are all
    /// members leaving. A node whose keyring is `gap` epochs behind
    /// `required_epoch` uses this to tell a leave (an Owner's daemon mints
    /// its key, `daemon::auto_rotation`) from a revocation (the revoking
    /// Owner minted its key with the `Remove`, and it is on its way). Keys
    /// don't name the removal they cover, so this is a heuristic for the
    /// concurrent case; see INTEGRATION_NOTES.md, "Members leave on their
    /// own".
    pub fn uncovered_removals_are_leaves(&self, gap: u64) -> bool {
        let mut seen = 0u64;
        for op in self.removals_in_effect().rev() {
            if seen == gap {
                break;
            }
            let GroupAction::Remove {
                member: GroupMember::Individual(m),
            } = &op.payload.action
            else {
                return false;
            };
            if *m != op.author {
                return false;
            }
            seen += 1;
        }
        gap > 0 && seen == gap
    }

    /// The lowest key epoch new content may be encrypted under, as far as
    /// this node's view of the membership goes: `1 + removals()`. Every
    /// revocation rotates the key once (`share-revoke`, daemon and direct
    /// mode), and so does every leave (an Owner's daemon), so after `n`
    /// removals keys up to epoch `n` are held by at least one removed
    /// member. Demotions don't count: a demoted member
    /// keeps read access. See `epochs::required` for the floor that a key
    /// fork adds, and INTEGRATION_NOTES.md, "Old keys after revocation".
    pub fn required_epoch(&self) -> u64 {
        1 + self.removals()
    }

    pub fn members(&self, group_id: MemberId) -> Vec<(MemberId, AuthRole)> {
        self.crdt
            .members(group_id)
            .into_iter()
            .map(|(id, access)| (id, AuthRole::from_access(&access)))
            .collect()
    }

    /// `true` iff `member` currently has any access level >= `Pull` on the
    /// given group.
    pub fn is_member(&self, group_id: MemberId, member: MemberId) -> bool {
        self.crdt
            .members(group_id)
            .iter()
            .any(|(id, _)| *id == member)
    }
}

/// Stable group id derived from a peerdup share id. Prefixed so it can never
/// collide with a real pubkey-as-MemberId.
pub fn group_id_for(share_id: &str) -> MemberId {
    let mut h = blake3::Hasher::new();
    h.update(b"peerdup-group/");
    h.update(share_id.as_bytes());
    MemberId(*h.finalize().as_bytes())
}

pub fn auth_log_path(data_dir: &Path, share_id: &str) -> PathBuf {
    data_dir::shares_dir(data_dir)
        .join(share_id)
        .join("auth.log")
}

/// Replay the auth log from disk into a fresh `AuthState`. Returns an empty
/// state if no log exists. Verifies every signature on the way in.
pub fn load(data_dir: &Path, share_id: &str) -> Result<AuthState> {
    let path = auth_log_path(data_dir, share_id);
    let group = group_id_for(share_id);
    if !path.exists() {
        return Ok(AuthState::empty_for(group));
    }
    let bytes = fs::read(&path).with_context(|| format!("reading {path:?}"))?;
    if bytes.len() > MAX_AUTH_LOG_BYTES {
        return Err(anyhow!(
            "{path:?} is {} bytes, over the {MAX_AUTH_LOG_BYTES}-byte limit",
            bytes.len()
        ));
    }
    let (ops, _): (Vec<SignedOp>, _) = bincode::serde::decode_from_slice(
        &bytes,
        bincode::config::standard().with_limit::<MAX_AUTH_LOG_BYTES>(),
    )
    .with_context(|| format!("decoding {path:?}"))?;
    let mut state = AuthState::empty_for(group);
    for op in ops {
        state
            .apply_remote(op)
            .with_context(|| format!("replaying op from {path:?}"))?;
    }
    if !state.pending.is_empty() {
        return Err(anyhow!(
            "auth.log left {} op(s) with unmet deps after replay; log is corrupt",
            state.pending.len()
        ));
    }
    Ok(state)
}

pub fn save(data_dir: &Path, share_id: &str, state: &AuthState) -> Result<()> {
    let path = auth_log_path(data_dir, share_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create_dir_all {parent:?}"))?;
    }
    let bytes = bincode::serde::encode_to_vec(&state.ops, bincode::config::standard())
        .context("encoding auth log")?;
    crate::data_dir::write_private_atomic(&path, &bytes)
        .with_context(|| format!("writing {path:?}"))?;
    Ok(())
}

#[cfg(test)]
mod from_hex_tests {
    use super::MemberId;

    #[test]
    fn non_ascii_of_the_right_length_is_an_error_not_a_panic() {
        // 64 bytes, but 'é' is two bytes, so byte offsets split it.
        let s = format!("{}é{}", "a".repeat(31), "b".repeat(31));
        assert_eq!(s.len(), 64);
        assert!(MemberId::from_hex(&s).is_err());
    }

    #[test]
    fn round_trips() {
        let id = MemberId([0xab; 32]);
        assert_eq!(MemberId::from_hex(&id.to_hex()).unwrap(), id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_key() -> SigningKey {
        SigningKey::generate()
    }

    fn me_of(k: &SigningKey) -> MemberId {
        MemberId(*k.verifying_key().as_bytes())
    }

    #[test]
    fn a_rejected_op_does_not_empty_the_group() {
        let alice = fresh_key();
        let bob = fresh_key();
        let carol = fresh_key();
        let group = group_id_for("share-reject");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        // A Writer can't add members. Whether the CRDT errors or ignores
        // the op, the existing membership must survive.
        let _ = state.add_member(&bob, group, me_of(&carol), AuthRole::Writer);
        assert!(state.is_member(group, me_of(&alice)));
        assert!(state.is_member(group, me_of(&bob)));
        assert!(!state.is_member(group, me_of(&carol)));
    }

    /// Sign an op with arbitrary deps, the way a malicious peer can.
    fn forge(
        key: &SigningKey,
        deps: Vec<OpId>,
        action: GroupAction<MemberId, ()>,
        group: MemberId,
    ) -> SignedOp {
        let author = me_of(key);
        let payload = GroupControlMessage {
            group_id: group,
            action,
        };
        let canonical =
            bincode::serde::encode_to_vec((&author, &deps, &payload), bincode::config::standard())
                .unwrap();
        SignedOp {
            author,
            deps,
            payload,
            signature: key.sign(&canonical).to_bytes(),
        }
    }

    fn sorted_members(state: &AuthState, group: MemberId) -> Vec<(MemberId, AuthRole)> {
        let mut m = state.members(group);
        m.sort_by_key(|(id, _)| id.0);
        m
    }

    /// Review finding 1: a second `Create` for an existing group, signed
    /// by a Reader or by someone outside the share, must not reset the
    /// group or hand the attacker a role.
    #[test]
    fn stranger_create_for_existing_group_is_refused() {
        let owner = fresh_key();
        let writer = fresh_key();
        let reader = fresh_key();
        let stranger = fresh_key();
        let group = group_id_for("share-takeover");
        let mut state = AuthState::empty_for(group);
        state.create_group(&owner, group).unwrap();
        state
            .add_member(&owner, group, me_of(&writer), AuthRole::Writer)
            .unwrap();
        state
            .add_member(&owner, group, me_of(&reader), AuthRole::Reader)
            .unwrap();
        let before = sorted_members(&state, group);

        for (attacker, role_before) in [(&reader, Some(AuthRole::Reader)), (&stranger, None)] {
            let create = |deps: Vec<OpId>| {
                forge(
                    attacker,
                    deps,
                    GroupAction::Create {
                        initial_members: vec![(
                            GroupMember::Individual(me_of(attacker)),
                            Access::manage(),
                        )],
                    },
                    group,
                )
            };
            // A Create with no deps (a fresh root) and one built on the
            // current heads (as if authored with a full copy of the log).
            let heads: Vec<OpId> = state.crdt.inner.heads(&[group]).into_iter().collect();
            for op in [create(Vec::new()), create(heads)] {
                let _ = state.apply_remote(op);
                assert_eq!(
                    sorted_members(&state, group),
                    before,
                    "a forged Create changed the membership"
                );
                assert_eq!(state.role_of(group, me_of(attacker)), role_before);
            }
        }
    }

    #[test]
    fn ops_for_another_group_are_refused() {
        let alice = fresh_key();
        let group_a = group_id_for("share-a");
        let group_b = group_id_for("share-b");
        let mut a = AuthState::empty_for(group_a);
        a.create_group(&alice, group_a).unwrap();
        let mut b = AuthState::empty_for(group_b);
        let op_b = b.create_group(&alice, group_b).unwrap();
        let err = a.apply_remote(op_b).unwrap_err().to_string();
        assert!(err.contains("different group"), "{err}");
    }

    #[test]
    fn only_owners_may_invite_or_revoke() {
        let alice = fresh_key();
        let bob = fresh_key();
        let group = group_id_for("share-owner");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        state.require_owner(group, &alice).unwrap();
        assert!(state.require_owner(group, &bob).is_err());
    }

    #[test]
    fn create_then_add_member() {
        let alice = fresh_key();
        let bob = fresh_key();
        let group = group_id_for("share-1");

        let mut state = AuthState::empty_for(group);
        let _create_op = state.create_group(&alice, group).unwrap();
        let _add_op = state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();

        let mut members = state.members(group);
        members.sort_by_key(|(m, _)| m.0);
        let mut expected = vec![
            (me_of(&alice), AuthRole::Owner),
            (me_of(&bob), AuthRole::Writer),
        ];
        expected.sort_by_key(|(m, _)| m.0);
        assert_eq!(members, expected);
    }

    #[test]
    fn op_round_trip_through_bincode_and_signature_verifies() {
        let alice = fresh_key();
        let group = group_id_for("share-roundtrip");

        let mut state = AuthState::empty_for(group);
        let op = state.create_group(&alice, group).unwrap();

        let bytes = op.encode().unwrap();
        let decoded = SignedOp::decode(&bytes).unwrap();
        assert_eq!(decoded.author, op.author);
        assert_eq!(decoded.deps, op.deps);
        assert_eq!(decoded.signature, op.signature);
        decoded.verify().unwrap();
        assert_eq!(decoded.id(), op.id());
    }

    #[test]
    fn tampered_op_fails_verify() {
        let alice = fresh_key();
        let group = group_id_for("share-tamper");
        let mut state = AuthState::empty_for(group);
        let op = state.create_group(&alice, group).unwrap();

        let mut bad = op.clone();
        bad.signature[0] ^= 1;
        assert!(bad.verify().is_err());

        let mut bad2 = op.clone();
        bad2.author = MemberId([0xAB; 32]);
        assert!(bad2.verify().is_err());
    }

    #[test]
    fn remote_replay_converges_with_local() {
        let alice = fresh_key();
        let bob = fresh_key();
        let group = group_id_for("share-converge");

        // Alice authors locally.
        let mut alice_state = AuthState::empty_for(group);
        let op1 = alice_state.create_group(&alice, group).unwrap();
        let op2 = alice_state
            .add_member(&alice, group, me_of(&bob), AuthRole::Reader)
            .unwrap();

        // Bob replays from gossip in original order.
        let mut bob_state = AuthState::empty_for(group);
        assert!(bob_state.apply_remote(op1.clone()).unwrap());
        assert!(bob_state.apply_remote(op2.clone()).unwrap());

        let mut a = alice_state.members(group);
        a.sort_by_key(|(m, _)| m.0);
        let mut b = bob_state.members(group);
        b.sort_by_key(|(m, _)| m.0);
        assert_eq!(a, b);
    }

    #[test]
    fn out_of_order_arrival_is_buffered_then_applied() {
        let alice = fresh_key();
        let bob = fresh_key();
        let group = group_id_for("share-ooo");

        let mut alice_state = AuthState::empty_for(group);
        let op1 = alice_state.create_group(&alice, group).unwrap();
        let op2 = alice_state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();

        let mut bob_state = AuthState::empty_for(group);
        // Apply op2 first; it has an unmet dep so it stays pending.
        assert!(!bob_state.apply_remote(op2.clone()).unwrap());
        assert!(bob_state.members(group).is_empty());
        // Now op1 arrives; op2 should drain in.
        assert!(bob_state.apply_remote(op1.clone()).unwrap());
        let mut members = bob_state.members(group);
        members.sort_by_key(|(m, _)| m.0);
        let mut expected = vec![
            (me_of(&alice), AuthRole::Owner),
            (me_of(&bob), AuthRole::Writer),
        ];
        expected.sort_by_key(|(m, _)| m.0);
        assert_eq!(members, expected);
    }

    #[test]
    fn duplicate_apply_is_a_noop() {
        let alice = fresh_key();
        let group = group_id_for("share-dup");
        let mut state = AuthState::empty_for(group);
        let op = state.create_group(&alice, group).unwrap();

        // The locally-applied op was already added; replaying it should be a noop.
        assert!(!state.apply_remote(op.clone()).unwrap());
        assert_eq!(state.ops().len(), 1);
    }

    #[test]
    fn revoke_drops_member() {
        let alice = fresh_key();
        let bob = fresh_key();
        let group = group_id_for("share-revoke");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        assert!(state.is_member(group, me_of(&bob)));

        state.remove_member(&alice, group, me_of(&bob)).unwrap();
        assert!(!state.is_member(group, me_of(&bob)));
        assert!(state.is_member(group, me_of(&alice)));
    }

    #[test]
    fn required_epoch_counts_removals() {
        let alice = fresh_key();
        let (bob, carol) = (fresh_key(), fresh_key());
        let group = group_id_for("share-required");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        assert_eq!(state.required_epoch(), 1, "create");
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        state
            .add_member(&alice, group, me_of(&carol), AuthRole::Reader)
            .unwrap();
        assert_eq!(state.required_epoch(), 1, "add, add");
        state.remove_member(&alice, group, me_of(&bob)).unwrap();
        assert_eq!(state.required_epoch(), 2, "remove");
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        assert!(state.is_member(group, me_of(&bob)));
        assert_eq!(state.required_epoch(), 2, "remove, re-add");
        state.remove_member(&alice, group, me_of(&carol)).unwrap();
        assert_eq!(state.required_epoch(), 3, "second remove");

        // A peer replaying the log reaches the same number.
        let mut replica = AuthState::empty_for(group);
        for op in state.ops() {
            replica.apply_remote(op.clone()).unwrap();
        }
        assert_eq!(replica.required_epoch(), 3);
    }

    /// A removed Owner can still sign ops whose deps predate its removal;
    /// they validate at those deps. The resolver filters them, and they
    /// must not count, or a revoked Owner could freeze the share by
    /// raising the required epoch past every key.
    #[test]
    fn a_removed_owners_backdated_removal_does_not_count() {
        let alice = fresh_key();
        let (mallory, carol) = (fresh_key(), fresh_key());
        let group = group_id_for("share-backdated");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&mallory), AuthRole::Owner)
            .unwrap();
        state
            .add_member(&alice, group, me_of(&carol), AuthRole::Writer)
            .unwrap();
        let before: Vec<OpId> = state.crdt.inner.heads(&[group]).into_iter().collect();
        state.remove_member(&alice, group, me_of(&mallory)).unwrap();
        assert_eq!(state.required_epoch(), 2);

        let backdated = forge(
            &mallory,
            before,
            GroupAction::Remove {
                member: GroupMember::Individual(me_of(&carol)),
            },
            group,
        );
        // Applied and filtered, or refused: either way it changes nothing.
        let _ = state.apply_remote(backdated);
        assert_eq!(state.required_epoch(), 2);
        assert!(state.is_member(group, me_of(&carol)));
        assert!(!state.is_member(group, me_of(&mallory)));
    }

    fn self_remove(key: &SigningKey, deps: Vec<OpId>, group: MemberId) -> SignedOp {
        forge(
            key,
            deps,
            GroupAction::Remove {
                member: GroupMember::Individual(me_of(key)),
            },
            group,
        )
    }

    fn heads_of(state: &AuthState, group: MemberId) -> Vec<OpId> {
        state.crdt.inner.heads(&[group]).into_iter().collect()
    }

    /// Any member may leave: a Reader, a Writer, and an Owner while another
    /// Owner remains. Each leave counts as a removal, and a peer replaying
    /// the log reaches the same membership and required epoch.
    #[test]
    fn members_may_leave_and_each_leave_raises_the_required_epoch() {
        let alice = fresh_key();
        let (owner2, writer, reader) = (fresh_key(), fresh_key(), fresh_key());
        let group = group_id_for("share-leave");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&owner2), AuthRole::Owner)
            .unwrap();
        state
            .add_member(&alice, group, me_of(&writer), AuthRole::Writer)
            .unwrap();
        state
            .add_member(&alice, group, me_of(&reader), AuthRole::Reader)
            .unwrap();
        assert_eq!(state.required_epoch(), 1);

        for (n, leaver) in [&reader, &writer, &owner2].into_iter().enumerate() {
            // As a remote peer's op would arrive: signed on our heads.
            let op = self_remove(leaver, heads_of(&state, group), group);
            assert!(state.apply_remote(op).unwrap(), "leave {n} refused");
            assert!(!state.is_member(group, me_of(leaver)));
            assert!(state.has_left(group, me_of(leaver)));
            assert_eq!(state.required_epoch(), 2 + n as u64);
            assert!(state.uncovered_removals_are_leaves(n as u64 + 1));
        }
        assert_eq!(
            sorted_members(&state, group),
            vec![(me_of(&alice), AuthRole::Owner)]
        );
        assert!(!state.has_left(group, me_of(&alice)));

        let mut replica = AuthState::empty_for(group);
        for op in state.ops() {
            replica.apply_remote(op.clone()).unwrap();
        }
        assert_eq!(
            sorted_members(&replica, group),
            sorted_members(&state, group)
        );
        assert_eq!(replica.required_epoch(), 4);
        // Replaying an op already applied changes nothing.
        let last = state.ops().last().unwrap().clone();
        assert!(!replica.apply_remote(last).unwrap());
        assert_eq!(replica.required_epoch(), 4);
    }

    /// The local helper authors the same op and gives a clear error for
    /// the only Owner and for a non-member.
    #[test]
    fn leave_refuses_the_only_owner_and_non_members() {
        let alice = fresh_key();
        let (bob, stranger) = (fresh_key(), fresh_key());
        let group = group_id_for("share-leave-local");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        let err = state.leave(&alice, group).unwrap_err().to_string();
        assert!(err.contains("only Owner"), "{err}");
        let err = state.leave(&stranger, group).unwrap_err().to_string();
        assert!(err.contains("not a member"), "{err}");
        assert_eq!(state.required_epoch(), 1);
        state.leave(&bob, group).unwrap();
        assert!(state.has_left(group, me_of(&bob)));
        assert!(state.leave(&bob, group).is_err(), "leaving twice");
        assert_eq!(state.required_epoch(), 2);
    }

    /// p2panda-auth 0.8 itself applies the only Owner's self-removal,
    /// which leaves a share that can never rotate again; our guard refuses
    /// it, in `apply_remote` too.
    #[test]
    fn the_only_owners_self_removal_is_refused_though_the_crdt_takes_it() {
        let alice = fresh_key();
        let bob = fresh_key();
        let group = group_id_for("share-sole-owner");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Reader)
            .unwrap();
        let leave = self_remove(&alice, heads_of(&state, group), group);

        // Upstream, without our guard: the CRDT takes it.
        let mut raw = CrdtState::new();
        for op in state.ops() {
            raw = Crdt::process(raw, op).unwrap();
        }
        let raw = Crdt::process(raw, &leave).expect("0.8 accepts a self-removal");
        assert!(!raw.members(group).iter().any(|(m, _)| *m == me_of(&alice)));

        // Through AuthState: refused, nothing changes.
        let err = state.apply_remote(leave).unwrap_err();
        assert!(format!("{err:#}").contains("only Owner"), "{err:#}");
        assert!(state.is_member(group, me_of(&alice)));
        assert_eq!(state.required_epoch(), 1);
    }

    /// A stranger's self-Remove, and a revoked member's signed after its
    /// revocation, are refused. One signed before its revocation (deps
    /// that predate it) is filtered by the resolver and doesn't count.
    #[test]
    fn a_non_member_or_removed_members_self_removal_changes_nothing() {
        let alice = fresh_key();
        let (bob, stranger) = (fresh_key(), fresh_key());
        let group = group_id_for("share-leave-removed");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        let before = heads_of(&state, group);

        let err = state
            .apply_remote(self_remove(&stranger, before.clone(), group))
            .unwrap_err();
        assert!(format!("{err:#}").contains("non-member"), "{err:#}");

        state.remove_member(&alice, group, me_of(&bob)).unwrap();
        assert_eq!(state.required_epoch(), 2);
        let after = heads_of(&state, group);
        let err = state
            .apply_remote(self_remove(&bob, after, group))
            .unwrap_err();
        assert!(format!("{err:#}").contains("non-member"), "{err:#}");

        // Applied and filtered, or refused: either way it changes nothing.
        let _ = state.apply_remote(self_remove(&bob, before, group));
        assert_eq!(state.required_epoch(), 2);
        assert!(!state.is_member(group, me_of(&bob)));
        assert!(!state.uncovered_removals_are_leaves(1), "the revocation");
    }

    /// A member that signs several leaves on different heads (concurrent
    /// with one another) can't raise the required epoch by more than one:
    /// upstream leaves self-removals out of its mutual-remove graph, and
    /// each one filters the others.
    #[test]
    fn repeated_leaves_by_one_member_do_not_add_up() {
        let alice = fresh_key();
        let (bob, carol) = (fresh_key(), fresh_key());
        let group = group_id_for("share-leave-twice");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        let early = heads_of(&state, group);
        state
            .add_member(&alice, group, me_of(&carol), AuthRole::Reader)
            .unwrap();
        let late = heads_of(&state, group);
        let _ = state.apply_remote(self_remove(&bob, late, group));
        let _ = state.apply_remote(self_remove(&bob, early, group));
        assert!(state.required_epoch() <= 2, "{}", state.required_epoch());
        assert!(state.is_member(group, me_of(&carol)));
        assert!(state.is_member(group, me_of(&alice)));
    }

    /// The known gap: two Owners, each seeing the other at its deps, leave
    /// at the same time. Each op is valid on its own, so the merged share
    /// has no Owner (INTEGRATION_NOTES.md, "Members leave on their own").
    #[test]
    fn two_owners_leaving_at_once_leave_no_owner() {
        let alice = fresh_key();
        let (bob, carol) = (fresh_key(), fresh_key());
        let group = group_id_for("share-owners-leave");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Owner)
            .unwrap();
        state
            .add_member(&alice, group, me_of(&carol), AuthRole::Writer)
            .unwrap();
        let heads = heads_of(&state, group);
        state
            .apply_remote(self_remove(&alice, heads.clone(), group))
            .unwrap();
        state.apply_remote(self_remove(&bob, heads, group)).unwrap();
        assert!(!state
            .members(group)
            .iter()
            .any(|(_, r)| *r == AuthRole::Owner));
        assert_eq!(state.required_epoch(), 3);
    }

    /// A revocation followed by a leave: the newest removal is a leave,
    /// the one before it a revocation.
    #[test]
    fn uncovered_removals_are_attributed_newest_first() {
        let alice = fresh_key();
        let (bob, carol) = (fresh_key(), fresh_key());
        let group = group_id_for("share-attribution");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        assert!(!state.uncovered_removals_are_leaves(0));
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        state
            .add_member(&alice, group, me_of(&carol), AuthRole::Reader)
            .unwrap();
        state.remove_member(&alice, group, me_of(&bob)).unwrap();
        assert!(!state.uncovered_removals_are_leaves(1));
        state.leave(&carol, group).unwrap();
        assert!(state.uncovered_removals_are_leaves(1));
        assert!(!state.uncovered_removals_are_leaves(2));
        assert!(!state.uncovered_removals_are_leaves(3), "only two removals");
    }

    /// `auth.log` bytes for a fixed log. Recorded on p2panda-auth 0.5.2
    /// (CI run 45930566953) and unchanged on 0.8, so logs already on disk
    /// keep loading. Never reorder or retype `GroupControlMessage`'s fields.
    /// Ed25519 signing is deterministic and the log is linear (one head at
    /// each step), so the bytes are too. A dependency bump that changes the
    /// serialised shape of an op (and so every signature and op id) fails
    /// here instead of on users' disks.
    const GOLDEN_AUTH_LOG_HEX: &str = "048a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c00388caa2dcdd877f0bf3e0fff6d45467419de4af125c4ba46a1f6c172a951e26d0001008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c0003406d1e03f7c8eae48127727bd726c1ea64e10290dc32854859b80aec8a2ace59e6c43785b5d7fdbf56b234d76528e516f4853acfd6e4996ce80ca00945469ce50e8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c01b181280d3b841f49a5e64624586e25cb5a678a5a930fdbe3bcbfc6d9fc92ad20388caa2dcdd877f0bf3e0fff6d45467419de4af125c4ba46a1f6c172a951e26d01008139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940002405dd89445d86b3ea21f000bb0dcc4137d992dc5da2cff0969366811d7a7d6cf94d2d663a7bb76732bd7a73b75f89f800c0d72cc6655ac9635ff48eb0a8939b1018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c01abc38666cb2bb1d59987578cda04c1b266099fc99e2f4224f8edad7f22f74d72388caa2dcdd877f0bf3e0fff6d45467419de4af125c4ba46a1f6c172a951e26d0100ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1000140ce5d0e0c1dac5e1769921d0e13963c9de8219428799c8f4dfb9de204ed9c8368e5b9cce316d6eeee5017f803d36313fde269198488a347b296e3eb2fcce2a30a8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c01e5cff498627b6f92a69fc59c752a650c8f1ad8afab30214d734ba2f8d358fb39388caa2dcdd877f0bf3e0fff6d45467419de4af125c4ba46a1f6c172a951e26d02008139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39440d4cea867aeef19f89335b2b8cfca7fe07a5cb8331e02151a06d84ef7f5d5b0eb72d3ba74dad7b099eab53cad64d3568d3d9a6789175d9dc33561cb36c4bd7f03";

    #[test]
    fn golden_auth_log_is_byte_stable() {
        let key = |b: u8| SigningKey::from_bytes(&[b; 32]);
        let (alice, bob, carol) = (key(1), key(2), key(3));
        let group = group_id_for("golden-share");
        let mut state = AuthState::empty_for(group);
        state.create_group(&alice, group).unwrap();
        state
            .add_member(&alice, group, me_of(&bob), AuthRole::Writer)
            .unwrap();
        state
            .add_member(&alice, group, me_of(&carol), AuthRole::Reader)
            .unwrap();
        state.remove_member(&alice, group, me_of(&bob)).unwrap();
        let bytes = bincode::serde::encode_to_vec(&state.ops, bincode::config::standard()).unwrap();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, GOLDEN_AUTH_LOG_HEX, "auth.log encoding changed");
    }

    #[test]
    fn member_id_hex_round_trip() {
        let m = MemberId([
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        let s = m.to_hex();
        assert_eq!(s.len(), 64);
        let back = MemberId::from_hex(&s).unwrap();
        assert_eq!(back, m);
    }
}
