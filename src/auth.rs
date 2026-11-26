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
use p2panda_auth::group::{
    GroupAction, GroupControlMessage, GroupCrdt, GroupCrdtState, GroupMember,
};
use p2panda_auth::traits::{IdentityHandle, Operation, OperationId, Orderer};
use p2panda_auth::{Access, AccessLevel};
use p2panda_core::{Signature, SigningKey, VerifyingKey};

/// Ed25519 signature length. p2panda-core 0.8 no longer exports it.
pub const SIGNATURE_LEN: usize = 64;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::Infallible;
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

impl IdentityHandle for MemberId {}

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

impl OperationId for OpId {}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedOp {
    pub author: MemberId,
    pub deps: Vec<OpId>,
    pub payload: GroupControlMessage<MemberId, ()>,
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
        let (op, _): (Self, _) =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard())
                .context("decoding signed op")?;
        Ok(op)
    }
}

impl Operation<MemberId, OpId, GroupControlMessage<MemberId, ()>> for SignedOp {
    fn id(&self) -> OpId {
        self.compute_id()
    }
    fn author(&self) -> MemberId {
        self.author
    }
    fn dependencies(&self) -> Vec<OpId> {
        self.deps.clone()
    }
    fn payload(&self) -> GroupControlMessage<MemberId, ()> {
        self.payload.clone()
    }
}

/// We construct operations directly (signed at the application layer) and
/// only use `GroupCrdt::process`, never `GroupCrdt::prepare` or the
/// high-level `Groups` API. So the orderer's `next_message` hook is never
/// called; the other two methods are stubbed to be inert.
#[derive(Debug, Default, Clone)]
pub struct NoOpOrderer;

impl Orderer<MemberId, OpId, GroupControlMessage<MemberId, ()>> for NoOpOrderer {
    type State = ();
    type Operation = SignedOp;
    type Error = Infallible;

    fn next_message(
        _y: Self::State,
        _payload: &GroupControlMessage<MemberId, ()>,
    ) -> Result<(Self::State, Self::Operation), Self::Error> {
        unreachable!("peerdup constructs auth ops directly via AuthState::*")
    }

    fn queue(y: Self::State, _msg: &Self::Operation) -> Result<Self::State, Self::Error> {
        Ok(y)
    }

    fn next_ready_message(
        y: Self::State,
    ) -> Result<(Self::State, Option<Self::Operation>), Self::Error> {
        Ok((y, None))
    }
}

/// Cap on ops buffered while their dependencies are missing.
const MAX_PENDING_OPS: usize = 256;

type Resolver = StrongRemove<MemberId, OpId, (), SignedOp>;
type Crdt = GroupCrdt<MemberId, OpId, (), Resolver, NoOpOrderer>;
type CrdtState = GroupCrdtState<MemberId, OpId, (), NoOpOrderer>;

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
            crdt: CrdtState::new(()),
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

    /// Construct, sign, and apply a locally-authored op.
    fn author(
        &mut self,
        my_key: &SigningKey,
        group_id: MemberId,
        action: GroupAction<MemberId, ()>,
    ) -> Result<SignedOp> {
        let me = MemberId(*my_key.verifying_key().as_bytes());
        let deps: Vec<OpId> = self.crdt.inner.heads().into_iter().collect();
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
        let prev = std::mem::replace(&mut self.crdt, CrdtState::new(()));
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

    fn rebuild_from_log(&mut self) -> Result<()> {
        let mut crdt = CrdtState::new(());
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
    let (ops, _): (Vec<SignedOp>, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
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
            let heads: Vec<OpId> = state.crdt.inner.heads().into_iter().collect();
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
