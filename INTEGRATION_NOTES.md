# Integration notes: librqbit 8.1 + p2panda-net 0.5.2

Verified against the crate sources in `~/.cargo/registry/src/index.crates.io-*/`
for the exact versions pinned in `Cargo.lock`.

## Encryption (Phase 4) design notes

### Threat model: wire-only
peerdup encrypts **what librqbit sees and what goes over the wire**. The
user's working copy in the share root is plaintext (apps need to read it
normally). An attacker with disk access to your share root sees plaintext
— that's an OS responsibility (LUKS / FileVault / BitLocker). An attacker
on the wire who learns the info-hash and joins the swarm sees only
ciphertext, useless without the key.

### Layout
```
<root>/file1.txt                          plaintext, user-visible
<root>/.peerdup/encrypted/file1.txt.bin   ciphertext, what librqbit sees
<data_dir>/shares/<id>/keys.bin           per-share keyring (0600)
```

### Watcher and walker filters
Because the shadow lives inside the share root, both `notify` watcher
events and `collect_files` walks must skip any path containing `.peerdup`.
Without this, peerdup's own writes to the shadow trigger watcher events
that look like local edits, and `compute_version_hash` would hash
ciphertext alongside plaintext (breaking version equality across peers).

### Ciphertext format
```
epoch(8 LE) ‖ nonce(24) ‖ ciphertext ‖ AEAD tag(16)
```
XChaCha20-Poly1305 (`chacha20poly1305` crate). Nonce is 192 bits (random
per encryption). Each blob is self-describing — the epoch tells the
receiver which key to use without out-of-band coordination.

### Keyring (`keys.bin`)
Concatenated 32-byte keys. Epoch N's key is at offset `(N-1)*32`. File
length / 32 = current epoch. Old keys are never removed; new keys are
appended. This is what makes "old content remains readable after
rotation" work — a peer that holds the keyring can decrypt any blob
encrypted under any past epoch.

### Rotation is opt-in via CLI
`peerdup share rotate-key <id>` appends a new key to `keys.bin`. Daemon
restart is required for the new key to become "current" for re-encryption.
Out-of-band keyring distribution is required so other peers can read
post-rotation content (Phase 5 will replace this with `share invite`
tickets driven by `p2panda-auth`).

### Why our `version_hash` is computed over plaintext, not ciphertext
Two peers with the same plaintext encrypt with their own random nonces,
producing different ciphertext bytes. If we hashed ciphertext, peers would
disagree about "do we have the same version?" and chase each other's
shadows forever. The plaintext is the source of truth for content
identity; ciphertext is just transport.

### Phase 4 deliverable not yet shipped: `p2panda-encryption` integration
The roadmap calls for using `p2panda-encryption` for group key derivation.
We use a randomly generated 32-byte key per share instead. Functionally
equivalent for the current wire-only threat model and decision criteria,
but it skips the integration that Phase 5's ACL-driven key rotation will
need. Deferred to a later substep (probably 4.3 or folded into Phase 5
when the rotation triggers go in).

## Deferred work

### Phase 3.5 — alternate conflict strategies (not blocking)
Phase 3.4 ships LWW as the only conflict strategy. The roadmap also calls
for **rename** ("keep both, rename one to `foo.txt.conflict-from-<peer>`")
and **pause-and-ask** ("mark conflicting and stop syncing until resolved").
Both are configurable per-share extensions of the existing
`Concurrent → lww_we_win` branch in `daemon::sync_loop`:

- **rename**: fetch remote into a staging copy, but instead of overwriting
  the conflicting files, write each conflicting file to
  `<basename>.conflict-from-<short-peer-id>.<ext>` alongside the local copy.
  Both peers do this so the rename is visible everywhere.
- **pause-and-ask**: set a per-share `paused_conflict: true` flag in
  `PersistedState`, stop both publishing and applying for that share until
  cleared via a new `peerdup share resolve <id>` subcommand.

`ShareConfig` gains `conflict_strategy: ConflictStrategy` (default `Lww`).
The Phase 3.4 LWW path stays as the default; the others are alternative
branches in the existing concurrent handler. Estimate: 1–2 days for
rename, ~1 day for pause-and-ask.

Skipped now because the Phase 3 done criterion is met by LWW alone, and
real-world conflict-strategy preferences are likely to come out of user
testing rather than upfront design.

## p2panda-auth (Phase 5c)

### Pure CRDT, no transport or persistence
`p2panda-auth` 0.5.2 is a *library* of generic types — `GroupCrdt`,
`GroupCrdtState`, `Access`, etc. — parameterised over `IdentityHandle`,
`OperationId`, `Conditions`, `Resolver`, and `Orderer` traits. It does
not sign, transport, persist, or order operations. The application must
provide:
- An identity scheme (we use raw 32-byte Ed25519 pubkeys, `MemberId`).
- An op id scheme (we use `blake3(canonical_bytes(op) || signature)`).
- Application-level signing (we Ed25519-sign the canonical
  `bincode((author, deps, payload))` with the local `identity.key`).
- Storage (we append-log signed ops to `<data_dir>/shares/<id>/auth.log`
  and replay on daemon start).
- Transport (we broadcast all known ops via gossip on every announce
  tick; receivers dedupe by op id).
- Dependency ordering (auth ops can arrive out of order via gossip; we
  buffer them in `AuthState.pending` and drain on each new arrival).

### The `Orderer` trait can be no-op
`p2panda-auth` only calls `Orderer::next_message` from `GroupCrdt::prepare`
(used by the high-level `Groups` API, e.g. `Groups::add()`). Calling
`GroupCrdt::process` directly — passing in a fully-formed operation —
never touches the orderer. peerdup constructs operations directly with
correct dependencies (= current graph heads at author time) and only
uses `process`. This means our `NoOpOrderer` can `unimplemented!()`
`next_message` safely; `queue` and `next_ready_message` are inert
no-ops.

### Group id distinct from member ids
Both group ids and member ids share the same `IdentityHandle` type
(`MemberId([u8; 32])`). We derive the group id as
`blake3("peerdup-group/" || share_id)` so it's globally unique *and*
provably can't collide with any 32-byte Ed25519 pubkey (different
preimage space).

### Ticket carries the full auth-log snapshot
`share-invite` runs `Add(invitee)` *before* generating the ticket and
embeds the entire current op log. The receiver replays it via
`AuthState::apply_remote` (signature-verified), then verifies that its
own pubkey appears as a member; otherwise the join is refused. This
matches how the keyring is bootstrapped — the ticket is the complete
"everything you need to join" payload. Tradeoff: ticket size grows with
membership-op count, but those are bounded (membership churn is small
compared to data ops).

### Two parallel notions of peer identity
Vector clocks (`PersistedState.clock`) key on the **hex string** of the
public key (set up that way in Phase 3 before auth existed). Auth keys
on the **raw 32-byte** representation (`MemberId([u8; 32])`). Both
derive from the same `identity.key`; helpers in `auth.rs`
(`MemberId::from_hex`, `MemberId::to_hex`) bridge the two when needed.
Could be unified later but unification touches `clock.rs` and
`share_state.rs` everywhere they hold a peer id, so we deferred it.

### Ticket format is now v2; v1 is rejected
`Ticket.version` was bumped from 1 to 2 to add `auth_log` and
`invitee_pubkey`. There is no migration path — v1 tickets fail to
decode. Acceptable because no shipped builds had real users yet.

## Phase 5d key distribution

### KEM choice: `crypto_box` sealed-box construction
Phase 5d distributes a freshly-rotated 32-byte share key to remaining members
by sealing it once per recipient with `crypto_box` (`SalsaBox` =
X25519 ECDH + XSalsa20-Poly1305). Each envelope carries a fresh
ephemeral X25519 public key, a 24-byte nonce, and the 32-byte AEAD
ciphertext + tag. The whole bundle (epoch + author + envelopes) is
Ed25519-signed by the rotator using the same `identity.key` that drives
the rest of peerdup's signing.

The recipient's static X25519 public key is derived from their Ed25519
identity via the standard `to_montgomery()` conversion (private side:
`ed25519_dalek::SigningKey::to_scalar_bytes()`). This reuses the
existing identity for KEM rather than introducing a separate X25519
identity.

**Tradeoff:** the same long-term key signs and decrypts. The Ed25519
spec community generally prefers separate keys for signing vs. key
agreement (see "On using the same key pair for Ed25519 and an X25519
based KEM," Brendel et al. 2021). For peerdup v1 we accept this — the
alternative (a separate X25519 pubkey on every ticket and gossip
announce) doubles identity-management surface for marginal benefit
given the rest of the threat model. Tracked as a possible later
hardening.

### Wire format
On the wire, a rotation rides as `ShareMsg::KeyRotation(SignedRotation)`:

```rust
struct SignedRotation {
    epoch: u64,
    rotator_pubkey: MemberId,        // raw Ed25519 32 bytes
    signature: [u8; 64],             // Ed25519 over canonical bytes below
    envelopes: Vec<KeyEnvelope>,
}
struct KeyEnvelope {
    recipient_pubkey: MemberId,
    ephemeral_pubkey: [u8; 32],      // X25519
    nonce: [u8; 24],                 // XSalsa20
    ciphertext: Vec<u8>,             // 32 + 16 = 48 bytes (key + AEAD tag)
}
```

Canonical bytes signed = `bincode((epoch, rotator_pubkey, envelopes))`
with `bincode::config::standard()`. Field tuple ordering is part of the
protocol — re-ordering invalidates every old signature.

### Manager-at-receive-vantage looseness
The receiver checks "rotator is currently an Owner" against *its* local
auth state at the time of receiving the rotation. If a rotator was
demoted between authoring the rotation and the receiver applying that
demotion, it would still be accepted; conversely, a rotation
authored before a demotion may be rejected if the demotion has already
propagated. This is acceptable for v1: revocation cascades are rare
and a rejected rotation is safe (it's just discarded), and the
alternative (track each rotation's "auth-state-at-author-time") would
require carrying an extra dependency vector on every rotation.

### On-disk: `pending_rotations/`
The CLI's `share-revoke` writes a per-rotation file at
`<data_dir>/shares/<id>/pending_rotations/<epoch>.bin` (atomic
tmp+rename, 0600 on Unix). The daemon loads all such files at start and
re-broadcasts each one on every announce tick until the operator
manually clears them. There's no automatic GC yet — a rotation
recipient who has come back online and installed the new epoch
will simply reply with `Idempotent` to subsequent re-broadcasts.

### Receiver buffering for out-of-order epochs
Rotations may arrive out of order (rare in practice; possible if two
managers rotate concurrently or a rotator broadcasts faster than gossip
propagates a previous one). Receivers maintain a per-share in-memory
`rotation_buffer: Vec<SignedRotation>` capped at 64 entries
(`ROTATION_BUFFER_CAP` in `daemon.rs`); arrivals whose `epoch >
current_epoch + 1` get queued and re-tried in epoch order each time a
new rotation slots in. Cap-overflow drops the oldest. The buffer is
ephemeral (in-memory only); a daemon restart re-loads it from disk
queue + lossy gossip catch-up.

## Things that look wrong but aren't

Three things in `src/main.rs` are deliberate and should not be "fixed" without
reading the linked rationale below.

### `disable_dht: true` in `SessionOptions`
Looks like we crippled BitTorrent's peer discovery. We didn't — for this demo
the leecher gets the seeder's address out of the gossip announcement and
passes it via `AddTorrentOptions.initial_peers`, so DHT is unused. The reason
to disable it is that librqbit persists its DHT UDP port to disk and re-uses
it on next start; running seed and leech on the same machine then collides
on that port and the second process fails to bind. See "librqbit DHT port
collision" below.

### Session output folder is the seed source folder itself
Looks like a typo — surely the output folder should be the *parent* of the
source, so librqbit places files at `<parent>/<torrent_name>/...`. Not for
single-file torrents: librqbit only auto-appends the torrent name as a
subfolder when there are 2+ files (`session.rs:997-999`). For our 1-file
demo, librqbit looks for `<output_folder>/<filename>` directly, so the
output folder *must* be the directory containing the file. See "Single-file
vs multi-file torrents" below.

### No `Arc::new(...)` around `Session::new(...).await?`
Looks like we forgot to wrap the session for sharing. We didn't — `Session::new`
already returns `Arc<Session>`, and `add_torrent` is defined on `&Arc<Self>`.
Wrapping it again gives `Arc<Arc<Session>>` and the call won't typecheck.
See "Session" below.

## librqbit

### `create_torrent`
- Lives in `librqbit::create_torrent_file` and is **re-exported from the crate
  root** (`librqbit/src/lib.rs` line 79: `pub use create_torrent_file::{create_torrent, CreateTorrentOptions};`).
  `use librqbit::create_torrent;` works.
- Signature:
  ```rust
  pub async fn create_torrent<'a>(
      path: &'a Path,
      options: CreateTorrentOptions<'a>,
  ) -> anyhow::Result<CreateTorrentResult>
  ```

### `CreateTorrentResult`
- `info_hash() -> Id20` (`Id20` is `Id<20>` from `librqbit_core::hash_id`).
- `as_bytes() -> anyhow::Result<Bytes>` returns the bencoded torrent file.
- `as_info() -> &TorrentMetaV1Owned`.

### `Id20`
- **Does NOT implement `Display`.** Use `info_hash.as_string()` to get the
  40-char hex string. Tuple access `info_hash.0` works but is fragile and
  emits raw bytes via `Debug`, not hex.

### `Session`
- `Session::new(default_output_folder)` returns `BoxFuture<Result<Arc<Self>>>`
  — i.e. **`Session::new(...).await?` already gives you `Arc<Session>`.**
  Wrapping it in `Arc::new(...)` again is a type error.
- `Session::new_with_opts(folder, SessionOptions { ... })` for custom config.
- `add_torrent` is defined on `&Arc<Self>`:
  ```rust
  pub fn add_torrent<'a>(
      self: &'a Arc<Self>,
      add: AddTorrent<'a>,
      opts: Option<AddTorrentOptions>,
  ) -> BoxFuture<'a, anyhow::Result<AddTorrentResponse>>
  ```
- `tcp_listen_port(&self) -> Option<u16>`. Critically, this returns `None`
  unless `SessionOptions.listen_port_range` was set at construction time.
  `Session::new` (default) does **not** bind a TCP listener at all. For the
  seed/leech demo you must use `Session::new_with_opts` with
  `listen_port_range: Some(port..port + 1)`.

### `SessionOptions`
- `listen_port_range: Option<std::ops::Range<u16>>` — half-open range, e.g.
  `41000..41001` to bind exactly one port.
- `disable_dht: bool`, `enable_upnp_port_forwarding: bool`, `peer_id`, etc.

### `AddTorrent`
- Two constructors: `AddTorrent::from_bytes(impl Into<Bytes>)` and
  `AddTorrent::from_url(impl Into<Cow<'a, str>>)`. The latter accepts a magnet
  URI.

### `AddTorrentOptions`
- `Default` impl exists.
- **Peer injection happens here, not via a method on the handle.** Set
  `initial_peers: Option<Vec<SocketAddr>>` at add time. There is no public
  `add_peer` / `add_peers` / `connect_to_peer` on `ManagedTorrent` or its
  handle in 8.1 — the only public path to inject peers is at `add_torrent`
  time.
- For overwriting a previously-downloaded file (or one that exists in the
  output dir), set `overwrite: true`.

### Torrent immutability (Phase 3 prep)
librqbit has **no public API for mutating an existing torrent's content.**
The only public mutation methods on `Session` are:

- `pause(&handle)` / `unpause(&handle)` — lifecycle, not content
- `update_only_files(...)` — change which files are downloaded; content fixed
- `delete(id, delete_files: bool)` — remove from session
- `stop()` — stop the whole session

There is no `add_file`, `update_torrent`, or "patch piece" API. This is by
design: a BitTorrent info-hash is a SHA1 over the metadata (file paths +
piece hashes), so any content change implies a new info-hash. Phase 3's
multi-master sync will need to **call `create_torrent` again on every
content change** and announce the new info-hash — there is no in-place
update path.

`AddTorrentResponse::AlreadyManaged` is returned when re-adding an
info-hash the session has already seen. So idempotent re-adds
(after restart, or after a no-op rewrite) are cheap and safe — useful
for Phase 3's "re-create torrent on watcher event" loop, where many
debounced events may resolve to the same info-hash.

### Reading a torrent's file manifest (3.4 orphan deletion)
After `add_torrent` and `wait_until_completed`, the file list is reachable via:
```rust
let manifest: BTreeSet<PathBuf> = handle
    .with_metadata(|md| {
        md.file_infos.iter().map(|fi| fi.relative_filename.clone()).collect()
    })?;
```
`with_metadata` is on `ManagedTorrentHandle`; `TorrentMetadata.file_infos`
is `Vec<FileInfo>`; `FileInfo.relative_filename` is the per-file path from
the share root. Returns an error if metadata isn't resolved yet — for
magnet adds this means after at least `wait_until_initialized()`.

Phase 3.4 uses this to compute the new manifest at apply time. Orphans
are computed as `old_manifest.difference(&new_manifest)` (set difference)
so files the user added between snapshots — which aren't in the old
manifest — are preserved through a concurrent apply.

### LWW conflict resolution: timestamp source
Phase 3.4's LWW uses `Utc::now()` at the moment the daemon **notices** a
local change (either the watcher debounce fires, or restart reconciliation
detects out-of-band edits). It does *not* read the file's mtime.

This is good enough for the 3.4 done criterion but two known weaknesses:

1. **Out-of-band edits get a "noticed" timestamp.** Edits made while the
   daemon is offline take their timestamp from when the daemon next starts,
   not from when the user actually edited. Two peers that both had edits
   while down, then start, will rank by daemon-start order, not edit order.
2. **Wall-clock skew between peers.** Standard LWW caveat. If peer A's
   clock is fast, A wins more conflicts than it deserves.

Tiebreak on equal timestamps: lexicographically larger `version_hash`
wins. Deterministic — both peers compute the same answer without any
extra coordination. (We considered tiebreak by `peer_id` but `version_hash`
avoids needing to put the peer id in announces.)

### librqbit's `create_torrent` info-hash is **not** content-deterministic
`librqbit::create_torrent` uses `walkdir::WalkDir::new(...)` without sorting,
so the file order in the resulting torrent metadata depends on filesystem
dir-entry order. Two peers with byte-identical content can compute different
info-hashes (verified empirically: peer A's tmpfs returned `[file2, file1]`,
peer B's returned `[file1, file2]`, yielding different info-hashes despite
identical content).

This breaks any "peer A and peer B agree on what version they have" check
that uses info-hash directly. Phase 3 sidesteps this by carrying a
peerdup-side `version_hash` (`blake3` over sorted `(rel_path, blake3(content))`
pairs) in announces; info-hash is used only as the BitTorrent magnet for
fetching the bytes. Two peers with identical content always compute the
same `version_hash`, even if their librqbit info-hashes differ.

If `create_torrent`'s file order ever needs to be deterministic at the
librqbit level, the fix is upstream — sort the `walkdir` iterator before
building file entries — or fork the function locally. Not needed for
Phase 3.

### Built-in folder watcher (`librqbit::watch`)
librqbit has a `watch.rs` module that watches a folder for **`.torrent`
and `.magnet` files** to be dropped in, then auto-imports them. It is
*not* a content watcher; it does not help Phase 3's "watch the share
folder for content changes." Phase 3 will need its own watcher built on
the `notify` crate (which librqbit pulls in transitively, so it's already
in the dep graph).

### State observation: notify-based, with polling fallback
For Phase 7's D-Bus signals that need real-time per-torrent state events:

- `ManagedTorrentHandle::stats() -> TorrentStats` is the polling-based API.
  Returns state (`Initializing | Paused | Live | Error | None`),
  `progress_bytes`, `uploaded_bytes`, `finished`, per-file progress.
- `wait_until_initialized()` and `wait_until_completed()` are
  one-shot transition awaits. Both are `BoxFuture<Result<()>>`.
- The internal `state_change_notify: tokio::sync::Notify` exists on each
  `ManagedTorrent` but is `pub(crate)` — not externally accessible. Even
  librqbit's own `wait_until_*` implementations have a `// TODO: rewrite,
  this polling is horrible` comment, polling at 1Hz with the Notify as a
  hint.
- There is **no public broadcast channel** for state changes. Options
  for Phase 7:
  1. Poll `stats()` from peerdup at e.g. 1Hz per active share, emit our
     own events. Simple; adds latency proportional to poll period.
  2. Spawn one task per share that awaits `wait_until_*` for the specific
     transitions we care about, forwards them to a peerdup broadcast.
     Loses intermediate progress but catches the named transitions.
  3. Upstream PR to librqbit exposing a real event channel. Cleanest;
     coordinate with ikatson during Phase 4–5 if it becomes important.

### Resume across restarts (verified)
Adding the same torrent again against an output folder that already contains
the matching files is the resume path. librqbit's `initial_checksum_validation`
(`torrent_state::initializing`) hashes the existing on-disk content against
the torrent's piece hashes; matching pieces are reported as "have", missing
pieces as "needed". On a clean re-add of fully-downloaded content the log
line is `Initial check results: have 14, needed 0, total selected 14` and
`wait_until_completed` fires immediately with no bytes over the wire.

Implication for the daemon: peerdup does **not** need its own state tracker
for resume. The daemon's per-share state on disk only needs to hold the
ShareConfig (topic, root_path, role); on restart the daemon re-runs
`create_torrent` (for seed) or re-`add_torrent` from the cached magnet (for
leech) and librqbit verifies the existing files in-place. We have not yet
tested partial-download resume mid-transfer; that's a separate verification
when it becomes load-bearing.

This means we don't need `SessionPersistenceConfig` either, at least for
Phase 2.

### `AddTorrentResponse` / `ManagedTorrentHandle`
- `add_torrent(...).await?.into_handle()` returns `Option<ManagedTorrentHandle>`.
  Returns `None` for list-only adds; otherwise `Some(handle)`.
- Useful methods on the handle: `info_hash() -> Id20`, `stats() -> TorrentStats`,
  `wait_until_initialized()`, `wait_until_completed()`. The completion future
  has signature `pub fn wait_until_completed(&self) -> BoxFuture<'_, anyhow::Result<()>>`
  so it must be awaited and `?`'d.

## p2panda-net

### `Gossip` (the actor handle returned from `Gossip::builder(...).spawn().await?`)
- The `Gossip` handle itself does **not** have `publish` or `subscribe`. Its
  only relevant public method is:
  ```rust
  pub async fn stream(&self, topic: TopicId) -> Result<GossipHandle, GossipError>
  ```
- `events() -> broadcast::Receiver<GossipEvent>` exists for cross-topic events
  but is not what you want for sending or receiving messages.
- **`Gossip` derives `Clone`.** Internally it's `Arc<RwLock<Inner>>` for the
  actor reference plus an `Arc<RwLock<GossipSenders>>` for per-topic senders;
  cloning is cheap. Hand clones to per-share tasks freely. The actor lives as
  long as at least one `Gossip` clone is alive — drop them all and existing
  `GossipHandle`s and `GossipSubscription`s start failing.

### `GossipHandle` (returned from `gossip.stream(topic).await?`)
- `publish(bytes: impl Into<Vec<u8>>) -> Result<(), mpsc::error::SendError<Vec<u8>>>`
  — publishes one message to the topic.
- `subscribe(&self) -> GossipSubscription` — returns a fresh receiver.
  Synchronous; no `.await`.
- `topic(&self) -> TopicId`.
- Holding the handle keeps the topic subscription alive (via an internal drop
  guard); drop it and the topic is torn down.

### `GossipSubscription`
- Implements `Stream<Item = Result<Vec<u8>, BroadcastStreamRecvError>>`. The
  payload is **already `Vec<u8>`** — there is no `.payload()` accessor and no
  wrapper struct. Iterate with `futures_util::StreamExt::next`.
- The `Err` variant signals broadcast lag; treat as recoverable.

### `PrivateKey` (`p2panda_core::identity::PrivateKey`)
- Constants live in the same module:
  `PRIVATE_KEY_LEN = 32`, `PUBLIC_KEY_LEN = 32`, `SIGNATURE_LEN = 64`.
- Construction:
  - `PrivateKey::new()` — generates from `OsRng`.
  - `PrivateKey::from_bytes(&[u8; 32]) -> Self` — **infallible**, takes a
    fixed-size array reference (not a slice).
  - `impl From<[u8; 32]>` and `impl From<&[u8; 32]>` exist.
  - `impl TryFrom<&[u8]> for PrivateKey` exists for slice input that needs
    length validation.
- Serialization:
  - `as_bytes(&self) -> &[u8; 32]` — borrowed reference to raw bytes.
  - `to_hex(&self) -> String` — 64-char hex string.
- `PrivateKey` derives `Clone` and is also `Default` (calls `new()`).
- For on-disk persistence, the round-trip is:
  ```rust
  // write
  std::fs::write(path, key.as_bytes())?;
  // read
  let bytes: [u8; PRIVATE_KEY_LEN] = std::fs::read(path)?
      .try_into()
      .map_err(|v: Vec<u8>| anyhow!("identity key wrong length: {}", v.len()))?;
  let key = PrivateKey::from_bytes(&bytes);
  ```
  Set 0600 perms via `std::fs::set_permissions(path, Permissions::from_mode(0o600))`
  on Unix after writing.

## Application-level gotchas

### Announce a reachable address
The previous handoff flagged this. `0.0.0.0` is a wildcard *bind* address;
peers cannot connect to it. For one-machine testing, announce `127.0.0.1`.
For LAN testing, enumerate non-loopback IPv4 interfaces (e.g. via
`local-ip-address`) and announce all of them.

### Two-instance port handling on one machine
Mandatory because `Session::new` doesn't bind a TCP listener at all and
`Session::new_with_opts(..., listen_port_range: Some(p..p+1))` binds exactly
the given port. If two instances on one machine are configured for the same
port, the second one fails to bind. The CLI exposes `--bt-port` to make this
explicit.

### Gossip subscription must be live before publishes are seen
`GossipSubscription` is a `tokio::sync::broadcast` receiver under the hood.
Publishes that happen before the leecher subscribes are not buffered.
Mitigation: the seeder publishes the announce on a 10-second loop, so a
late-joining leecher catches the next tick.

### librqbit DHT port collision on one machine
Default `SessionOptions` runs the DHT and persists its UDP port to disk
(`~/.local/share/librqbit/dht.json`). Two instances on one machine pick the
same port from the persisted state and the second one fails to bind:
`error binding socket, address 0.0.0.0:35525 / Address already in use`.
For the LAN/initial-peers demo, set `disable_dht: true` in `SessionOptions`.
For real-world use across machines, leave DHT on.

### Single-file vs multi-file torrents change the on-disk layout
`Session.add_torrent` resolves the on-disk root differently depending on
file count (`session.rs:988-999`):

- Multi-file torrent (≥ 2 files): the resolved root is
  `default_output_folder / <torrent_name>`. The torrent name is auto-appended
  as a subfolder.
- Single-file torrent (= 1 file): the subfolder is **not** added. The file
  lands directly under `default_output_folder`.

For seeding, this means: if `create_torrent` is called on a directory
containing a single file (e.g. `fixtures/test/hello.txt`), the seeder's
`default_output_folder` must be set to the **inner directory** (the one
holding the file, `fixtures/test`), not its parent. The naive
"output_folder = parent of source" works for multi-file torrents but
silently fails the initial checksum on single-file ones — librqbit looks
for `<parent>/<filename>` and finds nothing, then advertises the torrent as
"have 0".

The current seed implementation canonicalizes the source folder and uses it
directly as the session's default output folder, which works for both file
counts.
