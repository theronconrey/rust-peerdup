# Integration notes: p2panda-net 0.8 + iroh-blobs 0.105

Notes on non-obvious crate behavior and load-bearing design choices. The
sections on librqbit (marked *history*) describe the transport this project
used until the move to iroh-blobs; they stay for context.

## Transport: iroh-blobs (ROADMAP phase 6a decision)

**Decision.** File contents move as content-addressed blobs with
`iroh-blobs` over the same iroh endpoint p2panda-net runs on, replacing
librqbit. Chosen over keeping librqbit (and fixing its announced
`127.0.0.1` endpoints, its open swarm and its file-name leak) and over
tunnelling BitTorrent through iroh. A research pass found the project used
almost none of BitTorrent: DHT off, no trackers, no UPnP, one known peer.

**Design** (`src/transfer.rs`):
- One iroh-blobs `FsStore` per daemon at `<data_dir>/blobs`, served with
  `BlobsProtocol` through `p2panda_net::Endpoint::accept(iroh_blobs::ALPN, ..)`.
  Fetches open a connection with `Endpoint::connect(node_id, ALPN)` and
  run `store.remote().fetch(conn, hash)`, which only requests what isn't
  local yet.
- A version = one ciphertext blob per file (`crypto::encrypt`, epoch header
  included) plus one encrypted JSON manifest of `(path, plaintext blake3,
  blob hash)`. Gossip (`share_announce_v3`, signed; see "Signed
  announces") carries the manifest hash, the
  provider's node id (= identity key hex; p2panda's `NodeId` is
  `VerifyingKey`), the version hash, clock and timestamp.
- Receive: connect (30 s timeout), fetch the manifest, decrypt, validate
  it (`validate_manifest`: at most 100,000 entries and 4,096 bytes a
  path, no duplicates, no path that is both a file and a directory of
  another, nothing absolute or with `..` or `.peerdup`), check it against
  the announced version hash, then fetch (300 s timeout per blob),
  decrypt and blake3-check each file and stage it as `*.peerdup-tmp` beside
  its destination. Only when everything passes are the files renamed in
  and orphans deleted.
- Size limits, checked before transfer: the provider must prove a blob's
  size (`iroh_blobs::get::request::get_verified_size` checks the last
  chunk against the hash; a blob already complete in our store uses
  `BlobStatus::Complete { size }`). A manifest over 16 MiB or a file blob
  over 1 GiB (`MAX_BLOB_BYTES`) is refused: a whole file is held in memory
  twice while it is decrypted and checked (and while encrypted on the
  sender) until encryption streams.
- Staging never writes through a symlinked directory: every directory
  between the root and the file is checked with `symlink_metadata` (and
  made if missing), at staging and again at commit. Temp files are
  created with `create_new`.
- `StagedVersion` removes its uncommitted temp files on drop, so every
  error path, the per-version timeout and an aborted fetch task clean up.
- The fetch runs off the share's select loop (`daemon::start_fetch`): a
  spawned task with a copy of the keyring (a read lock held across the
  fetch would block a rotation's write lock, and with it the loop),
  bounded by a one-hour limit per version. At most one per share; the
  newest announce that arrives meanwhile waits in `next`. The result
  comes back on a channel tagged with a generation; the loop judges the
  version again against the state it has *now* (a local edit or another
  version may have landed) and only then commits on the loop. Cache
  updates travel with the staged version and are applied there, since
  the loop owns the `BlobCache`. `tests/e2e-sync.sh` stalls the provider
  with SIGSTOP mid-fetch and checks a local edit is still noticed.
- `BlobCache` (`shares/<id>/blobs.json`) maps `path -> (plaintext hash,
  blob hash, epoch)`. Unchanged files reuse their ciphertext, so their blob
  hash is stable and receivers fetch nothing for them. Receivers record
  what they fetched too, so a re-announce of the same version is free.
- The store is a cache: on start every share republishes from its
  plaintext. It is shut down cleanly on exit (`Transfer::shutdown`), since
  an unflushed store can lose its last writes.

**Pinned:** `iroh-blobs = "=0.105.0"`. Upstream says this line is not yet
production quality, and its suggested production version (0.35) needs a
pre-1.0 iroh that can't talk to the iroh 1.x p2panda-net 0.8 runs on.

**Reaching other networks** (`src/bootstrap.rs`): p2panda-net's
`Endpoint::connect` only uses its address book (no DNS fallback; unknown
nodes fail with `TransportInfoMissing`), and its iroh endpoint runs
`RelayMode::Custom` with only the relays it was given, so by default none.
So: `serve` passes relays (n0's public ones unless `--relay-url`/
`--no-relay`); the daemon writes its own `EndpointAddr` to
`<data_dir>/endpoint.json` once online; ticket v3 carries it and the
joiner keeps it as `shares/<id>/bootstrap.json`; on share start the
bootstrap goes into the address book (`NodeInfo::from(addr).bootstrap()`)
and every member is `add_topic`ed. `tests/e2e-xnet.sh` checks two
containers on isolated Docker networks sync (CI). p2panda also mixes the
network id into every ALPN, so blobs must go through p2panda's
`accept`/`connect`, not iroh-blobs' own downloader.

**Known gaps (next steps):**
- Members-only connections (done, `src/access.rs`): the endpoint runs
  p2panda-net's `ConnectionBlockList` in restrictive mode. Allowed = the
  union of every running share's members; recomputed at share start,
  after auth ops apply, after invite/revoke, and when a share stops.
  Blocked nodes are refused after the TLS handshake with code 403 for
  every ALPN, so a revoked member can't open a new connection for blobs
  or gossip. **`ConnectionBlockList::block` only affects new
  connections**: one the revoked node already has open stays up until it
  closes (idle timeout, restart, network change), and it can keep
  fetching blobs and receiving gossip over it until then. What it gets
  is ciphertext; after the rotation it can't decrypt new versions, and
  its announces are refused because it is no longer a Writer. Closing
  live connections on revocation is still to do. `allow()` lifts a
  block, so re-inviting works. Not yet per share: a
  member of share A could fetch share B's blobs if it learned their
  hashes (they are ciphertext under B's key).
- Relays: the default is n0's public relays (rate-limited, meant for
  development); bulk data goes through them when hole-punching fails.
  `--relay-url` is there; consider shipping a self-hosted `iroh-relay`
  (a Copr subpackage). p2panda-net's endpoint uses iroh's minimal preset
  with its own address-book lookup (per its source), so it shouldn't
  publish to n0's DNS; confirm with a capture (spike check 8).
- Invites made in direct mode use the address the daemon last wrote; if
  the daemon has never run, the ticket has none and the joiner can only
  find the inviter on the same LAN.

**Spike checklist** (pass/fail, from the research pass):
1. Cross-network: two hosts behind different NATs sync 1 GiB; direct path
   when possible; relay fallback with UDP blocked. *Two containers on
   isolated networks sync through a relay in CI (`tests/e2e-xnet.sh`);
   real NATs, 1 GiB and the UDP-blocked case are still to measure.*
2. Revocation: a removed node's fetch is refused. *Done:
   `tests/e2e-revoke.sh` (in CI) checks a revoked Writer gets no new
   files and its edits don't reach the Owner, and that a Reader's edits
   never leave its machine.*
3. Crash/resume: `kill -9` a receiver mid-fetch of a 2 GiB file and
   restart; measure how much is re-fetched (iroh-blobs #254).
4. Store durability: 500 change cycles, kill, restart; no panic or
   deadlock (#233, #252, #260); RSS flat (#266); disk bounded with GC off.
5. Dedup: change one file in a 1,000-file share; bytes on the wire are
   about that file. *Designed for (`BlobCache`); not yet measured.*
6. Multi-provider: kill the active provider mid-transfer; the fetch
   completes from another. *Today a fetch uses only the announcing
   provider; failover is future work.*
7. Packaging: RPM builds and passes rpmlint and the smoke test on
   `fedora:latest`; no OpenSSL; `License:` recomputed. *OpenSSL, native-tls,
   aws-lc-sys and librqbit are gone from `Cargo.lock`.*
8. Defaults audit: what does the daemon contact with no configuration
   (n0 relays, DNS)?
9. Version skew: can a node on the next iroh-blobs release fetch from
   0.105? Decide an ALPN versioning policy.
- Done: two daemons on one network sync initial content, an edit back, a
  new nested file and a deletion (`tests/e2e-sync.sh`, in CI against the
  installed RPM).

## Signed announces (`src/announce.rs`)

A version announce (`share_announce_v3`) is signed with the sender's
identity key over a domain tag, the share's group id, the manifest hash,
the provider, the version hash, the clock and the timestamp. Receivers
apply it only if the signature verifies and the signer is a current Writer
or Owner in their own auth state; Readers' and non-members' announces are
dropped with a warning, as are clocks with more than 1,024 entries. A
Reader's daemon still records its local edits but doesn't announce them
(it logs that), and the next newer version from a Writer replaces them.
Unsigned announces (`share_announce_v2`, `share_announce`) are ignored.

Bounds checked before the signature (`Announce::verify`):
- at most 1,024 clock entries;
- every clock key is a peer id, 64 lowercase hex characters;
- every clock value is at most 2^40 (`MAX_CLOCK_VALUE`).
  `VectorClock::increment` saturates, so before this bound a Writer
  could send `u64::MAX` and every later version, ours included, would
  compare `Equal` with it: the share froze for good;
- the timestamp is at most 10 minutes ahead of our clock
  (`MAX_CLOCK_SKEW_MINUTES`). A later timestamp always wins
  last-writer-wins, so an unbounded one would win every conflict.
  Peers whose clocks are more than 10 minutes apart see the faster one's
  announces refused until the slower clock catches up; keep NTP on.

Each send also carries a random `nonce` outside the signature. Gossip drops
repeated messages, and Ed25519 signatures are deterministic, so without it
the 10-second re-announces of one version are byte-identical and only the
first is delivered; a receiver whose fetch failed then never retries.
`tests/e2e-revoke.sh` caught exactly that: a Reader got the post-revocation
announce a second before the rotated key, failed to decrypt, and never saw
the version again.

## Gossip message size and wire format v4

p2panda-net 0.8.1's gossip has `DEFAULT_MAX_MESSAGE_SIZE = 4096`
(`GossipConfig::default()` uses it), and `GossipHandle::publish` returns
`GossipPublishError::MessageTooLarge` above it. The daemon only logged
that. Before v4 the envelope was JSON, which writes a bincode-encoded
auth op as an array of numbers, about 700 bytes an op, so `AuthOps`
(the whole log, every 10 s) failed past about five ops and a
`KeyRotation` past about seven members. Beyond the smallest shares,
members other than the inviter never heard of later Adds or Removes, or
of rotated keys.

Now (`src/wire.rs`):
- Gossip runs with `GossipConfig { max_message_size: 64 * 1024, .. }`
  (`wire::MAX_GOSSIP_MESSAGE`). **Every peer on a topic must use the same
  limit**: a peer with a smaller one can't receive the larger messages.
  There is no release yet, so no mixed versions to support.
- Every message is `bincode((v = 4, nonce, ShareMsg))`, standard config,
  decoded with `with_limit::<{ 64 * 1024 }>()`. `ShareMsg` is externally
  tagged (bincode can't decode serde's internally tagged enums). The
  first byte is the version: a v4 peer drops anything else, including the
  old JSON (`{`); an old peer fails to parse v4 as JSON and drops it.
- The random `nonce` makes every send unique. Gossip drops repeats, and
  the periodic re-broadcasts of the auth log and pending rotations would
  otherwise be byte-identical (the same problem the announce nonce
  fixed).
- Auth ops travel as raw `SignedOp::encode` bytes (about 200 bytes each),
  split into messages of at most 48 KiB (`wire::CHUNK_BUDGET`). Each op
  verifies on its own, and `AuthState`'s pending buffer (256 ops) puts
  out-of-order chunks back in order.
- A rotation is split into signed chunks of at most 256 envelopes
  (`rotation::ENVELOPES_PER_CHUNK`, about 35 KiB). `install_epoch_key` is
  idempotent (the same key for the current epoch is `Idempotent`), chunks
  without our envelope are `NotForUs`, and only the chunk with our
  envelope can be buffered, so the buffer dedups by signature.

`wire.rs` tests that 300 auth ops and 200 envelopes fit after chunking,
and that each chunk decodes and verifies; `tests/e2e-revoke.sh` runs a
share whose auth log is well over 4 KiB and fails on any publish error
in a daemon log.

## p2panda 0.8 (core, net) with p2panda-auth 0.5

p2panda-net 0.8 runs on iroh 1.x, which iroh-blobs needs. Our code moved to
p2panda-core 0.8 (`SigningKey`/`VerifyingKey`, `Topic`); p2panda-auth stays
at 0.5.2 because 0.8 removed `GroupControlMessage`, which the membership
code is built on. Nothing passes p2panda-core types into p2panda-auth, so
the two core versions never meet. Gossip topics are still
`blake3(topic string)`, the value p2panda-core 0.5's `Hash::new` produced,
so share topic ids didn't change.

p2panda-net 0.8's address book stores data in SQLite through sqlx, and
`libsqlite3-sys` would compile its bundled copy. The spec sets
`LIBSQLITE3_SYS_USE_PKG_CONFIG=1` (checked first in its build script, so it
overrides the `bundled` feature) and links Fedora's SQLite;
`packaging/vendor.sh` drops the bundled sources.

## Encryption (Phase 4) design notes

*Partly history:* since the move to iroh-blobs there is no ciphertext
shadow inside the share root; ciphertext lives in the blob store (see
"Transport: iroh-blobs"). The threat model, ciphertext format and keyring
below still apply.

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

### Phase 3.5 — conflict copies (done) and pause-and-ask (deferred)
**Conflict copies are the behaviour now**, not an option
(`daemon::commit_remote`). Last-writer-wins still picks which whole
version wins, but it only decides which content keeps the original name:
before a staged version is committed, a local file it would overwrite or
remove is renamed to `name (conflict from <first 8 hex of our peer id>
<YYYY-MM-DD HHMMSS> UTC).ext` (suffix before the last extension; a
dotfile keeps its whole name as the stem; `-2`, `-3` if taken) when it
holds a change the other side hasn't seen. The copy is a new local file,
so the watcher publishes a version that dominates and both sides converge
with exactly one copy (`tests/e2e-sync.sh` checks this).

"A change the other side hasn't seen" needs a reference point, and the
review's rule (on-disk hash differs from both the hash we last published
or applied and the incoming one) only covers edits not yet announced. In
the usual conflict the losing side *has* announced its edit, so its disk
matches what it published and that rule would overwrite it silently. So:
- `ShareState.manifest` maps each file to the plaintext hash we last
  published or applied; `ShareState.base` holds the files of the last
  version known to be shared with a peer (one we applied, or ours when a
  peer announced the same clock and version hash back). Both persist in
  `state.json` (format 2; a format-1 file has neither, the manifest is
  rebuilt from the root at start, and an empty base counts every local
  file as changed, so nothing is dropped).
- A **fast-forward** (their clock dominates ours) compares the disk with
  `manifest`: only unannounced edits become copies; unchanged orphans are
  deleted, modified ones become copies.
- A **concurrent** apply (theirs won LWW) compares with `base`: a file we
  changed since the base becomes a copy, a file only they changed is
  overwritten, a file we added that isn't in the base is kept under its
  name (merged), and one unchanged since the base that they dropped is
  deleted.
After an apply that kept files, the loop asks the watcher for a re-check,
so they are published. The winner of the LWW comparison keeps its clock
unmerged (see "The LWW winner doesn't merge the loser's clock"), so the
loser always takes the concurrent path.

Known limits: the base is per share, not per peer, so with three or more
peers editing concurrently it can be out of date and produce an extra
copy (never a loss). A conflict copy holds our whole file; there is no
merge within a file.

**pause-and-ask** ("mark conflicting and stop syncing until resolved") is
still deferred: a per-share `paused_conflict` flag in `PersistedState`
and a `share resolve <id>` subcommand.

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
  tick, in chunks of at most 48 KiB; receivers dedupe by op id).
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
On the wire, a rotation rides as `wire::ShareMsg::KeyRotation(SignedRotation)`,
one message per chunk of at most 256 envelopes (see "Gossip message size
and wire format v4"):

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

Canonical bytes signed = `bincode(("peerdup-rotation-v2", group_id,
epoch, rotator_pubkey, envelopes))` with `bincode::config::standard()`
(see "Rotation signatures are bound to the share"). Field tuple ordering
is part of the protocol — re-ordering invalidates every old signature.
Each chunk is signed over exactly the envelopes it carries, with the same
layout and tag; a recipient needs only the chunk with its envelope, and
the others verify but return `NotForUs`.

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
`share-revoke` writes one file per chunk at
`<data_dir>/shares/<id>/pending_rotations/<epoch>-<n>.bin` (atomic
tmp+rename, 0600 on Unix), each a bincode `SignedRotation`; a
`<epoch>.bin` from before chunking still loads. The daemon loads all such files at start and
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

## Phase 7: D-Bus IPC

### `zbus` 5 + tokio interop is gated behind a feature flag
`zbus = { version = "5", default-features = false, features = ["tokio"] }`
in `Cargo.toml`. The default features pull `async-io`, which adds a
second async runtime to the binary alongside tokio; the resulting binary
runs but has two reactors competing. The `tokio` feature is
load-bearing; do not relax `default-features = false` in a refactor.

### Method names: snake_case in Rust, PascalCase on the wire
zbus exposes a method named `share_add` in Rust as `ShareAdd` on the
bus, matching the `nmcli`/`firewall-cmd` convention that Fedora users
expect. The proxy on the client side has to call it as `ShareAdd`
(see `src/client.rs`). If you add a new method, do the snake_case in
Rust and it'll auto-convert; the wire-name mismatch only bites if you
rename existing methods.

### Activation file and how the bus picks it up
`~/.local/share/dbus-1/services/org.peerdup.Daemon1.service` tells
`dbus-broker` (or classic `dbus-daemon`) "if anyone calls a method on
`org.peerdup.Daemon1` and no one currently owns that name, start the
process specified in `Exec=` and wait for it to claim the name." We
delegate to `SystemdService=rust-peerdup.service` so the activation
goes through the existing systemd user unit (so the unit's
`Restart=on-failure`, environment vars, and `journalctl --user` story
all keep working). The bus reads the directory list at startup, not
per-call — `dbus-broker` supports `org.freedesktop.DBus.ReloadConfig`
to pick up new files without a session restart; classic `dbus-daemon`
needs a session bus restart. Most distro defaults are `dbus-broker`
now, so install-and-call works without restart.

### `--data-dir` has dual semantics
On Phase 7 client subcommands, `--data-dir` is the explicit "run
directly against disk, skip D-Bus" toggle. This is a deviation from
the original Phase 7 plan (which proposed a hard-error) chosen so the
existing container test rig in `tests/e2e-revoke.sh` keeps working
unchanged — the containers run with `--network host` and no session
bus, and their CLIs invoke against the same data dir as their detached
daemon. With the dual-mode flag, those tests don't need rewriting.
The `serve` subcommand still treats `--data-dir` as the daemon's
state-directory override.

### Auto-detect missing session bus
`crate::ipc::session_bus_likely_available` checks for
`DBUS_SESSION_BUS_ADDRESS` and falls back to `$XDG_RUNTIME_DIR/bus`.
Container daemons running with `--network host` typically have neither
(systemd's user manager doesn't run in the container, and the host's
abstract socket isn't reachable through the container's private mount
namespace), so the daemon auto-skips IPC registration and runs in
"legacy on-disk only" mode. This is the path the container peers in
`tests/e2e-revoke.sh` exercise.

### Per-share serialization point
Each share task owns its `auth_state`, `keyring` (behind `Arc<RwLock>`,
shared with the encrypt/decrypt paths only), and `pending_rotations`.
IPC method handlers send `ShareCommand` variants over an
`mpsc::Sender<ShareCommand>` and await a `oneshot::Receiver` for the
reply. This means two CLI invocations for the same share serialize
naturally on the channel; cross-share calls run in parallel because
each share has its own channel. The `runtime.shares` and `runtime.tasks`
locks are held only briefly (around lookup and spawn).

### Live revocation broadcasting
Phase 5d's revoke wrote `pending_rotations/<epoch>.bin` and depended on
a daemon restart to pick it up on the next start. Phase 7's
`handle_revoke` additionally pushes the new `SignedRotation` onto the
in-memory `pending_rotations` vector that the share loop's announce-tick
arm reads, so the rotation goes out on the next 10-second tick without
a restart. The on-disk write is still done so a daemon crash during
the broadcast tick doesn't lose the rotation.

## Things that look wrong but aren't

*History:* the three librqbit items below were about the librqbit
session, which no longer exists. For the current equivalents see "Transport: iroh-blobs"
(the blob cache, the staging step, and the `.peerdup` path filters).

### The LWW winner doesn't merge the loser's clock
Looks like the winner of a concurrent edit should merge the other clock
into its version so its next announce dominates. It must not: that
version would then dominate the loser's without containing the loser's
changes, the loser would apply it as a fast-forward (which only keeps
*unannounced* edits) and lose its announced edit without a conflict
copy. The fedora.yml e2e run caught this (a queued, merged re-announce
overtook the concurrent one after connect retries). The winner keeps its
version and clock (`Verdict::LocalWins`); the loser, which loses the same
deterministic comparison, applies the winner's version as a concurrent
one, keeps its changes as conflict copies, and its merged clock then
dominates both. Invariant: a version that dominates ours includes our
content.

### `AuthState::apply_remote` refuses a well-signed `Create`
Looks like it breaks replaying a log into a fresh state. It doesn't: the
state is bound to its group (`AuthState::empty_for`), and a `Create` is
accepted exactly once, as the first op with no dependencies. A second
one would reset the group (see "p2panda-auth: a second Create resets
group state"); don't relax `check_shape`.

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

## librqbit (history)

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
(Since Phase 3.5 the losing side's changes are kept as conflict copies;
see "Deferred work". The timestamp still decides which version wins.)
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

## Secrets on disk are created 0600, not chmod'ed to it

`identity.key`, `keys.bin`, `auth.log` and the pending rotation envelopes
all go through `data_dir::write_private_atomic`: the temp file is opened
with `O_CREAT|O_EXCL` and mode 0600, synced, then renamed into place. The
earlier pattern (`fs::write` then `set_permissions(0o600)`) left each
secret readable under the default umask (usually 0644) until the chmod ran.
If you add another file that holds key material, write it the same way.

## Rotation signatures are bound to the share (v2)

Since review round 2 the bytes a rotator signs are
`("peerdup-rotation-v2", group_id, epoch, rotator_pubkey, envelopes)`.
Before, the group id wasn't signed, so an Owner's rotation for share A
could be replayed into share B whenever the same recipient was in both
(common: one person's devices), installing A's key as B's next epoch. This
is a wire change: rotations signed by older builds no longer verify.
Pre-release, so there is no compatibility shim.

## AuthState: a rejected op must not empty the group

`Crdt::process` takes the CRDT state by value, and p2panda-auth 0.5.2's
`GroupCrdtState` is not `Clone`, so when it rejects an op the state it was
given is gone. `AuthState::process` then rebuilds the state by replaying
the ops already applied. Before, a rejected op left the share with an
empty group, after which every rotation was rejected as `NotAManager`. An
`AuthState` also only accepts ops for the group of its first op, buffers
at most 256 ops with missing dependencies, and invite/revoke check that
the local identity is an Owner before authoring anything.

## p2panda-auth: a second Create resets group state

p2panda-auth 0.5.2's `GroupCrdt::process` handles a `Create` for a group
that already exists as a fresh definition of the group: it does not check
that the group is new, or that the author has any role in it. Review
finding 1, confirmed by `stranger_create_for_existing_group_is_refused`
failing in CI (spike run 45737164708): after an Owner created the group
and added a Writer and a Reader, a Reader-signed `Create` with no
dependencies, applied through `apply_remote`, left the group as
`[(reader, Owner)]`. Anyone who could reach the gossip topic could have
done the same.

So `AuthState` enforces the shape of the log itself (`check_shape`):
- an `AuthState` is bound to its share's group from the start
  (`AuthState::empty_for(group_id_for(share_id))`);
- a `Create` is accepted only as the first op, and only with no
  dependencies;
- every other op must have dependencies.

The first `Create` therefore always comes from the share's creator: from
`share-add` on their machine, or from the ticket on a joiner's, whose log
is replayed and checked (`Ticket::verified_auth_state`) before anything
is written. A share whose `auth.log` is empty is refused at start, since
its first gossiped op would otherwise define the group. If you add
another way to build an `AuthState`, start it with `empty_for` and feed
it a log that begins with the real `Create`.

## Joining writes share.json last

`share-join` (direct and D-Bus) decodes the ticket, checks it was issued
for our key, and replays and verifies its auth log, requiring that no op
waits for a missing dependency and that we are a member, before it writes
anything. Then `ticket::install_join` writes `keys.bin`, `auth.log` and
`bootstrap.json`, and `share.json` last; `share::load_all` skips a share
directory without `share.json`, so the daemon never starts a share with
missing keys or membership. If a write fails the directory is removed,
and a directory without `share.json` (an interrupted join) is replaced on
the next join. `share-add` likewise writes `auth.log` before `share.json`
and refuses a share that already exists.

## Direct mode takes the daemon lock

`--data-dir` with a client command writes the same files the daemon owns
(`auth.log`, `keys.bin`, `share.json`). It now takes `daemon.lock` for the
duration and refuses if a daemon holds it; before, a running daemon's next
`auth::save` could silently overwrite a direct-mode revocation. Stop the
daemon, run the command, start it again (as `tests/e2e-revoke.sh` does),
or go through D-Bus.
