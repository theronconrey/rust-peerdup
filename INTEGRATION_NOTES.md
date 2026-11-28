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
- Members-only connections and per-share blob access: done, see
  "Members-only connections" below.
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

## Members-only connections

`src/access.rs`; both layers key on the node id, which is the member's
identity key and which iroh authenticates in the TLS handshake.

**Connections.** The endpoint's hook is `MembersOnly`, an iroh
`EndpointHooks` (p2panda-net 0.8.1 `Endpoint::builder(..).hooks(impl
EndpointHooks + Clone + 'static)`; iroh 1.5 runs every hook in order for
every connection, incoming and outgoing, every ALPN). It delegates the
decision to p2panda-net's `ConnectionBlockList` in restrictive mode:
allowed = the union of every running share's current members,
recomputed at share start, after auth ops apply, after invite/revoke,
and when a share stops. A refused node gets code 403 after the
handshake (`after_handshake`), and we never dial it (`before_connect`).

`ConnectionBlockList::block` only refuses *new* connections, so
`MembersOnly::after_handshake` also records every accepted connection
as a `WeakConnectionHandle` (iroh's hook docs: never keep a strong
`Connection` from a hook; it keeps the connection alive and disables
close-on-drop). When a node leaves the union, `Access::apply` blocks it
and then closes every recorded connection to it with application code
403, reason `membership revoked`, and logs `no longer a member of any
share: blocked, live connections closed node=<hex> closed=<n>`. The
hook records a connection *before* it asks the block list, under the
same lock the close takes, so a connection that races a block is either
recorded in time to be closed or refused by the block list. Records are
pruned when a connection closes (`WeakConnectionHandle::closed`) and
whenever a node's list is touched. `set_members`/`remove_share` are
serialised so allow/block calls apply in order.

Nothing reconnects around this: p2panda-net's endpoint actor keeps no
pool (each `connect` makes a new connection, through the hooks);
iroh-gossip dials through the same iroh endpoint, so a re-dial of the
revoked node is refused in `before_connect`, and its dials to us in
`after_handshake`. iroh-gossip holds one connection per peer for all
topics, so a close only affects the revoked node; HyParView replaces it
from the passive view, and the healer rejoins from the address book.
None of our protocols accepts 0-RTT (`on_accepting` is the default, a
full handshake), which matters: an incoming 0-RTT connection could carry
data before `after_handshake` runs. Keep it that way.

The cut is per daemon, not per share. A node revoked from share X that
is still a member of share Y on the same daemon keeps its connection,
and because iroh-gossip has no per-topic authorisation, it can stay in
X's gossip topic over it: it keeps hearing X's announces (manifest
hashes, version hashes, clocks), auth ops and rotation chunks (sealed to
the remaining members) until it disconnects. What stops it is the key
rotation (it can't decrypt new versions), the Writer check (its
announces are refused) and the blob gate below (it can't fetch X's
blobs). Rotating X's gossip topic on revocation (deriving it from the
new epoch's key) would close this; not done yet.

**Blobs.** A connection allowed for any share may carry requests for
any blob, so each request is checked on its own. `BlobsProtocol::new(&store,
Some(events))` gets an `EventSender` with `transfer::BLOB_EVENTS`:
`connected: ConnectMode::Intercept` (iroh-blobs 0.105's `ClientConnected`
carries `connection_id` and `endpoint_id`; requests carry only the
`connection_id`, so the map comes from here), `get:
RequestMode::Intercept`, and get-many, push and observe `Disabled` (our
fetches only send gets). `Access::serve_blob_events` answers: a get for
hash H from node N is allowed only if some running share has H in one of
its last `RECENT_VERSIONS` (4) versions and N is a current member of it
(`access::decide_blob`), otherwise `AbortReason::Permission` and a log
line `refused a blob request: <why> node=<hex> blob=<hash>`. A dropped
or unanswered decision is a refusal in iroh-blobs, so an unexpected
request type fails closed.

- Only single-blob requests (`GetRequest.ranges.is_blob()`, or empty).
  A request with child ranges treats H as a hash sequence and serves
  the blobs it names; a member holds the share key and can make a
  ciphertext blob whose bytes are other blobs' hashes, so children would
  reach any blob in the store.
- A version's hashes (manifest and every file blob) are recorded when
  `Transfer::publish` returns, before the version is announced, and
  when a fetched version is committed (we announce what we applied).
  A fetched version that is refused or discarded isn't recorded, so a
  Writer can't push real versions out of the window with junk.
- Keeping four versions lets a fetch of a just-superseded version (a
  quick second edit, a re-encryption after a rotation) finish. A share
  that publishes faster than a peer fetches can still push a version out
  mid-fetch; the fetch fails and the next announce is fetched, reusing
  the blobs it already has.
- A hash in two shares is allowed to members of either (it is the same
  bytes).
- The index is in memory, rebuilt as shares start and republish.
- Revocation needs no extra step: membership is read per request, so a
  revoked node's request on a still-open connection is refused.

`tests/e2e-isolation.sh` checks both layers with three daemons (A
revokes over D-Bus while running); `tests/e2e-revoke.sh` checks a member
that learns of a revocation over gossip cuts the revoked node off too.

## Share identity and topics (v4 tickets)

Before, a share's id was `hex(blake3(topic))[..16]` and its gossip topic
`blake3(topic)`, with the topic a string the user chose: guessable, and
two unrelated "photos" shares collided (review finding 5). With
iroh-gossip any connected node that knows a topic id can join it, and
p2panda's confidential (PSI) discovery only hides topics that have
entropy.

Now (`src/share.rs`):
- `share-add` makes a `TopicSecret`, 32 bytes from the OS RNG.
- share id = `hex(blake3::derive_key("rust-peerdup 2026-11-26 share id
  v1", secret))[..16]`; gossip topic = `blake3::derive_key("rust-peerdup
  2026-11-26 gossip topic v1", secret)`. blake3's KDF mode with one
  context string per value: the id (shown, logged, used in the auth
  group id) says nothing about the topic. The context strings are part
  of the format.
- `--name` is a label (`--topic` stays as a hidden alias): shown by
  `share-list`, returned as the second field of D-Bus `ShareList`,
  carried in tickets; at most 256 bytes and no control characters,
  since another machine's ticket supplies it. Never hashed.
- The secret is never logged, announced or returned over D-Bus
  (`TopicSecret`'s `Debug` prints `TopicSecret(..)`). The gossip topic
  id is as good as the secret for joining gossip; it is sent only to
  peers on the topic and never logged by us.
- Ticket v4 carries `name` and `topic: ShareTopic` (the secret, or a
  legacy topic string, below); `Ticket::decode` checks that `share_id`
  derives from it, which also keeps it a safe directory name. v3 tickets
  are refused (no releases yet).
- `share.json` holds the secret, so it is written like the other
  secrets: 0600 from creation, atomically (`write_private_atomic`). An
  older one that others can read is chmod'ed 0600 when loaded. On disk:
  `name`, and `topic_secret` (hex) or `legacy_topic`.
- Migration: a `share.json` from before (only `topic`) loads as
  `ShareTopic::Legacy`, named after its topic, with the old id and gossip
  topic, so it keeps syncing with its members; invites to it carry the
  legacy topic. The daemon warns at start that its topic can be guessed.
  Moving it to a random topic means a new share (and new invites): the
  members would all have to switch at once. A `share.json` whose id
  doesn't derive from its topic is skipped with an error.

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

## p2panda 0.8 (core, net, auth)

p2panda-net 0.8 runs on iroh 1.x, which iroh-blobs needs. Our code is on
p2panda-core, p2panda-net and p2panda-auth 0.8. p2panda-auth stayed on 0.5.2
for a while because 0.8 removed `GroupControlMessage`; see "p2panda-auth
0.5 to 0.8" for how the port kept `auth.log` byte-identical. Gossip topics were `blake3(topic
string)` across that move; since ticket v4 they derive from a random
secret (see "Share identity and topics").

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

### Rotation without a revocation
`share-rotate-key <id>` appends a new key to `keys.bin` and, since the
old-keys work, sends it to every other member exactly like a revocation
does (signed sealed-box envelopes, queued in `pending_rotations/`). Only
an Owner may run it: receivers accept rotations from Owners only. It used
to keep the key on the machine that made it, so every version published
after it was unreadable to everyone else. A running daemon re-encrypts
its current version under the new key straight away (see "Old keys after
revocation").

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
`p2panda-auth` 0.8 is a *library* of generic types — `GroupCrdt`,
`GroupCrdtState`, `Access`, etc. — parameterised over p2panda-core's
`Author` and `OperationId` traits, `Conditions` and a `Resolver`. It does
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

### No `Orderer`
0.5.2 had an `Orderer` trait that only its high-level `prepare` path used;
peerdup always called `process` with fully-formed ops and supplied a no-op
orderer. 0.8 removed the trait and the generic, so there is nothing to
supply. peerdup still builds each op itself, with the current group heads
(`heads(&[group])`) as its dependencies.

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
*(Since then: v3 added the inviter's address, v4 the topic secret and
name; each older version is refused.)*

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
`share-revoke` and `share-rotate-key` write one file per chunk at
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

## Old keys after revocation

A revoked member keeps every key it ever held (`KeyRing` never deletes
keys), so it can read anything encrypted under those keys if it gets the
ciphertext. Rotation only protects what is encrypted *after* it, and
until this change nothing made sure new content was: a Writer that
missed the revocation kept publishing under the old key, peers applied
and re-announced its versions, and nobody re-encrypted the current
version. `src/epochs.rs` holds the rule; the pieces:

**Required epoch.** In a node's own view, `max(1 + removals, floor)`:
- `AuthState::required_epoch` is `1 + removals`, where a removal is a
  `Remove` op in the log that p2panda-auth's strong-remove resolver did
  not filter (`inner.ignore`), or that is part of a mutual-remove cycle
  (`inner.mutual_removes`, filtered but in effect). Every revocation
  rotates once (daemon and direct mode), and every leave gets a rotation
  from an Owner's daemon ("Members leave on their own"), so after `n`
  removals keys up to epoch `n` are each held by some removed member. A filtered `Remove`
  never took effect and is not counted: a removed Owner can still sign
  `Remove` ops whose dependencies predate its removal (they validate at
  those dependencies, then get filtered), and counting them would let it
  raise the required epoch at will and freeze the share. Demotions don't
  count (the member keeps read access).
- The **floor** (`<share>/epoch_floor`, `crypto::raise_epoch_floor`) is
  set when a rotation brings a *different* key for an epoch we already
  hold (`InstallOutcome::Conflict`; before, the same epoch errored and an
  older one was silently `Stale`). Two Owners rotated concurrently, and
  one of the two keys may have gone to a member the other was revoking,
  so neither is trusted for new content: the floor becomes the next
  epoch. It never goes down.

**Publishing.** A node encrypts nothing new while its keyring is below
the required epoch (`publish_current` returns `Held`; the daemon logs
"local change waits for the rotated key"), not even into its local
store, and announces only a version at or above it. At start in that
state the persisted version comes back unpublished (`epoch` 0). When the
key arrives the change is published as usual.

**Receiving.** `transfer::fetch` takes the required epoch at the start
of the fetch and refuses, before decrypting, a manifest under an older
epoch, and, before staging, any file blob whose epoch differs from the
manifest's (`check_version_epochs`): otherwise a version could carry a
current-epoch manifest over old ciphertext. The share loop checks the
staged version again against the required epoch at commit time, since a
`Remove` may land mid-fetch. A refusal is an `EpochRefused` error, kept
apart from "no key for epoch N" (we are behind and retry later): it is
logged as "refused a remote version: version encrypted under epoch X;
this share requires >= Y after a revocation", and the manifest is
remembered so its 10-second re-announces aren't fetched again (cleared
when the required epoch changes). The epoch in the header isn't covered
by the AEAD, but it selects the key, so a relabelled blob fails to
decrypt; refusing on the claimed epoch never needs it to be true.

**Re-encrypting after a rotation.** Whenever a node's keyring advances
(its own revocation or rotation, or a key installed from gossip), the
share loop publishes its current version again under the new key:
same version hash, clock and timestamp, a new manifest hash, then it
announces, persists the state and saves the blob cache. Without this a
peer that was behind would refuse the current version forever, since
every copy was under the old key. There is no loop or storm: peers that
have the version compare `Equal` and fetch nothing, the clock is not
bumped (`next_state` bumps only when the content changed), and it runs
once per keyring epoch. Readers don't (they never announce). The blob
cache reuses ciphertext only for the same plaintext *and* epoch, so the
re-encryption really is under the new key. The start path publishes
under the current key anyway (the store is a cache).

**Minting.** An Owner revokes or rotates only if the key it mints will
satisfy the required epoch afterwards (`check_mint`): an Owner that knows
of a removal whose key hasn't arrived would otherwise mint a second key
for that epoch. The check runs before the `Remove` is authored, so a
refusal leaves no removal without its rotation. Invites also wait for
the required key (`check_invite`), or the joiner would get neither the
key nor an envelope for it.

**Residual risk.** The rule is enforced by each node on its own view.
A member that hasn't heard of the revocation (offline, partitioned)
still counts the revoked node as a member: its connection gate lets it
in and it serves it whatever it writes, under the old key, until the
revocation reaches it. The rule stops that content from spreading to
up-to-date members (they refuse it, and they refuse the revoked node's
connections), but it can't stop the revoked node from reading it
straight from the lagging member; no rotation can. Only the revocation
reaching the lagging member closes that. Two related limits:
- The lagging member may also apply the revoked node's own edits (a
  revoked Writer's announces still verify there). Once it catches up it
  re-encrypts its current version, which then carries those edits to
  everyone. Nothing distinguishes them afterwards.
- With two revocations by different Owners at about the same time, a
  node that has heard of only one removal can accept the key the *other*
  Owner minted, which that Owner also sent to the member whose removal
  the node has heard of. The same goes for an Owner that installed a
  rotated key before the `Remove` behind it arrived and then revokes
  someone else: its envelopes still include the first removed member.
  Either stops once the node hears of the other removal (the count
  rises) or sees the second key (a fork). Meanwhile the up-to-date
  members block that member's connections, so it can only get such
  content from lagging members, as above. A rotation that named the
  removals it was made after would close this exactly; that needs a wire
  change (`SignedRotation` v3) and is left for later.
Concurrent revocations by two Owners always produce two keys for one
epoch: the share then fails closed (the count asks for an epoch nobody
has, and the fork raises the floor) and publishes nothing until an Owner
runs `share-rotate-key`.

`tests/e2e-revoke.sh` covers the lagging Writer: D is stopped before the
revocation, edits offline, restarts without knowing; A refuses its
epoch-1 version, D gets the rotated key, re-encrypts ("republished under
epoch 2"), and A and C accept it. B is stopped while D lags, because D
would serve it (the residual risk), and never gets the edit.

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

### The blob gate refuses hash-sequence requests from members
Looks over-strict, since the requester is a member. A request with child
ranges makes the provider read the requested blob as a list of hashes
and serve those blobs, and a member can write such a list into a blob it
publishes (it holds the key, so it picks the ciphertext bytes). Allowing
it would serve other shares' blobs. Our fetches only ask for single
blobs.

### `MembersOnly` records a connection before it decides
Looks backwards. Blocking and closing happen in that order in
`Access::apply`; recording first in the hook means a connection that
races a revocation is either recorded in time to be closed or refused by
the block list. Recording after an accept would leave a window where it
is neither.

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

`identity.key`, `keys.bin`, `auth.log`, the pending rotation envelopes
and `share.json` (it holds the topic secret since ticket v4) all go
through `data_dir::write_private_atomic`: the temp file is opened
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

`Crdt::process` takes the CRDT state by value, and p2panda-auth's (0.5.2 and 0.8)
`GroupCrdtState` is not `Clone`, so when it rejects an op the state it was
given is gone. `AuthState::process` then rebuilds the state by replaying
the ops already applied. Before, a rejected op left the share with an
empty group, after which every rotation was rejected as `NotAManager`. An
`AuthState` also only accepts ops for the group of its first op, buffers
at most 256 ops with missing dependencies, and invite/revoke check that
the local identity is an Owner before authoring anything.

## p2panda-auth: a second Create resets group state

p2panda-auth's (0.5.2 and 0.8) `GroupCrdt::process` handles a `Create` for a group
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

## p2panda-auth 0.5 to 0.8

0.8 dropped `GroupControlMessage`: the `Operation` trait has `group_id()`
and `action()` instead of `payload()`. `auth.rs` keeps a local
`GroupControlMessage { group_id, action }` with the same fields in the same
order, so bincode encodes it exactly as 0.5.2 did and every existing
signature and op id still matches. `golden_auth_log_is_byte_stable` pins
the bytes (recorded on 0.5.2); never reorder or retype that struct.

`IdentityHandle` and the crate's `OperationId` became p2panda-core's
`Author` and `OperationId`; `StrongRemove`'s parameters were reordered;
`heads()` takes a list of groups. The second-Create reset (above) and the
by-value `process` with a non-`Clone` state are unchanged in 0.8, so
`check_shape` and `rebuild_from_log` stay.

### Any member may sign its own `Remove` (0.7+)
Since 0.7 (upstream #1234) the CRDT applies a `Remove` whose author is
the removed member, whatever their access level; 0.5.2 required a manager.
peerdup counts every `Remove` in effect toward the required key epoch
(`required_epoch = 1 + removals`), and only an Owner can mint the next key.
peerdup now uses this for `share-leave` (next section). `check_self_remove`
accepts a self-removal from anyone who was a member at the op's
dependencies, except the only Owner there, and refuses it from a
non-member. The rule reads only the op and its causal past, so every node
decides alike, in `apply_remote` and on replay.
`the_only_owners_self_removal_is_refused_though_the_crdt_takes_it` shows
the raw CRDT taking the op and `AuthState` refusing it.

Upstream details this relies on (checked in the 0.8.2 source,
`group/resolver.rs` and `group/authority_graphs.rs`):
- `AuthorityGraphs::add_removal` returns early when `remover == removed`,
  so a self-removal is never part of a mutual-remove cycle.
- Strong remove filters, for every `Remove` of X, the ops *by X*
  concurrent with it. Two leaves by one member on different heads filter
  each other: neither counts, and the member stays. A member can't inflate
  `removals()` by repeating its leave (`repeated_leaves_by_one_member_do_not_add_up`).
- A leave concurrent with an Owner revoking the same member is filtered
  (it is by the removed member); the revocation counts once.
- A removed member's leave signed on heads after its removal is refused
  (not a member at its deps); one signed on heads before it is filtered.

Existing `auth.log` files that hold a self-removal of the only Owner (an
Owner could `share-revoke` itself before) no longer replay; `share-revoke`
of yourself now points to `share-leave`.

## Members leave on their own

`share-leave <id>` (`ShareLeave` over D-Bus, `ShareCommand::Leave`):

1. **The op.** `daemon::record_leave` authors our own `Remove`
   (`AuthState::leave`, which refuses the only Owner and non-members with
   a clear error), saves `auth.log`, then writes `<share>/leaving`.
   Direct mode (`--data-dir`) does the same under the daemon lock; the
   marker makes the next daemon start finish the leave. A second
   `share-leave` doesn't sign a second op (`has_left`): two leaves on
   different heads would cancel each other upstream (above).
2. **Telling the others.** `finish_leave` stops syncing (no fetch, no
   publish, no reconcile), sends the auth log for `LEAVE_GRACE_TICKS` (6)
   announce ticks, about 50 s with the first at once, then does what
   `share-remove` does: drops the share's access entry and state
   directory and the `.peerdup` shadow, and takes itself out of
   `runtime.shares`. The plaintext files stay. Once one member has the op,
   every member re-sends the whole log each tick, and members that apply
   it cut the leaver's connections (`access.rs`), so the leaver only has
   to reach one peer. A shutdown during the grace keeps the marker and the
   next start resumes. If no member is online during the grace, the leave
   never leaves the machine: the others still list the node until an
   Owner revokes it.
3. **The rotation.** Every leave raises `required_epoch`, so until a key
   covers it nobody may publish (`epochs::may_encrypt`; logged once per
   change at info, "local change waits for the share's next key"). An
   Owner's share loop checks `daemon::auto_rotation` on every pass:
   - nothing unless its keyring is behind `AuthState::required_epoch` and
     it is a current Owner;
   - nothing unless the uncovered removals are leaves:
     `uncovered_removals_are_leaves(gap)` looks at the `gap` most
     recently applied removals in effect. A revocation's key is minted
     with its `Remove` by the revoking Owner (synchronously, in the
     daemon and in direct mode) and re-sent every tick, so a gap left by
     a revocation is never auto-filled, and a node never double-rotates
     a revocation it just made (it has no gap);
   - wait while a rotation for a later epoch is buffered (the missing
     one is on its way);
   - the **designated rotator**, the current Owner with the lowest
     `MemberId`, mints at once; any other Owner only after the gap has
     lasted `LEAVE_ROTATE_GRACE` (60 s, six ticks of the designated
     rotator's re-sends).
   `auto_rotate` mints epochs until the keyring meets the required epoch
   (several leaves before a rotation need several), each sent to the
   other current members as a revocation's is (`mint_and_queue`). The
   loop then re-encrypts and publishes held changes as after any
   rotation. The epoch floor is not a trigger: healing a fork stays a
   manual `share-rotate-key`.

**Stall window.** Between a leave reaching a node and the new key
reaching it, that node publishes nothing new, and members that know of
the leave refuse versions still under the old key. With the
designated rotator online that is a gossip round trip plus up to one
tick; with it offline, up to `LEAVE_ROTATE_GRACE` plus a tick, after
which another Owner mints. With no Owner online, until one comes back.
An Owner can't revoke or invite during the window (`check_mint`,
`check_invite`): wait for the key.

**Forks.** Two Owners can still mint the same epoch: the designated
rotator was offline past the grace and comes back, or a leave and a
revocation of the same member cross. The receiving nodes see two keys
for one epoch (`InstallOutcome::Conflict`), raise the epoch floor, and
fail closed exactly as for two concurrent revocations ("Old keys after
revocation"): nothing new is published until an Owner runs
`share-rotate-key`. Auto-rotation doesn't trigger on the floor, so a fork
never feeds more automatic minting.

**Attribution is a heuristic.** Keys don't name the removal they cover.
In the concurrent case (another Owner revokes someone before it hears of
a leave, and its key arrives here before the leave does) a node may count
the gap as a revocation's and wait; the revoking Owner, which applied its
own revocation first, sees a leave as the newest removal and mints after
the grace. If that Owner is offline, the share waits for it or for a
manual `share-rotate-key` (fails closed). A rotation that named the
removals it covers would make this exact; it needs a wire change
(`SignedRotation` v3).

**Two Owners leaving at once.** Each sees the other as an Owner at its
dependencies, so both ops are valid and the merged share has no Owner
(`two_owners_leaving_at_once_leave_no_owner`). Resolving that
deterministically would mean dropping an already-applied op (and
everything that depends on it) when the other arrives, so it is left as
a known gap: such a share keeps its content but can never rotate or
publish again; re-create it. The guard does stop the common case, the
last Owner leaving.

**Leaving is not revocation.** The leaver keeps everything it had,
including every key up to the epoch current at its leave, and the
rotation only protects what is encrypted after it. A concurrent manual
`share-rotate-key` that hadn't seen the leave can even hand the leaver
the new epoch (no fork follows, since no second key is minted for it).
Revoke a member you no longer trust (SECURITY.md).

`tests/e2e-leave.sh` covers it end to end: a Reader leaves in direct mode,
the Owner rotates, a Writer's edit reaches the Owner under the new epoch,
the leaver's data dir loses the share and keeps its files, and the only
Owner's leave is refused.
