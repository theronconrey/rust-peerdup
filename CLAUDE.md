# CLAUDE.md

Context for AI coding agents working in this repo. Read this file and
[`INTEGRATION_NOTES.md`](INTEGRATION_NOTES.md) before making changes.

## What this is

`rust-peerdup` is a Rust implementation of the peerdup folder-sync daemon,
built on `p2panda` (gossip, identity) and `librqbit` (BitTorrent transfer).
It is a parallel implementation to the Python `peerdup` repo — both follow
the same [`ROADMAP.md`](ROADMAP.md) but make different technology choices.
See [`README.md`](README.md) for the user-facing rationale.

## Where to read first

1. **[`INTEGRATION_NOTES.md`](INTEGRATION_NOTES.md)** — the source of truth
   for non-obvious crate behavior (librqbit's non-deterministic info-hash,
   the wire-only encryption threat model, librqbit's lack of a public
   state-change event channel, etc.). The "Things that look wrong but
   aren't" section in particular catches three design choices that
   commonly get "fixed" by readers unfamiliar with the constraints.
2. **[`ROADMAP.md`](ROADMAP.md)** — phase plan. The phases are in strict
   dependency order; skipping ahead generally doesn't work.
3. **[`README.md`](README.md)** — current phase status table, build/run
   instructions.

## Behaviors worth knowing

### Don't trust librqbit's info-hash for content equality
`librqbit::create_torrent` walks directories in filesystem order, which
varies per host. Two peers with byte-identical content compute different
info-hashes. This repo carries its own `version_hash` (blake3 over sorted
`(rel_path, blake3(content))` pairs) for "is this the same content?"
comparisons; info-hash is used only as the BitTorrent magnet for
fetching. Don't merge changes that compare info-hashes to mean "same
content."

### Encryption boundary
The user-visible share root holds **plaintext** (apps need to read/write
files normally). `<root>/.peerdup/encrypted/` holds **ciphertext** that
librqbit operates on. Two filters keep these from interfering:

- The notify watcher skips events whose paths all pass through `.peerdup`.
- `collect_files` skips any directory entry named `.peerdup`.

If you add another filesystem walk or watcher, apply the same filter or
you'll either feedback-loop the watcher or hash ciphertext alongside
plaintext.

### Vector clocks need a stable peer identity
The daemon's identity (`<data_dir>/identity.key`, an Ed25519 private key)
is the peer id used in vector-clock keys. If you regenerate the identity
between runs, you'll appear as a "new peer" in everyone else's clocks
and concurrent-edit detection breaks. The `identity::load_or_create`
helper handles this; don't bypass it.

### Encryption keys never delete
`KeyRing` (in `crypto.rs`) holds all keys ever generated for a share,
indexed by epoch. Each ciphertext blob carries its epoch in an 8-byte
header so receivers know which key to use. Rotation appends a new key;
nothing ever removes one. This is what makes "old ciphertext stays
readable after rotation" work; if you delete old keys you break that.

### Auth ops are append-only and signed (Phase 5c)
Each share has its own membership CRDT (`auth.rs`, built on
`p2panda-auth`). Operations (`Create`/`Add`/`Remove`/`Promote`/`Demote`)
are Ed25519-signed by the author using the daemon's `identity.key` and
stored in `<data_dir>/shares/<id>/auth.log` — bincode-encoded
`Vec<SignedOp>`, replaced atomically on update. Don't strip the
signature step or skip `apply_remote`'s `op.verify()` call when adding
a new ingestion path; those are the only thing keeping a malicious
peer from forging Add/Remove ops on the wire. Auth state and the
encryption keyring are *separate* — they're persisted under the same
share dir but have independent lifecycles. Phase 5d wires the rotation
trigger so a `Remove` op also produces a fresh epoch.

### Revocation triggers a key rotation (Phase 5d)
`share-revoke` does three things atomically on disk: (1) appends the
`Remove` op to `auth.log`, (2) appends a fresh 32-byte epoch key to
`keys.bin`, and (3) writes one signed sealed-box envelope per remaining
member to `<data_dir>/shares/<id>/pending_rotations/<epoch>.bin`. Since
Phase 7 the running daemon's revoke handler also pushes the rotation
into the in-memory `pending_rotations` vector so the next 10-second
announce tick broadcasts it without a daemon restart. Receivers verify
the rotator is a current Owner in their local auth state, decrypt the
envelope addressed to them, and `install_epoch_key` the result.
Out-of-order arrivals are buffered in memory (capped at 64). The KEM is
`crypto_box` (X25519 + XSalsa20-Poly1305) with the static recipient key
derived from their Ed25519 identity; see `INTEGRATION_NOTES.md`
"Phase 5d key distribution" for the tradeoff.

### CLI talks to daemon over D-Bus (Phase 7)
The CLI dispatches to `org.peerdup.Daemon1` on the session bus at
`/org/peerdup/Daemon1` by default. An activation `.service` file
installed at `~/.local/share/dbus-1/services/` lets the bus auto-start
the daemon on first call. `--data-dir` has dual semantics: with `serve`
it sets the daemon's data dir, with a client subcommand it opts out of
D-Bus and runs directly on disk (the container test rig depends on
this). When the daemon comes up without a session bus available
(`DBUS_SESSION_BUS_ADDRESS` unset and `$XDG_RUNTIME_DIR/bus` missing),
it logs a single info line and runs without IPC; this keeps headless
container peers working without Containerfile churn.

The IPC surface has no auth gate beyond the session bus's user scoping
— anyone with access to the user's bus can invoke any method. Acceptable
for v1 since the data dir already has the same scope; if a multi-user
or polkit-gated story becomes necessary, the gate is added in
`src/ipc.rs::Daemon1Iface`.

Per-share state mutations (`auth_state`, `keyring`, `pending_rotations`)
flow through the share loop's `mpsc::Sender<ShareCommand>` and are
serialised on the share task's stack. The IPC dispatcher only holds
the `runtime.shares` lock long enough to look up the sender; reads
that don't need a per-share task (`Whoami`, `ShareList`, `SharePeers`)
go directly off `runtime.data_dir` from disk.

## How to build, test, run

```bash
cargo build              # debug
cargo build --release    # optimised
cargo test               # unit tests (~10 currently, in clock/crypto/ticket)
cargo check              # quick type-check without codegen
```

End-to-end smoke test (two daemons on one machine):

```bash
PEER_A=/tmp/peerdup-a
PEER_B=/tmp/peerdup-b
ROOT_A=/tmp/peerdup-share-a
ROOT_B=/tmp/peerdup-share-b
rm -rf $PEER_A $PEER_B $ROOT_A $ROOT_B
mkdir -p $ROOT_A
echo "hello" > $ROOT_A/test.txt

./target/debug/rust-peerdup --data-dir $PEER_A \
    share-add --topic demo --path $ROOT_A --role sync

TICKET=$(./target/debug/rust-peerdup --data-dir $PEER_A \
    share-invite "$(./target/debug/rust-peerdup --data-dir $PEER_A share-list | tail -1 | awk '{print $1}')")

./target/debug/rust-peerdup --data-dir $PEER_B \
    share-join "$TICKET" --path $ROOT_B

# Run each in a separate terminal (or via & + wait):
./target/debug/rust-peerdup --data-dir $PEER_A serve --bt-port 41000 &
./target/debug/rust-peerdup --data-dir $PEER_B serve --bt-port 41001 &

sleep 5 && diff -r $ROOT_A $ROOT_B --exclude=.peerdup
```

## Logging

`RUST_LOG` env var controls verbosity. The default filter is
`rust_peerdup=info`. Useful settings:

- `RUST_LOG=rust_peerdup=info` — peerdup events only (the default)
- `RUST_LOG=rust_peerdup=info,librqbit=info` — peerdup + librqbit progress
- `RUST_LOG=rust_peerdup=debug` — verbose per-share announce/poll detail

The crate's tracing target is `rust_peerdup` (with underscore — Cargo
package name `rust-peerdup` becomes module `rust_peerdup`).

## Commit style

Default to one focused commit per coherent change. The existing commit
log will set the convention as it grows.

## Known limitations not yet in INTEGRATION_NOTES

If you discover a non-obvious crate behavior or a load-bearing design
choice while making changes, **add it to INTEGRATION_NOTES.md** rather
than only fixing the immediate problem. The notes file is the artifact
that compounds across sessions.
