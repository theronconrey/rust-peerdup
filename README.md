# rust-peerdup

A folder-sync daemon built on [`p2panda`](https://p2panda.org/) for peer
discovery and gossip, and [`librqbit`](https://github.com/ikatson/rqbit) for
BitTorrent-based content transfer. End-to-end encrypted, multi-master,
runs as a long-lived daemon managing multiple shares.

## Why a separate Rust implementation

The original [`peerdup`](https://github.com/theronconrey/peerdup) is a
Python project. This repo is a parallel Rust implementation, kept side by
side rather than replacing it, for two reasons:

1. **Putting `p2panda` through its paces.** p2panda is a Rust-native
   ecosystem of crates for decentralised application building. Doing a
   real implementation against it — gossip, encryption, group auth, sync —
   surfaces things a sample app wouldn't. Findings live in
   [`INTEGRATION_NOTES.md`](INTEGRATION_NOTES.md).
2. **Cross-platform packaging flexibility.** The eventual goal includes
   a GNOME Shell extension on Linux and a native app on Windows (and
   probably macOS). Rust makes the Windows and macOS builds dramatically
   more tractable than the Python+libtorrent stack would have, and a
   single codebase that compiles for all three is easier to ship than
   per-platform variants.

The Python `peerdup` keeps moving on its own track; this repo is free to
make different design calls (e.g. librqbit instead of libtorrent, p2panda
instead of a custom transport).

## Status

Implementation phases follow [`ROADMAP.md`](ROADMAP.md). At time of
writing:

| Phase | Status |
|---|---|
| 1. Foundation (Hello-World transfer) | ✅ Done |
| 2. Persistent state & daemon | ✅ Done |
| 3. Multi-master sync (watcher, vector clocks, LWW, orphan deletion) | ✅ Done |
| 4. Encryption at rest (file-level, KeyRing with epoch tagging, key rotation) | ✅ Done |
| 5a. Invite/join via copy-paste tickets | ✅ Done |
| 5b. Peer activity listing (`share peers`) | ✅ Done |
| 5c. `p2panda-auth` group CRDT integration | ⏳ TODO |
| 5d. Auto key rotation on revocation | ⏳ TODO |
| 5e. 4-peer revocation e2e test | ⏳ TODO |
| 6+ | Per ROADMAP.md |

Detailed design notes, including non-obvious gotchas about librqbit and
p2panda, live in [`INTEGRATION_NOTES.md`](INTEGRATION_NOTES.md). Read it
before making changes — the "Things that look wrong but aren't" section
in particular saves an hour of unnecessary fixing.

## Quick start

```bash
cargo build --release

# Set up a share on peer A:
./target/release/rust-peerdup --data-dir ~/.peerdup-a \
    share-add --topic mydemo --path ~/Sync/mydemo --role sync

# Generate an invite (send the resulting string only over a secure channel):
./target/release/rust-peerdup --data-dir ~/.peerdup-a \
    share-invite <share-id>

# On peer B, import the share:
./target/release/rust-peerdup --data-dir ~/.peerdup-b \
    share-join <ticket-string> --path ~/Sync/mydemo

# Start daemons (different BT ports if on the same machine):
./target/release/rust-peerdup --data-dir ~/.peerdup-a serve --bt-port 41000
./target/release/rust-peerdup --data-dir ~/.peerdup-b serve --bt-port 41001
```

Edits in either share root propagate within ~1–2 seconds.

## Layout

```
src/
├── main.rs           CLI: parsing, dispatch
├── daemon.rs         Per-share sync_loop, JoinSet, signal handling
├── share.rs          ShareConfig, ShareRole, on-disk layout
├── share_state.rs    Per-share runtime state (vhash, clock, manifest, timestamp)
├── clock.rs          VectorClock + ClockOrdering
├── crypto.rs         KeyRing + XChaCha20-Poly1305 encryption
├── ticket.rs         Invite ticket encode/decode
├── identity.rs       Ed25519 identity load/persist
├── data_dir.rs       Path resolution
└── lock.rs           Daemon exclusive-lock file
```

Tests are in-module (`#[cfg(test)] mod tests`); run with `cargo test`.

## License

MIT — see [`LICENSE`](LICENSE).
