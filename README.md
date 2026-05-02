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
| 5c. `p2panda-auth` group CRDT integration | ✅ Done |
| 5d. Auto key rotation on revocation | ✅ Done |
| 5e. 4-peer revocation e2e test | ✅ Done |
| 6+ | Per ROADMAP.md |

Detailed design notes, including non-obvious gotchas about librqbit and
p2panda, live in [`INTEGRATION_NOTES.md`](INTEGRATION_NOTES.md). Read it
before making changes — the "Things that look wrong but aren't" section
in particular saves an hour of unnecessary fixing.

## Install

The repo ships a shell installer that builds a release binary, drops it
at `~/.local/bin/rust-peerdup`, and installs a `systemd --user` unit:

```bash
git clone https://github.com/theronconrey/rust-peerdup
cd rust-peerdup
./install.sh
```

Re-run `install.sh` to upgrade in place. `./uninstall.sh` reverses both
the binary and unit (and leaves your data directory alone).

## Two-machine quick start

Once installed on both machines (call them **A** and **B**):

```bash
# 1. On B: print the public key so A can name you in the invite.
rust-peerdup whoami
#   prints:  d18c65e7…

# 2. On A: create a share and invite B.
rust-peerdup share-add --topic mydemo --path ~/Sync/mydemo --role sync
SHARE_ID=$(rust-peerdup share-list | tail -1 | awk '{print $1}')
rust-peerdup share-invite "$SHARE_ID" <B-pubkey-hex> --auth-role writer
#   prints the ticket string. Send it to B over a secure channel.

# 3. On B: consume the ticket.
rust-peerdup share-join <ticket-string> --path ~/Sync/mydemo

# 4. On both: start the daemon.
systemctl --user enable --now rust-peerdup
journalctl --user -u rust-peerdup -f  # watch sync events live
```

Edits in either share root propagate within ~1–2 seconds.

For two daemons on the **same** machine (e.g. local smoke testing),
override the data dir and BT port to avoid collisions:

```bash
rust-peerdup --data-dir /tmp/peerdup-a serve --bt-port 41000 &
rust-peerdup --data-dir /tmp/peerdup-b serve --bt-port 41001 &
```

Inspect membership and revoke peers:

```bash
rust-peerdup share-members <share-id>
rust-peerdup share-revoke  <share-id> <peer-pubkey-hex>
```

## Layout

```
src/
├── main.rs           CLI: parsing, dispatch
├── daemon.rs         Per-share sync_loop, JoinSet, signal handling
├── share.rs          ShareConfig, ShareRole, on-disk layout
├── share_state.rs    Per-share runtime state (vhash, clock, manifest, timestamp)
├── clock.rs          VectorClock + ClockOrdering
├── crypto.rs         KeyRing + XChaCha20-Poly1305 encryption
├── auth.rs           Membership CRDT (p2panda-auth) + signed op log
├── rotation.rs       Phase 5d signed sealed-box key rotation envelopes
├── ticket.rs         Invite ticket encode/decode
├── identity.rs       Ed25519 identity load/persist
├── data_dir.rs       Path resolution
└── lock.rs           Daemon exclusive-lock file

systemd/rust-peerdup.service  systemd user unit installed by install.sh
install.sh               build + install (binary + unit)
uninstall.sh             remove binary + unit (keeps data dir)
```

Tests are in-module (`#[cfg(test)] mod tests`); run with `cargo test`.

The 4-peer revocation end-to-end test lives at
[`tests/e2e-revoke.sh`](tests/e2e-revoke.sh). It spins up A on the host
plus B/C/D in podman containers (via `containers/run-peer.sh`), runs
the full invite → sync → revoke → rotate flow, and asserts that the
revoked peer can fetch ciphertext but cannot derive plaintext. Run it
with:

```bash
podman build -t rust-peerdup-peer -f containers/Containerfile .  # one-time
./tests/e2e-revoke.sh
```

## License

MIT — see [`LICENSE`](LICENSE).
