# rust-peerdup

A folder-sync daemon built on [`p2panda`](https://p2panda.org/) for peer
discovery and gossip, and [`iroh-blobs`](https://github.com/n0-computer/iroh-blobs)
over [iroh](https://iroh.computer/) for content transfer. File contents and
names are encrypted end to end, multi-master, and it runs as a long-lived
daemon managing multiple shares.

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
make different design calls (e.g. iroh-blobs instead of libtorrent, p2panda
instead of a custom transport).

## Status

Implementation phases follow [`ROADMAP.md`](ROADMAP.md). At time of
writing:

| Phase | Status |
|---|---|
| 1. Foundation (Hello-World transfer) | ✅ Done |
| 2. Persistent state & daemon | ✅ Done |
| 3. Multi-master sync (watcher, vector clocks, LWW, orphan deletion) | ⚠️ Partial: single host; no conflict copies |
| 4. Encryption at rest (file-level, KeyRing with epoch tagging, key rotation) | ✅ Contents and names encrypted on the wire |
| 5a. Invite/join via copy-paste tickets | ✅ Done |
| 5b. Peer activity listing (`share peers`) | ✅ Done |
| 5c. `p2panda-auth` group CRDT integration | ✅ Done |
| 5d. Auto key rotation on revocation | ✅ Done |
| 5e. 4-peer revocation e2e test | ✅ Done |
| Write permission enforced on sync announces (readers, revoked members) | ✅ Done (signed announces) |
| 7. D-Bus IPC surface | ⚠️ Partial: CLI talks to the daemon over `org.peerdup.Daemon1`; no signals yet |
| 6a. Transport: iroh-blobs over iroh | ✅ Done (spike checks open) |
| 6. Only members can connect (replaces the BitTorrent admission gate) | ✅ Done for new connections; a revoked member's open connection isn't closed yet |
| 7.5. Sync across networks | ⚠️ In progress: works via relays; conflict copies and random topics next |

Detailed design notes, including non-obvious gotchas about iroh and
p2panda, live in [`INTEGRATION_NOTES.md`](INTEGRATION_NOTES.md). Read it
before making changes — the "Things that look wrong but aren't" section
in particular saves an hour of unnecessary fixing.

## Install

On Fedora, from the
[theronconrey/peerdup](https://copr.fedorainfracloud.org/coprs/theronconrey/peerdup/)
Copr project (the same place as tamarack):

```bash
sudo dnf copr enable theronconrey/peerdup
sudo dnf install rust-peerdup
```

The package ships the binary, a man page, the `systemd --user` unit and the
D-Bus activation file. Nothing is enabled for you: the first CLI call starts
the daemon over D-Bus, or enable it at login with
`systemctl --user enable --now rust-peerdup`.

No firewall changes are needed. Peers connect out over iroh (QUIC over
UDP), punch through NATs where they can, and fall back to a relay where
they can't. On one LAN they find each other by mDNS; across networks, an
invite carries the inviter's address, so create invites while the
inviter's daemon is running (or has run once).

### Relays

Relayed traffic stays end-to-end encrypted, but a relay sees which nodes
talk to each other and how much. By default the daemon uses n0's public
relays, which are rate-limited and meant for development. To use your own
(for example a self-hosted `iroh-relay`), or none:

```bash
systemctl --user edit rust-peerdup
# [Service]
# ExecStart=
# ExecStart=/usr/bin/rust-peerdup serve --relay-url https://relay.example.org
#   (repeat --relay-url for more; --no-relay for none)
```

### From source (development)

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

# 3. On B: consume the ticket. "-" reads it from stdin (paste, then
#    Ctrl-D), so it doesn't show up in /proc or your shell history.
rust-peerdup share-join - --path ~/Sync/mydemo

# 4. On both: start the daemon.
systemctl --user enable --now rust-peerdup
journalctl --user -u rust-peerdup -f  # watch sync events live
```

Edits in either share root propagate within ~1–2 seconds.

For two daemons on the **same** machine (e.g. local smoke testing), give
each its own data dir (`tests/e2e-sync.sh` does exactly this):

```bash
rust-peerdup --data-dir /tmp/peerdup-a serve --no-dbus &
rust-peerdup --data-dir /tmp/peerdup-b serve --no-dbus &
```

Inspect membership and revoke peers:

```bash
rust-peerdup share-members <share-id>
rust-peerdup share-revoke  <share-id> <peer-pubkey-hex>
```

## D-Bus IPC

Since Phase 7, the daemon exposes its API on the user session bus as
`org.peerdup.Daemon1` at `/org/peerdup/Daemon1`. Client CLI subcommands
default to talking to the running daemon over D-Bus. With the activation
file (`~/.local/share/dbus-1/services/org.peerdup.Daemon1.service`,
installed by `install.sh`) the daemon auto-starts on first call — no
manual `systemctl --user start` needed.

```bash
busctl --user list | grep peerdup        # daemon registered?
busctl --user introspect org.peerdup.Daemon1 /org/peerdup/Daemon1
```

The `--data-dir` flag has dual semantics in Phase 7:

- With `serve`: tells the daemon where to keep state.
- With a client subcommand: opts the CLI out of D-Bus entirely and
  performs the operation directly against the on-disk state. Useful
  for headless test rigs (the daemons in the `tests/e2e-*.sh` scripts
  run this way), and matches the Phase 2–6 behaviour. The "running
  daemon will not see this change until restart" caveat from the older
  phases applies in this mode.
- With no flag: routes through D-Bus, and the running daemon picks up
  changes live.

When no session bus is detected at `serve` time (no
`DBUS_SESSION_BUS_ADDRESS` and no `$XDG_RUNTIME_DIR/bus`), the daemon
auto-skips IPC registration and runs in legacy mode without surface
churn — the container test rig depends on this.

## Layout

```
src/
├── main.rs           CLI: parsing, dispatch
├── daemon.rs         DaemonRuntime, per-share sync_loop, JoinSet, ShareCommand dispatch
├── wire.rs           Gossip wire format v4: versioned bincode envelope, chunking
├── ipc.rs            org.peerdup.Daemon1 D-Bus interface (Phase 7)
├── client.rs         Thin DaemonClient wrapping zbus::Proxy (Phase 7)
├── transfer.rs       iroh-blobs store, encrypted manifests, fetch + verify
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

systemd/rust-peerdup.service       systemd user unit installed by install.sh
dbus-1/org.peerdup.Daemon1.service D-Bus session activation file
rust-peerdup.spec                  RPM spec (vendored crates; see CONTRIBUTING.md)
packaging/vendor.sh                makes the RPM's source and vendor tarballs
.packit.yaml                       Copr builds for PRs, main and releases
install.sh                          build + install (binary + unit + activation)
uninstall.sh                        remove binary + unit + activation (keeps data dir)
```

Tests are in-module (`#[cfg(test)] mod tests`); run with `cargo test`.

End-to-end tests, each a script that starts real daemons (CI runs all
three against the binary from the RPM):

```bash
tests/e2e-sync.sh   target/debug/rust-peerdup   # two peers, one network
tests/e2e-revoke.sh target/debug/rust-peerdup   # owner, writer, reader; revoke
tests/e2e-xnet.sh   target/debug/rust-peerdup   # two isolated networks (docker)
```

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md): everything here follows Fedora's
packaging guidelines, and pull requests are built in Copr and checked in a
Fedora container before they merge.

## License

MIT — see [`LICENSE`](LICENSE). The RPM also lists the licenses of the
crates it is built from.
