# Change requests and status updates (2026-11-23)

The last commit here is `ab3c828` (2026-05-02). This document records what
has changed around the project since then, which docs are stale, and the
changes needed before peerdup can be the folder-sync feature of
[Tamarack](https://github.com/theronconrey/tamarack), a Fedora NAS appliance.

Findings marked **(code)** come from reading the source at `ab3c828`. They
have not been reproduced by running the daemon; each change request's first
step is a test that shows the problem.

## 1. Status updates

### Upstream dependencies

| Crate | Pinned here | Latest (checked 2026-11-23) | Notes |
|---|---|---|---|
| `p2panda-net`, `p2panda-core`, `p2panda-auth` | 0.5.2 | 0.8.1 (2026-11-13) | Three minor releases behind (0.6, 0.7, 0.8). Expect API changes in gossip and auth. |
| `librqbit` | 8.1.1 | 9.0.1 (2026-08-20) | New major. Re-check every librqbit claim in `INTEGRATION_NOTES.md` (non-deterministic info-hash, no torrent-mutation API, `output_folder` behaviour). |

### Phase 6 (swarm admission gate)

[ikatson/rqbit#582](https://github.com/ikatson/rqbit/issues/582) asks for a
`PeerFilter` trait so peerdup can reject non-members after the BT and BEP-10
handshakes. The maintainer said "a simple PR sounds good", and asked whether
this is the only missing piece; this repo's owner offered to send a PR. No
PR is linked yet. Phase 6 is therefore **blocked on us sending the PR**, not
on upstream. Check whether librqbit 9 changed the peer-connection code
before writing it.

### Stale text in this repo

- `ROADMAP.md`: the Phase 2 heading still says "(NEXT)", and "Phase 2
  detailed instructions" opens with "This is the next milestone". Phase 2
  is done. Move the detailed instructions to an appendix or delete them.
- `ROADMAP.md` Phase 4 still lists `p2panda-encryption` as a deliverable.
  `INTEGRATION_NOTES.md` says it was deferred. Either schedule it (see
  CR-7) or mark it dropped.
- `ROADMAP.md` status snapshot: add the dependency upgrade (CR-7) and the
  data-safety work (CR-1, CR-2) ahead of Phase 8. Phase 8 (UI) should not
  start until CR-1 lands.
- `CLAUDE.md` "Encryption boundary" describes the shadow inside the share
  root; update it when CR-4 lands.

## 2. Change requests

Priorities: **P0** = data loss or unusable at NAS scale; **P1** = needed
before Tamarack ships the sync switch; **P2** = later.

### CR-1 (P0): Per-file versions and merges

**Problem (code).** Versions and last-write-wins apply to the whole share.
In `daemon::sync_loop`, on `ClockOrdering::Concurrent` the loser takes the
winner's whole snapshot through `apply_remote_sync`. Then `delete_orphans`
removes every path in the loser's old manifest that is missing from the
winner's. So when two devices edit concurrently:

- the losing device's edits to files the winner didn't touch are
  overwritten with the winner's older copies;
- files the losing device added are deleted.

The 3.4 notes protect files added *between* snapshots, but not files that
are part of the losing snapshot.

**Change.**

- Keep a version (vector clock plus content hash) per file, not only per
  share. Announces carry the changed files, or a manifest of
  `(path, content hash, clock)`.
- Merge per file:
  - a file changed on one side takes that side's copy;
  - a file changed on both sides is a real conflict;
  - a delete loses to a concurrent edit.
- For real conflicts, make Phase 3.5 "rename" the default:
  `name (conflict from <device name>).ext`, created the same way on every
  peer. Keep LWW as an option.
- Keep tombstones for deletes so a returning peer doesn't resurrect them.

**Done when:** a test where A edits `x`, B edits `y` and adds `z`
concurrently ends with both edits and `z` on every peer. The same test on
`x` alone ends with both versions present.

### CR-2 (P0): Re-send only what changed

**Problem (code).** On every local change, `sync_plaintext_to_shadow`
re-encrypts **every** file in the manifest. Each encryption uses a fresh
random 192-bit nonce, so every ciphertext byte changes. The new torrent
therefore shares no pieces with the old one, and receivers download the
whole share again. A one-byte edit to a 2 TB share sends 2 TB. In addition,
`snapshot_content` re-reads and re-hashes every file on every change.

**Change.**

- **Keep a per-file index** (path, size, mtime, inode, content hash). Only
  re-hash and re-encrypt files whose size or mtime changed.
- **Make ciphertext deterministic for unchanged plaintext.** Either:
  - reuse the existing ciphertext while the plaintext hash and epoch are
    unchanged (simplest); or
  - derive the nonce from `HMAC(key, content hash)` (convergent per share).
    This leaks "same file" within a share only, which is acceptable under
    the wire-only threat model.

  Record the choice in `INTEGRATION_NOTES.md`.
- **Smaller transfer units.** Use one torrent per file (or per directory
  batch) rather than one per share version, so a change announces only the
  affected torrents. The `version_hash` stays as the share-level summary.

**Done when:** editing one file in a 10 GB test share transfers roughly that
file's size (measured from librqbit stats), and an idle rescan reads no file
contents.

### CR-3 (P1): Stream encryption

**Problem (code).** `crypto::encrypt` takes the whole file. Its caller reads
the file with `std::fs::read`, and decryption works the same way. A 20 GB
video needs 20 GB of RAM.

**Change.** Use a chunked AEAD format, for example a STREAM construction
over XChaCha20-Poly1305 with 1 MiB chunks. Put the epoch and the chunk size
in a versioned header (`format = 2`), and keep a reader for the current
format.

**Done when:** syncing a file larger than RAM succeeds with bounded memory.

### CR-4 (P1): Move the shadow and state out of the share root

**Problem.** The ciphertext shadow lives in `<root>/.peerdup/encrypted`.
That doubles the disk space inside the share. On a NAS it also shows up
over SMB, NFS and DLNA and in snapshots, unless every one of those excludes
it. The watcher and walk filters exist only because of this layout.

**Change.** Default the shadow to `<data_dir>/shares/<id>/shadow/`, which is
`/var/lib/peerdup/...` in system mode (CR-5). Keep `.peerdup` only as a
migration source. The "Session output folder is the seed source folder"
note still holds; it just points at the new path.

**Done when:** the share root contains only the user's files.

### CR-5 (P1): System-service mode

Tamarack runs services system-wide on a headless box, with no session bus.

**Change.**

- `serve --system`:
  - claims `org.peerdup.Daemon1` on the **system** bus;
  - runs as a dedicated `peerdup` user;
  - uses `StateDirectory=peerdup`;
  - ships a hardened system unit (`ProtectSystem=strict`, with
    `ReadWritePaths` limited to the configured share roots).
- Authorize every mutating method with polkit (`org.peerdup.manage`), so a
  caller such as the Tamarack engine is allowed by policy. Add the gate in
  `src/ipc.rs::Daemon1Iface`, as `CLAUDE.md` anticipates.
- Shares in system mode can point at roots owned by other users. Document
  the required permissions (an ACL or group on the share).
- Ship an SELinux policy module (a `peerdup_t` domain), or document what
  Tamarack's policy must allow.
- Keep session mode unchanged for desktop users.

**Done when:** Tamarack's engine can create a share, invite, list members
and revoke over the system bus, with SELinux enforcing.

### CR-6 (P1): D-Bus surface for a management UI

Tamarack's Shares tab needs, per share:

- devices, each with an owner-chosen name, its role, when it was last seen,
  and its state (in sync, syncing, or behind by N files);
- the conflict list;
- invites returned as text that the UI renders as a QR code.

**Change.**

- Add a device name to invite tickets, which means a ticket format v3. v2
  is still accepted.
- Add properties and signals for per-peer sync state and conflicts.
- Version the interface (`Daemon1` stays compatible; additions only).

### CR-7 (P1): Upgrade dependencies

- Move to p2panda 0.8.x and librqbit 9.x.
- Re-verify every librqbit and p2panda claim in `INTEGRATION_NOTES.md`, and
  date each one.
- Decide on `p2panda-encryption` (deferred since Phase 4): adopt it for
  group key agreement now that revocation rotation exists, or drop it from
  the roadmap with the reason.

### CR-8 (P1): Unblock Phase 6

Send the `PeerFilter` PR promised in rqbit#582, against librqbit 9. The
maintainer's open question was whether this is all peerdup needs, so answer
that in the PR description: the filter, plus whatever CR-2's per-file
torrents require.

### CR-9 (P2): Fedora packaging

Tamarack only ships Fedora-packaged software. p2panda, librqbit, iroh and
much of their dependency tree aren't in Fedora.

**Change.** Count the crates that are missing (`cargo tree` against
Fedora's `rust-*` packages). Check Fedora's current policy on vendored Rust
dependencies for applications. Then choose: package the crates, or vendor
them if policy allows.

### CR-10 (P2): Scale and soak testing

Add a benchmark and soak test:

- a share with 100k files and about 1 TB;
- three peers;
- a week of random edits, with one peer restarting.

Measure transfer volume, memory, CPU, inotify watch usage (and how
`fs.inotify.max_user_watches` is handled), and convergence. Run it against
CR-1 and CR-2 before Tamarack turns the sync switch on.

### CR-11 (P2): NAT traversal

Sync outside the home network depends on Phase 10, which uses hole-punching
via p2panda's iroh layer plus a relay. Until then Tamarack will label sync
"home network only". Re-check what p2panda 0.8 provides here, since it may
already cover part of this.

## 3. Suggested order

1. CR-7 (upgrade first, so the other work targets current APIs).
2. CR-1 and CR-2 together: both reshape announces and the manifest.
3. CR-3 and CR-4.
4. CR-5 and CR-6: Tamarack integration.
5. CR-8 in parallel, since it's mostly upstream work.
6. CR-10 before any Tamarack release; then CR-9 and CR-11.

The Tamarack side of this lives in that project's Cockpit design notes,
under "Shares: keep in sync with other devices (peerdup)".
