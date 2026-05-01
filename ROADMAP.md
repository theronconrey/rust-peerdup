# peerdup roadmap to completion

A phase-by-phase plan from current state (Hello-World transfer working) to
"peerdup is a real product users install and rely on." Phases are listed in
strict dependency order — each one builds on the last. Skip a phase and the
later ones don't have what they need.

Time estimates assume one focused engineer, full-time. They are best-effort
guesses, not commitments. Add 50% if part-time, double for "with surprises."

---

## Status snapshot

| Phase | State | Estimate |
|---|---|---|
| 1. Foundation | ✅ Done | — |
| 2. Persistent state & daemon | ✅ Done | — |
| 3. Multi-master sync | ✅ Done | — |
| 4. Encryption at rest | ✅ Done (file-level; `p2panda-encryption` deferred — see notes) | — |
| 5. ACL via p2panda-auth | 🚧 In progress (5a/5b/5c done; 5d/5e pending) | 1–2 weeks remaining |
| 6. Swarm admission gate | 👉 Next after Phase 5 | 2–3 weeks |
| 7. D-Bus IPC surface | Planned | 2–3 weeks |
| 8. Linux UI | Planned | 4–6 weeks |
| 9. Cross-platform packaging | Planned | 4–8 weeks |
| 10. Production hardening | Planned | Ongoing |

**Phase 5 substep tracking** (mirrors `README.md`):

| Substep | State |
|---|---|
| 5a. Invite/join via copy-paste tickets | ✅ Done |
| 5b. Peer activity listing (`share peers`) | ✅ Done |
| 5c. `p2panda-auth` group CRDT integration | ✅ Done (members/revoke CLI, gossip, signed ops, `auth.log` persistence) |
| 5d. Auto key rotation on revocation | ⏳ TODO |
| 5e. 4-peer revocation e2e test | ⏳ TODO |

**Total to v1.0:** roughly 6–9 months of focused work, with phases 3–6 being
the technically meatiest.

---

## Phases

### Phase 1 — Foundation (done)

**Goal:** prove the panda+rqbit integration shape works.

**What landed:** single Rust binary with `p2panda-net` for gossip discovery
and `librqbit` for BT data transfer. CLI dispatch (`seed` / `leech`).
Hello-World folder transfer between two terminals on one machine.
`INTEGRATION_NOTES.md` capturing the load-bearing API findings.

**Why it mattered:** every subsequent phase assumes this integration shape.
Without a working baseline, the encryption, ACL, and admission-gate work
would be theoretical.

---

### Phase 2 — Persistent state & daemon (NEXT)

**Goal:** transform the one-shot demo into a long-running daemon that
manages multiple shares across restarts.

**Why this phase:** every phase from 3 onward needs a stable peerdup process
identity, persistent on-disk state, and the ability to manage more than one
share. Without this, you can't even test "does revoking a member rotate
the key" because there's no notion of a share that persists across two
runs.

**Key deliverables:**
- Persistent identity (keypair on disk, 0600 perms).
- Multi-share state directory layout.
- `peerdup serve` daemon mode managing N shares concurrently.
- CLI subcommands for share lifecycle (`add`, `list`, `remove`).
- Restart recovery: shares resume from disk state.

**Out of scope:**
- Encryption (Phase 4)
- ACL or membership (Phase 5)
- File watching for changes (Phase 3)
- IPC between CLI and daemon (Phase 7) — for now, CLI edits state files
  directly and changes take effect on daemon restart.

**Done criteria:** add two shares, start daemon, verify both transfer.
Stop daemon. Restart daemon. Verify both shares still work without
re-adding them.

**Detailed instructions:** see "Phase 2 detailed instructions" below.

---

### Phase 3 — Multi-master sync

**Goal:** turn the seed/leech split into bidirectional sync where every
peer is both seed and leech, with file changes propagating in both
directions.

**Why this phase:** the seed/leech distinction was a Hello-World scaffold.
peerdup's actual product is multi-master — any peer edits, all peers see.
This is where "BitTorrent for sync" stops being a metaphor and starts
being real.

**Key deliverables:**
- File watcher on each share's root path (use `notify` crate).
- Per-share monotonic version counter, per peer.
- Re-create torrent + announce on local change (debounced — bunch up
  rapid changes into a single new version).
- Receive announcements from other peers, fetch new torrents, apply changes
  to local filesystem.
- Conflict detection: when two peers advance from a common ancestor
  concurrently, surface a conflict.
- Conflict strategies: LWW (last-write-wins by timestamp), rename
  (keep both, rename one), pause-and-ask (mark conflicting and stop syncing
  until resolved).
- Rename optimization: detect file moves by name+size, avoid re-transferring
  bytes when a file just moved.

**Out of scope:**
- Encryption — content still goes over the wire as plaintext for now.
- Selective sync (sync only some files in a folder).
- Versioning / file history.

**Done criteria:** two peers, shared folder. Edit a file on peer A, see it
on peer B within seconds. Edit different files on both simultaneously, both
peers converge. Edit the same file on both, conflict surfaces according to
configured strategy.

**Why this is the biggest phase:** sync is hard. The actual peerdup product
lives or dies on whether this phase ships well. Budget more time than feels
right.

---

### Phase 4 — Encryption at rest

**Goal:** files are encrypted before being torrented; only group members
with the share key can decrypt.

**Why this phase:** without encryption, anyone who learns an info-hash can
leech the share. This is the first phase that gives peerdup a real
confidentiality story.

**Key deliverables:**
- `p2panda-encryption` integration for group key derivation.
- Per-share symmetric key with epoch counter.
- Encryption layer between peerdup's file representation and librqbit's
  torrent input. Files are encrypted to a per-share-key ciphertext blob
  before `create_torrent` sees them.
- Decryption on the receive side.
- Static placeholder for key rotation triggers (real triggers come in
  Phase 5).
- Epoch tracking: each torrent records which key epoch it was encrypted
  under, so old torrents stay readable after key rotation.

**Architecture decision to make early:** file-level encryption (encrypt each
file individually before torrenting, simpler, info-hash changes when key
rotates) vs. piece-level encryption (encrypt at librqbit's piece boundary,
deeper integration but better for incremental updates). **Recommendation:**
file-level for v1. Piece-level can come later as an optimization.

**Out of scope:**
- Member-triggered key rotation (Phase 5).
- Forward secrecy beyond what `p2panda-encryption` provides by default.
- Key escrow or recovery.

**Done criteria:** two peers with the same group key see normal sync. A
third peer with the wrong key (or no key) cannot decrypt anything even if
it learns the info-hash. Rotating the key (manually triggered for now)
produces a new info-hash for new content; old content remains readable
with the old key.

---

### Phase 5 — ACL via p2panda-auth

**Goal:** real membership management. Owners and writers can grant and
revoke members. Membership is a CRDT, not a registry row.

**Why this phase:** without ACL, "the share key" is just a shared secret
known by everyone who's ever joined. Revocation is impossible — once a
peer has the key, they have it forever. ACL gives you proper membership
semantics including post-compromise security.

**Key deliverables:**
- `p2panda-auth` group per share. Owner = share creator.
- Roles: owner, writer, reader. Writers can publish new versions; readers
  can only consume.
- `peerdup share invite <id>` produces a ticket that grants a role.
- `peerdup share join <ticket>` consumes a ticket to gain access.
- `peerdup share members <id>` lists current members.
- `peerdup share revoke <id> <peer>` removes a member.
- Revocation triggers a key rotation in the `p2panda-encryption` layer
  (Phase 4 placeholder gets wired up).
- Auth state synced over the same gossip topic.

**Out of scope:**
- Capability-based granularity beyond owner/writer/reader.
- Per-file ACL (some peers can read some files, not others).
- Time-limited invitations.

**Done criteria:** four-peer scenario. Peer A creates share, invites B and
C as writers. They sync. A revokes B. New content from A and C is unreadable
to B; B's continued participation in the swarm is rejected.
Last bit becomes real in Phase 6.

---

### Phase 6 — Swarm admission gate (BEP-10)

**Goal:** the auth layer actually enforces against the BT data plane.
Revoked peers are dropped from the swarm, not just denied the new key.

**Why this phase:** until this lands, a revoked peer can still
participate in the swarm and see metadata, attempt connections, etc.,
even if they can't decrypt new content. This phase closes that gap.

**Key deliverables:**
- BEP-10 extension protocol message added to peerdup's BT exchange.
- On peer connect (incoming or outgoing), verify counterpart is a current
  member of the share via auth proof.
- Reject the BT connection if not a current member.
- librqbit hook for this: investigate whether it can be done as a
  callback / interceptor, or whether peerdup needs to fork/PR an
  extension hook upstream.

**Out of scope:**
- Hole-punching coordination (Phase 10).
- Performance optimization of the handshake.

**Done criteria:** revoked peer (from Phase 5 scenario) cannot establish
BT connections to other members. Logs on both sides show admission
denied. Existing connections to that peer are dropped.

**Risk to flag:** this phase may require upstream contribution to librqbit
to expose the right hooks. Open the conversation with ikatson early.

---

### Phase 7 — D-Bus IPC surface

**Goal:** the daemon exposes a stable API that other processes (CLI,
GNOME extension, GTK app) can call.

**Why this phase:** Phase 2's "CLI edits state files, daemon picks it up
on restart" is a placeholder. Real UX needs the CLI and the daemon to
talk live. Phase 8's Shell extension absolutely requires it (the
extension is JS in gnome-shell's process — IPC is the only path).

**Key deliverables:**
- `zbus`-based D-Bus service exposing share lifecycle, member management,
  status, events.
- Refactor CLI subcommands to talk to the daemon over D-Bus instead of
  editing files.
- Auto-spawn daemon if not running (via systemd user service, or direct
  fork).
- Stable `org.peerdup.Daemon` interface contract — versioned, documented.

**Out of scope:**
- Non-D-Bus IPC for non-Linux platforms (Phase 9).
- GraphQL or HTTP API.

**Done criteria:** all CLI commands work against a running daemon over
D-Bus. `busctl` introspection shows the API. The daemon emits signals
for share state changes that a future client can subscribe to.

---

### Phase 8 — Linux UI

**Goal:** users get a desktop experience that fits GNOME, not just a
terminal.

**Why this phase:** peerdup's audience is "people who want sync that
works without a server" — many of them are not terminal-first. The
GNOME shell extension is what makes peerdup feel like a system feature
rather than an app.

**Key deliverables:**
- GNOME Shell extension (JavaScript, in gnome-shell's GJS runtime).
  - Status indicator in the top bar.
  - Per-share list with sync state.
  - Notifications for conflicts, completed syncs, member changes.
  - All state via D-Bus (Phase 7's interface).
- Optional GTK4 + libadwaita app for heavier UI.
  - Share management (add/remove, change root path).
  - Member management UI.
  - Conflict resolution UI.
  - Could ship later than the extension; not v1-blocking.

**Out of scope:**
- KDE / other desktop integrations.
- Mobile.

**Done criteria:** install peerdup, install the extension, see the
status indicator. Add a share via the indicator menu. Watch the icon
update during sync. Get a notification when a peer joins.

---

### Phase 9 — Cross-platform packaging

**Goal:** Windows and macOS users can install peerdup.

**Why this phase:** until this lands, peerdup is "a Linux thing,"
which significantly caps the audience. The Rust consolidation makes
this dramatically more feasible than the original Python+libtorrent
stack would have allowed.

**Key deliverables:**
- Windows: x64 and arm64 builds via `cargo-xwin` or Windows runners,
  signed installer (MSI via `cargo-wix`), winget manifest.
- macOS: x64 and arm64 builds, signed and notarized `.app` bundle, dmg
  installer or Homebrew formula.
- Linux: Flatpak via Flathub for non-distro-managed installs, in
  addition to whatever the distro packagers do.
- Per-platform UI choice:
  - Windows/macOS: GTK4 app (Phase 8) is the primary UI; no shell
    extension equivalent.
  - Or: native system tray + window approach using a smaller cross-platform
    toolkit. Decide before this phase starts.
- Code-signing infrastructure (Authenticode certificate for Windows,
  Apple Developer ID for macOS).

**Out of scope:**
- Mobile platforms.
- Microsoft Store / Mac App Store distribution (these require their
  own packaging formats).

**Done criteria:** fresh Windows machine, fresh macOS machine, fresh
Linux machine. Install peerdup on each. Add the same share. Files sync
across all three.

---

### Phase 10 — Production hardening (ongoing)

**Goal:** peerdup is reliable under real-world conditions.

**Key deliverables (sequenced as discovered):**
- Hole-punching coordination via panda's iroh layer for peers behind
  NATs (replaces the BEP-55 we decided not to implement).
- Relay fallback for symmetric NATs (small self-hostable relay component).
- Telemetry: opt-in metrics for sync performance, error rates.
- Crash reporting (opt-in).
- Documentation: user docs, operator docs, API reference, threat model.
- Performance tuning: memory usage with many shares, large folders,
  many peers.
- Migration tooling for users coming from Syncthing or other tools.
- Security audit before any "stable" release.

**Done criteria:** define when v1.0 ships. Suggested bar:
- 100+ users running for a month with no data-loss bug reports.
- All Phase 1–9 deliverables landed.
- Documented security model reviewed externally.

---

# Phase 2 detailed instructions

This is the next milestone. Goal is to turn the demo into a daemon
managing multiple shares across restarts. Estimated 2–3 weeks.

## Step 0 — pick a state directory

Use the `directories` crate (already commonly used in Rust) to resolve a
platform-appropriate location:

```rust
use directories::ProjectDirs;

let dirs = ProjectDirs::from("", "peerdup", "peerdup")
    .ok_or_else(|| anyhow!("can't resolve project dirs"))?;
let data_dir = dirs.data_dir();   // ~/.local/share/peerdup on Linux
let config_dir = dirs.config_dir(); // ~/.config/peerdup on Linux
```

Allow override via `--data-dir <path>` flag for testing.

## Step 1 — define on-disk layout

```
$DATA_DIR/peerdup/
├── identity.key              # 32 bytes Ed25519 private key, 0600
├── state.json                # top-level: schema_version, peer_id_hex
├── daemon.lock               # exclusive lock file (prevents two daemons)
└── shares/
    ├── <share-id>/
    │   ├── share.json        # ShareConfig (topic, root_path, role, created_at)
    │   └── librqbit-state/   # librqbit's working dir for this share
    └── <share-id>/
        ├── share.json
        └── librqbit-state/
```

`<share-id>` is `hex(blake3(topic_bytes))` truncated to 16 chars. Stable
across runs given the same topic.

## Step 2 — implement identity persistence

Replace the current `PrivateKey::new()` with load-or-create:

```rust
fn load_or_create_identity(path: &Path) -> Result<PrivateKey> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let bytes: [u8; 32] = bytes.try_into()
            .map_err(|_| anyhow!("identity.key wrong length"))?;
        Ok(PrivateKey::from_bytes(&bytes))   // verify exact API
    } else {
        let key = PrivateKey::new();
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(path, key.as_bytes())?; // verify exact API
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(key)
    }
}
```

**Verify:** `PrivateKey::from_bytes` and `as_bytes` are the actual
`p2panda-core` accessors. If not, find the equivalents.

## Step 3 — define share types

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShareConfig {
    pub id: String,             // hex(blake3(topic))[..16]
    pub topic: String,           // human-readable, hashed for topic id
    pub root_path: PathBuf,
    pub role: ShareRole,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ShareRole {
    Seed,    // we have the source data, others fetch from us
    Leech,   // we want the data, others have it
    Sync,    // bidirectional (Phase 3 — out of scope here)
}
```

For Phase 2, only `Seed` and `Leech` exist. `Sync` is Phase 3.

`ShareConfig` is persisted as `shares/<id>/share.json`. Use
`serde_json::to_writer_pretty` for human-readability.

## Step 4 — daemon lock

Prevent two daemons running on the same data dir:

```rust
// Add to Cargo.toml: fs2 = "0.4"
use fs2::FileExt;

let lock_path = data_dir.join("daemon.lock");
let lock_file = std::fs::OpenOptions::new()
    .create(true).write(true).open(&lock_path)?;
lock_file.try_lock_exclusive()
    .map_err(|_| anyhow!("another peerdup daemon is already running"))?;
// hold lock_file for the daemon's lifetime; lock releases on drop
```

## Step 5 — restructure CLI

Replace the current top-level CLI with subcommands:

```rust
#[derive(Parser)]
#[command(name = "peerdup")]
struct Cli {
    /// Override data directory (default: $XDG_DATA_HOME/peerdup)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon: manages all configured shares until stopped.
    Serve,
    /// Add a new share (modifies state; takes effect on next daemon start).
    ShareAdd {
        #[arg(long)]
        topic: String,
        #[arg(long)]
        path: PathBuf,
        #[arg(long, value_enum)]
        role: ShareRoleArg,
    },
    /// List configured shares.
    ShareList,
    /// Remove a share.
    ShareRemove { id: String },
}
```

Phase 2 limitation, document loudly: `share-add` and `share-remove`
write to disk but do NOT notify a running daemon. Daemon must restart
to pick up changes. Phase 7 fixes this with D-Bus.

## Step 6 — daemon implementation

Pseudocode for `peerdup serve`:

```rust
async fn serve(data_dir: &Path) -> Result<()> {
    let _lock = acquire_daemon_lock(data_dir)?;
    let identity = load_or_create_identity(&data_dir.join("identity.key"))?;
    tracing::info!(peer_id = %identity.public_key(), "daemon starting");

    // Bring up panda layer (same as Hello-World).
    let address_book = AddressBook::builder().spawn().await?;
    let endpoint = Endpoint::builder(address_book.clone())
        .private_key(identity).spawn().await?;
    let _mdns = MdnsDiscovery::builder(/* ... */).spawn().await?;
    let _discovery = Discovery::builder(/* ... */).spawn().await?;
    let gossip = Gossip::builder(/* ... */).spawn().await?;

    // One librqbit Session for the whole daemon — librqbit can manage
    // multiple torrents in one session.
    let session = create_session(data_dir).await?;

    // Load all configured shares from disk.
    let configs = load_share_configs(&data_dir.join("shares"))?;
    tracing::info!(count = configs.len(), "loaded shares");

    // Spawn one task per share.
    let mut tasks = JoinSet::new();
    for config in configs {
        let share_task = run_share(
            config,
            session.clone(),
            gossip.clone(),
            data_dir.to_path_buf(),
        );
        tasks.spawn(share_task);
    }

    // Wait for shutdown signal or any task crash.
    tokio::select! {
        _ = shutdown_signal() => {
            tracing::info!("shutdown requested");
        }
        Some(result) = tasks.join_next() => {
            tracing::error!(?result, "share task exited unexpectedly");
        }
    }

    tasks.shutdown().await;
    Ok(())
}

async fn run_share(
    config: ShareConfig,
    session: Arc<Session>,
    gossip: Gossip,
    data_dir: PathBuf,
) -> Result<()> {
    let topic = TopicId::from(Hash::new(config.topic.as_bytes()));
    match config.role {
        ShareRole::Seed => seed_loop(config, session, gossip, topic).await,
        ShareRole::Leech => leech_loop(config, session, gossip, topic, data_dir).await,
        ShareRole::Sync => Err(anyhow!("Sync role is not implemented in Phase 2")),
    }
}
```

The seed/leech functions are mostly the existing code from Phase 1, but:
- Seed announces forever, doesn't return.
- Leech, after `Download completed`, switches to seeding mode (re-announce
  the same torrent so other peers can join from us). For Phase 2 this is
  optional; the simplest version just exits the leech loop after completion.
  Document the choice in INTEGRATION_NOTES.

## Step 7 — restart recovery

The trick is that librqbit handles its own resume data. When you call
`session.add_torrent` for a torrent it has seen before (matching info-hash),
it should resume rather than restart. Verify this is true; if not, peerdup
needs to track "have we already added this torrent" itself.

The expected restart flow:
1. Daemon stops, `daemon.lock` released.
2. librqbit's working dir under `shares/<id>/librqbit-state/` retains
   resume data.
3. Daemon starts, loads share configs.
4. For each share, `run_share` calls `add_torrent`; librqbit picks up
   from where it left off.
5. Gossip rejoins the topic; announcements resume.

## Step 8 — graceful shutdown

```rust
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).unwrap();
        let mut int = signal(SignalKind::interrupt()).unwrap();
        tokio::select! {
            _ = term.recv() => {},
            _ = int.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
}
```

On shutdown, allow each share task a few seconds to flush state, then
hard-cancel.

## Step 9 — testing protocol

Manual end-to-end test that proves the milestone:

```bash
# Setup two data dirs to simulate two peers on one machine
export PEER_A=/tmp/peerdup-test-a
export PEER_B=/tmp/peerdup-test-b
rm -rf $PEER_A $PEER_B

# Create source data
mkdir -p /tmp/peerdup-source
echo "alpha" > /tmp/peerdup-source/file1.txt
echo "beta"  > /tmp/peerdup-source/file2.txt

# Add share on peer A as seeder
./target/debug/peerdup --data-dir $PEER_A share-add \
    --topic demo --path /tmp/peerdup-source --role seed

# Add share on peer B as leecher, writing to a different output dir
./target/debug/peerdup --data-dir $PEER_B share-add \
    --topic demo --path /tmp/peerdup-output-b --role leech

# Start daemon A, then B (in separate terminals)
./target/debug/peerdup --data-dir $PEER_A serve
./target/debug/peerdup --data-dir $PEER_B serve

# Verify B got the files
diff -r /tmp/peerdup-source /tmp/peerdup-output-b

# Stop both daemons (Ctrl-C). Restart both.
# Verify they come back up without re-adding shares.
# Verify INTEGRATION_NOTES gets a note about whether librqbit resumed
# cleanly or had to re-fetch.

# Add a second share on both, repeat. Verify both work concurrently.
```

## Step 10 — done criteria checklist

Tick all of these before declaring Phase 2 done:

- [ ] Identity persists across restarts (same peer ID after stop/start)
- [ ] `share-add` writes a valid `share.json` to disk
- [ ] `share-list` reads and displays configured shares
- [ ] `share-remove` deletes a share's directory
- [ ] `serve` starts, loads all configured shares, runs them concurrently
- [ ] Two daemons cannot run on the same `data_dir` (lock works)
- [ ] Daemon shuts down cleanly on SIGTERM / Ctrl-C
- [ ] Daemon restart resumes shares without re-adding them
- [ ] Multi-share works: two shares on the same daemon don't interfere
- [ ] `INTEGRATION_NOTES.md` updated with: librqbit resume behavior,
      identity API actual names, any gotchas found

## What to flag back to the next agent

After Phase 2 ships, the next agent (Phase 3, multi-master sync) will
want answers to:

1. Does librqbit support adding files to an existing torrent, or do
   changes always require a new torrent (new info-hash)? This determines
   how change detection works.
2. What's the latency from "file changes on disk" to "torrent re-created
   and announced"? If high, the file watcher needs aggressive debouncing.
3. Does librqbit emit events for torrent state changes (started, paused,
   completed, peer connected) that we can subscribe to? Phase 7's D-Bus
   signals will need this.

Note these in `INTEGRATION_NOTES.md` as you discover them, even if they
don't block Phase 2.

---

# Notes on this roadmap

The phasing above is a best guess made before Phase 2 has happened.
Reality will reveal that some phases are smaller than expected and others
are larger. The order is more confident than the sizes — Phase 5 must
follow Phase 4 because revocation needs encryption to mean anything;
Phase 6 must follow Phase 5 because admission needs ACL to check against;
Phase 7 must follow Phase 6 because the IPC surface needs the operations
it exposes to actually exist.

Phases 8 and 9 can be partly parallelized once Phase 7 is in. Phase 10
runs continuously alongside everything from Phase 5 onward.

If at any phase boundary the next phase looks bigger than the budget
estimate above by 2x or more, stop and reconsider scope before proceeding.
