mod auth;
mod clock;
mod crypto;
mod daemon;
mod data_dir;
mod identity;
mod lock;
mod share;
mod share_state;
mod ticket;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use share::{ShareConfig, ShareRole};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "peerdup", about = "p2panda + librqbit folder sync")]
struct Cli {
    /// Override data directory. Default: $XDG_DATA_HOME/peerdup on Linux.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon: bring up panda + librqbit, run all configured shares
    /// concurrently until SIGINT/SIGTERM.
    Serve {
        /// BitTorrent listen port. Defaults to 41000. Pick distinct ports
        /// for two daemons on one machine.
        #[arg(long, default_value_t = 41000)]
        bt_port: u16,
    },
    /// Add a new share. Writes to disk; a running daemon will not pick it up
    /// until restart (Phase 7 will fix this).
    ShareAdd {
        /// Logical topic string. Hashed into the gossip topic id; both peers
        /// must use the same topic to find each other.
        #[arg(long)]
        topic: String,
        /// Path to the folder this share covers. For seeders, this is the
        /// source. For leechers, this is where files will be written.
        #[arg(long)]
        path: PathBuf,
        /// Role for this peer in the share.
        #[arg(long, value_enum)]
        role: ShareRole,
    },
    /// List configured shares.
    ShareList,
    /// Remove a share by id. Daemon restart required for the change to take effect.
    ShareRemove { id: String },
    /// Rotate the encryption key for a share. Generates a new key, appends
    /// it to the keyring (as a new epoch). Old ciphertexts encrypted under
    /// previous epochs remain decryptable. Daemon restart picks up the new
    /// key for re-encryption of new content.
    ShareRotateKey { id: String },
    /// Print an invitation ticket for a share. Adds the invitee to the
    /// share's auth group as a side effect, so the daemon picks up the new
    /// member on its next start. The ticket contains the share's keyring
    /// and an auth-log snapshot; send it only over secure channels.
    ShareInvite {
        id: String,
        /// Invitee's 64-char hex public key (from `peerdup whoami` on their
        /// machine). The new `Add` op binds this key as a member.
        invitee_pubkey: String,
        /// Transport role to suggest for the receiving peer (Seed/Leech/Sync).
        #[arg(long, value_enum, default_value = "sync")]
        role: ShareRole,
        /// Auth-level role: owner (manage), writer, or reader. Default writer.
        #[arg(long, value_enum, default_value = "writer")]
        auth_role: auth::AuthRole,
    },
    /// Consume an invitation ticket: register the share locally, import
    /// its keyring, and replay the embedded auth log. The receiver picks
    /// the local path for their working copy.
    ShareJoin {
        /// Base64 ticket string from `share invite`.
        ticket: String,
        /// Local folder where this peer's working copy lives.
        #[arg(long)]
        path: PathBuf,
    },
    /// List peers observed in this share's history. This is activity-based,
    /// not ACL-based — it shows everyone whose edits we've seen via vector
    /// clock entries. For ACL-based membership, use `share members`.
    SharePeers { id: String },
    /// List current ACL members and their roles for a share. Reads the
    /// local replay of the share's auth log.
    ShareMembers { id: String },
    /// Revoke a member from a share's auth group. Authors a `Remove` op
    /// signed with the local identity; the change propagates to other
    /// peers via gossip on next daemon tick. Phase 5d will additionally
    /// trigger an encryption-key rotation; for now this only updates the
    /// membership CRDT.
    ShareRevoke {
        id: String,
        /// 64-char hex public key of the member to remove.
        peer_pubkey: String,
    },
    /// Print this daemon's identity public key. Share this with an inviter
    /// so they can pass it to `share invite`.
    Whoami,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_peerdup=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let data_dir = data_dir::resolve(cli.data_dir)?;

    match cli.cmd {
        Cmd::Serve { bt_port } => cmd_serve(data_dir, bt_port).await,
        Cmd::ShareAdd { topic, path, role } => cmd_share_add(data_dir, topic, path, role),
        Cmd::ShareList => cmd_share_list(data_dir),
        Cmd::ShareRemove { id } => cmd_share_remove(data_dir, id),
        Cmd::ShareRotateKey { id } => cmd_share_rotate_key(data_dir, id),
        Cmd::ShareInvite {
            id,
            invitee_pubkey,
            role,
            auth_role,
        } => cmd_share_invite(data_dir, id, invitee_pubkey, role, auth_role),
        Cmd::ShareJoin { ticket, path } => cmd_share_join(data_dir, ticket, path),
        Cmd::SharePeers { id } => cmd_share_peers(data_dir, id),
        Cmd::ShareMembers { id } => cmd_share_members(data_dir, id),
        Cmd::ShareRevoke { id, peer_pubkey } => cmd_share_revoke(data_dir, id, peer_pubkey),
        Cmd::Whoami => cmd_whoami(data_dir),
    }
}

async fn cmd_serve(data_dir: PathBuf, bt_port: u16) -> Result<()> {
    std::fs::create_dir_all(&data_dir)?;
    let lock_file = lock::acquire(&data_dir::lock_path(&data_dir))?;
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let configs = share::load_all(&data_dir)?;
    let result = daemon::serve(data_dir, bt_port, identity, configs).await;
    drop(lock_file);
    result
}

fn cmd_share_add(
    data_dir: PathBuf,
    topic: String,
    path: PathBuf,
    role: ShareRole,
) -> Result<()> {
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    if matches!(role, ShareRole::Seed) && !path.exists() {
        return Err(anyhow!("seed path does not exist: {path:?}"));
    }
    let config = ShareConfig::new(topic, path, role);
    config.save(&data_dir)?;

    // Bootstrap the share's auth group with this peer as Owner. `share-add`
    // is the creator path; `share-join` is where a non-creator imports an
    // existing log instead of creating one.
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let group_id = auth::group_id_for(&config.id);
    let mut auth_state = auth::AuthState::empty();
    auth_state.create_group(&identity, group_id)?;
    auth::save(&data_dir, &config.id, &auth_state)?;

    println!("Added share {} ({})", config.id, config.topic);
    println!(
        "Auth group bootstrapped with {} as owner",
        identity.public_key().to_hex()
    );
    Ok(())
}

fn cmd_share_list(data_dir: PathBuf) -> Result<()> {
    let configs = share::load_all(&data_dir)?;
    if configs.is_empty() {
        println!("No shares configured at {:?}", data_dir);
        return Ok(());
    }
    println!("{:<18} {:<8} {:<20} {}", "ID", "ROLE", "TOPIC", "PATH");
    for c in configs {
        let role = format!("{:?}", c.role).to_lowercase();
        println!(
            "{:<18} {:<8} {:<20} {}",
            c.id,
            role,
            truncate(&c.topic, 20),
            c.root_path.display()
        );
    }
    Ok(())
}

fn cmd_share_rotate_key(data_dir: PathBuf, id: String) -> Result<()> {
    let configs = share::load_all(&data_dir)?;
    if !configs.iter().any(|c| c.id == id) {
        return Err(anyhow!("share {id} not found"));
    }
    let new_epoch = crypto::rotate_keyring(&data_dir, &id)?;
    println!("Rotated share {id}: new epoch is {new_epoch}");
    println!("(running daemon will not see this change until restart)");
    println!(
        "Distribute the updated keys.bin to other peers; without it they cannot read content \
         encrypted under epoch {new_epoch}."
    );
    Ok(())
}

fn cmd_share_peers(data_dir: PathBuf, id: String) -> Result<()> {
    let configs = share::load_all(&data_dir)?;
    if !configs.iter().any(|c| c.id == id) {
        return Err(anyhow!("share {id} not found"));
    }

    let me = identity::load_or_create(&data_dir::identity_path(&data_dir))
        .map(|k| k.public_key().to_hex())
        .ok();

    let state = share_state::load(&data_dir, &id)?;
    let Some(state) = state else {
        println!("share {id}: no peer activity recorded yet");
        return Ok(());
    };

    let mut peers: Vec<(&String, &u64)> = state.clock.0.iter().collect();
    peers.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    println!("{:<66} {:>9} {}", "PEER_ID", "VERSIONS", "");
    for (peer, ctr) in peers {
        let marker = if me.as_deref() == Some(peer) { "(self)" } else { "" };
        println!("{:<66} {:>9} {}", peer, ctr, marker);
    }
    Ok(())
}

fn cmd_share_members(data_dir: PathBuf, id: String) -> Result<()> {
    let configs = share::load_all(&data_dir)?;
    if !configs.iter().any(|c| c.id == id) {
        return Err(anyhow!("share {id} not found"));
    }
    let auth_state = auth::load(&data_dir, &id)?;
    if auth_state.is_empty() {
        println!("share {id}: no auth state on disk");
        return Ok(());
    }
    let group_id = auth::group_id_for(&id);
    let me = identity::load_or_create(&data_dir::identity_path(&data_dir))
        .map(|k| auth::MemberId(*k.public_key().as_bytes()))
        .ok();
    let mut members = auth_state.members(group_id);
    members.sort_by_key(|(m, _)| m.0);
    println!("{:<66} {:<8} {}", "PEER_PUBKEY", "ROLE", "");
    for (m, role) in members {
        let marker = if Some(m) == me { "(self)" } else { "" };
        println!("{:<66} {:<8} {marker}", m.to_hex(), role);
    }
    Ok(())
}

fn cmd_share_revoke(data_dir: PathBuf, id: String, peer_pubkey_hex: String) -> Result<()> {
    let configs = share::load_all(&data_dir)?;
    if !configs.iter().any(|c| c.id == id) {
        return Err(anyhow!("share {id} not found"));
    }
    let target = auth::MemberId::from_hex(&peer_pubkey_hex)
        .context("parsing peer public key")?;
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let group_id = auth::group_id_for(&id);
    let mut auth_state = auth::load(&data_dir, &id)?;
    if auth_state.is_empty() {
        return Err(anyhow!("share {id} has no auth state on disk"));
    }
    if !auth_state.is_member(group_id, target) {
        return Err(anyhow!(
            "{} is not a current member of share {id}",
            peer_pubkey_hex
        ));
    }
    auth_state.remove_member(&identity, group_id, target)?;
    auth::save(&data_dir, &id, &auth_state)?;
    println!("Revoked {} from share {id}", peer_pubkey_hex);
    println!("(running daemon will not see this change until restart; key rotation lands in 5d)");
    Ok(())
}

fn cmd_whoami(data_dir: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&data_dir)?;
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    println!("{}", identity.public_key().to_hex());
    Ok(())
}

fn cmd_share_invite(
    data_dir: PathBuf,
    id: String,
    invitee_pubkey_hex: String,
    role: ShareRole,
    auth_role: auth::AuthRole,
) -> Result<()> {
    let configs = share::load_all(&data_dir)?;
    let cfg = configs
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| anyhow!("share {id} not found"))?;
    let invitee = auth::MemberId::from_hex(&invitee_pubkey_hex)
        .context("parsing invitee public key")?;
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let group_id = auth::group_id_for(&id);

    // Replay existing log, then author and persist the new Add op.
    let mut auth_state = auth::load(&data_dir, &id)?;
    if auth_state.is_empty() {
        return Err(anyhow!(
            "share {id} has no auth state on disk; can only invite from the creator's machine \
             (re-run `share-add` if this is a fresh state directory)"
        ));
    }
    if auth_state.is_member(group_id, invitee) {
        return Err(anyhow!(
            "{} is already a member of share {id}",
            invitee_pubkey_hex
        ));
    }
    auth_state.add_member(&identity, group_id, invitee, auth_role)?;
    auth::save(&data_dir, &id, &auth_state)?;

    let ring = crypto::load_or_create_keyring(&data_dir, &id)?;
    let ticket = ticket::Ticket {
        version: ticket::TICKET_VERSION,
        share_id: cfg.id.clone(),
        topic: cfg.topic.clone(),
        keys: ring.export_keys(),
        auth_log: auth_state.ops().to_vec(),
        invitee_pubkey: invitee.0,
        role,
    };
    let encoded = ticket.encode()?;
    eprintln!("# Send this string to the joining peer over a secure channel");
    eprintln!("# (Signal, encrypted email, etc.). Anyone who has it can read");
    eprintln!("# the share's content under the current keyring.");
    eprintln!();
    println!("{encoded}");
    Ok(())
}

fn cmd_share_join(data_dir: PathBuf, ticket_str: String, path: PathBuf) -> Result<()> {
    let ticket = ticket::Ticket::decode(&ticket_str)?;
    let configs = share::load_all(&data_dir)?;
    if configs.iter().any(|c| c.id == ticket.share_id) {
        return Err(anyhow!(
            "share {} is already configured locally; remove it first if you want to re-join",
            ticket.share_id
        ));
    }

    // Verify the ticket targets us. Mismatched pubkeys are almost always
    // operator error (wrong invitee fed to `share-invite`) — fail loudly
    // rather than join with a key the auth log doesn't recognise.
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let me = *identity.public_key().as_bytes();
    if ticket.invitee_pubkey != me {
        return Err(anyhow!(
            "ticket was issued for a different public key (expected {}, this peer is {}); \
             ask the inviter to re-run `share invite` with the correct key",
            auth::MemberId(ticket.invitee_pubkey).to_hex(),
            identity.public_key().to_hex()
        ));
    }

    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    std::fs::create_dir_all(&path)?;

    // Build the local ShareConfig from the ticket. The id and topic come
    // from the ticket so all peers agree; root_path is local.
    let cfg = ShareConfig {
        id: ticket.share_id.clone(),
        topic: ticket.topic.clone(),
        root_path: path,
        role: ticket.role,
        created_at: chrono::Utc::now(),
    };
    cfg.save(&data_dir)?;

    // Write keys.bin from the imported keyring.
    crypto::install_keyring(&data_dir, &ticket.share_id, &ticket.keys)?;

    // Replay the auth log. We pass each op through `apply_remote` so it is
    // signature-verified and dependency-checked exactly like a gossip arrival.
    let mut auth_state = auth::AuthState::empty();
    for op in &ticket.auth_log {
        auth_state.apply_remote(op.clone()).with_context(|| {
            format!("applying auth log op while joining share {}", ticket.share_id)
        })?;
    }
    let group_id = auth::group_id_for(&ticket.share_id);
    if !auth_state.is_member(group_id, auth::MemberId(me)) {
        return Err(anyhow!(
            "ticket's auth log does not list us as a member; refusing to join"
        ));
    }
    auth::save(&data_dir, &ticket.share_id, &auth_state)?;

    println!(
        "Joined share {} ({}) at {}",
        cfg.id,
        cfg.topic,
        cfg.root_path.display()
    );
    println!(
        "Imported {} key{} (current epoch: {})",
        ticket.keys.len(),
        if ticket.keys.len() == 1 { "" } else { "s" },
        ticket.keys.len()
    );
    println!(
        "Imported {} auth op{}; {} current member{}",
        ticket.auth_log.len(),
        if ticket.auth_log.len() == 1 { "" } else { "s" },
        auth_state.members(group_id).len(),
        if auth_state.members(group_id).len() == 1 {
            ""
        } else {
            "s"
        }
    );
    Ok(())
}

fn cmd_share_remove(data_dir: PathBuf, id: String) -> Result<()> {
    // Look up the share's root_path (if still resolvable) so we can also
    // clean its `.peerdup` shadow dir.
    let configs = share::load_all(&data_dir)?;
    let root = configs
        .iter()
        .find(|c| c.id == id)
        .map(|c| c.root_path.clone());

    share::remove(&data_dir, &id)?;
    if let Some(root) = root {
        let shadow_parent = root.join(".peerdup");
        if shadow_parent.exists() {
            if let Err(e) = std::fs::remove_dir_all(&shadow_parent) {
                eprintln!(
                    "warning: could not remove {}: {e}",
                    shadow_parent.display()
                );
            }
        }
    }
    println!("Removed share {id}");
    println!("(running daemon will not see this change until restart)");
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}
