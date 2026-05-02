mod auth;
mod client;
mod clock;
mod crypto;
mod daemon;
mod data_dir;
mod identity;
mod ipc;
mod lock;
mod rotation;
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
    ///
    /// **Routing semantics (Phase 7):**
    ///
    /// - With `serve`: tells the daemon where to keep its state.
    /// - With a client subcommand: opts out of D-Bus entirely and runs the
    ///   command directly against the on-disk state. Useful for headless
    ///   environments without a session bus (e.g. container test rigs).
    ///   Daemon-not-running notes about "running daemon will not see this
    ///   change until restart" apply in this mode.
    /// - With no flag and a client subcommand: routes through D-Bus to the
    ///   running daemon, auto-activating it on first call.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon: bring up panda + librqbit, run all configured shares
    /// concurrently until SIGINT/SIGTERM. Registers `org.peerdup.Daemon1`
    /// on the session bus so the CLI can drive it live.
    Serve {
        /// BitTorrent listen port. Defaults to 41000. Pick distinct ports
        /// for two daemons on one machine.
        #[arg(long, default_value_t = 41000)]
        bt_port: u16,
        /// Skip D-Bus session-bus registration. Useful for headless test
        /// rigs that don't have a session bus or want to avoid bus-name
        /// collisions across multiple in-process daemons. The daemon also
        /// auto-skips IPC when no session bus is detected.
        #[arg(long, default_value_t = false)]
        no_dbus: bool,
    },
    /// Add a new share. With `--data-dir` set, writes to disk directly
    /// (Phase 2 semantics — daemon restart required to pick up). Without
    /// `--data-dir`, calls `ShareAdd` over D-Bus on the running daemon.
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
    /// Remove a share by id.
    ShareRemove { id: String },
    /// Rotate the encryption key for a share. Generates a new key, appends
    /// it to the keyring (as a new epoch). Old ciphertexts encrypted under
    /// previous epochs remain decryptable.
    ShareRotateKey { id: String },
    /// Print an invitation ticket for a share. Adds the invitee to the
    /// share's auth group as a side effect.
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
    /// its keyring, replay the auth log.
    ShareJoin {
        /// Base64 ticket string from `share invite`.
        ticket: String,
        /// Local folder where this peer's working copy lives.
        #[arg(long)]
        path: PathBuf,
    },
    /// List peers observed in this share's history. Activity-based, not
    /// ACL-based — for ACL membership use `share members`.
    SharePeers { id: String },
    /// List current ACL members and their roles for a share.
    ShareMembers { id: String },
    /// Revoke a member from a share's auth group.
    ShareRevoke {
        id: String,
        /// 64-char hex public key of the member to remove.
        peer_pubkey: String,
    },
    /// Print this daemon's identity public key.
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
    let direct_dir = cli.data_dir.clone();

    match cli.cmd {
        Cmd::Serve { bt_port, no_dbus } => {
            let data_dir = data_dir::resolve(direct_dir)?;
            cmd_serve(data_dir, bt_port, !no_dbus).await
        }
        Cmd::ShareAdd { topic, path, role } => match direct_dir {
            Some(dd) => cmd_share_add_direct(dd, topic, path, role),
            None => cmd_share_add(topic, path, role).await,
        },
        Cmd::ShareList => match direct_dir {
            Some(dd) => cmd_share_list_direct(dd),
            None => cmd_share_list().await,
        },
        Cmd::ShareRemove { id } => match direct_dir {
            Some(dd) => cmd_share_remove_direct(dd, id),
            None => cmd_share_remove(id).await,
        },
        Cmd::ShareRotateKey { id } => match direct_dir {
            Some(dd) => cmd_share_rotate_key_direct(dd, id),
            None => cmd_share_rotate_key(id).await,
        },
        Cmd::ShareInvite {
            id,
            invitee_pubkey,
            role,
            auth_role,
        } => match direct_dir {
            Some(dd) => cmd_share_invite_direct(dd, id, invitee_pubkey, role, auth_role),
            None => cmd_share_invite(id, invitee_pubkey, role, auth_role).await,
        },
        Cmd::ShareJoin { ticket, path } => match direct_dir {
            Some(dd) => cmd_share_join_direct(dd, ticket, path),
            None => cmd_share_join(ticket, path).await,
        },
        Cmd::SharePeers { id } => match direct_dir {
            Some(dd) => cmd_share_peers_direct(dd, id),
            None => cmd_share_peers(id).await,
        },
        Cmd::ShareMembers { id } => match direct_dir {
            Some(dd) => cmd_share_members_direct(dd, id),
            None => cmd_share_members(id).await,
        },
        Cmd::ShareRevoke { id, peer_pubkey } => match direct_dir {
            Some(dd) => cmd_share_revoke_direct(dd, id, peer_pubkey),
            None => cmd_share_revoke(id, peer_pubkey).await,
        },
        Cmd::Whoami => match direct_dir {
            Some(dd) => cmd_whoami_direct(dd),
            None => cmd_whoami().await,
        },
    }
}

async fn cmd_serve(data_dir: PathBuf, bt_port: u16, register_dbus: bool) -> Result<()> {
    std::fs::create_dir_all(&data_dir)?;
    let lock_file = lock::acquire(&data_dir::lock_path(&data_dir))?;
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let configs = share::load_all(&data_dir)?;
    let result = daemon::serve(data_dir, bt_port, identity, configs, register_dbus).await;
    drop(lock_file);
    result
}

// ── D-Bus client paths (default) ─────────────────────────────────────────────

async fn cmd_share_add(topic: String, path: PathBuf, role: ShareRole) -> Result<()> {
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    if matches!(role, ShareRole::Seed) && !path.exists() {
        return Err(anyhow!("seed path does not exist: {path:?}"));
    }
    let client = client::DaemonClient::connect().await?;
    let role_str = role_to_str(role);
    let share_id = client.share_add(&topic, &path, role_str).await?;
    println!("Added share {share_id} ({topic})");
    Ok(())
}

async fn cmd_share_list() -> Result<()> {
    let client = client::DaemonClient::connect().await?;
    let shares = client.share_list().await?;
    if shares.is_empty() {
        println!("No shares configured");
        return Ok(());
    }
    println!("{:<18} {:<8} {:<20} {}", "ID", "ROLE", "TOPIC", "PATH");
    for (id, topic, path, role, _created_at) in shares {
        println!(
            "{:<18} {:<8} {:<20} {}",
            id,
            role,
            truncate(&topic, 20),
            path
        );
    }
    Ok(())
}

async fn cmd_share_rotate_key(id: String) -> Result<()> {
    let client = client::DaemonClient::connect().await?;
    let new_epoch = client.share_rotate_key(&id).await?;
    println!("Rotated share {id}: new epoch is {new_epoch}");
    println!(
        "Distribute the updated keys.bin to other peers; without it they cannot read content \
         encrypted under epoch {new_epoch}."
    );
    Ok(())
}

async fn cmd_share_peers(id: String) -> Result<()> {
    let client = client::DaemonClient::connect().await?;
    let me = client.whoami().await.ok();
    let peers = client.share_peers(&id).await?;
    if peers.is_empty() {
        println!("share {id}: no peer activity recorded yet");
        return Ok(());
    }
    println!("{:<66} {:>9} {}", "PEER_ID", "VERSIONS", "");
    for (peer, ctr) in peers {
        let marker = if me.as_deref() == Some(&peer) { "(self)" } else { "" };
        println!("{:<66} {:>9} {}", peer, ctr, marker);
    }
    Ok(())
}

async fn cmd_share_members(id: String) -> Result<()> {
    let client = client::DaemonClient::connect().await?;
    let me = client.whoami().await.ok();
    let members = client.share_members(&id).await?;
    if members.is_empty() {
        println!("share {id}: no auth state on disk");
        return Ok(());
    }
    println!("{:<66} {:<8} {}", "PEER_PUBKEY", "ROLE", "");
    for (pubkey, role) in members {
        let marker = if me.as_deref() == Some(&pubkey) { "(self)" } else { "" };
        println!("{:<66} {:<8} {marker}", pubkey, role);
    }
    Ok(())
}

async fn cmd_share_revoke(id: String, peer_pubkey_hex: String) -> Result<()> {
    let client = client::DaemonClient::connect().await?;
    let new_epoch = client.share_revoke(&id, &peer_pubkey_hex).await?;
    println!("Revoked {peer_pubkey_hex} from share {id}");
    println!("Rotated keyring to epoch {new_epoch}.");
    println!("Distribution queued for remaining members; the daemon will broadcast on the next announce tick.");
    Ok(())
}

async fn cmd_whoami() -> Result<()> {
    let client = client::DaemonClient::connect().await?;
    let pubkey = client.whoami().await?;
    println!("{pubkey}");
    Ok(())
}

async fn cmd_share_invite(
    id: String,
    invitee_pubkey_hex: String,
    role: ShareRole,
    auth_role: auth::AuthRole,
) -> Result<()> {
    let client = client::DaemonClient::connect().await?;
    let role_str = role_to_str(role);
    let auth_role_str = match auth_role {
        auth::AuthRole::Owner => "owner",
        auth::AuthRole::Writer => "writer",
        auth::AuthRole::Reader => "reader",
    };
    let ticket = client
        .share_invite(&id, &invitee_pubkey_hex, role_str, auth_role_str)
        .await?;
    eprintln!("# Send this string to the joining peer over a secure channel");
    eprintln!("# (Signal, encrypted email, etc.). Anyone who has it can read");
    eprintln!("# the share's content under the current keyring.");
    eprintln!();
    println!("{ticket}");
    Ok(())
}

async fn cmd_share_join(ticket_str: String, path: PathBuf) -> Result<()> {
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let client = client::DaemonClient::connect().await?;
    let share_id = client.share_join(&ticket_str, &path).await?;
    println!("Joined share {share_id} at {}", path.display());
    Ok(())
}

async fn cmd_share_remove(id: String) -> Result<()> {
    let client = client::DaemonClient::connect().await?;
    client.share_remove(&id).await?;
    println!("Removed share {id}");
    Ok(())
}

// ── Direct on-disk paths (when --data-dir is provided) ───────────────────────
//
// These mirror the Phase 2-6 behaviour: edit on-disk state, log a "daemon
// must restart" warning where applicable. Used by container test rigs and
// by anyone running without a session bus.

fn cmd_share_add_direct(
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

fn cmd_share_list_direct(data_dir: PathBuf) -> Result<()> {
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

fn cmd_share_rotate_key_direct(data_dir: PathBuf, id: String) -> Result<()> {
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

fn cmd_share_peers_direct(data_dir: PathBuf, id: String) -> Result<()> {
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

fn cmd_share_members_direct(data_dir: PathBuf, id: String) -> Result<()> {
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

fn cmd_share_revoke_direct(
    data_dir: PathBuf,
    id: String,
    peer_pubkey_hex: String,
) -> Result<()> {
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

    let mut remaining: Vec<auth::MemberId> = auth_state
        .members(group_id)
        .into_iter()
        .map(|(m, _role)| m)
        .filter(|m| *m != target)
        .collect();
    remaining.sort_by_key(|m| m.0);

    let new_epoch = crypto::rotate_keyring(&data_dir, &id)?;
    let new_key = {
        let ring = crypto::load_or_create_keyring(&data_dir, &id)?;
        *ring
            .key_for_epoch(new_epoch)
            .ok_or_else(|| anyhow!("rotated keyring missing epoch {new_epoch}"))?
    };

    let rotation_msg = rotation::build_signed_rotation(
        &identity, new_epoch, &new_key, &remaining,
    )?;
    rotation::save_pending(&data_dir, &id, &rotation_msg)?;

    println!("Revoked {} from share {id}", peer_pubkey_hex);
    println!("Rotated keyring to epoch {new_epoch}.");
    println!(
        "Distribution queued for {} remaining member{}.",
        remaining.len(),
        if remaining.len() == 1 { "" } else { "s" },
    );
    println!("(running daemon will not see this change until restart)");
    Ok(())
}

fn cmd_whoami_direct(data_dir: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&data_dir)?;
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    println!("{}", identity.public_key().to_hex());
    Ok(())
}

fn cmd_share_invite_direct(
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

    let mut auth_state = auth::load(&data_dir, &id)?;
    if auth_state.is_empty() {
        return Err(anyhow!(
            "share {id} has no auth state on disk; can only invite from the creator's machine"
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

fn cmd_share_join_direct(
    data_dir: PathBuf,
    ticket_str: String,
    path: PathBuf,
) -> Result<()> {
    let ticket = ticket::Ticket::decode(&ticket_str)?;
    let configs = share::load_all(&data_dir)?;
    if configs.iter().any(|c| c.id == ticket.share_id) {
        return Err(anyhow!(
            "share {} is already configured locally; remove it first if you want to re-join",
            ticket.share_id
        ));
    }

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

    let cfg = ShareConfig {
        id: ticket.share_id.clone(),
        topic: ticket.topic.clone(),
        root_path: path,
        role: ticket.role,
        created_at: chrono::Utc::now(),
    };
    cfg.save(&data_dir)?;

    crypto::install_keyring(&data_dir, &ticket.share_id, &ticket.keys)?;

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
    Ok(())
}

fn cmd_share_remove_direct(data_dir: PathBuf, id: String) -> Result<()> {
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

fn role_to_str(role: ShareRole) -> &'static str {
    match role {
        ShareRole::Seed => "seed",
        ShareRole::Leech => "leech",
        ShareRole::Sync => "sync",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}
