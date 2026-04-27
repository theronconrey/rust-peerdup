mod clock;
mod crypto;
mod daemon;
mod data_dir;
mod identity;
mod lock;
mod share;
mod share_state;
mod ticket;

use anyhow::{anyhow, Result};
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
        /// BitTorrent listen port. Use distinct ports for two daemons on one machine.
        #[arg(long)]
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
    /// Print an invitation ticket for a share. The ticket contains the
    /// share's keyring; send it only over secure channels.
    ShareInvite {
        id: String,
        /// Role to suggest for the receiving peer. Not enforced yet (5c+).
        #[arg(long, value_enum, default_value = "sync")]
        role: ShareRole,
    },
    /// Consume an invitation ticket: register the share locally and import
    /// its keyring. The receiver picks the local path for their working copy.
    ShareJoin {
        /// Base64 ticket string from `share invite`.
        ticket: String,
        /// Local folder where this peer's working copy lives.
        #[arg(long)]
        path: PathBuf,
    },
    /// List peers observed in this share's history. This is activity-based,
    /// not ACL-based — it shows everyone whose edits we've seen via vector
    /// clock entries. Real membership semantics arrive with p2panda-auth in
    /// a later substep.
    SharePeers { id: String },
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
        Cmd::ShareInvite { id, role } => cmd_share_invite(data_dir, id, role),
        Cmd::ShareJoin { ticket, path } => cmd_share_join(data_dir, ticket, path),
        Cmd::SharePeers { id } => cmd_share_peers(data_dir, id),
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
    println!("Added share {} ({})", config.id, config.topic);
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

fn cmd_share_invite(data_dir: PathBuf, id: String, role: ShareRole) -> Result<()> {
    let configs = share::load_all(&data_dir)?;
    let cfg = configs
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| anyhow!("share {id} not found"))?;
    let ring = crypto::load_or_create_keyring(&data_dir, &id)?;
    let ticket = ticket::Ticket {
        version: 1,
        share_id: cfg.id.clone(),
        topic: cfg.topic.clone(),
        keys: ring.export_keys(),
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
