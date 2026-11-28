// SPDX-License-Identifier: MIT
mod access;
mod announce;
mod auth;
mod bootstrap;
mod client;
mod clock;
mod crypto;
mod daemon;
mod data_dir;
mod epochs;
mod identity;
mod ipc;
mod lock;
mod rotation;
mod share;
mod share_state;
mod ticket;
mod transfer;
mod wire;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use share::{ShareConfig, ShareRole};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rust-peerdup",
    version,
    about = "p2panda + librqbit folder sync"
)]
struct Cli {
    /// Override data directory. Default: $XDG_DATA_HOME/rust-peerdup on Linux.
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
    /// Run the daemon: bring up p2panda gossip and the blob store, run all
    /// configured shares concurrently until SIGINT/SIGTERM. Registers
    /// `org.peerdup.Daemon1` on the session bus so the CLI can drive it live.
    Serve {
        /// Ignored. File transfer no longer uses a BitTorrent port; kept so
        /// existing units and scripts that pass it keep working.
        #[arg(long, hide = true)]
        bt_port: Option<u16>,
        /// Skip D-Bus session-bus registration. Useful for headless test
        /// rigs that don't have a session bus or want to avoid bus-name
        /// collisions across multiple in-process daemons. The daemon also
        /// auto-skips IPC when no session bus is detected.
        #[arg(long, default_value_t = false)]
        no_dbus: bool,
        /// Relay server for reaching peers behind NAT; repeat for more.
        /// Replaces the default, n0's public relays (rate-limited, meant
        /// for development). Relayed traffic is end-to-end encrypted.
        #[arg(long = "relay-url", value_name = "URL")]
        relay_urls: Vec<String>,
        /// Use no relay at all. Peers on other networks are then reachable
        /// only at a directly routable address.
        #[arg(long, default_value_t = false, conflicts_with = "relay_urls")]
        no_relay: bool,
    },
    /// Add a new share. With `--data-dir` set, writes to disk directly
    /// (Phase 2 semantics; daemon restart required to pick up). Without
    /// `--data-dir`, calls `ShareAdd` over D-Bus on the running daemon.
    ShareAdd {
        /// A name for the share, shown by share-list and carried in
        /// invites. Just a label: the share's id and gossip topic come from
        /// a random secret made here, so two shares with the same name are
        /// different shares. (--topic is the old spelling.)
        #[arg(long, alias = "topic")]
        name: String,
        /// Path to the folder this share covers.
        #[arg(long)]
        path: PathBuf,
        /// Role for this peer in the share. Only sync runs; seed and leech
        /// are disabled because they are not encrypted.
        #[arg(long, value_enum)]
        role: ShareRole,
    },
    /// List configured shares.
    ShareList,
    /// Drop a share from this machine only. The other members are not told
    /// and still list you; to leave a share, use share-leave. The files in
    /// the share folder stay.
    ShareRemove { id: String },
    /// Leave a share: sign your own removal, tell the other members, then
    /// drop the share from this machine. The files in the share folder
    /// stay. An Owner of the share sends the remaining members a new key,
    /// so you can't read what they add later; you keep everything up to
    /// now. The only Owner of a share can't leave it. With --data-dir the
    /// daemon finishes the leave when it next starts.
    ShareLeave { id: String },
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
        /// Transport role to suggest for the receiving peer. Only sync runs;
        /// seed and leech are disabled because they are not encrypted.
        #[arg(long, value_enum, default_value = "sync")]
        role: ShareRole,
        /// Auth-level role: owner (manage), writer, or reader. Default writer.
        #[arg(long, value_enum, default_value = "writer")]
        auth_role: auth::AuthRole,
    },
    /// Consume an invitation ticket: register the share locally, import
    /// its keyring, replay the auth log.
    ShareJoin {
        /// Ticket from `share-invite`, or `-` to read it from standard
        /// input (recommended). A ticket holds the share's keys, and on the
        /// command line it is visible to other local users and lands in
        /// shell history.
        ticket: String,
        /// Local folder where this peer's working copy lives.
        #[arg(long)]
        path: PathBuf,
    },
    /// List peers observed in this share's history. Activity-based, not
    /// ACL-based; for ACL membership use `share members`.
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
        Cmd::Serve {
            bt_port,
            no_dbus,
            relay_urls,
            no_relay,
        } => {
            if bt_port.is_some() {
                tracing::warn!("--bt-port is ignored: file transfer now runs over iroh");
            }
            let data_dir = data_dir::resolve(direct_dir)?;
            let relays = if no_relay {
                Vec::new()
            } else if relay_urls.is_empty() {
                bootstrap::default_relay_urls()
            } else {
                relay_urls
                    .iter()
                    .map(|u| bootstrap::parse_relay_url(u))
                    .collect::<Result<Vec<_>>>()?
            };
            cmd_serve(data_dir, !no_dbus, relays).await
        }
        Cmd::ShareAdd { name, path, role } => match direct_dir {
            Some(dd) => cmd_share_add_direct(dd, name, path, role),
            None => cmd_share_add(name, path, role).await,
        },
        Cmd::ShareList => match direct_dir {
            Some(dd) => cmd_share_list_direct(dd),
            None => cmd_share_list().await,
        },
        Cmd::ShareRemove { id } => match direct_dir {
            Some(dd) => cmd_share_remove_direct(dd, id),
            None => cmd_share_remove(id).await,
        },
        Cmd::ShareLeave { id } => match direct_dir {
            Some(dd) => cmd_share_leave_direct(dd, id),
            None => cmd_share_leave(id).await,
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
        Cmd::ShareJoin { ticket, path } => {
            let ticket = resolve_ticket_arg(ticket)?;
            match direct_dir {
                Some(dd) => cmd_share_join_direct(dd, ticket, path),
                None => cmd_share_join(ticket, path).await,
            }
        }
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

/// Direct mode (`--data-dir` with a client command) edits the same files
/// the daemon owns. Take the daemon's lock for the duration, so a running
/// daemon's next save can't silently overwrite the change.
fn lock_for_direct_write(data_dir: &std::path::Path) -> Result<std::fs::File> {
    lock::acquire(&data_dir::lock_path(data_dir)).map_err(|_| {
        anyhow!(
            "a rust-peerdup daemon is running on {data_dir:?}; run this without --data-dir to go through it, or stop the daemon first"
        )
    })
}

/// `-` reads the ticket from stdin; anything else is the ticket itself,
/// with a warning, since argv is readable by other users via /proc.
fn resolve_ticket_arg(arg: String) -> Result<String> {
    if arg == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading ticket from stdin")?;
        let ticket = buf.trim().to_string();
        if ticket.is_empty() {
            return Err(anyhow!("no ticket on stdin"));
        }
        Ok(ticket)
    } else {
        eprintln!(
            "warning: the ticket was passed on the command line, where other local users can see it; \
             next time use `share-join - --path ...` and paste it on stdin"
        );
        Ok(arg)
    }
}

async fn cmd_serve(
    data_dir: PathBuf,
    register_dbus: bool,
    relays: Vec<p2panda_net::iroh_endpoint::RelayUrl>,
) -> Result<()> {
    std::fs::create_dir_all(&data_dir)?;
    let lock_file = lock::acquire(&data_dir::lock_path(&data_dir))?;
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let configs = share::load_all(&data_dir)?;
    let result = daemon::serve(data_dir, identity, configs, register_dbus, relays).await;
    drop(lock_file);
    result
}

// ── D-Bus client paths (default) ─────────────────────────────────────────────

async fn cmd_share_add(name: String, path: PathBuf, role: ShareRole) -> Result<()> {
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
    let share_id = client.share_add(&name, &path, role_str).await?;
    println!("Added share {share_id} ({name})");
    Ok(())
}

async fn cmd_share_list() -> Result<()> {
    let client = client::DaemonClient::connect().await?;
    let shares = client.share_list().await?;
    if shares.is_empty() {
        println!("No shares configured");
        return Ok(());
    }
    println!("{:<18} {:<8} {:<20} PATH", "ID", "ROLE", "NAME");
    for (id, name, path, role, _created_at) in shares {
        println!(
            "{:<18} {:<8} {:<20} {}",
            id,
            role,
            truncate(&name, 20),
            path
        );
    }
    Ok(())
}

async fn cmd_share_rotate_key(id: String) -> Result<()> {
    let client = client::DaemonClient::connect().await?;
    let new_epoch = client.share_rotate_key(&id).await?;
    println!("Rotated share {id}: new epoch is {new_epoch}");
    println!("The daemon sends the new key to the other members on the next announce tick.");
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
    println!("{:<66} {:>9} ", "PEER_ID", "VERSIONS");
    for (peer, ctr) in peers {
        let marker = if me.as_deref() == Some(&peer) {
            "(self)"
        } else {
            ""
        };
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
    println!("{:<66} {:<8} ", "PEER_PUBKEY", "ROLE");
    for (pubkey, role) in members {
        let marker = if me.as_deref() == Some(&pubkey) {
            "(self)"
        } else {
            ""
        };
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

async fn cmd_share_leave(id: String) -> Result<()> {
    let client = client::DaemonClient::connect().await?;
    client.share_leave(&id).await?;
    println!("Leaving share {id}.");
    println!(
        "The daemon tells the other members over the next minute, then removes the share \
         from this machine. The files in the share folder stay."
    );
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
    name: String,
    path: PathBuf,
    role: ShareRole,
) -> Result<()> {
    let _lock = lock_for_direct_write(&data_dir)?;
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    if matches!(role, ShareRole::Seed) && !path.exists() {
        return Err(anyhow!("seed path does not exist: {path:?}"));
    }
    let config = ShareConfig::create(name, path, role)?;
    if share::load_all(&data_dir)?
        .iter()
        .any(|c| c.id == config.id)
    {
        return Err(anyhow!("share {} is already configured", config.id));
    }

    // Auth log first, share.json last: the daemon only starts shares that
    // have both.
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let group_id = auth::group_id_for(&config.id);
    let mut auth_state = auth::AuthState::empty_for(group_id);
    auth_state.create_group(&identity, group_id)?;
    auth::save(&data_dir, &config.id, &auth_state)?;
    config.save(&data_dir)?;

    println!("Added share {} ({})", config.id, config.name);
    println!(
        "Auth group bootstrapped with {} as owner",
        identity.verifying_key().to_hex()
    );
    Ok(())
}

fn cmd_share_list_direct(data_dir: PathBuf) -> Result<()> {
    let configs = share::load_all(&data_dir)?;
    if configs.is_empty() {
        println!("No shares configured at {:?}", data_dir);
        return Ok(());
    }
    println!("{:<18} {:<8} {:<20} PATH", "ID", "ROLE", "NAME");
    for c in configs {
        let role = format!("{:?}", c.role).to_lowercase();
        println!(
            "{:<18} {:<8} {:<20} {}",
            c.id,
            role,
            truncate(&c.name, 20),
            c.root_path.display()
        );
    }
    Ok(())
}

fn cmd_share_rotate_key_direct(data_dir: PathBuf, id: String) -> Result<()> {
    let _lock = lock_for_direct_write(&data_dir)?;
    let configs = share::load_all(&data_dir)?;
    if !configs.iter().any(|c| c.id == id) {
        return Err(anyhow!("share {id} not found"));
    }
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let group_id = auth::group_id_for(&id);
    let auth_state = auth::load(&data_dir, &id)?;
    auth_state.require_owner(group_id, &identity)?;
    let ring = crypto::load_or_create_keyring(&data_dir, &id)?;
    epochs::check_mint(
        ring.current_epoch(),
        epochs::required(
            auth_state.required_epoch(),
            crypto::load_epoch_floor(&data_dir, &id),
        ),
    )?;
    let me = auth::MemberId(*identity.verifying_key().as_bytes());
    let mut others: Vec<auth::MemberId> = auth_state
        .members(group_id)
        .into_iter()
        .map(|(m, _role)| m)
        .filter(|m| *m != me)
        .collect();
    others.sort_by_key(|m| m.0);
    let (new_epoch, _chunks) =
        rotation::mint_and_queue(&data_dir, &id, &identity, group_id, &others)?;
    println!("Rotated share {id}: new epoch is {new_epoch}");
    println!(
        "The new key is queued for {} other member{}; the daemon sends it when it starts.",
        others.len(),
        if others.len() == 1 { "" } else { "s" },
    );
    Ok(())
}

fn cmd_share_peers_direct(data_dir: PathBuf, id: String) -> Result<()> {
    let configs = share::load_all(&data_dir)?;
    if !configs.iter().any(|c| c.id == id) {
        return Err(anyhow!("share {id} not found"));
    }
    let me = identity::load_or_create(&data_dir::identity_path(&data_dir))
        .map(|k| k.verifying_key().to_hex())
        .ok();
    let state = share_state::load(&data_dir, &id)?;
    let Some(state) = state else {
        println!("share {id}: no peer activity recorded yet");
        return Ok(());
    };
    let mut peers: Vec<(&String, &u64)> = state.clock.0.iter().collect();
    peers.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    println!("{:<66} {:>9} ", "PEER_ID", "VERSIONS");
    for (peer, ctr) in peers {
        let marker = if me.as_deref() == Some(peer) {
            "(self)"
        } else {
            ""
        };
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
        .map(|k| auth::MemberId(*k.verifying_key().as_bytes()))
        .ok();
    let mut members = auth_state.members(group_id);
    members.sort_by_key(|(m, _)| m.0);
    println!("{:<66} {:<8} ", "PEER_PUBKEY", "ROLE");
    for (m, role) in members {
        let marker = if Some(m) == me { "(self)" } else { "" };
        println!("{:<66} {:<8} {marker}", m.to_hex(), role);
    }
    Ok(())
}

fn cmd_share_revoke_direct(data_dir: PathBuf, id: String, peer_pubkey_hex: String) -> Result<()> {
    let _lock = lock_for_direct_write(&data_dir)?;
    let configs = share::load_all(&data_dir)?;
    if !configs.iter().any(|c| c.id == id) {
        return Err(anyhow!("share {id} not found"));
    }
    let target = auth::MemberId::from_hex(&peer_pubkey_hex).context("parsing peer public key")?;
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let group_id = auth::group_id_for(&id);
    let mut auth_state = auth::load(&data_dir, &id)?;
    if auth_state.is_empty() {
        return Err(anyhow!("share {id} has no auth state on disk"));
    }
    auth_state.require_owner(group_id, &identity)?;
    if target == auth::MemberId(*identity.verifying_key().as_bytes()) {
        return Err(anyhow!("to remove this node from a share, use share-leave"));
    }
    if !auth_state.is_member(group_id, target) {
        return Err(anyhow!(
            "{} is not a current member of share {id}",
            peer_pubkey_hex
        ));
    }
    // The key minted below must satisfy the required epoch after this
    // removal (see the daemon's handle_revoke).
    epochs::check_mint(
        crypto::load_or_create_keyring(&data_dir, &id)?.current_epoch(),
        epochs::required(
            auth_state.required_epoch() + 1,
            crypto::load_epoch_floor(&data_dir, &id),
        ),
    )?;
    auth_state.remove_member(&identity, group_id, target)?;
    auth::save(&data_dir, &id, &auth_state)?;

    let mut remaining: Vec<auth::MemberId> = auth_state
        .members(group_id)
        .into_iter()
        .map(|(m, _role)| m)
        .filter(|m| *m != target)
        .collect();
    remaining.sort_by_key(|m| m.0);

    let (new_epoch, _chunks) =
        rotation::mint_and_queue(&data_dir, &id, &identity, group_id, &remaining)?;

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
    println!("{}", identity.verifying_key().to_hex());
    Ok(())
}

fn cmd_share_invite_direct(
    data_dir: PathBuf,
    id: String,
    invitee_pubkey_hex: String,
    role: ShareRole,
    auth_role: auth::AuthRole,
) -> Result<()> {
    let _lock = lock_for_direct_write(&data_dir)?;
    role.ensure_encrypted()?;
    let configs = share::load_all(&data_dir)?;
    let cfg = configs
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| anyhow!("share {id} not found"))?;
    let invitee =
        auth::MemberId::from_hex(&invitee_pubkey_hex).context("parsing invitee public key")?;
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let group_id = auth::group_id_for(&id);

    let mut auth_state = auth::load(&data_dir, &id)?;
    if auth_state.is_empty() {
        return Err(anyhow!(
            "share {id} has no auth state on disk; can only invite from the creator's machine"
        ));
    }
    auth_state.require_owner(group_id, &identity)?;
    let ring = crypto::load_or_create_keyring(&data_dir, &id)?;
    epochs::check_invite(
        ring.current_epoch(),
        epochs::required(
            auth_state.required_epoch(),
            crypto::load_epoch_floor(&data_dir, &id),
        ),
    )?;
    if auth_state.is_member(group_id, invitee) {
        return Err(anyhow!(
            "{} is already a member of share {id}",
            invitee_pubkey_hex
        ));
    }
    auth_state.add_member(&identity, group_id, invitee, auth_role)?;
    auth::save(&data_dir, &id, &auth_state)?;

    let ticket = ticket::Ticket {
        version: ticket::TICKET_VERSION,
        share_id: cfg.id.clone(),
        name: cfg.name.clone(),
        topic: cfg.topic.clone(),
        keys: ring.export_keys(),
        auth_log: auth_state.ops().to_vec(),
        invitee_pubkey: invitee.0,
        role,
        inviter_addr: bootstrap::load_own_addr(&data_dir),
    };
    let encoded = ticket.encode()?;
    eprintln!("# Send this string to the joining peer over a secure channel");
    eprintln!("# (Signal, encrypted email, etc.). Anyone who has it can read");
    eprintln!("# the share's content under the current keyring.");
    eprintln!();
    println!("{encoded}");
    Ok(())
}

fn cmd_share_join_direct(data_dir: PathBuf, ticket_str: String, path: PathBuf) -> Result<()> {
    let _lock = lock_for_direct_write(&data_dir)?;
    // Everything in the ticket is checked before anything is written.
    let ticket = ticket::Ticket::decode(&ticket_str)?;
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let auth_state =
        ticket.verified_auth_state(auth::MemberId(*identity.verifying_key().as_bytes()))?;
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
    let cfg = ticket::install_join(&data_dir, &ticket, &auth_state, path)?;

    println!(
        "Joined share {} ({}) at {}",
        cfg.id,
        cfg.name,
        cfg.root_path.display()
    );
    Ok(())
}

fn cmd_share_leave_direct(data_dir: PathBuf, id: String) -> Result<()> {
    let _lock = lock_for_direct_write(&data_dir)?;
    let configs = share::load_all(&data_dir)?;
    if !configs.iter().any(|c| c.id == id) {
        return Err(anyhow!("share {id} not found"));
    }
    let identity = identity::load_or_create(&data_dir::identity_path(&data_dir))?;
    let mut auth_state = auth::load(&data_dir, &id)?;
    if auth_state.is_empty() {
        return Err(anyhow!("share {id} has no auth state on disk"));
    }
    daemon::record_leave(&data_dir, &id, &identity, &mut auth_state)
        .with_context(|| format!("leaving share {id}"))?;
    println!("Leaving share {id}.");
    println!(
        "The daemon tells the other members when it next starts (for about a minute), \
         then removes the share from this machine. The files in the share folder stay."
    );
    Ok(())
}

fn cmd_share_remove_direct(data_dir: PathBuf, id: String) -> Result<()> {
    let _lock = lock_for_direct_write(&data_dir)?;
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
                eprintln!("warning: could not remove {}: {e}", shadow_parent.display());
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

/// At most `max` characters (not bytes: a name may be any UTF-8).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

#[cfg(test)]
mod cli_tests {
    use super::Cli;
    use clap::CommandFactory;

    /// The RPM's man page is made by help2man, which Fedora builds without
    /// locale support: non-ASCII in --help comes out as a page that is not
    /// valid UTF-8 (rpmlint file-not-utf8). Keep every help string ASCII.
    #[test]
    fn help_text_is_ascii() {
        let mut cmd = Cli::command();
        cmd.build();
        let mut texts = vec![cmd.render_long_help().to_string()];
        for sub in cmd.get_subcommands_mut() {
            texts.push(sub.render_long_help().to_string());
        }
        for text in texts {
            if let Some(c) = text.chars().find(|c| !c.is_ascii()) {
                panic!("non-ASCII {c:?} in help text:\n{text}");
            }
        }
    }

    #[test]
    fn truncate_counts_characters_not_bytes() {
        assert_eq!(super::truncate("photos", 20), "photos");
        // Byte 19 is inside a two-byte character; slicing there panicked.
        let name = "a".repeat(18) + "\u{e9}\u{e9}\u{e9}";
        assert_eq!(
            super::truncate(&name, 20),
            "a".repeat(18) + "\u{e9}\u{2026}"
        );
        let long = "\u{e9}".repeat(30);
        assert_eq!(super::truncate(&long, 20).chars().count(), 20);
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
