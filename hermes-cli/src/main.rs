//! `hermes` — a small command-line control client for the Hermes daemon.
//!
//! It speaks the same IPC protocol the desktop UI uses, so it can drive a
//! node end to end without a GUI: connect to signaling, manage the server
//! directory, create/join rooms, and inspect live per-peer link state.
//! This is the GUI-free path for testing on headless or Linux machines.
//!
//! The daemon is the long-lived, stateful process; each `hermes`
//! invocation is a short-lived client. So the usual flow is several
//! commands in sequence (`connect`, then `create`/`join`, then `status`),
//! all talking to the same running daemon.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use hermes_core::directory::ServerKind;
use hermes_core::room::RoomMode;
use hermes_daemon::protocol::{CommandPayload, Event, ResponseBody};
use hermes_daemon::DaemonClient;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map_or("help", String::as_str);
    let rest = if args.len() > 2 { &args[2..] } else { &[] };

    let result = match cmd {
        "identity" => identity().await,
        "connect" => connect(rest).await,
        "servers" => servers().await,
        "add-server" => add_server(rest).await,
        "use-signaling" => use_signaling(rest).await,
        "create" => create(rest).await,
        "join" => join(rest).await,
        "status" => status().await,
        "watch" => watch().await,
        "leave" => leave().await,
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}\n");
            print_help();
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn print_help() {
    eprintln!(
        "hermes — control client for the Hermes daemon\n\n\
         USAGE:\n\
         \x20 hermes <command> [args]\n\n\
         COMMANDS:\n\
         \x20 identity                              print this node's id\n\
         \x20 connect [--signaling <ws-url>]        connect to a signaling server\n\
         \x20                                       (default: the directory's active one)\n\
         \x20 servers                               list known signaling/relay servers\n\
         \x20 add-server <signaling|relay> <name> <address>\n\
         \x20                                       add a server to the directory\n\
         \x20 use-signaling <name>                  make a signaling server the active one\n\
         \x20 create <name> [--mode p2p|relayed] [--relay <host:port>]\n\
         \x20                                       create a room; prints the invite code\n\
         \x20 join <INVITE-CODE>                    join a room by code\n\
         \x20 status                                show connection, room, and live peers\n\
         \x20 watch                                 stream daemon events until Ctrl-C\n\
         \x20 leave                                 leave the current room\n\n\
         The daemon (hermes-daemon) must be running first."
    );
}

async fn client() -> Result<DaemonClient> {
    DaemonClient::connect_default()
        .await
        .context("could not reach hermes-daemon — is it running? (Linux: as your user with CAP_NET_ADMIN; Windows: as Administrator)")
}

/// Unwrap an `Ok`-ish response, turning `Error` bodies into a CLI error.
fn expect_ok(body: ResponseBody) -> Result<()> {
    match body {
        ResponseBody::Error { code, message } => bail!("daemon [{code}]: {message}"),
        _ => Ok(()),
    }
}

/// Leading non-`--` arguments, in order, stopping at the first flag.
fn positionals(args: &[String]) -> Vec<&str> {
    args.iter()
        .take_while(|a| !a.starts_with("--"))
        .map(String::as_str)
        .collect()
}

/// Value following `--name`, if present.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

async fn identity() -> Result<()> {
    let c = client().await?;
    match c.call(CommandPayload::GetIdentity).await? {
        ResponseBody::Identity { node_id_base64 } => {
            println!("{node_id_base64}");
            Ok(())
        }
        other => bail!("unexpected response: {other:?}"),
    }
}

async fn connect(args: &[String]) -> Result<()> {
    let signaling_url = flag(args, "--signaling");
    let c = client().await?;
    expect_ok(c.call(CommandPayload::Connect { signaling_url }).await?)?;
    println!("connected to signaling server");
    Ok(())
}

async fn servers() -> Result<()> {
    let c = client().await?;
    let ResponseBody::Servers(list) = c.call(CommandPayload::GetServers).await? else {
        bail!("unexpected response");
    };
    println!(
        "signaling servers (active: {}):",
        list.active_signaling.as_deref().unwrap_or("<first>")
    );
    for s in &list.signaling {
        let active = if list.active_signaling.as_deref() == Some(&s.name) {
            "*"
        } else {
            " "
        };
        println!("  {active} {:20} {:?}  {}", s.name, s.source, s.address);
    }
    println!("relay servers:");
    for s in &list.relays {
        println!("    {:20} {:?}  {}", s.name, s.source, s.address);
    }
    if let Some(url) = &list.manifest_url {
        println!("directory manifest: {url}");
    }
    Ok(())
}

async fn add_server(args: &[String]) -> Result<()> {
    let p = positionals(args);
    let (Some(kind_s), Some(name), Some(address)) = (p.first(), p.get(1), p.get(2)) else {
        bail!("usage: add-server <signaling|relay> <name> <address>");
    };
    let kind = match *kind_s {
        "signaling" => ServerKind::Signaling,
        "relay" => ServerKind::Relay,
        other => bail!("kind must be 'signaling' or 'relay', got '{other}'"),
    };
    let c = client().await?;
    expect_ok(
        c.call(CommandPayload::AddServer {
            kind,
            name: (*name).to_string(),
            address: (*address).to_string(),
        })
        .await?,
    )?;
    println!("added {kind:?} server '{name}' -> {address}");
    Ok(())
}

async fn use_signaling(args: &[String]) -> Result<()> {
    let p = positionals(args);
    let Some(name) = p.first() else {
        bail!("usage: use-signaling <name>");
    };
    let c = client().await?;
    expect_ok(
        c.call(CommandPayload::SetActiveSignaling {
            name: (*name).to_string(),
        })
        .await?,
    )?;
    println!("active signaling server is now '{name}'");
    Ok(())
}

async fn create(args: &[String]) -> Result<()> {
    let p = positionals(args);
    let Some(name) = p.first() else {
        bail!("usage: create <name> [--mode p2p|relayed] [--relay <host:port>]");
    };
    let mode = match flag(args, "--mode").as_deref() {
        None | Some("p2p" | "peer_to_peer") => RoomMode::PeerToPeer,
        Some("relayed" | "relay" | "central") => RoomMode::Relayed,
        Some(other) => bail!("--mode must be 'p2p' or 'relayed', got '{other}'"),
    };
    let relay_addr = flag(args, "--relay");
    if mode == RoomMode::Relayed && relay_addr.is_none() {
        bail!("relayed rooms need --relay <host:port>");
    }

    let c = client().await?;
    // Subscribe before issuing the command so we don't miss the event.
    let mut events = c
        .take_events()
        .await
        .context("event stream already taken")?;
    expect_ok(
        c.call(CommandPayload::CreateRoom {
            name: (*name).to_string(),
            mode,
            relay_addr,
        })
        .await?,
    )?;
    // The invite code arrives as a RoomEntered event, not in the response.
    wait_for_room(&mut events).await
}

async fn join(args: &[String]) -> Result<()> {
    let p = positionals(args);
    let Some(code) = p.first() else {
        bail!("usage: join <INVITE-CODE>");
    };
    let c = client().await?;
    let mut events = c
        .take_events()
        .await
        .context("event stream already taken")?;
    expect_ok(
        c.call(CommandPayload::JoinRoom {
            code: (*code).to_uppercase(),
        })
        .await?,
    )?;
    wait_for_room(&mut events).await
}

/// Wait for the daemon to confirm room entry (or surface a signaling error).
async fn wait_for_room(events: &mut tokio::sync::mpsc::Receiver<Event>) -> Result<()> {
    loop {
        match tokio::time::timeout(Duration::from_secs(15), events.recv()).await {
            Ok(Some(Event::RoomEntered {
                invite_code,
                mode,
                relay_addr,
                ..
            })) => {
                println!(
                    "in room — mode {mode:?}{}",
                    relay_addr.map_or(String::new(), |r| format!(", relay {r}"))
                );
                if let Some(code) = invite_code {
                    println!("INVITE CODE: {code}");
                    println!("(share this with the other machine, then run: hermes join {code})");
                }
                return Ok(());
            }
            Ok(Some(Event::SignalingError { code, message })) => {
                bail!("signaling [{code}]: {message}");
            }
            Ok(Some(_)) => {} // some other event; keep waiting
            Ok(None) => bail!("daemon closed the connection"),
            Err(_) => bail!(
                "timed out waiting for the room (is the daemon connected? run `hermes connect`)"
            ),
        }
    }
}

async fn status() -> Result<()> {
    let c = client().await?;
    let ResponseBody::State(s) = c.call(CommandPayload::GetState).await? else {
        bail!("unexpected response");
    };

    println!("node       {}", s.node_id_base64);
    println!("connected  {}", s.connected);
    if let Some(l) = &s.local_endpoint {
        println!("local      {l}");
    }
    if let Some(r) = &s.reflexive_endpoint {
        println!("public     {r}");
    }
    match &s.room {
        None => println!("room       (not in a room)"),
        Some(room) => {
            print!("room       {} [{:?}]", room.name, room.mode);
            if let Some(r) = &room.relay_addr {
                print!(" relay={r}");
            }
            println!();
        }
    }
    if let Some(healthy) = s.relay_healthy {
        println!(
            "relay      {}",
            if healthy {
                "healthy"
            } else {
                "UNREACHABLE — relayed traffic is likely down (auto-retrying)"
            }
        );
    }

    let links: HashMap<_, _> = s.links.iter().map(|l| (l.node_id, l)).collect();
    if s.peers.is_empty() {
        println!("peers      (none)");
    } else {
        println!(
            "\n{:<16} {:<15} {:<8} {:<18} {:<10}",
            "ALIAS", "VIRTUAL IP", "PATH", "TRAFFIC tx/rx", "HANDSHAKE"
        );
        for p in &s.peers {
            let link = links.get(&p.node_id);
            let path = match link {
                Some(l) => {
                    if l.relayed {
                        "relayed"
                    } else {
                        "direct"
                    }
                }
                None => peer_status_label(&p.status),
            };
            let traffic = link.map_or_else(
                || "—".to_string(),
                |l| format!("{}/{}", human_bytes(l.bytes_tx), human_bytes(l.bytes_rx)),
            );
            let handshake = match link {
                Some(l) if l.last_handshake_secs > 0 => format!("{}s ago", l.last_handshake_secs),
                Some(l) if l.bytes_tx + l.bytes_rx > 0 => "handshaking".to_string(),
                _ => "—".to_string(),
            };
            println!(
                "{:<16} {:<15} {:<8} {:<18} {:<10}",
                truncate(&p.alias, 16),
                p.virtual_ipv4.0,
                path,
                traffic,
                handshake
            );
        }
    }
    Ok(())
}

async fn watch() -> Result<()> {
    let c = client().await?;
    let mut events = c
        .take_events()
        .await
        .context("event stream already taken")?;
    println!("watching daemon events (Ctrl-C to stop)…");
    while let Some(ev) = events.recv().await {
        println!("{ev:?}");
    }
    println!("daemon event stream closed");
    Ok(())
}

async fn leave() -> Result<()> {
    let c = client().await?;
    expect_ok(c.call(CommandPayload::LeaveRoom).await?)?;
    println!("left the room");
    Ok(())
}

fn peer_status_label(status: &hermes_core::room::PeerStatus) -> &'static str {
    use hermes_core::room::PeerStatus as S;
    match status {
        S::Discovered => "found",
        S::Connecting => "connecting",
        S::Connected(_) => "connected",
        S::Stale => "stale",
        S::Gone => "gone",
    }
}

fn human_bytes(n: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let f = n as f64;
    if n < 1024 {
        format!("{n}B")
    } else if n < 1024 * 1024 {
        format!("{:.1}K", f / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1}M", f / (1024.0 * 1024.0))
    } else {
        format!("{:.2}G", f / (1024.0 * 1024.0 * 1024.0))
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}
