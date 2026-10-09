//! A headless Hermes peer that answers pings — a test fixture for driving
//! a real node end to end without a second virtual adapter.
//!
//! It joins a **relayed** room by invite code, builds a WireGuard tunnel
//! to every member through the relay, and answers ARP requests and ICMP
//! echo requests for its own virtual IP. A real node in the same room can then
//! `ping` it, which exercises that node's whole data path: its adapter
//! (wintun on Windows, plus the L2/L3 shim), routing, tunnels, the relay,
//! and the daemon behind it.
//!
//! ```text
//! cargo run -p hermes-core --example echo_peer -- <signaling-url> <INVITE-CODE>
//! ```
//!
//! Prints `ECHO-PEER <virtual-ip>` once it's in the room.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hermes_core::broadcast::{arp, MacRouter};
use hermes_core::crypto::{NodeSecret, VirtualIpv4, VirtualMac};
use hermes_core::mesh::{is_transient_recv_error, Mesh};
use hermes_core::relay::{spawn_registration, RegistrationConfig};
use hermes_core::room::{InviteCode, RoomMode};
use hermes_core::signaling::{ClientMessage, PeerInfo, ServerMessage, SignalingClient};
use hermes_core::tunnel::{PeerPath, PeerTunnel};
use tokio::net::UdpSocket;

const ETH: usize = 14;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [url, code] = args.as_slice() else {
        anyhow::bail!("usage: echo_peer <signaling-url> <INVITE-CODE>");
    };
    let code: InviteCode = code
        .parse()
        .map_err(|_| anyhow::anyhow!("bad invite code"))?;

    let secret = Arc::new(NodeSecret::generate());
    let me = secret.public().node_id;
    let my_mac = VirtualMac::from_node_id(&me);

    let client = SignalingClient::connect(url, &secret, "echo-peer".into()).await?;
    let mut inbox = client.take_inbox().expect("fresh client");
    client
        .send(ClientMessage::JoinRoom {
            code,
            restore: None,
        })
        .await?;

    let (room_id, members, relay_addr, ip_salt) = loop {
        match inbox.recv().await {
            Some(ServerMessage::RoomJoined {
                room_id,
                members,
                mode,
                relay_addr,
                ip_salt,
            }) => {
                anyhow::ensure!(mode == RoomMode::Relayed, "echo_peer needs a relayed room");
                let relay = relay_addr.expect("relayed room has a relay");
                break (room_id, members, relay, ip_salt);
            }
            Some(ServerMessage::Error { code, message }) => anyhow::bail!("{code}: {message}"),
            Some(_) => {}
            None => anyhow::bail!("signaling closed"),
        }
    };
    let relay: SocketAddr = tokio::net::lookup_host(&relay_addr)
        .await?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| anyhow::anyhow!("relay {relay_addr} has no IPv4 address"))?;

    let my_ip = VirtualIpv4::from_node_id_salted(&me, [10, 42], ip_salt).0;
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let router = Arc::new(MacRouter::new(my_mac));
    router.set_own_ipv4(Some(my_ip));
    let mesh = Arc::new(Mesh::new(socket.clone(), secret.clone(), router.clone()));
    mesh.set_relay(Some(relay));
    let _registration = spawn_registration(
        socket.clone(),
        relay,
        room_id,
        secret.clone(),
        mesh.relay_health(),
        RegistrationConfig::default(),
    );

    for peer in members {
        add_peer(&mesh, &secret, relay, &peer).await?;
    }
    // Members joining later.
    {
        let (mesh, secret) = (mesh.clone(), secret.clone());
        tokio::spawn(async move {
            while let Some(msg) = inbox.recv().await {
                match msg {
                    ServerMessage::PeerJoined { peer } => {
                        let _ = add_peer(&mesh, &secret, relay, &peer).await;
                    }
                    ServerMessage::PeerLeft { node_id } => mesh.remove_peer(node_id).await,
                    _ => {}
                }
            }
        });
    }
    println!("ECHO-PEER {my_ip}");

    let mut buf = [0u8; 2048];
    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) if is_transient_recv_error(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        let Ok(Some(frame)) = mesh.dispatch_inbound(from, &buf[..n]).await else {
            continue;
        };
        // Linux peers ARP before they ping (Windows' shim doesn't need to).
        let reply = match arp::parse_request(&frame) {
            Some(req) if req.target_ip == my_ip => Some(arp::build_reply(&req, my_mac, my_ip)),
            Some(_) => None,
            None => echo_reply(&frame, my_mac, my_ip),
        };
        if let Some(reply) = reply {
            let _ = mesh.dispatch_outbound(&reply).await;
        }
    }
}

async fn add_peer(
    mesh: &Mesh,
    secret: &NodeSecret,
    relay: SocketAddr,
    peer: &PeerInfo,
) -> anyhow::Result<()> {
    anyhow::ensure!(peer.key_binding_is_valid(), "peer key binding invalid");
    mesh.router.register(
        VirtualMac::from_node_id(&peer.node_id),
        VirtualIpv4::from_node_id_salted(&peer.node_id, [10, 42], peer.ip_salt),
        peer.node_id,
    );
    let tunnel = PeerTunnel::new(
        peer.node_id,
        peer.wireguard_public,
        secret,
        PeerPath::Relayed {
            relay,
            dest: peer.node_id,
        },
        mesh.socket.clone(),
    )?;
    mesh.add_peer(tunnel.clone()).await;
    // Start the handshake now rather than waiting for the first ping.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = tunnel.send_ping().await;
    });
    Ok(())
}

/// Internet checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0)
}

/// If `frame` is an ICMP echo request to `my_ip`, build the reply frame.
fn echo_reply(frame: &[u8], my_mac: VirtualMac, my_ip: Ipv4Addr) -> Option<Vec<u8>> {
    if frame.len() < ETH + 20 || frame[12..14] != [0x08, 0x00] {
        return None;
    }
    let ip = &frame[ETH..];
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if ip[0] >> 4 != 4 || ihl < 20 || total < ihl + 8 || total > ip.len() || ip[9] != 1 {
        return None;
    }
    if Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]) != my_ip || ip[ihl] != 8 {
        return None; // not an echo request for us
    }

    let mut reply = Vec::with_capacity(ETH + total);
    reply.extend_from_slice(&frame[6..12]); // back to the sender's MAC
    reply.extend_from_slice(&my_mac.0);
    reply.extend_from_slice(&[0x08, 0x00]);
    let mut out = ip[..total].to_vec();
    out.copy_within(12..16, 16); // dst <- old src
    out[12..16].copy_from_slice(&my_ip.octets()); // src <- us
    out[8] = 64; // TTL
    out[10..12].copy_from_slice(&[0, 0]);
    let hsum = checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&hsum.to_be_bytes());
    out[ihl] = 0; // echo reply
    out[ihl + 2..ihl + 4].copy_from_slice(&[0, 0]);
    let isum = checksum(&out[ihl..]);
    out[ihl + 2..ihl + 4].copy_from_slice(&isum.to_be_bytes());
    reply.extend_from_slice(&out);
    Some(reply)
}
