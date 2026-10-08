//! Peer-to-peer path, end to end at the socket level: two real meshes on
//! loopback exchange ICE probes through their demultiplexers, build
//! direct WireGuard tunnels to the winning endpoints, and carry Ethernet
//! frames — then one side's NAT mapping "changes" and the other must
//! follow it (roaming). Also covers STUN through the shared socket and the
//! anti-spoofing source-MAC check.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

use hermes_core::broadcast::MacRouter;
use hermes_core::crypto::{NodeSecret, VirtualIpv4, VirtualMac};
use hermes_core::mesh::Mesh;
use hermes_core::nat::ice;
use hermes_core::tunnel::{PeerPath, PeerTunnel};

struct Node {
    mesh: Arc<Mesh>,
    secret: Arc<NodeSecret>,
    mac: VirtualMac,
    frames: mpsc::UnboundedReceiver<BytesMut>,
}

/// A mesh plus the inbound pump the driver would normally run.
async fn node() -> Node {
    let secret = Arc::new(NodeSecret::generate());
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mac = VirtualMac::from_node_id(&secret.public().node_id);
    let router = Arc::new(MacRouter::new(mac));
    let mesh = Arc::new(Mesh::new(socket.clone(), secret.clone(), router));
    let (tx, frames) = mpsc::unbounded_channel();
    {
        let mesh = mesh.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                if let Ok(Some(frame)) = mesh.dispatch_inbound(from, &buf[..n]).await {
                    let _ = tx.send(frame);
                }
            }
        });
    }
    Node {
        mesh,
        secret,
        mac,
        frames,
    }
}

/// Make `a` know `b`'s addresses (as `on_peer_joined` would).
fn introduce(a: &Node, b: &Node) {
    let id = b.secret.public().node_id;
    a.mesh
        .router
        .register(b.mac, VirtualIpv4::from_node_id(&id, [10, 42]), id);
}

fn frame(dst: VirtualMac, src: VirtualMac, body: &[u8]) -> Vec<u8> {
    let mut f = dst.0.to_vec();
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&[0x88, 0xB5]); // local experimental ethertype
    f.extend_from_slice(body);
    f
}

fn host_candidate(addr: SocketAddr) -> hermes_core::nat::Candidate {
    ice::gather_candidates(Some(addr), None, None, None).remove(0)
}

async fn tunnel_to(from: &Node, to: &Node, endpoint: SocketAddr) {
    let peer = to.secret.public();
    let t = PeerTunnel::new(
        peer.node_id,
        peer.wireguard_public,
        &from.secret,
        PeerPath::Direct(endpoint),
        from.mesh.socket.clone(),
    )
    .unwrap();
    from.mesh.add_peer(t).await;
}

async fn expect_frame(n: &mut Node, want: &[u8]) {
    let got = timeout(Duration::from_secs(5), n.frames.recv())
        .await
        .expect("frame never arrived")
        .expect("pump died");
    assert_eq!(&got[..], want);
}

#[tokio::test]
async fn ice_probe_then_tunnel_carries_frames_both_ways() {
    let (mut a, mut b) = (node().await, node().await);
    introduce(&a, &b);
    introduce(&b, &a);
    let a_addr = a.mesh.socket.local_addr().unwrap();
    let b_addr = b.mesh.socket.local_addr().unwrap();

    // Both sides probe simultaneously, as after a candidate exchange. A
    // dead candidate is included to prove it doesn't block the live one.
    let dead = host_candidate("127.0.0.1:9".parse().unwrap());
    let a_targets = [dead.clone(), host_candidate(b_addr)];
    let b_targets = [host_candidate(a_addr), dead];
    let (ra, rb) = tokio::join!(
        ice::probe_candidates(&a.mesh, &a_targets, Duration::from_secs(3)),
        ice::probe_candidates(&b.mesh, &b_targets, Duration::from_secs(3)),
    );
    let (ra, rb) = (ra.expect("a probe"), rb.expect("b probe"));
    assert_eq!(ra.endpoint, b_addr);
    assert_eq!(rb.endpoint, a_addr);

    tunnel_to(&a, &b, ra.endpoint).await;
    tunnel_to(&b, &a, rb.endpoint).await;

    let to_b = frame(b.mac, a.mac, b"hello from a");
    a.mesh.dispatch_outbound(&to_b).await.unwrap();
    expect_frame(&mut b, &to_b).await;

    let to_a = frame(a.mac, b.mac, b"hello from b");
    b.mesh.dispatch_outbound(&to_a).await.unwrap();
    expect_frame(&mut a, &to_a).await;

    // Broadcast floods to the peer as well.
    let bcast = frame(VirtualMac::BROADCAST, a.mac, b"anyone?");
    a.mesh.dispatch_outbound(&bcast).await.unwrap();
    expect_frame(&mut b, &bcast).await;

    let stats = a.mesh.link_stats();
    assert_eq!(stats.len(), 1);
    assert!(!stats[0].relayed);
    assert!(stats[0].frames_tx >= 2);
}

#[tokio::test]
async fn spoofed_source_mac_is_dropped() {
    let (a, mut b) = (node().await, node().await);
    introduce(&a, &b);
    introduce(&b, &a);
    let a_addr = a.mesh.socket.local_addr().unwrap();
    let b_addr = b.mesh.socket.local_addr().unwrap();
    tunnel_to(&a, &b, b_addr).await;
    tunnel_to(&b, &a, a_addr).await;

    // A claims to be some other station.
    let forged = frame(b.mac, VirtualMac([0x02, 0xBA, 0xD0, 0, 0, 1]), b"forged");
    a.mesh.dispatch_outbound(&forged).await.unwrap();
    let honest = frame(b.mac, a.mac, b"honest");
    a.mesh.dispatch_outbound(&honest).await.unwrap();
    // Only the honest frame surfaces.
    expect_frame(&mut b, &honest).await;
    assert!(b.frames.try_recv().is_err());
}

/// A one-mapping "NAT" between B and A: B sends to `inside`, the NAT
/// forwards to A from its current outside socket, and relays A's replies
/// back. `rebind` swaps the outside socket — what a home router does after
/// a reboot or a Wi-Fi → cellular switch.
struct Nat {
    inside: SocketAddr,
    rebind: Arc<AtomicBool>,
}

async fn nat(a_addr: SocketAddr) -> Nat {
    let inside_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let inside = inside_sock.local_addr().unwrap();
    let rebind = Arc::new(AtomicBool::new(false));
    let flag = rebind.clone();
    tokio::spawn(async move {
        let mut outside = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut b_addr: Option<SocketAddr> = None;
        let mut ib = [0u8; 2048];
        let mut ob = [0u8; 2048];
        loop {
            if flag.swap(false, Ordering::SeqCst) {
                outside = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            }
            tokio::select! {
                r = inside_sock.recv_from(&mut ib) => {
                    let (n, from) = r.unwrap();
                    b_addr = Some(from);
                    let _ = outside.send_to(&ib[..n], a_addr).await;
                }
                r = outside.recv_from(&mut ob) => {
                    if let (Ok((n, _)), Some(b)) = (r, b_addr) {
                        let _ = inside_sock.send_to(&ob[..n], b).await;
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    });
    Nat { inside, rebind }
}

#[tokio::test]
async fn tunnel_follows_a_roaming_peer() {
    let (mut a, mut b) = (node().await, node().await);
    introduce(&a, &b);
    introduce(&b, &a);
    let a_addr = a.mesh.socket.local_addr().unwrap();
    let nat = nat(a_addr).await;

    // B reaches A through the NAT; A initially knows a stale endpoint for
    // B (e.g. a candidate from before the NAT changed), so the very first
    // packet from B already arrives from an unknown address.
    tunnel_to(&b, &a, a_addr).await;
    tunnel_to(&a, &b, "127.0.0.1:9".parse().unwrap()).await;
    // B's tunnel to A must go via the NAT's inside address.
    b.mesh
        .tunnel(a.secret.public().node_id)
        .unwrap()
        .set_path(PeerPath::Direct(nat.inside));

    let to_a = frame(a.mac, b.mac, b"through the nat");
    b.mesh.dispatch_outbound(&to_a).await.unwrap();
    expect_frame(&mut a, &to_a).await;
    let first = a.mesh.peer_path(b.secret.public().node_id).unwrap();
    assert_ne!(
        first,
        PeerPath::Direct("127.0.0.1:9".parse().unwrap()),
        "A did not learn B's endpoint"
    );

    // A can answer on the learned path.
    let to_b = frame(b.mac, a.mac, b"reply");
    a.mesh.dispatch_outbound(&to_b).await.unwrap();
    expect_frame(&mut b, &to_b).await;

    // The NAT rebinds: B's traffic now comes from a new outside port.
    nat.rebind.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let again = frame(a.mac, b.mac, b"after rebind");
    b.mesh.dispatch_outbound(&again).await.unwrap();
    expect_frame(&mut a, &again).await;
    let second = a.mesh.peer_path(b.secret.public().node_id).unwrap();
    assert_ne!(first, second, "A did not follow B to its new endpoint");

    let reply = frame(b.mac, a.mac, b"still here");
    a.mesh.dispatch_outbound(&reply).await.unwrap();
    expect_frame(&mut b, &reply).await;
}

#[tokio::test]
async fn stun_binding_through_the_mesh_demux() {
    let n = node().await;
    // A fake STUN server that reports the sender's address.
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            if len < 20 {
                continue;
            }
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();
            let resp = stun_response(&txid, from);
            server.send_to(&resp, from).await.unwrap();
        }
    });

    let reflexive = n
        .mesh
        .stun_binding(server_addr, Duration::from_secs(2))
        .await
        .expect("stun");
    assert_eq!(reflexive, n.mesh.socket.local_addr().unwrap());
}

/// Minimal XOR-MAPPED-ADDRESS (IPv4) Binding success response.
fn stun_response(txid: &[u8; 12], addr: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = addr else {
        panic!("v4 only")
    };
    let cookie: [u8; 4] = 0x2112_A442u32.to_be_bytes();
    let port = v4.port() ^ 0x2112;
    let mut m = vec![0x01, 0x01, 0x00, 0x0c];
    m.extend_from_slice(&cookie);
    m.extend_from_slice(txid);
    m.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
    m.extend_from_slice(&port.to_be_bytes());
    m.extend(v4.ip().octets().iter().zip(cookie).map(|(o, c)| o ^ c));
    m
}
