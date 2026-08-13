//! End-to-end tests against the **real** `hermes-relay` binary.
//!
//! Each test spawns the actual server process and talks to it over a
//! loopback UDP socket, so what is exercised is the shipped forwarding
//! path — parsing, signature verification, the replay guard, and the
//! room-scoped session table — rather than a reimplementation of it.
//!
//! The centrepiece is `wireguard_handshake_through_relay`, which drives a
//! complete WireGuard handshake + encrypted frame delivery through the
//! relay using the same `PeerTunnel` code the engine uses.

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use hermes_core::crypto::NodeSecret;
use hermes_core::relay::protocol::{self, RelayPacket};
use hermes_core::room::RoomId;
use hermes_core::tunnel::{PeerPath, PeerTunnel};

struct RelayProcess {
    child: Child,
    addr: SocketAddr,
}

impl RelayProcess {
    /// Spawn the relay binary on a free loopback port and wait until it
    /// answers a registration.
    async fn start() -> Self {
        // Claim a port, then release it for the relay. A race is possible
        // in principle; in practice the window is microseconds and the
        // readiness loop below would catch it as a failure to start.
        let port = {
            let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            probe.local_addr().unwrap().port()
        };
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        let child = Command::new(env!("CARGO_BIN_EXE_hermes-relay"))
            .env("HERMES_RELAY_BIND", addr.to_string())
            .env("RUST_LOG", "warn")
            .spawn()
            .expect("failed to spawn hermes-relay");

        let relay = Self { child, addr };
        relay.await_ready().await;
        relay
    }

    /// Poll with real registrations until one is acked.
    async fn await_ready(&self) {
        let secret = NodeSecret::generate();
        let room = RoomId::new_v4();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        for attempt in 0..100 {
            let pkt = protocol::encode_register(&room, &secret, now_ms() + attempt);
            if socket.send_to(&pkt, self.addr).await.is_err() {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            let mut buf = [0u8; 2048];
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await
            {
                if matches!(
                    protocol::parse_packet(&buf[..len]),
                    Some(RelayPacket::RegisterAck { .. })
                ) {
                    return;
                }
            }
        }
        panic!("relay never became ready");
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A registered node: its socket, identity, and room.
struct Node {
    socket: Arc<UdpSocket>,
    secret: Arc<NodeSecret>,
    room: RoomId,
}

impl Node {
    async fn register(relay: SocketAddr, room: RoomId) -> Self {
        let node = Self {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            secret: Arc::new(NodeSecret::generate()),
            room,
        };
        node.send_register(relay, now_ms()).await;
        node.expect_ack().await;
        node
    }

    async fn send_register(&self, relay: SocketAddr, ts: u64) {
        let pkt = protocol::encode_register(&self.room, &self.secret, ts);
        self.socket.send_to(&pkt, relay).await.unwrap();
    }

    async fn expect_ack(&self) {
        let mut buf = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(2), self.socket.recv_from(&mut buf))
            .await
            .expect("timed out waiting for REGISTER_ACK")
            .unwrap();
        assert!(
            matches!(
                protocol::parse_packet(&buf[..len]),
                Some(RelayPacket::RegisterAck { .. })
            ),
            "expected a REGISTER_ACK",
        );
    }

    fn node_id(&self) -> hermes_core::crypto::NodeId {
        self.secret.public().node_id
    }
}

#[tokio::test]
async fn data_is_forwarded_between_registered_room_members() {
    let relay = RelayProcess::start().await;
    let room = RoomId::new_v4();

    let a = Node::register(relay.addr, room).await;
    let b = Node::register(relay.addr, room).await;

    let payload = b"ciphertext from A to B";
    let data = protocol::encode_data(&b.node_id(), payload);
    a.socket.send_to(&data, relay.addr).await.unwrap();

    let mut buf = [0u8; 2048];
    let (len, from) = timeout(Duration::from_secs(2), b.socket.recv_from(&mut buf))
        .await
        .expect("B never received the forwarded payload")
        .unwrap();

    assert_eq!(from, relay.addr, "forward should come from the relay");
    match protocol::parse_packet(&buf[..len]) {
        Some(RelayPacket::Forward { src, payload: got }) => {
            assert_eq!(src, a.node_id(), "relay must name the true sender");
            assert_eq!(got, payload);
        }
        other => panic!("expected FORWARD, got {other:?}"),
    }
}

#[tokio::test]
async fn rooms_are_isolated() {
    let relay = RelayProcess::start().await;

    let room_a = RoomId::new_v4();
    let room_b = RoomId::new_v4();

    let insider = Node::register(relay.addr, room_a).await;
    let outsider = Node::register(relay.addr, room_b).await;

    // The outsider knows the insider's node id but is in another room.
    // Forwarding is scoped to a room, so this must go nowhere.
    let data = protocol::encode_data(&insider.node_id(), b"cross-room probe");
    outsider.socket.send_to(&data, relay.addr).await.unwrap();

    let mut buf = [0u8; 2048];
    let result = timeout(
        Duration::from_millis(500),
        insider.socket.recv_from(&mut buf),
    )
    .await;
    assert!(
        result.is_err(),
        "a node in another room must not be reachable",
    );
}

#[tokio::test]
async fn unregistered_senders_cannot_inject() {
    let relay = RelayProcess::start().await;
    let room = RoomId::new_v4();
    let target = Node::register(relay.addr, room).await;

    // A socket that never registered — the relay cannot attribute it to a
    // room, so it has nothing to forward against.
    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let data = protocol::encode_data(&target.node_id(), b"injected");
    stranger.send_to(&data, relay.addr).await.unwrap();

    let mut buf = [0u8; 2048];
    let result = timeout(
        Duration::from_millis(500),
        target.socket.recv_from(&mut buf),
    )
    .await;
    assert!(result.is_err(), "unregistered DATA must be dropped");
}

#[tokio::test]
async fn replayed_registration_cannot_hijack_a_session() {
    let relay = RelayProcess::start().await;
    let room = RoomId::new_v4();

    let victim = Node::register(relay.addr, room).await;
    let sender = Node::register(relay.addr, room).await;

    // Capture a REGISTER exactly as the victim sent it, then replay it
    // verbatim from a different socket — the classic session-steal.
    let stale_ts = now_ms();
    victim.send_register(relay.addr, stale_ts + 1).await;
    victim.expect_ack().await;

    let captured = protocol::encode_register(&room, &victim.secret, stale_ts);
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    attacker.send_to(&captured, relay.addr).await.unwrap();

    // The replay carries a timestamp that is not strictly increasing, so
    // it must be rejected outright — no ack.
    let mut buf = [0u8; 2048];
    let acked = timeout(Duration::from_millis(400), attacker.recv_from(&mut buf)).await;
    assert!(acked.is_err(), "a replayed REGISTER must not be acked");

    // And the victim's session must still point at the victim.
    let data = protocol::encode_data(&victim.node_id(), b"still mine");
    sender.socket.send_to(&data, relay.addr).await.unwrap();

    let (len, _) = timeout(Duration::from_secs(2), victim.socket.recv_from(&mut buf))
        .await
        .expect("victim should still receive its own traffic")
        .unwrap();
    assert!(matches!(
        protocol::parse_packet(&buf[..len]),
        Some(RelayPacket::Forward { .. })
    ));

    // The attacker must not have been handed the redirected traffic.
    let stolen = timeout(Duration::from_millis(300), attacker.recv_from(&mut buf)).await;
    assert!(
        stolen.is_err(),
        "session was hijacked by a replayed REGISTER"
    );
}

/// The full stack: two `PeerTunnel`s complete a WireGuard handshake and
/// deliver an encrypted Ethernet frame, with every datagram travelling
/// through the relay process.
#[tokio::test]
async fn wireguard_handshake_through_relay() {
    let relay = RelayProcess::start().await;
    let room = RoomId::new_v4();

    let a = Node::register(relay.addr, room).await;
    let b = Node::register(relay.addr, room).await;

    let a_pub = a.secret.public();
    let b_pub = b.secret.public();

    let tunnel_a = PeerTunnel::new(
        b_pub.node_id,
        b_pub.wireguard_public,
        &a.secret,
        PeerPath::Relayed {
            relay: relay.addr,
            dest: b_pub.node_id,
        },
        a.socket.clone(),
    )
    .unwrap();

    let tunnel_b = PeerTunnel::new(
        a_pub.node_id,
        a_pub.wireguard_public,
        &b.secret,
        PeerPath::Relayed {
            relay: relay.addr,
            dest: a_pub.node_id,
        },
        b.socket.clone(),
    )
    .unwrap();

    // Each side needs a pump: unwrap the relay's FORWARD framing and feed
    // the ciphertext to its tunnel, exactly as Mesh::dispatch_inbound does.
    let (frames_tx, mut frames_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);

    for (socket, tunnel, sink) in [
        (a.socket.clone(), tunnel_a.clone(), None),
        (b.socket.clone(), tunnel_b.clone(), Some(frames_tx.clone())),
    ] {
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, _)) = socket.recv_from(&mut buf).await {
                let Some(RelayPacket::Forward { payload, .. }) =
                    protocol::parse_packet(&buf[..len])
                else {
                    continue; // acks and anything else
                };
                if let Ok(Some(frame)) = tunnel.on_datagram(payload).await {
                    if let Some(sink) = &sink {
                        let _ = sink.send(frame.to_vec()).await;
                    }
                }
            }
        });
    }

    // A minimal Ethernet frame: broadcast destination, A's source, ARP.
    let eth_frame: Vec<u8> = {
        let mut f = vec![0xFFu8; 6];
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x0A]);
        f.extend_from_slice(&[0x08, 0x06]);
        f.extend_from_slice(b"hermes relay e2e payload");
        f
    };

    // The first send only triggers the handshake — boringtun drops the
    // data packet while no session exists — so retry until it lands.
    let received = async {
        loop {
            tunnel_a.send(&eth_frame).await.unwrap();
            if let Ok(Some(frame)) = timeout(Duration::from_millis(250), frames_rx.recv()).await {
                return frame;
            }
        }
    };

    let frame = timeout(Duration::from_secs(15), received)
        .await
        .expect("no frame arrived through the relay");

    assert_eq!(frame, eth_frame, "frame must survive the round trip intact");

    // And the traffic really did traverse the relay path.
    assert!(
        matches!(tunnel_a.path(), PeerPath::Relayed { .. }),
        "tunnel should be on the relayed path",
    );
    let stats = tunnel_a.stats();
    assert!(
        stats.bytes_tx.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "counters should have moved",
    );
}
