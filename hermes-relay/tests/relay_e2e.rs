//! End-to-end tests against the real `hermes-relay` binary.
//!
//! Each test spawns the compiled relay server (cargo exposes the path via
//! `CARGO_BIN_EXE_hermes-relay`), registers nodes over real UDP, and
//! verifies forwarding, room isolation, replay protection — and finally a
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
    async fn spawn() -> Self {
        // Reserve a free port, release it, and hand it to the relay.
        let port = {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_hermes-relay"))
            .env("HERMES_RELAY_BIND", addr.to_string())
            .env("RUST_LOG", "warn")
            .spawn()
            .expect("spawn hermes-relay");
        let proc = Self { child, addr };

        // Wait until it acks a registration.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let secret = NodeSecret::generate();
        let room = RoomId::new_v4();
        for _ in 0..50 {
            sock.send_to(
                &protocol::encode_register(&room, &secret, now_ms()),
                proc.addr,
            )
            .await
            .unwrap();
            let mut buf = [0u8; 64];
            if let Ok(Ok((n, _))) =
                timeout(Duration::from_millis(100), sock.recv_from(&mut buf)).await
            {
                if matches!(
                    protocol::parse_packet(&buf[..n]),
                    Some(RelayPacket::RegisterAck { .. })
                ) {
                    return proc;
                }
            }
        }
        panic!("relay never came up");
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

/// A test client: one socket and one identity.
struct Client {
    sock: UdpSocket,
    secret: NodeSecret,
}

impl Client {
    async fn new() -> Self {
        Self {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            secret: NodeSecret::generate(),
        }
    }

    fn id(&self) -> hermes_core::crypto::NodeId {
        self.secret.public().node_id
    }

    /// Register and wait for the ack.
    async fn register(&self, relay: SocketAddr, room: RoomId) {
        let pkt = protocol::encode_register(&room, &self.secret, now_ms());
        self.sock.send_to(&pkt, relay).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = timeout(Duration::from_secs(2), self.sock.recv_from(&mut buf))
            .await
            .expect("ack timeout")
            .unwrap();
        assert!(
            matches!(protocol::parse_packet(&buf[..n]), Some(RelayPacket::RegisterAck { room_id }) if room_id == room),
            "expected REGISTER_ACK"
        );
    }

    /// Receive one datagram, or `None` after `wait`.
    async fn recv(&self, wait: Duration) -> Option<Vec<u8>> {
        let mut buf = [0u8; 2048];
        match timeout(wait, self.sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }
}

#[tokio::test]
async fn data_is_forwarded_with_sender_identity() {
    let relay = RelayProcess::spawn().await;
    let room = RoomId::new_v4();
    let (alice, bob) = (Client::new().await, Client::new().await);
    alice.register(relay.addr, room).await;
    bob.register(relay.addr, room).await;

    alice
        .sock
        .send_to(&protocol::encode_data(&bob.id(), b"hello bob"), relay.addr)
        .await
        .unwrap();
    let got = bob.recv(Duration::from_secs(2)).await.expect("no forward");
    match protocol::parse_packet(&got) {
        Some(RelayPacket::Forward { src, payload }) => {
            assert_eq!(src, alice.id());
            assert_eq!(payload, b"hello bob");
        }
        other => panic!("expected FORWARD, got {other:?}"),
    }
}

#[tokio::test]
async fn rooms_are_isolated() {
    let relay = RelayProcess::spawn().await;
    let (alice, mallory) = (Client::new().await, Client::new().await);
    alice.register(relay.addr, RoomId::new_v4()).await;
    mallory.register(relay.addr, RoomId::new_v4()).await;

    mallory
        .sock
        .send_to(&protocol::encode_data(&alice.id(), b"psst"), relay.addr)
        .await
        .unwrap();
    assert!(
        alice.recv(Duration::from_millis(500)).await.is_none(),
        "cross-room DATA must not be forwarded"
    );
}

#[tokio::test]
async fn replayed_register_cannot_hijack_a_session() {
    let relay = RelayProcess::spawn().await;
    let room = RoomId::new_v4();
    let (alice, bob, attacker) = (
        Client::new().await,
        Client::new().await,
        Client::new().await,
    );

    // Alice registers; the attacker captures that exact packet...
    let captured = protocol::encode_register(&room, &alice.secret, now_ms());
    alice.sock.send_to(&captured, relay.addr).await.unwrap();
    assert!(
        alice.recv(Duration::from_secs(2)).await.is_some(),
        "alice ack"
    );
    bob.register(relay.addr, room).await;

    // ...and replays it from its own address.
    attacker.sock.send_to(&captured, relay.addr).await.unwrap();
    assert!(
        attacker.recv(Duration::from_millis(500)).await.is_none(),
        "replay must not be acked"
    );

    // Traffic for Alice still reaches Alice, not the attacker.
    bob.sock
        .send_to(
            &protocol::encode_data(&alice.id(), b"for alice"),
            relay.addr,
        )
        .await
        .unwrap();
    assert!(
        alice.recv(Duration::from_secs(2)).await.is_some(),
        "alice lost her session"
    );
    assert!(attacker.recv(Duration::from_millis(300)).await.is_none());
}

/// Feed every FORWARD arriving on `sock` into `tunnel`; return the first
/// decrypted Ethernet frame.
async fn pump_until_frame(sock: Arc<UdpSocket>, tunnel: Arc<PeerTunnel>) -> Vec<u8> {
    let mut buf = [0u8; 2048];
    loop {
        let (n, _) = sock.recv_from(&mut buf).await.unwrap();
        if let Some(RelayPacket::Forward { payload, .. }) = protocol::parse_packet(&buf[..n]) {
            if let Ok(Some(frame)) = tunnel.on_datagram(payload).await {
                return frame.to_vec();
            }
        }
    }
}

#[tokio::test]
async fn wireguard_handshake_and_frame_through_relay() {
    let relay = RelayProcess::spawn().await;
    let room = RoomId::new_v4();
    let (alice, bob) = (Client::new().await, Client::new().await);
    alice.register(relay.addr, room).await;
    bob.register(relay.addr, room).await;

    let a_sock = Arc::new(alice.sock);
    let b_sock = Arc::new(bob.sock);
    let (a_pub, b_pub) = (alice.secret.public(), bob.secret.public());

    let a_tunnel = PeerTunnel::new(
        b_pub.node_id,
        b_pub.wireguard_public,
        &alice.secret,
        PeerPath::Relayed {
            relay: relay.addr,
            dest: b_pub.node_id,
        },
        a_sock.clone(),
    )
    .unwrap();
    let b_tunnel = PeerTunnel::new(
        a_pub.node_id,
        a_pub.wireguard_public,
        &bob.secret,
        PeerPath::Relayed {
            relay: relay.addr,
            dest: a_pub.node_id,
        },
        b_sock.clone(),
    )
    .unwrap();

    // Alice's side just needs to process the handshake response.
    let a_pump = tokio::spawn(pump_until_frame(a_sock, a_tunnel.clone()));
    let b_pump = tokio::spawn(pump_until_frame(b_sock, b_tunnel.clone()));

    // The first send triggers the handshake; boringtun queues the frame
    // and releases it once the session is up.
    let frame: Vec<u8> = (0..120u8).collect();
    a_tunnel.send(&frame).await.unwrap();

    let got = timeout(Duration::from_secs(5), b_pump)
        .await
        .expect("frame never arrived through the relay")
        .unwrap();
    assert_eq!(got, frame);
    assert!(
        a_tunnel
            .stats()
            .bytes_tx
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
    assert!(
        b_tunnel
            .stats()
            .frames_rx
            .load(std::sync::atomic::Ordering::Relaxed)
            == 1
    );
    a_pump.abort();
}
