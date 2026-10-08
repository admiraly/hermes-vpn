//! Session lifecycle against the real `hermes-signaling` binary: what
//! happens when connections die, nodes reconnect, and the server itself
//! restarts. These are the paths the engine's auto-reconnect exercises.

use std::process::{Child, Command};
use std::time::Duration;

use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

use hermes_core::crypto::{NodeId, NodeSecret};
use hermes_core::room::{InviteCode, RoomId, RoomMode};
use hermes_core::signaling::protocol::{ClientMessage, RoomRestore, ServerMessage};
use hermes_core::signaling::{Keepalive, SignalingClient};

struct Server {
    child: Child,
    port: u16,
}

impl Server {
    async fn spawn(port: u16, idle_timeout_secs: Option<u64>) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hermes-signaling"));
        cmd.env("HERMES_SIGNALING_BIND", format!("127.0.0.1:{port}"))
            .env("RUST_LOG", "warn");
        if let Some(secs) = idle_timeout_secs {
            cmd.env("HERMES_SIGNALING_IDLE_TIMEOUT_SECS", secs.to_string());
        }
        // Wrap immediately so Drop kills the process even if we panic below.
        let server = Self {
            child: cmd.spawn().expect("spawn hermes-signaling"),
            port,
        };
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return server;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("signaling server never came up");
    }

    fn url(&self) -> String {
        format!("ws://127.0.0.1:{}/v1", self.port)
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.kill();
    }
}

struct Peer {
    client: SignalingClient,
    inbox: Receiver<ServerMessage>,
    id: NodeId,
}

async fn connect(url: &str, secret: &NodeSecret, alias: &str, keepalive: Keepalive) -> Peer {
    let client = SignalingClient::connect_with(url, secret, alias.into(), keepalive)
        .await
        .expect("connect");
    let inbox = client.take_inbox().unwrap();
    Peer {
        client,
        inbox,
        id: secret.public().node_id,
    }
}

fn fast_pings() -> Keepalive {
    Keepalive {
        ping_interval: Duration::from_millis(200),
        idle_timeout: Duration::from_secs(10),
    }
}

/// Wait for the first message matching `pred` (skipping others).
async fn expect<T>(
    p: &mut Peer,
    what: &str,
    mut pred: impl FnMut(&ServerMessage) -> Option<T>,
) -> T {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(remaining, p.inbox.recv()).await {
            Ok(Some(msg)) => {
                if let Some(v) = pred(&msg) {
                    return v;
                }
            }
            Ok(None) => panic!("inbox closed waiting for {what}"),
            Err(_) => panic!("timed out waiting for {what}"),
        }
    }
}

/// Assert no message matching `pred` arrives within `window`.
async fn expect_none(
    p: &mut Peer,
    window: Duration,
    what: &str,
    pred: impl Fn(&ServerMessage) -> bool,
) {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(remaining, p.inbox.recv()).await {
            Ok(Some(msg)) => assert!(!pred(&msg), "unexpected {what}: {msg:?}"),
            Ok(None) | Err(_) => return,
        }
    }
}

async fn create(p: &mut Peer, mode: RoomMode, relay: Option<&str>) -> (RoomId, InviteCode) {
    p.client
        .send(ClientMessage::CreateRoom {
            name: "lifecycle".into(),
            mode,
            relay_addr: relay.map(str::to_string),
        })
        .await
        .unwrap();
    expect(p, "RoomCreated", |m| match m {
        ServerMessage::RoomCreated {
            room_id,
            invite_code,
            ..
        } => Some((*room_id, *invite_code)),
        _ => None,
    })
    .await
}

async fn join(
    p: &mut Peer,
    code: InviteCode,
    restore: Option<RoomRestore>,
) -> Result<(RoomId, Vec<NodeId>), String> {
    p.client
        .send(ClientMessage::JoinRoom { code, restore })
        .await
        .unwrap();
    expect(p, "RoomJoined/Error", |m| match m {
        ServerMessage::RoomJoined {
            room_id, members, ..
        } => Some(Ok((*room_id, members.iter().map(|m| m.node_id).collect()))),
        ServerMessage::Error { code, .. } => Some(Err(code.clone())),
        _ => None,
    })
    .await
}

fn is_peer_left(node: NodeId) -> impl Fn(&ServerMessage) -> bool {
    move |m| matches!(m, ServerMessage::PeerLeft { node_id } if *node_id == node)
}

/// A node reconnects while the server still holds its old, dying session.
/// When the old connection finally closes, the room must keep the *new*
/// session and nobody may be told the node left.
#[tokio::test]
async fn stale_session_is_replaced_without_peer_left() {
    let server = Server::spawn(39811, None).await;
    let (alice_s, bob_s, carol_s) = (
        NodeSecret::generate(),
        NodeSecret::generate(),
        NodeSecret::generate(),
    );
    let mut alice = connect(&server.url(), &alice_s, "alice", Keepalive::default()).await;
    let (room, code) = create(&mut alice, RoomMode::PeerToPeer, None).await;

    let mut bob_old = connect(&server.url(), &bob_s, "bob", Keepalive::default()).await;
    join(&mut bob_old, code, None).await.unwrap();

    // Bob reconnects (new connection, same identity) and re-joins.
    let mut bob_new = connect(&server.url(), &bob_s, "bob", Keepalive::default()).await;
    let (joined, members) = join(&mut bob_new, code, None).await.unwrap();
    assert_eq!(joined, room);
    assert_eq!(
        members,
        vec![alice.id],
        "a node must not see itself as a member"
    );

    // Now the old connection dies.
    drop(bob_old);
    expect_none(
        &mut alice,
        Duration::from_secs(1),
        "PeerLeft for a node that is still here",
        is_peer_left(bob_s.public().node_id),
    )
    .await;

    // Bob is still a member: a newcomer sees exactly one Bob, and
    // candidates addressed to Bob reach the live session.
    let mut carol = connect(&server.url(), &carol_s, "carol", Keepalive::default()).await;
    let (_, members) = join(&mut carol, code, None).await.unwrap();
    assert_eq!(members.iter().filter(|m| **m == bob_new.id).count(), 1);
    carol
        .client
        .send(ClientMessage::RelayCandidates {
            to: bob_new.id,
            candidates: vec![],
        })
        .await
        .unwrap();
    expect(&mut bob_new, "PeerCandidates from carol", |m| match m {
        ServerMessage::PeerCandidates { from, .. } if *from == carol.id => Some(()),
        _ => None,
    })
    .await;
}

/// The server restarts and loses every room. Members re-joining with
/// restore info must land back in the same room (same id and code); a
/// plain join of an unknown code still fails.
#[tokio::test]
async fn room_is_restored_after_server_restart() {
    let mut server = Server::spawn(39812, None).await;
    let (alice_s, bob_s) = (NodeSecret::generate(), NodeSecret::generate());
    let mut alice = connect(&server.url(), &alice_s, "alice", Keepalive::default()).await;
    let (room, code) = create(&mut alice, RoomMode::Relayed, Some("relay.example:8788")).await;

    server.kill();
    drop(alice);
    let server = Server::spawn(39812, None).await;

    // Without restore info the code is simply unknown now.
    let mut bob = connect(&server.url(), &bob_s, "bob", Keepalive::default()).await;
    assert_eq!(join(&mut bob, code, None).await, Err("invalid_code".into()));

    // Alice's automatic re-join carries what she remembers.
    let mut alice = connect(&server.url(), &alice_s, "alice", Keepalive::default()).await;
    let restore = RoomRestore {
        room_id: room,
        name: "lifecycle".into(),
        mode: RoomMode::Relayed,
        relay_addr: Some("relay.example:8788".into()),
    };
    let (restored, members) = join(&mut alice, code, Some(restore)).await.unwrap();
    assert_eq!(restored, room, "restored room must keep its id");
    assert!(members.is_empty());

    // Now the plain code works again and leads to the same room, with the
    // original mode and relay.
    bob.client
        .send(ClientMessage::JoinRoom {
            code,
            restore: None,
        })
        .await
        .unwrap();
    expect(&mut bob, "RoomJoined", |m| match m {
        ServerMessage::RoomJoined {
            room_id,
            members,
            mode,
            relay_addr,
            ..
        } => {
            assert_eq!(*room_id, room);
            assert_eq!(*mode, RoomMode::Relayed);
            assert_eq!(relay_addr.as_deref(), Some("relay.example:8788"));
            assert_eq!(members.len(), 1);
            Some(())
        }
        _ => None,
    })
    .await;
}

/// Restore info can't be used to hijack an existing room id.
#[tokio::test]
async fn restore_cannot_clobber_a_live_room() {
    let server = Server::spawn(39813, None).await;
    let (alice_s, mallory_s) = (NodeSecret::generate(), NodeSecret::generate());
    let mut alice = connect(&server.url(), &alice_s, "alice", Keepalive::default()).await;
    let (room, _code) = create(&mut alice, RoomMode::PeerToPeer, None).await;

    let mut mallory = connect(&server.url(), &mallory_s, "mallory", Keepalive::default()).await;
    let fake = RoomRestore {
        room_id: room,
        name: "mine now".into(),
        mode: RoomMode::PeerToPeer,
        relay_addr: None,
    };
    assert_eq!(
        join(&mut mallory, InviteCode::generate(), Some(fake)).await,
        Err("invalid_code".into())
    );
}

/// Joining a different room leaves the current one.
#[tokio::test]
async fn joining_another_room_leaves_the_first() {
    let server = Server::spawn(39814, None).await;
    let (alice_s, bob_s, carol_s) = (
        NodeSecret::generate(),
        NodeSecret::generate(),
        NodeSecret::generate(),
    );
    let mut alice = connect(&server.url(), &alice_s, "alice", Keepalive::default()).await;
    let (_, code1) = create(&mut alice, RoomMode::PeerToPeer, None).await;
    let mut carol = connect(&server.url(), &carol_s, "carol", Keepalive::default()).await;
    let (_, code2) = create(&mut carol, RoomMode::PeerToPeer, None).await;

    let mut bob = connect(&server.url(), &bob_s, "bob", Keepalive::default()).await;
    join(&mut bob, code1, None).await.unwrap();
    join(&mut bob, code2, None).await.unwrap();

    expect(&mut alice, "PeerLeft(bob) in room 1", |m| {
        is_peer_left(bob.id)(m).then_some(())
    })
    .await;
    expect(&mut carol, "PeerJoined(bob) in room 2", |m| match m {
        ServerMessage::PeerJoined { peer } if peer.node_id == bob.id => Some(()),
        _ => None,
    })
    .await;
}

/// A client that goes silent (half-open connection) is dropped by the
/// server, and the rest of the room is told it left.
#[tokio::test]
async fn silent_client_is_dropped_and_peers_told() {
    let server = Server::spawn(39815, Some(1)).await;
    let (alice_s, bob_s) = (NodeSecret::generate(), NodeSecret::generate());
    let mut alice = connect(&server.url(), &alice_s, "alice", fast_pings()).await;
    let (_, code) = create(&mut alice, RoomMode::PeerToPeer, None).await;

    // Bob never pings — the stand-in for a connection that died silently.
    let never = Keepalive {
        ping_interval: Duration::from_secs(3600),
        idle_timeout: Duration::from_secs(3600),
    };
    let mut bob = connect(&server.url(), &bob_s, "bob", never).await;
    join(&mut bob, code, None).await.unwrap();

    expect(&mut alice, "PeerLeft(bob) after idle timeout", |m| {
        is_peer_left(bob.id)(m).then_some(())
    })
    .await;
    // Alice, who pings, is still connected.
    assert!(!alice.client.is_closed());
}

/// The client side of the same problem: a server that stops talking is
/// declared dead so the engine's supervisor can reconnect.
#[tokio::test]
async fn client_detects_a_silent_server() {
    let server = Server::spawn(39816, None).await;
    let secret = NodeSecret::generate();
    // No pings from us, so the server sends nothing unprompted.
    let peer = connect(
        &server.url(),
        &secret,
        "alice",
        Keepalive {
            ping_interval: Duration::from_secs(3600),
            idle_timeout: Duration::from_secs(1),
        },
    )
    .await;
    timeout(Duration::from_secs(4), peer.client.closed())
        .await
        .expect("client never noticed the silent connection");
}

/// With regular pings a quiet connection stays up indefinitely.
#[tokio::test]
async fn pinging_client_stays_connected() {
    let server = Server::spawn(39817, Some(1)).await;
    let secret = NodeSecret::generate();
    let peer = connect(
        &server.url(),
        &secret,
        "alice",
        Keepalive {
            ping_interval: Duration::from_millis(200),
            idle_timeout: Duration::from_secs(1),
        },
    )
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !peer.client.is_closed(),
        "pings should keep both sides happy"
    );
}
