//! End-to-end tests against the real `hermes-signaling` binary: spawn it,
//! authenticate two clients with real Ed25519 challenge/response, create
//! a relayed room, join it by invite code, and check that the room mode
//! and relay assignment propagate to every member.

use std::process::{Child, Command};
use std::time::Duration;

use tokio::time::timeout;

use hermes_core::crypto::NodeSecret;
use hermes_core::room::RoomMode;
use hermes_core::signaling::protocol::{ClientMessage, ServerMessage};
use hermes_core::signaling::SignalingClient;

struct SignalingProcess {
    child: Child,
    url: String,
}

impl SignalingProcess {
    async fn spawn(port: u16) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_hermes-signaling"))
            .env("HERMES_SIGNALING_BIND", format!("127.0.0.1:{port}"))
            .env("RUST_LOG", "warn")
            .spawn()
            .expect("spawn hermes-signaling");
        let proc = Self {
            child,
            url: format!("ws://127.0.0.1:{port}/v1"),
        };
        // Wait for the listener to come up.
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return proc;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("signaling server never came up");
    }
}

impl Drop for SignalingProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn relayed_room_mode_propagates_to_creator_and_joiner() {
    let server = SignalingProcess::spawn(39801).await;

    let alice = NodeSecret::generate();
    let bob = NodeSecret::generate();

    // Connect both clients — this exercises the signed-challenge auth.
    let alice_client = SignalingClient::connect(&server.url, &alice, "alice".into())
        .await
        .expect("alice connect");
    let mut alice_inbox = alice_client.take_inbox().unwrap();

    let bob_client = SignalingClient::connect(&server.url, &bob, "bob".into())
        .await
        .expect("bob connect");
    let mut bob_inbox = bob_client.take_inbox().unwrap();

    // Alice creates a relayed room.
    alice_client
        .send(ClientMessage::CreateRoom {
            name: "game night".into(),
            mode: RoomMode::Relayed,
            relay_addr: Some("relay.example.net:8788".into()),
            password: None,
        })
        .await
        .unwrap();

    let (room_id, invite) = match timeout(Duration::from_secs(3), alice_inbox.recv())
        .await
        .expect("timeout")
        .expect("closed")
    {
        ServerMessage::RoomCreated {
            room_id,
            invite_code,
            mode,
            relay_addr,
            ..
        } => {
            assert_eq!(mode, RoomMode::Relayed);
            assert_eq!(relay_addr.as_deref(), Some("relay.example.net:8788"));
            (room_id, invite_code)
        }
        other => panic!("expected RoomCreated, got {other:?}"),
    };

    // Bob joins by invite code and must learn the same mode + relay.
    bob_client
        .send(ClientMessage::JoinRoom {
            code: invite,
            restore: None,
            password: None,
        })
        .await
        .unwrap();

    match timeout(Duration::from_secs(3), bob_inbox.recv())
        .await
        .expect("timeout")
        .expect("closed")
    {
        ServerMessage::RoomJoined {
            room_id: joined_id,
            members,
            mode,
            relay_addr,
            ..
        } => {
            assert_eq!(joined_id, room_id);
            assert_eq!(mode, RoomMode::Relayed);
            assert_eq!(relay_addr.as_deref(), Some("relay.example.net:8788"));
            assert_eq!(members.len(), 1);
            assert_eq!(members[0].node_id, alice.public().node_id);
            assert_eq!(members[0].alias, "alice");
        }
        other => panic!("expected RoomJoined, got {other:?}"),
    }

    // Alice gets the PeerJoined for Bob.
    match timeout(Duration::from_secs(3), alice_inbox.recv())
        .await
        .expect("timeout")
        .expect("closed")
    {
        ServerMessage::PeerJoined { peer } => {
            assert_eq!(peer.node_id, bob.public().node_id);
            assert_eq!(peer.alias, "bob");
        }
        other => panic!("expected PeerJoined, got {other:?}"),
    }
}

#[tokio::test]
async fn relayed_room_without_relay_address_is_rejected() {
    let server = SignalingProcess::spawn(39802).await;

    let carol = NodeSecret::generate();
    let client = SignalingClient::connect(&server.url, &carol, "carol".into())
        .await
        .expect("connect");
    let mut inbox = client.take_inbox().unwrap();

    client
        .send(ClientMessage::CreateRoom {
            name: "broken".into(),
            mode: RoomMode::Relayed,
            relay_addr: None,
            password: None,
        })
        .await
        .unwrap();

    match timeout(Duration::from_secs(3), inbox.recv())
        .await
        .expect("timeout")
        .expect("closed")
    {
        ServerMessage::Error { code, .. } => assert_eq!(code, "relay_required"),
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn p2p_room_is_the_default_and_carries_no_relay() {
    let server = SignalingProcess::spawn(39803).await;

    let dave = NodeSecret::generate();
    let client = SignalingClient::connect(&server.url, &dave, "dave".into())
        .await
        .expect("connect");
    let mut inbox = client.take_inbox().unwrap();

    client
        .send(ClientMessage::CreateRoom {
            name: "classic".into(),
            mode: RoomMode::PeerToPeer,
            relay_addr: None,
            password: None,
        })
        .await
        .unwrap();

    match timeout(Duration::from_secs(3), inbox.recv())
        .await
        .expect("timeout")
        .expect("closed")
    {
        ServerMessage::RoomCreated {
            mode, relay_addr, ..
        } => {
            assert_eq!(mode, RoomMode::PeerToPeer);
            assert!(relay_addr.is_none());
        }
        other => panic!("expected RoomCreated, got {other:?}"),
    }
}

/// A peer-to-peer room may carry an optional fallback relay; it must
/// propagate to every joiner exactly like the relayed-room case, so both
/// sides can fail over to the same relay when a direct path can't be made.
#[tokio::test]
async fn p2p_room_fallback_relay_propagates_to_joiner() {
    let server = SignalingProcess::spawn(39804).await;

    let erin = NodeSecret::generate();
    let frank = NodeSecret::generate();

    let erin_client = SignalingClient::connect(&server.url, &erin, "erin".into())
        .await
        .expect("erin connect");
    let mut erin_inbox = erin_client.take_inbox().unwrap();
    let frank_client = SignalingClient::connect(&server.url, &frank, "frank".into())
        .await
        .expect("frank connect");
    let mut frank_inbox = frank_client.take_inbox().unwrap();

    // P2P room, but with a fallback relay attached.
    erin_client
        .send(ClientMessage::CreateRoom {
            name: "p2p with safety net".into(),
            mode: RoomMode::PeerToPeer,
            relay_addr: Some("fallback.example.net:8788".into()),
            password: None,
        })
        .await
        .unwrap();

    let invite = match timeout(Duration::from_secs(3), erin_inbox.recv())
        .await
        .expect("timeout")
        .expect("closed")
    {
        ServerMessage::RoomCreated {
            mode,
            relay_addr,
            invite_code,
            ..
        } => {
            assert_eq!(mode, RoomMode::PeerToPeer);
            assert_eq!(relay_addr.as_deref(), Some("fallback.example.net:8788"));
            invite_code
        }
        other => panic!("expected RoomCreated, got {other:?}"),
    };

    frank_client
        .send(ClientMessage::JoinRoom {
            code: invite,
            restore: None,
            password: None,
        })
        .await
        .unwrap();

    match timeout(Duration::from_secs(3), frank_inbox.recv())
        .await
        .expect("timeout")
        .expect("closed")
    {
        ServerMessage::RoomJoined {
            mode, relay_addr, ..
        } => {
            assert_eq!(mode, RoomMode::PeerToPeer);
            assert_eq!(relay_addr.as_deref(), Some("fallback.example.net:8788"));
        }
        other => panic!("expected RoomJoined, got {other:?}"),
    }
}
