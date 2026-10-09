//! A hostile signaling server must not be able to man-in-the-middle a
//! tunnel by handing a client a WireGuard key that isn't the peer's.
//!
//! The "server" here is a minimal WebSocket server written for the test.
//! It authenticates the client normally, then answers the client's room
//! join with a member whose key it chooses. A client must accept the real
//! key (control) and refuse substituted or unvouched ones.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

use hermes_core::crypto::NodeSecret;
use hermes_core::room::RoomId;
use hermes_core::signaling::{ClientMessage, PeerInfo, ServerMessage};
use hermes_core::tap::mock::mock_adapter_factory;
use hermes_core::tap::AdapterMode;
use hermes_core::{EngineConfig, EngineEvent, HermesEngine};

/// What the hostile server tells the client about "Alice".
#[derive(Clone, Copy, Debug)]
enum Attack {
    /// Alice's real key and binding (control: must be accepted).
    None,
    /// The server's own key, with Alice's genuine binding for her real key.
    SubstitutedKey,
    /// The server's own key, no binding at all.
    NoBinding,
    /// The server's own key, and a binding it signed itself.
    ForgedBinding,
}

async fn hostile_server(attack: Attack) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1", listener.local_addr().unwrap());
    let alice = NodeSecret::generate();
    let evil = NodeSecret::generate();

    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let send = |msg: ServerMessage| Message::Text(serde_json::to_string(&msg).unwrap());

        // Authenticate the client (we don't bother verifying: it's ours).
        ws.send(send(ServerMessage::Challenge { nonce: vec![9; 32] }))
            .await
            .unwrap();
        let hello = ws.next().await.unwrap().unwrap();
        let Message::Text(t) = hello else {
            panic!("hello")
        };
        assert!(matches!(
            serde_json::from_str::<ClientMessage>(&t).unwrap(),
            ClientMessage::Hello { .. }
        ));
        ws.send(send(ServerMessage::Welcome {
            session_id: "x".into(),
        }))
        .await
        .unwrap();

        // Wait for the client's JoinRoom, then answer with a crafted member.
        loop {
            let Message::Text(t) = ws.next().await.unwrap().unwrap() else {
                continue;
            };
            if matches!(
                serde_json::from_str::<ClientMessage>(&t).unwrap(),
                ClientMessage::JoinRoom { .. }
            ) {
                break;
            }
        }
        let a = alice.public();
        let (wireguard_public, wireguard_binding) = match attack {
            Attack::None => (a.wireguard_public, alice.sign_wireguard_binding()),
            Attack::SubstitutedKey => (
                evil.public().wireguard_public,
                alice.sign_wireguard_binding(),
            ),
            Attack::NoBinding => (evil.public().wireguard_public, Vec::new()),
            // Signed by the server's key, claimed under Alice's identity.
            Attack::ForgedBinding => (
                evil.public().wireguard_public,
                evil.sign_wireguard_binding(),
            ),
        };
        ws.send(send(ServerMessage::RoomJoined {
            room_id: RoomId::new_v4(),
            members: vec![PeerInfo {
                node_id: a.node_id,
                wireguard_public,
                wireguard_binding,
                alias: "alice".into(),
                ip_salt: 0,
            }],
            mode: hermes_core::RoomMode::PeerToPeer,
            relay_addr: None,
            ip_salt: 0,
        }))
        .await
        .unwrap();
        // Keep the connection open while the client reacts.
        while ws.next().await.is_some() {}
    });
    (url, task)
}

async fn run(attack: Attack) -> (bool, Option<String>) {
    let (url, _server) = hostile_server(attack).await;
    let data_dir =
        std::env::temp_dir().join(format!("hermes-keybind-{attack:?}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let (factory, _handles) = mock_adapter_factory(AdapterMode::Ethernet);
    let engine = HermesEngine::new(EngineConfig {
        data_dir,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        stun_server: String::new(),
        upnp: false,
        ..EngineConfig::default()
    })
    .unwrap()
    .with_adapter_factory(factory);
    let mut events = engine.take_events().unwrap();
    engine.connect(Some(&url)).await.unwrap();
    engine
        .join_room("WLFK-7X4K-QR2S".parse().unwrap())
        .await
        .unwrap();

    let (mut added, mut error) = (false, None);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while let Ok(Some(ev)) = timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        events.recv(),
    )
    .await
    {
        match ev {
            EngineEvent::PeerAdded(_) => {
                added = true;
                break;
            }
            EngineEvent::SignalingError { code, .. } if code == "bad_peer_key" => {
                error = Some(code);
                break;
            }
            _ => {}
        }
    }
    let peers_in_room = engine.current_room().map_or(0, |room| room.peers().len());
    assert_eq!(
        peers_in_room,
        usize::from(added),
        "room table must match what was accepted"
    );
    engine.shutdown().await;
    (added, error)
}

#[tokio::test]
async fn genuine_key_is_accepted() {
    assert_eq!(run(Attack::None).await, (true, None));
}

#[tokio::test]
async fn substituted_key_is_refused() {
    assert_eq!(
        run(Attack::SubstitutedKey).await,
        (false, Some("bad_peer_key".into()))
    );
}

#[tokio::test]
async fn missing_binding_is_refused() {
    assert_eq!(
        run(Attack::NoBinding).await,
        (false, Some("bad_peer_key".into()))
    );
}

#[tokio::test]
async fn forged_binding_is_refused() {
    assert_eq!(
        run(Attack::ForgedBinding).await,
        (false, Some("bad_peer_key".into()))
    );
}
