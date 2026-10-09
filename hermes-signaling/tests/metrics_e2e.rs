//! The signaling server's optional /metrics endpoint, scraped from a real
//! process after real activity.

use std::process::{Child, Command};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use hermes_core::crypto::NodeSecret;
use hermes_core::crypto::RoomKeys;
use hermes_core::room::{InviteCode, RoomMode};
use hermes_core::signaling::protocol::{ClientMessage, ServerMessage};
use hermes_core::signaling::SignalingClient;

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn scrape(port: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

fn value(text: &str, series: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix(series).and_then(|r| r.trim().parse().ok()))
        .unwrap_or_else(|| panic!("series {series} missing in:\n{text}"))
}

#[tokio::test]
async fn metrics_reflect_real_activity() {
    let (ws, metrics) = (free_port(), free_port());
    let _server = Server(
        Command::new(env!("CARGO_BIN_EXE_hermes-signaling"))
            .env("HERMES_SIGNALING_BIND", format!("127.0.0.1:{ws}"))
            .env(
                "HERMES_SIGNALING_METRICS_BIND",
                format!("127.0.0.1:{metrics}"),
            )
            .env("RUST_LOG", "warn")
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", metrics)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let url = format!("ws://127.0.0.1:{ws}/v1");

    let (alice_s, bob_s) = (NodeSecret::generate(), NodeSecret::generate());
    let alice = SignalingClient::connect(&url, &alice_s, "alice".into())
        .await
        .unwrap();
    let mut alice_in = alice.take_inbox().unwrap();
    let code = InviteCode::generate();
    let keys = RoomKeys::derive(&code, None);
    alice
        .send(ClientMessage::create_room(
            "m".into(),
            RoomMode::PeerToPeer,
            None,
            &keys,
            &alice_s,
        ))
        .await
        .unwrap();
    loop {
        if let Some(ServerMessage::RoomCreated { .. }) = alice_in.recv().await {
            break;
        }
    }
    let bob = SignalingClient::connect(&url, &bob_s, "bob".into())
        .await
        .unwrap();
    let mut bob_in = bob.take_inbox().unwrap();
    bob.send(ClientMessage::join_room(&keys, &bob_s, None))
        .await
        .unwrap();
    bob.send(ClientMessage::join_room(
        &RoomKeys::derive(&InviteCode::generate(), None),
        &bob_s,
        None,
    ))
    .await
    .unwrap();
    // Drain bob's two replies (RoomJoined, then the invalid-code error).
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(3), bob_in.recv())
            .await
            .unwrap();
    }

    let text = scrape(metrics).await;
    assert_eq!(value(&text, "hermes_signaling_sessions "), 2);
    assert_eq!(value(&text, "hermes_signaling_rooms "), 1);
    assert_eq!(value(&text, "hermes_signaling_connections_total "), 2);
    assert_eq!(
        value(
            &text,
            "hermes_signaling_room_events_total{kind=\"created\"} "
        ),
        1
    );
    assert_eq!(
        value(
            &text,
            "hermes_signaling_room_events_total{kind=\"invalid_code\"} "
        ),
        1
    );
    // The first join was real, the second wasn't: only one "joined" counts.
    assert_eq!(
        value(
            &text,
            "hermes_signaling_room_events_total{kind=\"joined\"} "
        ),
        1
    );
    assert!(
        !text.contains("alice") && !text.contains(&code.to_string()),
        "no names or codes in metrics"
    );

    drop(bob);
    drop(bob_in);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        value(&scrape(metrics).await, "hermes_signaling_sessions "),
        1
    );
}
