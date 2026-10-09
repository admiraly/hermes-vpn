//! Per-IP abuse limits on the real `hermes-signaling` binary.

use std::process::{Child, Command};
use std::time::Duration;

use tokio::time::timeout;

use hermes_core::crypto::{NodeSecret, RoomKeys};
use hermes_core::room::InviteCode;
use hermes_core::signaling::protocol::{ClientMessage, ServerMessage};
use hermes_core::signaling::SignalingClient;

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn spawn(port: u16, env: &[(&str, &str)]) -> Server {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hermes-signaling"));
    cmd.env("HERMES_SIGNALING_BIND", format!("127.0.0.1:{port}"))
        .env("RUST_LOG", "warn");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let server = Server(cmd.spawn().expect("spawn hermes-signaling"));
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

/// Invite-code guessing is capped: after the allowance, join attempts are
/// refused without even looking the code up.
#[tokio::test]
async fn join_attempts_are_rate_limited_per_ip() {
    let port = 39821;
    // The health-probe TCP connects above don't count: they never upgrade.
    let _server = spawn(port, &[("HERMES_SIGNALING_ROOM_OPS_PER_MIN", "3")]).await;
    let guesser = NodeSecret::generate();
    let client = SignalingClient::connect(
        &format!("ws://127.0.0.1:{port}/v1"),
        &guesser,
        "guesser".into(),
    )
    .await
    .unwrap();
    let mut inbox = client.take_inbox().unwrap();

    let mut codes = Vec::new();
    for _ in 0..5 {
        client
            .send(ClientMessage::join_room(
                &RoomKeys::derive(&InviteCode::generate(), None),
                &guesser,
                None,
            ))
            .await
            .unwrap();
        match timeout(Duration::from_secs(3), inbox.recv())
            .await
            .unwrap()
            .unwrap()
        {
            ServerMessage::Error { code, .. } => codes.push(code),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(codes[..3], ["invalid_code", "invalid_code", "invalid_code"]);
    assert_eq!(codes[3..], ["rate_limited", "rate_limited"]);
}

/// Opening connections is capped per IP too (identities are free, so the
/// IP is the only meaningful key).
#[tokio::test]
async fn connections_are_rate_limited_per_ip() {
    let port = 39822;
    let _server = spawn(port, &[("HERMES_SIGNALING_CONNECTIONS_PER_MIN", "2")]).await;
    let url = format!("ws://127.0.0.1:{port}/v1");
    let mut kept = Vec::new();
    for _ in 0..2 {
        kept.push(
            SignalingClient::connect(&url, &NodeSecret::generate(), "ok".into())
                .await
                .expect("within the allowance"),
        );
    }
    let third = SignalingClient::connect(&url, &NodeSecret::generate(), "flood".into()).await;
    assert!(
        third.is_err(),
        "third connection in a minute must be refused"
    );
}
