//! Auto-reconnect, end to end: a real `HermesEngine` connected to the
//! real signaling binary must survive the server dying and coming back —
//! emitting Disconnected → Reconnecting → Reconnected and ending up
//! connected again, with no user action.

use std::process::{Child, Command};
use std::time::Duration;

use tokio::time::timeout;

use hermes_core::{EngineConfig, EngineEvent, HermesEngine};

const PORT: u16 = 39805;

fn spawn_server() -> Child {
    Command::new(env!("CARGO_BIN_EXE_hermes-signaling"))
        .env("HERMES_SIGNALING_BIND", format!("127.0.0.1:{PORT}"))
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("spawn hermes-signaling")
}

async fn wait_listening() {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", PORT))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("signaling server never came up");
}

/// Drain events until `pred` matches one, or panic after `budget`.
async fn expect_event(
    events: &mut tokio::sync::mpsc::Receiver<EngineEvent>,
    budget: Duration,
    what: &str,
    mut pred: impl FnMut(&EngineEvent) -> bool,
) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for {what}");
        match timeout(remaining, events.recv()).await {
            Ok(Some(ev)) => {
                if pred(&ev) {
                    return;
                }
            }
            Ok(None) => panic!("event stream closed while waiting for {what}"),
            Err(_) => panic!("timed out waiting for {what}"),
        }
    }
}

#[tokio::test]
async fn engine_reconnects_after_server_restart() {
    let mut server = spawn_server();
    wait_listening().await;

    let data_dir = std::env::temp_dir().join(format!("hermes-reconnect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let engine = HermesEngine::new(EngineConfig {
        data_dir: data_dir.clone(),
        ..EngineConfig::default()
    })
    .expect("engine");
    let mut events = engine.take_events().expect("events");

    let url = format!("ws://127.0.0.1:{PORT}/v1");
    engine.connect(Some(&url)).await.expect("initial connect");
    assert!(engine.is_connected());

    // Kill the server: the engine must notice and start reconnecting.
    server.kill().expect("kill server");
    let _ = server.wait();

    expect_event(&mut events, Duration::from_secs(10), "Disconnected", |e| {
        matches!(e, EngineEvent::SignalingDisconnected)
    })
    .await;
    expect_event(&mut events, Duration::from_secs(10), "Reconnecting", |e| {
        matches!(e, EngineEvent::SignalingReconnecting { .. })
    })
    .await;

    // While the server is down, more Reconnecting attempts tick with
    // backoff; is_connected reports the truth.
    assert!(!engine.is_connected());

    // Bring the server back: the engine must re-establish on its own.
    let mut server = spawn_server();
    wait_listening().await;

    expect_event(&mut events, Duration::from_secs(20), "Reconnected", |e| {
        matches!(e, EngineEvent::SignalingReconnected)
    })
    .await;
    assert!(engine.is_connected());

    // Explicit disconnect stops the supervisor for good: killing the
    // server again must NOT produce another reconnect cycle.
    engine.disconnect().await;
    server.kill().expect("kill server again");
    let _ = server.wait();

    let quiet = timeout(Duration::from_secs(3), async {
        loop {
            match events.recv().await {
                Some(EngineEvent::SignalingReconnecting { .. })
                | Some(EngineEvent::SignalingReconnected) => {
                    panic!("supervisor kept reconnecting after explicit disconnect")
                }
                Some(_) => continue,
                None => break,
            }
        }
    })
    .await;
    // Either the stream stayed quiet until timeout (Err) or it closed
    // cleanly (Ok) — both mean no rogue reconnects.
    let _ = quiet;

    let _ = std::fs::remove_dir_all(data_dir);
}
