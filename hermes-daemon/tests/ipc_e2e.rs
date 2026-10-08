//! Full IPC round-trip: a real `Server` (with a real engine + directory)
//! serving a real `DaemonClient` over an in-memory duplex stream — the
//! same code path as the named pipe / unix socket, minus the OS.

use hermes_core::directory::ServerKind;
use hermes_core::EngineConfig;
use hermes_daemon::protocol::{CommandPayload, ResponseBody};
use hermes_daemon::{DaemonClient, Server};

fn test_config(tag: &str) -> EngineConfig {
    let data_dir =
        std::env::temp_dir().join(format!("hermes-ipc-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    EngineConfig {
        data_dir,
        ..EngineConfig::default()
    }
}

async fn connect_pair(tag: &str) -> (std::path::PathBuf, DaemonClient) {
    let config = test_config(tag);
    let data_dir = config.data_dir.clone();
    let server = Server::new(config).expect("server");
    let (a, b) = tokio::io::duplex(64 * 1024);
    tokio::spawn(server.serve_client(a));
    let client = DaemonClient::from_stream(b).await.expect("handshake");
    (data_dir, client)
}

#[tokio::test]
async fn handshake_identity_and_state() {
    let (data_dir, client) = connect_pair("ident").await;

    match client.call(CommandPayload::GetIdentity).await.unwrap() {
        ResponseBody::Identity { node_id_base64 } => {
            assert!(!node_id_base64.is_empty());
        }
        other => panic!("unexpected: {other:?}"),
    }

    match client.call(CommandPayload::GetState).await.unwrap() {
        ResponseBody::State(snap) => {
            assert!(!snap.connected);
            assert!(snap.room.is_none());
            assert!(snap.peers.is_empty());
        }
        other => panic!("unexpected: {other:?}"),
    }

    let _ = std::fs::remove_dir_all(data_dir);
}

#[tokio::test]
async fn server_directory_management_over_ipc() {
    let (data_dir, client) = connect_pair("dir").await;

    // Built-in defaults must be visible.
    let listing = match client.call(CommandPayload::GetServers).await.unwrap() {
        ResponseBody::Servers(l) => l,
        other => panic!("unexpected: {other:?}"),
    };
    assert!(!listing.signaling.is_empty());
    assert!(!listing.relays.is_empty());

    // Add a custom relay + signaling server.
    let body = client
        .call(CommandPayload::AddServer {
            kind: ServerKind::Relay,
            name: "VPS relay".into(),
            address: "vps.example.net:8788".into(),
        })
        .await
        .unwrap();
    assert!(matches!(body, ResponseBody::Ok), "{body:?}");

    let body = client
        .call(CommandPayload::AddServer {
            kind: ServerKind::Signaling,
            name: "VPS".into(),
            address: "wss://vps.example.net/v1".into(),
        })
        .await
        .unwrap();
    assert!(matches!(body, ResponseBody::Ok), "{body:?}");

    // Select the new signaling server as active.
    let body = client
        .call(CommandPayload::SetActiveSignaling { name: "VPS".into() })
        .await
        .unwrap();
    assert!(matches!(body, ResponseBody::Ok), "{body:?}");

    // Everything must round-trip through the listing.
    let listing = match client.call(CommandPayload::GetServers).await.unwrap() {
        ResponseBody::Servers(l) => l,
        other => panic!("unexpected: {other:?}"),
    };
    assert!(listing.relays.iter().any(|s| s.name == "VPS relay"));
    assert_eq!(listing.active_signaling.as_deref(), Some("VPS"));

    // Selecting a nonexistent server fails cleanly.
    let body = client
        .call(CommandPayload::SetActiveSignaling {
            name: "does-not-exist".into(),
        })
        .await
        .unwrap();
    assert!(matches!(body, ResponseBody::Error { .. }), "{body:?}");

    // Remove the custom relay again.
    let body = client
        .call(CommandPayload::RemoveServer {
            kind: ServerKind::Relay,
            name: "VPS relay".into(),
        })
        .await
        .unwrap();
    assert!(matches!(body, ResponseBody::Ok), "{body:?}");

    // The directory must have persisted to disk.
    assert!(data_dir.join("servers.toml").exists());

    let _ = std::fs::remove_dir_all(data_dir);
}

#[tokio::test]
async fn display_name_round_trip() {
    let (data_dir, client) = connect_pair("alias").await;

    let body = client
        .call(CommandPayload::SetAlias {
            alias: "  Lisa's desktop ".into(),
        })
        .await
        .unwrap();
    assert!(matches!(body, ResponseBody::Ok), "{body:?}");

    match client.call(CommandPayload::GetState).await.unwrap() {
        ResponseBody::State(snap) => assert_eq!(snap.alias, "Lisa's desktop"),
        other => panic!("unexpected: {other:?}"),
    }

    // Invalid names are refused with a clear error.
    let body = client
        .call(CommandPayload::SetAlias {
            alias: "   ".into(),
        })
        .await
        .unwrap();
    assert!(matches!(body, ResponseBody::Error { .. }), "{body:?}");

    let _ = std::fs::remove_dir_all(data_dir);
}
