//! A restarted daemon rejoins the room it was in — and only when it should.
//!
//! Real `hermes-signaling` process, real `hermes_daemon::Server`s (with
//! in-memory adapters, so no privileges), talking over the IPC protocol.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use tokio::time::timeout;

use hermes_core::room::{InviteCode, RoomMode};
use hermes_core::tap::mock::mock_adapter_factory;
use hermes_core::tap::AdapterMode;
use hermes_core::{EngineConfig, HermesEngine};
use hermes_daemon::protocol::{CommandPayload, Event, ResponseBody};
use hermes_daemon::resume::{Resume, ResumeStore};
use hermes_daemon::{DaemonClient, Server};

struct Signaling(Child);
impl Drop for Signaling {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn spawn_signaling(port: u16) -> Signaling {
    let s = Signaling(
        Command::new(env!("CARGO_BIN_EXE_hermes-signaling"))
            .env("HERMES_SIGNALING_BIND", format!("127.0.0.1:{port}"))
            .env("RUST_LOG", "warn")
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("signaling never came up");
}

fn data_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hermes-resume-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// A daemon `Server` on `data_dir` with an in-memory adapter.
fn daemon(dir: &PathBuf) -> std::sync::Arc<Server> {
    let (factory, _handles) = mock_adapter_factory(AdapterMode::Ethernet);
    let engine = HermesEngine::new(EngineConfig {
        data_dir: dir.clone(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        stun_server: String::new(),
        upnp: false,
        ..EngineConfig::default()
    })
    .unwrap()
    .with_adapter_factory(factory);
    Server::from_engine(engine, dir.clone())
}

async fn ipc(server: &std::sync::Arc<Server>) -> DaemonClient {
    let (a, b) = tokio::io::duplex(64 * 1024);
    tokio::spawn(server.clone().serve_client(a));
    DaemonClient::from_stream(b).await.unwrap()
}

async fn ok(client: &DaemonClient, cmd: CommandPayload) {
    let body = client.call(cmd).await.unwrap();
    assert!(matches!(body, ResponseBody::Ok), "{body:?}");
}

async fn wait_room_entered(events: &mut tokio::sync::broadcast::Receiver<Event>) -> Option<String> {
    timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(Event::RoomEntered { invite_code, .. }) = events.recv().await {
                return invite_code;
            }
        }
    })
    .await
    .expect("never entered the room")
}

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..150 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Create a room on a plain engine ("Bob") that stays in it, so the room
/// outlives the daemon under test. Returns (engine, invite code).
async fn keep_room_alive(url: &str, tag: &str) -> (HermesEngine, InviteCode) {
    let (factory, _h) = mock_adapter_factory(AdapterMode::Ethernet);
    let engine = HermesEngine::new(EngineConfig {
        data_dir: data_dir(tag),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        stun_server: String::new(),
        upnp: false,
        ..EngineConfig::default()
    })
    .unwrap()
    .with_adapter_factory(factory);
    let mut events = engine.take_events().unwrap();
    engine.connect(Some(url)).await.unwrap();
    engine
        .create_room("resume".into(), RoomMode::PeerToPeer, None)
        .await
        .unwrap();
    let code = loop {
        if let Some(hermes_core::EngineEvent::RoomEntered {
            invite_code: Some(code),
            ..
        }) = events.recv().await
        {
            break code;
        }
    };
    // Keep draining events so the engine never blocks on a full channel.
    tokio::spawn(async move { while events.recv().await.is_some() {} });
    (engine, code)
}

#[tokio::test]
async fn restarted_daemon_rejoins_its_room() {
    let port = 39841;
    let _signaling = spawn_signaling(port).await;
    let url = format!("ws://127.0.0.1:{port}/v1");
    let (bob, code) = keep_room_alive(&url, "bob").await;

    // First run: join by hand; the room is remembered.
    let dir = data_dir("alice");
    let first = daemon(&dir);
    let client = ipc(&first).await;
    let mut events = first.subscribe_events();
    ok(
        &client,
        CommandPayload::Connect {
            signaling_url: Some(url.clone()),
        },
    )
    .await;
    ok(
        &client,
        CommandPayload::JoinRoom {
            code: code.to_string(),
        },
    )
    .await;
    wait_room_entered(&mut events).await;
    let store = ResumeStore::new(&dir);
    wait_until("resume.json to be written", || store.load().is_some()).await;
    assert_eq!(
        store.load(),
        Some(Resume {
            signaling_url: url.clone(),
            invite_code: code.to_string()
        })
    );

    // "Reboot": a plain stop must NOT forget the room.
    first.engine().shutdown().await;
    drop(client);
    assert!(
        store.load().is_some(),
        "a shutdown must keep the saved room"
    );

    // Second run: nobody tells it anything, and it's back in the room with Bob.
    let second = daemon(&dir);
    let mut events = second.subscribe_events();
    wait_room_entered(&mut events).await;
    wait_until("Bob to appear in the resumed room", || {
        second
            .engine()
            .current_room()
            .is_some_and(|r| !r.peers().is_empty())
    })
    .await;
    assert_eq!(second.engine().current_invite(), Some(code));

    second.engine().shutdown().await;
    bob.shutdown().await;
}

#[tokio::test]
async fn explicit_leave_is_not_resumed() {
    let port = 39842;
    let _signaling = spawn_signaling(port).await;
    let url = format!("ws://127.0.0.1:{port}/v1");
    let (bob, code) = keep_room_alive(&url, "bob2").await;

    let dir = data_dir("alice2");
    let server = daemon(&dir);
    let client = ipc(&server).await;
    let mut events = server.subscribe_events();
    ok(
        &client,
        CommandPayload::Connect {
            signaling_url: Some(url),
        },
    )
    .await;
    ok(
        &client,
        CommandPayload::JoinRoom {
            code: code.to_string(),
        },
    )
    .await;
    wait_room_entered(&mut events).await;
    let store = ResumeStore::new(&dir);
    wait_until("resume.json", || store.load().is_some()).await;

    ok(&client, CommandPayload::LeaveRoom).await;
    assert!(store.load().is_none(), "leave must forget the room");

    // A restart finds nothing to rejoin.
    server.engine().shutdown().await;
    let again = daemon(&dir);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(again.engine().current_room().is_none());
    assert!(!again.engine().is_connected());

    again.engine().shutdown().await;
    bob.shutdown().await;
}

#[tokio::test]
async fn a_room_that_no_longer_exists_is_forgotten() {
    let port = 39843;
    let _signaling = spawn_signaling(port).await;
    let url = format!("ws://127.0.0.1:{port}/v1");

    let dir = data_dir("alice3");
    std::fs::create_dir_all(&dir).unwrap();
    let store = ResumeStore::new(&dir);
    store
        .save(&Resume {
            signaling_url: url,
            invite_code: InviteCode::generate().to_string(),
        })
        .unwrap();

    let server = daemon(&dir);
    wait_until("the dead room to be forgotten", || store.load().is_none()).await;
    assert!(server.engine().current_room().is_none());
    server.engine().shutdown().await;
}
