//! Whole-engine end to end, no privileges needed: two real `HermesEngine`s
//! talk through the real `hermes-signaling` binary, connect peer to peer
//! over loopback, and exchange traffic through in-memory adapters.
//!
//! One side poses as a Linux TAP adapter (Ethernet frames), the other as
//! Windows wintun (IP packets), so the L2/L3 shim — ARP answering, MAC
//! synthesis, unwrapping — runs here on every platform.

use std::net::Ipv4Addr;
use std::process::{Child, Command};
use std::time::Duration;

use tokio::sync::mpsc::{Receiver, UnboundedReceiver};
use tokio::time::timeout;

use hermes_core::broadcast::{arp, ETHERTYPE_IPV4};
use hermes_core::crypto::{VirtualIpv4, VirtualMac};
use hermes_core::room::{PeerStatus, RoomMode};
use hermes_core::tap::mock::{mock_adapter_factory, MockHandle};
use hermes_core::tap::AdapterMode;
use hermes_core::{EngineConfig, EngineEvent, HermesEngine};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn spawn_signaling(port: u16) -> Server {
    let server = Server(
        Command::new(env!("CARGO_BIN_EXE_hermes-signaling"))
            .env("HERMES_SIGNALING_BIND", format!("127.0.0.1:{port}"))
            .env("RUST_LOG", "warn")
            .spawn()
            .expect("spawn hermes-signaling"),
    );
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

struct Node {
    engine: HermesEngine,
    events: Receiver<EngineEvent>,
    handles: UnboundedReceiver<MockHandle>,
    mac: VirtualMac,
}

fn node(tag: &str, mode: AdapterMode) -> Node {
    let data_dir =
        std::env::temp_dir().join(format!("hermes-engine-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let config = EngineConfig {
        data_dir,
        alias: tag.into(),
        // Loopback only: the host candidate is then 127.0.0.1:port, and
        // there is no STUN or router to wait for.
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        stun_server: String::new(),
        upnp: false,
        ..EngineConfig::default()
    };
    let (factory, handles) = mock_adapter_factory(mode);
    let engine = HermesEngine::new(config)
        .unwrap()
        .with_adapter_factory(factory);
    let events = engine.take_events().unwrap();
    let mac = VirtualMac::from_node_id(&engine.identity().node_id);
    Node {
        engine,
        events,
        handles,
        mac,
    }
}

/// Wait for an event matching `pred`.
async fn wait_event<T>(
    events: &mut Receiver<EngineEvent>,
    what: &str,
    mut pred: impl FnMut(&EngineEvent) -> Option<T>,
) -> T {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(remaining, events.recv()).await {
            Ok(Some(ev)) => {
                if let Some(v) = pred(&ev) {
                    return v;
                }
            }
            Ok(None) => panic!("event stream closed waiting for {what}"),
            Err(_) => panic!("timed out waiting for {what}"),
        }
    }
}

async fn next_written(handle: &mut MockHandle, what: &str) -> Vec<u8> {
    timeout(Duration::from_secs(10), handle.written.recv())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        .unwrap_or_else(|| panic!("adapter closed waiting for {what}"))
}

fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = u16::try_from(20 + payload.len()).unwrap();
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

fn ethernet(dst: VirtualMac, src: VirtualMac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = dst.0.to_vec();
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

#[tokio::test]
async fn linux_style_and_windows_style_nodes_exchange_traffic() {
    let port = 39831;
    let _server = spawn_signaling(port).await;
    let url = format!("ws://127.0.0.1:{port}/v1");

    let mut linux = node("linux", AdapterMode::Ethernet);
    let mut windows = node("windows", AdapterMode::Ip);

    // Linux creates a peer-to-peer room, Windows joins by invite code.
    linux.engine.connect(Some(&url)).await.unwrap();
    linux
        .engine
        .create_room("e2e".into(), RoomMode::PeerToPeer, None)
        .await
        .unwrap();
    let code = wait_event(&mut linux.events, "RoomEntered", |e| match e {
        EngineEvent::RoomEntered { invite_code, .. } => invite_code.clone(),
        _ => None,
    })
    .await;
    windows.engine.connect(Some(&url)).await.unwrap();
    windows.engine.join_room(code).await.unwrap();

    // Both sides must reach "connected over a direct path" to the other.
    let connected = |e: &EngineEvent| match e {
        EngineEvent::PeerStatusChanged {
            status: PeerStatus::Connected(_),
            ..
        } => Some(()),
        _ => None,
    };
    wait_event(&mut linux.events, "linux: peer connected", connected).await;
    wait_event(&mut windows.events, "windows: peer connected", connected).await;

    let mut linux_os = timeout(Duration::from_secs(5), linux.handles.recv())
        .await
        .unwrap()
        .expect("linux adapter");
    let mut windows_os = timeout(Duration::from_secs(5), windows.handles.recv())
        .await
        .unwrap()
        .expect("windows adapter");
    let (linux_ip, windows_ip) = (linux_os.config.ipv4, windows_os.config.ipv4);
    assert_ne!(linux_ip, windows_ip);
    assert_eq!(linux_os.config.mac, linux.mac);

    // --- Windows → Linux: wintun hands the shim a bare IP packet.
    let to_linux = ipv4_packet(windows_ip, linux_ip, b"hello linux");
    windows_os.inject(&to_linux);
    let frame = next_written(&mut linux_os, "frame at linux").await;
    assert_eq!(
        &frame[..6],
        &linux.mac.0,
        "shim must address the Linux node's MAC"
    );
    assert_eq!(&frame[6..12], &windows.mac.0, "shim must stamp its own MAC");
    assert_eq!(&frame[12..14], &ETHERTYPE_IPV4.to_be_bytes());
    assert_eq!(&frame[14..14 + to_linux.len()], &to_linux[..]);

    // --- Linux → Windows: a TAP frame; the shim strips it to an IP packet.
    let to_windows = ipv4_packet(linux_ip, windows_ip, b"hello windows");
    linux_os.inject(&ethernet(
        windows.mac,
        linux.mac,
        ETHERTYPE_IPV4,
        &to_windows,
    ));
    let packet = next_written(&mut windows_os, "packet at windows").await;
    assert_eq!(packet, to_windows, "wintun gets exactly the IP packet");

    // --- ARP: Linux asks who has the Windows IP; the shim answers for it
    // (Windows never sees ARP on a wintun interface).
    linux_os.inject(&arp::build_request(linux.mac, linux_ip, windows_ip));
    let reply = next_written(&mut linux_os, "ARP reply at linux").await;
    assert_eq!(&reply[..6], &linux.mac.0);
    assert_eq!(
        &reply[6..12],
        &windows.mac.0,
        "reply carries the Windows node's MAC"
    );
    assert_eq!(&reply[12..14], &[0x08, 0x06]);
    assert_eq!(&reply[20..22], &[0, 2], "ARP operation = reply");

    // --- Broadcast (what game/LAN discovery uses) reaches the other side.
    let bcast = ipv4_packet(linux_ip, Ipv4Addr::new(10, 42, 255, 255), b"anyone there?");
    linux_os.inject(&ethernet(
        VirtualMac::BROADCAST,
        linux.mac,
        ETHERTYPE_IPV4,
        &bcast,
    ));
    assert_eq!(
        next_written(&mut windows_os, "broadcast at windows").await,
        bcast
    );

    // Sanity: the engine's address derivation matches what the adapters got.
    let linux_id = linux.engine.identity().node_id;
    let seen_by_windows = windows
        .engine
        .current_room()
        .unwrap()
        .peers()
        .into_iter()
        .find(|p| p.node_id == linux_id)
        .unwrap();
    assert_eq!(seen_by_windows.virtual_ipv4, VirtualIpv4(linux_ip));

    linux.engine.shutdown().await;
    windows.engine.shutdown().await;
}

#[tokio::test]
async fn owner_can_remove_a_member_through_the_engine() {
    let port = 39832;
    let _server = spawn_signaling(port).await;
    let url = format!("ws://127.0.0.1:{port}/v1");
    let mut owner = node("owner", AdapterMode::Ethernet);
    let mut guest = node("guest", AdapterMode::Ethernet);

    owner.engine.connect(Some(&url)).await.unwrap();
    owner
        .engine
        .create_room_with_password("kick".into(), RoomMode::PeerToPeer, None, Some("pw".into()))
        .await
        .unwrap();
    let code = wait_event(&mut owner.events, "RoomEntered", |e| match e {
        EngineEvent::RoomEntered { invite_code, .. } => *invite_code,
        _ => None,
    })
    .await;
    assert!(owner.engine.is_room_owner());

    // Wrong password: no such room, and we are not in one.
    guest.engine.connect(Some(&url)).await.unwrap();
    guest
        .engine
        .join_room_with_password(code, Some("nope".into()))
        .await
        .unwrap();
    let denied = wait_event(&mut guest.events, "wrong-password error", |e| match e {
        EngineEvent::SignalingError { code, .. } => Some(code.clone()),
        _ => None,
    })
    .await;
    // A wrong password derives a different token: the server just sees an
    // unknown code.
    assert_eq!(denied, "invalid_code");
    assert!(guest.engine.current_room().is_none());

    guest
        .engine
        .join_room_with_password(code, Some("pw".into()))
        .await
        .unwrap();
    wait_event(&mut guest.events, "guest RoomEntered", |e| match e {
        EngineEvent::RoomEntered { .. } => Some(()),
        _ => None,
    })
    .await;
    assert!(!guest.engine.is_room_owner());
    let guest_id = guest.engine.identity().node_id;
    wait_event(&mut owner.events, "owner sees guest", |e| match e {
        EngineEvent::PeerAdded(p) if p.node_id == guest_id => Some(()),
        _ => None,
    })
    .await;

    // The guest cannot remove the owner; the owner can remove the guest.
    guest
        .engine
        .kick_member(owner.engine.identity().node_id, false)
        .await
        .unwrap();
    let refused = wait_event(&mut guest.events, "not_owner", |e| match e {
        EngineEvent::SignalingError { code, .. } => Some(code.clone()),
        _ => None,
    })
    .await;
    assert_eq!(refused, "not_owner");

    owner.engine.kick_member(guest_id, true).await.unwrap();
    let banned = wait_event(&mut guest.events, "Kicked", |e| match e {
        EngineEvent::Kicked { banned } => Some(*banned),
        _ => None,
    })
    .await;
    assert!(banned);
    assert!(guest.engine.current_room().is_none());
    assert!(guest.engine.current_invite().is_none(), "no auto re-join");

    owner.engine.shutdown().await;
    guest.engine.shutdown().await;
}

/// Rotation through whole engines: members follow the new code without
/// the server ever learning it, the old code stops working, and a newcomer
/// with the new code is accepted by the members (their proofs were
/// re-issued under the new key).
#[tokio::test]
async fn rotating_the_invite_keeps_members_and_admits_newcomers_only_with_the_new_code() {
    let port = 39833;
    let _server = spawn_signaling(port).await;
    let url = format!("ws://127.0.0.1:{port}/v1");
    let mut owner = node("rot-owner", AdapterMode::Ethernet);
    let mut member = node("rot-member", AdapterMode::Ethernet);
    let mut late = node("rot-late", AdapterMode::Ethernet);

    owner.engine.connect(Some(&url)).await.unwrap();
    owner
        .engine
        .create_room("rot".into(), RoomMode::PeerToPeer, None)
        .await
        .unwrap();
    let old = wait_event(&mut owner.events, "RoomEntered", |e| match e {
        EngineEvent::RoomEntered { invite_code, .. } => *invite_code,
        _ => None,
    })
    .await;
    member.engine.connect(Some(&url)).await.unwrap();
    member.engine.join_room(old).await.unwrap();
    let connected = |e: &EngineEvent| match e {
        EngineEvent::PeerStatusChanged {
            status: PeerStatus::Connected(_),
            ..
        } => Some(()),
        _ => None,
    };
    wait_event(&mut member.events, "member connected", connected).await;

    owner.engine.rotate_invite().await.unwrap();
    let fresh_owner = wait_event(&mut owner.events, "owner InviteRotated", |e| match e {
        EngineEvent::InviteRotated { invite_code } => Some(*invite_code),
        _ => None,
    })
    .await;
    let fresh_member = wait_event(&mut member.events, "member InviteRotated", |e| match e {
        EngineEvent::InviteRotated { invite_code } => Some(*invite_code),
        _ => None,
    })
    .await;
    assert_eq!(fresh_owner, fresh_member);
    assert_ne!(fresh_owner, old);
    assert_eq!(member.engine.current_invite(), Some(fresh_owner));

    // The old code no longer opens the room...
    late.engine.connect(Some(&url)).await.unwrap();
    late.engine.join_room(old).await.unwrap();
    let denied = wait_event(&mut late.events, "invalid_code", |e| match e {
        EngineEvent::SignalingError { code, .. } => Some(code.clone()),
        _ => None,
    })
    .await;
    assert_eq!(denied, "invalid_code");

    // ...the new one does, and both existing members verify as genuine.
    late.engine.join_room(fresh_owner).await.unwrap();
    wait_event(&mut late.events, "late connected to someone", connected).await;
    assert!(!late.engine.peers().is_empty());

    for n in [&owner, &member, &late] {
        n.engine.shutdown().await;
    }
}
