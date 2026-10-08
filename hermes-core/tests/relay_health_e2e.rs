//! Relay health detection, end to end at the socket level: a fake relay
//! acks registrations, goes silent, and comes back — the health watch
//! channel must flip unhealthy and then recover, and the mesh demux must
//! be the component feeding acks into it (same code path as production).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use hermes_core::broadcast::MacRouter;
use hermes_core::crypto::{NodeSecret, VirtualMac};
use hermes_core::mesh::{is_transient_recv_error, Mesh};
use hermes_core::relay::{protocol, spawn_registration, RegistrationConfig, RelayPacket};
use hermes_core::room::RoomId;

/// A fake relay that acks REGISTERs only while `answering` is true.
async fn run_fake_relay(socket: Arc<UdpSocket>, answering: Arc<AtomicBool>) {
    let mut buf = [0u8; 2048];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buf).await else {
            return;
        };
        if !answering.load(Ordering::SeqCst) {
            continue;
        }
        if let Some(RelayPacket::Register { room_id, .. }) = protocol::parse_packet(&buf[..len]) {
            let ack = protocol::encode_register_ack(&room_id);
            let _ = socket.send_to(&ack, from).await;
        }
    }
}

/// Wait until the watch channel reports `want`, or panic after `budget`.
async fn wait_for_health(
    rx: &mut tokio::sync::watch::Receiver<bool>,
    want: bool,
    budget: Duration,
    what: &str,
) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if *rx.borrow() == want {
            return;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "timed out waiting for health={want} ({what})"
        );
        let _ = timeout(remaining, rx.changed()).await;
    }
}

#[tokio::test]
async fn relay_health_flips_on_silence_and_recovers() {
    // Fake relay.
    let relay_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_addr = relay_sock.local_addr().unwrap();
    let answering = Arc::new(AtomicBool::new(true));
    tokio::spawn(run_fake_relay(relay_sock, answering.clone()));

    // Client mesh + registration, with test-sized timings. Feeding acks
    // through the mesh demux (not directly into RelayHealth) exercises
    // the production path.
    let secret = Arc::new(NodeSecret::generate());
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let own_mac = VirtualMac::from_node_id(&secret.public().node_id);
    let router = Arc::new(MacRouter::new(own_mac));
    let mesh = Arc::new(Mesh::new(socket.clone(), secret.clone(), router));
    mesh.set_relay(Some(relay_addr));

    // Pump inbound datagrams into the mesh, like the driver does.
    {
        let mesh = mesh.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (len, from) = match socket.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(e) if is_transient_recv_error(&e) => continue,
                    Err(_) => break,
                };
                let _ = mesh.dispatch_inbound(from, &buf[..len]).await;
            }
        });
    }

    let health = mesh.relay_health();
    let mut rx = health.subscribe();

    let cfg = RegistrationConfig {
        reregister_interval: Duration::from_millis(50),
        initial_interval: Duration::from_millis(50),
        initial_rounds: 2,
        ack_timeout: Duration::from_millis(300),
    };
    let reg = spawn_registration(
        socket.clone(),
        relay_addr,
        RoomId::new_v4(),
        secret,
        health.clone(),
        cfg,
    );

    // Phase 1: relay answering → healthy (and stays healthy).
    wait_for_health(&mut rx, true, Duration::from_secs(2), "initial").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(health.is_healthy(), "flapped while relay was answering");

    // Phase 2: relay goes silent → unhealthy within the ack timeout
    // window (plus slack for the registration tick).
    answering.store(false, Ordering::SeqCst);
    wait_for_health(&mut rx, false, Duration::from_secs(3), "after silence").await;

    // Phase 3: relay answers again → recovers automatically.
    answering.store(true, Ordering::SeqCst);
    wait_for_health(&mut rx, true, Duration::from_secs(3), "after recovery").await;

    reg.abort();
}
