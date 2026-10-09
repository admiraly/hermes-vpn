//! The relay's optional /metrics endpoint, scraped from a real process
//! after real traffic.

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use hermes_core::crypto::NodeSecret;
use hermes_core::relay::protocol;
use hermes_core::room::RoomId;

struct Relay(Child);
impl Drop for Relay {
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

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
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
async fn metrics_reflect_real_traffic() {
    let (udp, metrics) = (free_port(), free_port());
    let _relay = Relay(
        Command::new(env!("CARGO_BIN_EXE_hermes-relay"))
            .env("HERMES_RELAY_BIND", format!("127.0.0.1:{udp}"))
            .env("HERMES_RELAY_METRICS_BIND", format!("127.0.0.1:{metrics}"))
            .env("RUST_LOG", "warn")
            .spawn()
            .unwrap(),
    );
    let relay: SocketAddr = format!("127.0.0.1:{udp}").parse().unwrap();
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", metrics)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let before = scrape(metrics).await;
    assert!(before.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(value(&before, "hermes_relay_sessions "), 0);

    // Two nodes register; Alice sends Bob 3 packets of 100 bytes; a
    // stranger's DATA is dropped; a forged REGISTER is rejected.
    let room = RoomId::new_v4();
    let (alice, bob) = (NodeSecret::generate(), NodeSecret::generate());
    let a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (sock, secret) in [(&a_sock, &alice), (&b_sock, &bob)] {
        sock.send_to(&protocol::encode_register(&room, secret, now_ms()), relay)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
    }
    for _ in 0..3 {
        a_sock
            .send_to(
                &protocol::encode_data(&bob.public().node_id, &[7u8; 100]),
                relay,
            )
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        timeout(Duration::from_secs(2), b_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
    }
    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    stranger
        .send_to(&protocol::encode_data(&bob.public().node_id, b"hi"), relay)
        .await
        .unwrap();
    let mut forged = protocol::encode_register(&room, &NodeSecret::generate(), now_ms());
    let last = forged.len() - 1;
    forged[last] ^= 0xFF;
    stranger.send_to(&forged, relay).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let after = scrape(metrics).await;
    assert_eq!(value(&after, "hermes_relay_sessions "), 2);
    assert_eq!(
        value(&after, "hermes_relay_registers_total{result=\"accepted\"} "),
        2
    );
    assert_eq!(
        value(
            &after,
            "hermes_relay_registers_total{result=\"bad_signature\"} "
        ),
        1
    );
    assert_eq!(value(&after, "hermes_relay_forwarded_packets_total "), 3);
    assert_eq!(value(&after, "hermes_relay_forwarded_bytes_total "), 300);
    assert_eq!(
        value(
            &after,
            "hermes_relay_dropped_packets_total{reason=\"unregistered_sender\"} "
        ),
        1
    );
    // No identifying data leaks into the exposition.
    assert!(!after.contains("127.0.0.1"), "no addresses in metrics");
    assert!(
        !after.contains(&alice.public().node_id.to_base64()),
        "no node ids in metrics"
    );
}

#[tokio::test]
async fn metrics_are_off_by_default() {
    let udp = free_port();
    let _relay = Relay(
        Command::new(env!("CARGO_BIN_EXE_hermes-relay"))
            .env("HERMES_RELAY_BIND", format!("127.0.0.1:{udp}"))
            .env("RUST_LOG", "warn")
            .spawn()
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Nothing listens on TCP at the relay's port, or anywhere we'd expect.
    assert!(TcpStream::connect(("127.0.0.1", udp)).await.is_err());
}
