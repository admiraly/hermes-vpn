//! Hermes relay server — the "central server" behind relayed rooms.
//!
//! A single UDP socket. Clients `REGISTER` (Ed25519-signed) to announce
//! "I am node N in room R at this address"; afterwards their `DATA`
//! packets addressed to another member of the same room are rewritten to
//! `FORWARD` and delivered to that member's registered address.
//!
//! ## Multi-homed hosts
//!
//! A UDP reply must come from the address the client sent to — clients
//! ignore relay traffic from any other source, and so do most NATs. A
//! socket bound to `0.0.0.0` can't promise that: the kernel picks the
//! reply's source address by routing, which on a host with several IPs
//! may be a different one. So a wildcard bind (the default) opens **one
//! socket per local IPv4 address** instead, re-scanning periodically for
//! addresses that come and go, and each session remembers which socket
//! its client talks to. Binding a specific address uses just that one.
//!
//! The relay never sees plaintext — payloads are WireGuard ciphertext,
//! end-to-end encrypted between the two peers — and it never needs any
//! long-term secret of its own. See `docs/ARCHITECTURE.md` for the wire
//! format and the replay-protection rules implemented here.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use hermes_core::crypto::NodeId;
use hermes_core::relay::protocol::{self, RelayPacket};
use hermes_core::room::RoomId;
use hermes_core::tap::DATAGRAM_BUFFER_SIZE;

/// A registration goes stale if not refreshed within this window.
/// Clients re-register every 15 s.
const SESSION_TTL: Duration = Duration::from_secs(60);

/// How often the reaper sweeps stale sessions.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// How often a wildcard-bound relay re-scans the host's addresses.
const RESCAN_INTERVAL: Duration = Duration::from_secs(30);

/// Largest datagram we accept — the client's datagram buffer size, so the
/// relay can never truncate a frame a client could legitimately send.
const MAX_DATAGRAM: usize = DATAGRAM_BUFFER_SIZE;

/// One registered (room, node) endpoint.
struct Session {
    addr: SocketAddr,
    /// The local socket this client talks to — every reply to it must
    /// leave through the same socket (and therefore the same address).
    via: Arc<UdpSocket>,
    last_seen: Instant,
    /// Highest registration timestamp seen — replay guard.
    last_ts: u64,
}

#[derive(Default)]
struct State {
    /// (room, node) → session.
    sessions: DashMap<(RoomId, NodeId), Session>,
    /// Current source address → (room, node). Lets DATA packets identify
    /// their sender without carrying credentials.
    by_addr: DashMap<SocketAddr, (RoomId, NodeId)>,
}

/// Outcome of processing a REGISTER.
#[derive(Debug, PartialEq, Eq)]
enum Registration {
    /// Accepted — ack it.
    Accepted,
    /// Bad signature.
    BadSignature,
    /// Stale timestamp from a new address — a replayed capture.
    Replay,
}

impl State {
    #[allow(clippy::too_many_arguments)]
    fn register(
        &self,
        from: SocketAddr,
        via: &Arc<UdpSocket>,
        room_id: RoomId,
        node_id: NodeId,
        timestamp_ms: u64,
        signature: &[u8; 64],
    ) -> Registration {
        if !protocol::verify_register(&room_id, &node_id, timestamp_ms, signature) {
            return Registration::BadSignature;
        }
        let key = (room_id, node_id);
        let now = Instant::now();

        let previous_addr = match self.sessions.get_mut(&key) {
            Some(mut s) => {
                // Strictly newer timestamps may move the session anywhere
                // (the client's NAT mapping changed). An old or repeated
                // timestamp is only a harmless retransmit if it comes from
                // the address already registered; from anywhere else it's
                // someone replaying a captured packet to hijack the session.
                if timestamp_ms <= s.last_ts && s.addr != from {
                    return Registration::Replay;
                }
                let prev = s.addr;
                s.addr = from;
                s.via = via.clone();
                s.last_seen = now;
                s.last_ts = s.last_ts.max(timestamp_ms);
                Some(prev)
            }
            None => {
                self.sessions.insert(
                    key,
                    Session {
                        addr: from,
                        via: via.clone(),
                        last_seen: now,
                        last_ts: timestamp_ms,
                    },
                );
                None
            }
        };

        if let Some(prev) = previous_addr {
            if prev != from {
                self.by_addr.remove(&prev);
                info!(node = %node_id.short(), %prev, new = %from, "session moved");
            }
        } else {
            info!(node = %node_id.short(), room = %room_id, %from, "session registered");
        }

        // One address = one session: if this socket was registered as
        // something else (e.g. it left one room for another), drop that.
        if let Some(old) = self.by_addr.insert(from, key) {
            if old != key {
                self.sessions.remove(&old);
            }
        }
        Registration::Accepted
    }

    /// Where a DATA packet from `from` to `dest` should be forwarded (the
    /// destination's address and the socket to send it from), and the
    /// sender's node id. `None` if the sender isn't registered or the
    /// destination isn't in the sender's room.
    fn route(
        &self,
        from: SocketAddr,
        dest: NodeId,
    ) -> Option<(SocketAddr, Arc<UdpSocket>, NodeId)> {
        let (room, src) = *self.by_addr.get(&from)?;
        let target = self.sessions.get(&(room, dest))?;
        Some((target.addr, target.via.clone(), src))
    }

    fn sweep(&self) {
        let now = Instant::now();
        let mut expired = Vec::new();
        self.sessions.retain(|key, s| {
            let alive = now.duration_since(s.last_seen) < SESSION_TTL;
            if !alive {
                expired.push((*key, s.addr));
            }
            alive
        });
        for (key, addr) in expired {
            // Only drop the address mapping if it still points at the
            // expired session (the socket may have re-registered since).
            self.by_addr.remove_if(&addr, |_, v| *v == key);
            debug!(node = %key.1.short(), "session expired");
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind: SocketAddr = std::env::var("HERMES_RELAY_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8788".into())
        .parse()?;
    let state = Arc::new(State::default());

    // Stale-session reaper.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                ticker.tick().await;
                state.sweep();
            }
        });
    }

    tokio::select! {
        res = run_listeners(bind, state) => res,
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received");
            Ok(())
        }
    }
}

/// Bind and serve. A specific address gets one socket; a wildcard gets
/// one socket per local IPv4 address, kept in sync with the host.
async fn run_listeners(bind: SocketAddr, state: Arc<State>) -> anyhow::Result<()> {
    if !bind.ip().is_unspecified() {
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        info!(%bind, "hermes-relay listening");
        serve(socket, state).await;
        return Ok(());
    }

    let mut port = bind.port();
    let mut listeners: HashMap<IpAddr, JoinHandle<()>> = HashMap::new();
    loop {
        let wanted = local_ipv4_addrs();
        listeners.retain(|ip, task| {
            let keep = wanted.contains(ip) && !task.is_finished();
            if !keep {
                task.abort();
                info!(%ip, "address gone — stopped listening on it");
            }
            keep
        });
        for ip in wanted {
            if listeners.contains_key(&ip) {
                continue;
            }
            match UdpSocket::bind(SocketAddr::new(ip, port)).await {
                Ok(socket) => {
                    let local = socket.local_addr()?;
                    // With port 0, the first socket picks the port and the
                    // rest share it, so clients see one relay port.
                    port = local.port();
                    info!(bind = %local, "hermes-relay listening");
                    listeners.insert(ip, tokio::spawn(serve(Arc::new(socket), state.clone())));
                }
                Err(e) => warn!(%ip, port, ?e, "could not bind"),
            }
        }
        if listeners.is_empty() {
            anyhow::bail!("could not bind any local IPv4 address on port {port}");
        }
        tokio::time::sleep(RESCAN_INTERVAL).await;
    }
}

/// Every IPv4 address configured on this host, loopback included.
fn local_ipv4_addrs() -> Vec<IpAddr> {
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => {
            let mut ips: Vec<IpAddr> = ifaces
                .iter()
                .map(if_addrs::Interface::ip)
                .filter(IpAddr::is_ipv4)
                .collect();
            ips.sort_unstable();
            ips.dedup();
            ips
        }
        Err(e) => {
            warn!(?e, "could not enumerate interfaces");
            Vec::new()
        }
    }
}

/// Serve one socket until it fails.
async fn serve(socket: Arc<UdpSocket>, state: Arc<State>) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                // ICMP port-unreachable from a vanished client surfaces as
                // a recv error on some platforms (Windows WSAECONNRESET).
                // It's never fatal for a UDP server.
                debug!(?e, "recv_from error");
                continue;
            }
        };
        match protocol::parse_packet(&buf[..len]) {
            Some(RelayPacket::Register {
                room_id,
                node_id,
                timestamp_ms,
                signature,
            }) => match state.register(from, &socket, room_id, node_id, timestamp_ms, &signature) {
                Registration::Accepted => {
                    let ack = protocol::encode_register_ack(&room_id);
                    if let Err(e) = socket.send_to(&ack, from).await {
                        debug!(%from, ?e, "ack send failed");
                    }
                }
                Registration::BadSignature => {
                    warn!(%from, node = %node_id.short(), "REGISTER with bad signature");
                }
                Registration::Replay => {
                    warn!(%from, node = %node_id.short(), "replayed REGISTER rejected");
                }
            },
            Some(RelayPacket::Data { dest, payload }) => match state.route(from, dest) {
                Some((target, via, src)) => {
                    let fwd = protocol::encode_forward(&src, payload);
                    if let Err(e) = via.send_to(&fwd, target).await {
                        debug!(%target, ?e, "forward send failed");
                    }
                }
                None => debug!(%from, dest = %dest.short(), "undeliverable DATA dropped"),
            },
            // Clients never send ACK/FORWARD; anything else is noise.
            _ => debug!(%from, len, "ignoring non-relay datagram"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermes_core::crypto::NodeSecret;
    use hermes_core::relay::protocol::encode_register;

    async fn sock() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    fn register(
        state: &State,
        via: &Arc<UdpSocket>,
        from: &str,
        room: RoomId,
        secret: &NodeSecret,
        ts: u64,
    ) -> Registration {
        let pkt = encode_register(&room, secret, ts);
        let Some(RelayPacket::Register {
            room_id,
            node_id,
            timestamp_ms,
            signature,
        }) = protocol::parse_packet(&pkt)
        else {
            panic!("bad packet");
        };
        state.register(
            from.parse().unwrap(),
            via,
            room_id,
            node_id,
            timestamp_ms,
            &signature,
        )
    }

    #[tokio::test]
    async fn replay_from_new_address_is_rejected_but_retransmit_is_fine() {
        let state = State::default();
        let via = sock().await;
        let room = RoomId::new_v4();
        let alice = NodeSecret::generate();
        let reg = |from: &str, ts| register(&state, &via, from, room, &alice, ts);
        assert_eq!(reg("1.1.1.1:1000", 10), Registration::Accepted);
        // Same packet again from the same address: a retransmit.
        assert_eq!(reg("1.1.1.1:1000", 10), Registration::Accepted);
        // Same packet from an attacker's address: replay.
        assert_eq!(reg("6.6.6.6:666", 10), Registration::Replay);
        // A genuinely newer registration may move (NAT rebinding).
        assert_eq!(reg("2.2.2.2:2000", 11), Registration::Accepted);
        assert!(state
            .by_addr
            .get(&"1.1.1.1:1000".parse().unwrap())
            .is_none());
    }

    #[tokio::test]
    async fn routing_is_scoped_to_the_senders_room() {
        let state = State::default();
        let via = sock().await;
        let (room_a, room_b) = (RoomId::new_v4(), RoomId::new_v4());
        let (alice, bob, mallory) = (
            NodeSecret::generate(),
            NodeSecret::generate(),
            NodeSecret::generate(),
        );
        register(&state, &via, "1.1.1.1:1", room_a, &alice, 1);
        register(&state, &via, "2.2.2.2:2", room_a, &bob, 1);
        register(&state, &via, "3.3.3.3:3", room_b, &mallory, 1);

        let bob_id = bob.public().node_id;
        let (target, _, src) = state.route("1.1.1.1:1".parse().unwrap(), bob_id).unwrap();
        assert_eq!(target, "2.2.2.2:2".parse().unwrap());
        assert_eq!(src, alice.public().node_id);
        // Mallory is in another room: can't reach Bob.
        assert!(state.route("3.3.3.3:3".parse().unwrap(), bob_id).is_none());
        // Unregistered senders can't send at all.
        assert!(state.route("9.9.9.9:9".parse().unwrap(), bob_id).is_none());
    }

    /// Two clients reaching the relay on different local addresses: a
    /// forward to each must leave through the socket *that* client uses.
    #[tokio::test]
    async fn forwards_leave_through_the_destinations_socket() {
        let state = State::default();
        let (sock_a, sock_b) = (sock().await, sock().await);
        let room = RoomId::new_v4();
        let (alice, bob) = (NodeSecret::generate(), NodeSecret::generate());
        register(&state, &sock_a, "1.1.1.1:1", room, &alice, 1);
        register(&state, &sock_b, "2.2.2.2:2", room, &bob, 1);

        let (_, via, _) = state
            .route("1.1.1.1:1".parse().unwrap(), bob.public().node_id)
            .unwrap();
        assert!(Arc::ptr_eq(&via, &sock_b));
        let (_, via, _) = state
            .route("2.2.2.2:2".parse().unwrap(), alice.public().node_id)
            .unwrap();
        assert!(Arc::ptr_eq(&via, &sock_a));

        // A newer registration through the other address moves the session.
        register(&state, &sock_a, "2.2.2.2:2", room, &bob, 2);
        let (_, via, _) = state
            .route("1.1.1.1:1".parse().unwrap(), bob.public().node_id)
            .unwrap();
        assert!(Arc::ptr_eq(&via, &sock_a));
    }
}
