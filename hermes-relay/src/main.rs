//! Hermes relay server — the "central server" behind relayed rooms.
//!
//! A single UDP socket. Clients `REGISTER` (Ed25519-signed) to announce
//! "I am node N in room R at this address"; afterwards their `DATA`
//! packets addressed to another member of the same room are rewritten to
//! `FORWARD` and delivered to that member's registered address.
//!
//! The relay never sees plaintext — payloads are WireGuard ciphertext,
//! end-to-end encrypted between the two peers — and it never needs any
//! long-term secret of its own. See `docs/ARCHITECTURE.md` for the wire
//! format and the replay-protection rules implemented here.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
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

/// Largest datagram we accept — the client's datagram buffer size, so the
/// relay can never truncate a frame a client could legitimately send.
const MAX_DATAGRAM: usize = DATAGRAM_BUFFER_SIZE;

/// One registered (room, node) endpoint.
struct Session {
    addr: SocketAddr,
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
    fn register(
        &self,
        from: SocketAddr,
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
                s.last_seen = now;
                s.last_ts = s.last_ts.max(timestamp_ms);
                Some(prev)
            }
            None => {
                self.sessions.insert(
                    key,
                    Session {
                        addr: from,
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

    /// Where a DATA packet from `from` to `dest` should be forwarded, and
    /// the sender's node id. `None` if the sender isn't registered or the
    /// destination isn't in the sender's room.
    fn route(&self, from: SocketAddr, dest: NodeId) -> Option<(SocketAddr, NodeId)> {
        let (room, src) = *self.by_addr.get(&from)?;
        let target = self.sessions.get(&(room, dest))?.addr;
        Some((target, src))
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

    let bind = std::env::var("HERMES_RELAY_BIND").unwrap_or_else(|_| "0.0.0.0:8788".into());
    let socket = Arc::new(UdpSocket::bind(&bind).await?);
    info!(%bind, "hermes-relay listening");

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
        res = serve(socket, state) => res,
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received");
            Ok(())
        }
    }
}

async fn serve(socket: Arc<UdpSocket>, state: Arc<State>) -> anyhow::Result<()> {
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
            }) => match state.register(from, room_id, node_id, timestamp_ms, &signature) {
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
                Some((target, src)) => {
                    let fwd = protocol::encode_forward(&src, payload);
                    if let Err(e) = socket.send_to(&fwd, target).await {
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

    fn register(
        state: &State,
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
            room_id,
            node_id,
            timestamp_ms,
            &signature,
        )
    }

    #[test]
    fn replay_from_new_address_is_rejected_but_retransmit_is_fine() {
        let state = State::default();
        let room = RoomId::new_v4();
        let alice = NodeSecret::generate();
        assert_eq!(
            register(&state, "1.1.1.1:1000", room, &alice, 10),
            Registration::Accepted
        );
        // Same packet again from the same address: a retransmit.
        assert_eq!(
            register(&state, "1.1.1.1:1000", room, &alice, 10),
            Registration::Accepted
        );
        // Same packet from an attacker's address: replay.
        assert_eq!(
            register(&state, "6.6.6.6:666", room, &alice, 10),
            Registration::Replay
        );
        // A genuinely newer registration may move (NAT rebinding).
        assert_eq!(
            register(&state, "2.2.2.2:2000", room, &alice, 11),
            Registration::Accepted
        );
        assert!(state
            .by_addr
            .get(&"1.1.1.1:1000".parse().unwrap())
            .is_none());
    }

    #[test]
    fn routing_is_scoped_to_the_senders_room() {
        let state = State::default();
        let (room_a, room_b) = (RoomId::new_v4(), RoomId::new_v4());
        let (alice, bob, mallory) = (
            NodeSecret::generate(),
            NodeSecret::generate(),
            NodeSecret::generate(),
        );
        register(&state, "1.1.1.1:1", room_a, &alice, 1);
        register(&state, "2.2.2.2:2", room_a, &bob, 1);
        register(&state, "3.3.3.3:3", room_b, &mallory, 1);

        let bob_id = bob.public().node_id;
        let (target, src) = state.route("1.1.1.1:1".parse().unwrap(), bob_id).unwrap();
        assert_eq!(target, "2.2.2.2:2".parse().unwrap());
        assert_eq!(src, alice.public().node_id);
        // Mallory is in another room: can't reach Bob.
        assert!(state.route("3.3.3.3:3".parse().unwrap(), bob_id).is_none());
        // Unregistered senders can't send at all.
        assert!(state.route("9.9.9.9:9".parse().unwrap(), bob_id).is_none());
    }
}
