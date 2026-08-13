//! `hermes-relay` — the "central server" that backs relayed rooms.
//!
//! A single UDP socket and two tables. Nodes REGISTER themselves as
//! members of a room; thereafter each DATA packet they send names a
//! destination node, and the relay FORWARDs the payload to whichever
//! address that node last registered from.
//!
//! What the relay deliberately does **not** do is understand any of the
//! traffic. Payloads are WireGuard datagrams encrypted end-to-end between
//! the two peers, so a relay operator sees ciphertext, packet sizes, and
//! who talks to whom — never room contents. That is what makes running
//! one for other people a reasonable thing to do.
//!
//! Registrations are Ed25519-signed by the claiming node (a node id *is*
//! an Ed25519 public key) and carry a timestamp that must strictly
//! increase per `(room, node)`. A captured REGISTER is therefore useless
//! for hijacking a session: replaying it fails the timestamp check, and
//! forging a fresh one requires the node's private key.
//!
//! Known limits, tracked in CHECKLIST.md under P3: anyone who learns a
//! room UUID can register in it and inject DATA. WireGuard rejects the
//! injected packets at the far end, so the cost is bandwidth rather than
//! confidentiality — but there is no per-IP rate limiting yet.

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
                let now = Instant::now();
                // Collect first, then remove: mutating a DashMap while
                // iterating it risks deadlocking against the hot path.
                let expired: Vec<(RoomId, NodeId)> = state
                    .sessions
                    .iter()
                    .filter(|e| now.duration_since(e.value().last_seen) > SESSION_TTL)
                    .map(|e| *e.key())
                    .collect();

                for key in expired {
                    if let Some((_, session)) = state.sessions.remove(&key) {
                        // Only clear the address index if it still points
                        // at this session — the node may have re-registered
                        // from a new address in the meantime.
                        state.by_addr.remove_if(&session.addr, |_, (room, node)| {
                            *room == key.0 && *node == key.1
                        });
                        debug!(room = %key.0, node = %key.1.short(), "session expired");
                    }
                }
            }
        });
    }

    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(?e, "recv_from failed");
                continue;
            }
        };

        let Some(packet) = protocol::parse_packet(&buf[..len]) else {
            debug!(%from, len, "unparseable datagram dropped");
            continue;
        };

        match packet {
            RelayPacket::Register {
                room_id,
                node_id,
                timestamp_ms,
                signature,
            } => {
                if !protocol::verify_register(&room_id, &node_id, timestamp_ms, &signature) {
                    warn!(%from, room = %room_id, node = %node_id.short(), "bad registration signature");
                    continue;
                }

                let key = (room_id, node_id);

                // Replay guard: timestamps must strictly increase, so a
                // captured REGISTER cannot move a session's address.
                if let Some(existing) = state.sessions.get(&key) {
                    if timestamp_ms <= existing.last_ts {
                        warn!(
                            %from,
                            room = %room_id,
                            node = %node_id.short(),
                            "stale registration timestamp rejected",
                        );
                        continue;
                    }
                }

                // If the node moved, drop the stale address mapping.
                let previous_addr = state.sessions.get(&key).map(|s| s.addr);
                if let Some(old) = previous_addr {
                    if old != from {
                        state.by_addr.remove(&old);
                        info!(
                            room = %room_id,
                            node = %node_id.short(),
                            %old, new = %from,
                            "session roamed to a new address",
                        );
                    }
                }

                state.sessions.insert(
                    key,
                    Session {
                        addr: from,
                        last_seen: Instant::now(),
                        last_ts: timestamp_ms,
                    },
                );
                state.by_addr.insert(from, key);

                if previous_addr.is_none() {
                    info!(room = %room_id, node = %node_id.short(), %from, "node registered");
                }

                let ack = protocol::encode_register_ack(&room_id);
                if let Err(e) = socket.send_to(&ack, from).await {
                    warn!(%from, ?e, "failed to send register ack");
                }
            }

            RelayPacket::Data { dest, payload } => {
                // The sender is identified by its source address, which
                // it can only have gotten into the table by completing a
                // signed registration.
                let Some((room_id, src)) = state.by_addr.get(&from).map(|e| *e.value()) else {
                    debug!(%from, "DATA from an unregistered address dropped");
                    continue;
                };

                // Forwarding is scoped to the room: a member of one room
                // cannot reach a node in another even knowing its id.
                let Some(dest_addr) = state.sessions.get(&(room_id, dest)).map(|s| s.addr) else {
                    debug!(
                        room = %room_id,
                        dest = %dest.short(),
                        "DATA for a node with no live session dropped",
                    );
                    continue;
                };

                let out = protocol::encode_forward(&src, payload);
                if let Err(e) = socket.send_to(&out, dest_addr).await {
                    warn!(%dest_addr, ?e, "forward failed");
                }
            }

            // Client-bound message types. Receiving one means a
            // misconfigured peer is pointing a relay at us, or someone
            // is probing the port.
            RelayPacket::RegisterAck { .. } | RelayPacket::Forward { .. } => {
                debug!(%from, "ignoring client-bound relay packet");
            }
        }
    }
}
