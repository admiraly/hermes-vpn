//! Full-mesh peer management.
//!
//! The mesh owns:
//! - The shared UDP socket used for all WireGuard + signaling NAT traffic.
//! - One [`PeerTunnel`] per peer in the current room.
//! - The demultiplexer that routes incoming UDP datagrams to the right tunnel.
//! - The [`MacRouter`] and [`FrameClassifier`] used to decide where
//!   outgoing frames (from our TAP adapter) go.
//!
//! The [`driver`] submodule runs the two tasks that actually shuttle
//! packets at runtime.

pub mod driver;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock as SyncRwLock;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::broadcast::{MacRouter, RouteDecision};
use crate::crypto::{NodeId, NodeSecret};
use crate::error::{HermesError, Result};
use crate::relay::{self, RelayHealth, RelayPacket};
use crate::tunnel::{PeerPath, PeerTunnel};

pub use driver::{spawn as spawn_driver, DriverHandle};

/// A live snapshot of one peer's tunnel — the running counters and the
/// path currently in use. Surfaced through the daemon so a UI can show
/// whether a peer went direct or fell back to a relay, and how much
/// traffic is flowing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkStats {
    /// Which peer this link reaches.
    pub node_id: NodeId,
    /// `true` if datagrams currently travel via a relay (relayed room, or
    /// a p2p peer that failed over to its fallback relay).
    pub relayed: bool,
    /// Encrypted bytes sent on the wire.
    pub bytes_tx: u64,
    /// Encrypted bytes received from the wire.
    pub bytes_rx: u64,
    /// Ethernet frames handed into the tunnel.
    pub frames_tx: u64,
    /// Ethernet frames received from the tunnel.
    pub frames_rx: u64,
    /// Seconds since the most recent successful WireGuard handshake. `0`
    /// means none has completed yet (the tunnel is still coming up).
    pub last_handshake_secs: u64,
}

/// The mesh coordinator.
pub struct Mesh {
    /// Shared UDP socket.
    pub socket: Arc<UdpSocket>,
    /// Our identity.
    pub secret: Arc<NodeSecret>,
    /// MAC → peer routing table.
    pub router: Arc<MacRouter>,
    /// Peer tunnels keyed by node id.
    tunnels: DashMap<NodeId, Arc<PeerTunnel>>,
    /// Secondary index: remote `SocketAddr` → node id. Used by the inbound
    /// demultiplexer for *direct* tunnels. Relayed tunnels are not in
    /// here — their datagrams arrive from the relay's address and carry
    /// the source node id in the relay framing instead.
    by_addr: RwLock<HashMap<SocketAddr, NodeId>>,
    /// The relay this room uses, if any. In a relayed room it is the only
    /// data path; in a p2p room it is an optional fallback that peers use
    /// only when their direct path fails. Read on every inbound datagram,
    /// so it is behind a sync lock rather than an async one.
    relay: SyncRwLock<Option<SocketAddr>>,
    /// Liveness of that relay, fed by the `REGISTER_ACK`s this demux sees
    /// and evaluated by the registration keepalive.
    relay_health: Arc<RelayHealth>,
}

impl Mesh {
    /// Build a mesh over an already-bound UDP socket.
    #[must_use]
    pub fn new(socket: Arc<UdpSocket>, secret: Arc<NodeSecret>, router: Arc<MacRouter>) -> Self {
        Self {
            socket,
            secret,
            router,
            tunnels: DashMap::new(),
            by_addr: RwLock::new(HashMap::new()),
            relay: SyncRwLock::new(None),
            relay_health: Arc::new(RelayHealth::default()),
        }
    }

    /// Point the mesh at a relay (or clear it when leaving a room).
    pub fn set_relay(&self, relay: Option<SocketAddr>) {
        *self.relay.write() = relay;
    }

    /// The relay currently configured for this room.
    #[must_use]
    pub fn relay(&self) -> Option<SocketAddr> {
        *self.relay.read()
    }

    /// The shared relay-health state.
    #[must_use]
    pub fn relay_health(&self) -> Arc<RelayHealth> {
        self.relay_health.clone()
    }

    /// Register a tunnel to a peer.
    ///
    /// A direct tunnel is also indexed by its remote address, which is how
    /// [`Self::dispatch_inbound`] attributes an incoming datagram to it.
    /// Relayed tunnels are not: their datagrams all arrive from the relay,
    /// and the sender is named in the relay framing instead.
    pub async fn add_peer(&self, tunnel: Arc<PeerTunnel>) {
        let node = tunnel.peer;
        if let PeerPath::Direct(addr) = tunnel.path() {
            self.by_addr.write().await.insert(addr, node);
        }
        debug!(peer = %node.short(), path = %tunnel.path(), "tunnel added to mesh");
        self.tunnels.insert(node, tunnel);
    }

    /// Tear down the tunnel to a peer and forget its routes.
    pub async fn remove_peer(&self, node: NodeId) {
        self.tunnels.remove(&node);
        self.by_addr.write().await.retain(|_, n| *n != node);
        self.router.unregister(node);
        debug!(peer = %node.short(), "tunnel removed from mesh");
    }

    /// Every peer we currently hold a tunnel to.
    #[must_use]
    pub fn peers(&self) -> Vec<NodeId> {
        self.tunnels.iter().map(|e| *e.key()).collect()
    }

    /// The path a peer's tunnel currently uses, if we have one.
    #[must_use]
    pub fn peer_path(&self, node: NodeId) -> Option<PeerPath> {
        self.tunnels.get(&node).map(|t| t.path())
    }

    /// A snapshot of every tunnel's counters, for the UI and `hermes status`.
    #[must_use]
    pub fn link_stats(&self) -> Vec<LinkStats> {
        self.tunnels
            .iter()
            .map(|entry| {
                let tunnel = entry.value();
                let stats = tunnel.stats();
                LinkStats {
                    node_id: *entry.key(),
                    relayed: matches!(tunnel.path(), PeerPath::Relayed { .. }),
                    bytes_tx: stats.bytes_tx.load(Ordering::Relaxed),
                    bytes_rx: stats.bytes_rx.load(Ordering::Relaxed),
                    frames_tx: stats.frames_tx.load(Ordering::Relaxed),
                    frames_rx: stats.frames_rx.load(Ordering::Relaxed),
                    last_handshake_secs: stats.last_handshake_secs.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// Route one Ethernet frame from the virtual adapter onto the mesh.
    ///
    /// Unicast goes to a single tunnel; broadcast, multicast, and unknown
    /// unicast are replicated to every peer, which is what makes ARP,
    /// mDNS, SSDP, and LAN game discovery work across the room.
    ///
    /// # Errors
    /// Returns an error only for a frame too short to have a destination
    /// MAC. Per-peer send failures are logged and skipped — one dead
    /// tunnel must not stop a broadcast reaching everyone else.
    pub async fn dispatch_outbound(&self, frame: &[u8]) -> Result<()> {
        if frame.len() < 6 {
            return Err(HermesError::Mesh("frame too short to route".into()));
        }
        let dst =
            crate::crypto::VirtualMac([frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]]);

        match self.router.route(dst) {
            RouteDecision::Local => {
                // Addressed to us; the local stack already has it.
                Ok(())
            }
            RouteDecision::Unicast(node) => {
                let Some(tunnel) = self.tunnels.get(&node).map(|t| t.value().clone()) else {
                    debug!(peer = %node.short(), "no tunnel for routed frame");
                    return Ok(());
                };
                tunnel.send(frame).await
            }
            RouteDecision::Flood => {
                // Snapshot first: holding DashMap references across an
                // await would deadlock against add_peer/remove_peer.
                let tunnels: Vec<Arc<PeerTunnel>> =
                    self.tunnels.iter().map(|e| e.value().clone()).collect();
                for tunnel in tunnels {
                    if let Err(e) = tunnel.send(frame).await {
                        debug!(peer = %tunnel.peer.short(), ?e, "flood send failed");
                    }
                }
                Ok(())
            }
        }
    }

    /// Demultiplex one UDP datagram off the shared socket.
    ///
    /// Four kinds of traffic arrive here, told apart without any per-packet
    /// state. Relay-protocol packets are tagged with a magic byte that can
    /// never collide with WireGuard (whose first byte is always 1–4); NAT
    /// probes are a fixed 4-byte magic; everything else is WireGuard from a
    /// known peer address.
    ///
    /// Returns the decrypted Ethernet frame when the datagram carried one.
    ///
    /// # Errors
    /// Propagates tunnel decryption failures. Unrecognised datagrams are
    /// dropped rather than reported as errors — this socket is reachable
    /// by anyone.
    pub async fn dispatch_inbound(
        &self,
        from: SocketAddr,
        datagram: &[u8],
    ) -> Result<Option<bytes::BytesMut>> {
        // 1. Relay protocol.
        if relay::is_relay_packet(datagram) {
            return self.handle_relay_packet(from, datagram).await;
        }

        // 2. NAT hole-punching probe — echo it so the sender's
        //    probe_candidates() sees this candidate pair working.
        if datagram == crate::nat::ice::PROBE_MAGIC {
            if let Err(e) = self
                .socket
                .send_to(crate::nat::ice::PROBE_MAGIC, from)
                .await
            {
                debug!(%from, ?e, "failed to echo NAT probe");
            }
            return Ok(None);
        }

        // 3. WireGuard from a peer we hold a direct tunnel to.
        let node = self.by_addr.read().await.get(&from).copied();
        let Some(node) = node else {
            debug!(%from, len = datagram.len(), "datagram from unknown source dropped");
            return Ok(None);
        };
        let Some(tunnel) = self.tunnels.get(&node).map(|t| t.value().clone()) else {
            warn!(peer = %node.short(), "address indexed but tunnel is gone");
            return Ok(None);
        };
        tunnel.on_datagram(datagram).await
    }

    /// Handle a datagram carrying the relay's own framing.
    async fn handle_relay_packet(
        &self,
        from: SocketAddr,
        datagram: &[u8],
    ) -> Result<Option<bytes::BytesMut>> {
        let Some(packet) = relay::parse_packet(datagram) else {
            debug!(%from, "malformed relay packet dropped");
            return Ok(None);
        };

        match packet {
            // Our registration was accepted: the relay is alive.
            RelayPacket::RegisterAck { .. } => {
                self.relay_health.note_ack();
                Ok(None)
            }
            // Ciphertext from a peer, delivered by the relay.
            RelayPacket::Forward { src, payload } => {
                let Some(tunnel) = self.tunnels.get(&src).map(|t| t.value().clone()) else {
                    debug!(peer = %src.short(), "relayed datagram for unknown peer");
                    return Ok(None);
                };
                tunnel.on_datagram(payload).await
            }
            // Server-bound message types. A client receiving one means
            // something is misconfigured or someone is probing us.
            RelayPacket::Register { .. } | RelayPacket::Data { .. } => {
                debug!(%from, "ignoring server-bound relay packet");
                Ok(None)
            }
        }
    }
}
