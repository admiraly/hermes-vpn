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