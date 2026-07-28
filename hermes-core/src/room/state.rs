//! Room state: members, virtual IP/MAC allocation, liveness.

use std::net::Ipv4Addr;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{NodeId, VirtualIpv4, VirtualMac};
use crate::nat::PathKind;

/// Room identifier.
pub type RoomId = Uuid;

/// How traffic flows between the members of a room.
///
/// Chosen by the room's creator and distributed to every member by the
/// signaling server, so the whole room always agrees on one mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoomMode {
    /// Direct peer-to-peer tunnels negotiated via NAT traversal. The
    /// signaling server only brokers the rendezvous.
    #[default]
    PeerToPeer,
    /// All tunnel traffic is forwarded by a relay (central) server.
    /// Still end-to-end encrypted — the relay sees ciphertext only.
    Relayed,
}

/// Connection status for a peer from our perspective.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerStatus {
    /// We're aware of this peer but haven't started traversal.
    Discovered,
    /// Traversal in progress.
    Connecting,
    /// Tunnel is up and carrying frames.
    Connected(PathKind),
    /// Tunnel was up but has gone silent. Will be retried.
    Stale,
    /// Peer has left the room.
    Gone,
}

/// One peer's record inside a room.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    /// Peer identity.
    pub node_id: NodeId,
    /// Peer's X25519 public key (for WireGuard).
    pub wireguard_public: [u8; 32],
    /// Peer's self-chosen alias.
    pub alias: String,
    /// Peer's virtual IPv4 address within the room subnet.
    pub virtual_ipv4: VirtualIpv4,
    /// Peer's virtual MAC.
    pub virtual_mac: VirtualMac,
    /// Current connection status.
    pub status: PeerStatus,
    /// Last observed round-trip latency in milliseconds.
    pub latency_ms: Option<u32>,
}

/// A joined room.
#[derive(Debug)]
pub struct Room {
    /// The room's id.
    pub id: RoomId,
    /// Display name.
    pub name: String,
    /// Two-byte IPv4 subnet prefix (e.g. `[10, 42]` for `10.42.0.0/16`).
    pub subnet_prefix: [u8; 2],
    /// Traffic mode for this room.
    pub mode: RoomMode,
    /// Relay server address (`host:port`) when `mode` is
    /// [`RoomMode::Relayed`].
    pub relay_addr: Option<String>,
    /// Peer table.
    peers: DashMap<NodeId, PeerRecord>,
}

impl Room {
    /// Construct a fresh room with the default subnet prefix.
    #[must_use]
    pub fn new(id: RoomId, name: String, mode: RoomMode, relay_addr: Option<String>) -> Self {
        Self {
            id,
            name,
            subnet_prefix: [10, 42],
            mode,
            relay_addr,
            peers: DashMap::new(),
        }
    }

    /// Insert or update a peer record.
    pub fn upsert_peer(&self, record: PeerRecord) {
        self.peers.insert(record.node_id, record);
    }

    /// Remove a peer.
    pub fn remove_peer(&self, node_id: NodeId) -> Option<PeerRecord> {
        self.peers.remove(&node_id).map(|(_, v)| v)
    }

    /// Snapshot of all peers (cloned).
    #[must_use]
    pub fn peers(&self) -> Vec<PeerRecord> {
        self.peers.iter().map(|r| r.value().clone()).collect()
    }

    /// The virtual IPv4 address for a given node, derived from its identity.
    #[must_use]
    pub fn virtual_ipv4_for(&self, node: NodeId) -> Ipv4Addr {
        VirtualIpv4::from_node_id(&node, self.subnet_prefix).0
    }

    /// Update the status field of an existing peer.
    pub fn set_status(&self, node_id: NodeId, status: PeerStatus) {
        if let Some(mut entry) = self.peers.get_mut(&node_id) {
            entry.status = status;
        }
    }

    /// Update the latency field of an existing peer.
    pub fn set_latency(&self, node_id: NodeId, latency_ms: u32) {
        if let Some(mut entry) = self.peers.get_mut(&node_id) {
            entry.latency_ms = Some(latency_ms);
        }
    }
}
