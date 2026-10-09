//! Wire protocol for the signaling server.
//!
//! Messages are JSON objects with an internally-tagged `type` field so
//! they're easy to inspect with `wscat` for debugging. All peer-addressed
//! messages include a `from` field populated by the server, so clients
//! never need to trust the sender-provided identity — the server
//! authenticates peers at WebSocket connect time via a signed challenge.

use serde::{Deserialize, Serialize};

use crate::crypto::NodeId;
use crate::nat::Candidate;
use crate::room::{InviteCode, RoomId, RoomMode};

/// Messages sent from client → server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Authenticate this WebSocket. Must be the first message.
    Hello {
        /// The node identity this connection belongs to.
        node_id: NodeId,
        /// WireGuard X25519 public key — derived deterministically from
        /// the node's Ed25519 identity and advertised here so other peers
        /// can pin it when building their tunnels.
        wireguard_public: [u8; 32],
        /// Ed25519 signature of the server-provided challenge nonce.
        signature: Vec<u8>,
        /// Ed25519 signature binding `wireguard_public` to `node_id` (see
        /// `crypto::verify_wireguard_binding`). Peers verify it themselves,
        /// so the server relaying it cannot swap in a different key.
        #[serde(default)]
        wireguard_binding: Vec<u8>,
        /// Human-visible alias.
        alias: String,
        /// Protocol version the client speaks.
        protocol_version: u16,
    },
    /// Create a new room. Server replies with `RoomCreated` including the
    /// invite code.
    CreateRoom {
        /// Human-visible room name.
        name: String,
        /// Traffic mode for the room (peer-to-peer or relayed).
        mode: RoomMode,
        /// Relay server address (`host:port`). Required when `mode` is
        /// [`RoomMode::Relayed`]; the server stores it and hands it to
        /// every member so the whole room uses the same relay.
        relay_addr: Option<String>,
    },
    /// Join an existing room via invite code.
    JoinRoom {
        /// Invite code.
        code: InviteCode,
        /// Sent only by an automatic re-join after a reconnect: the room as
        /// this member knew it. If the server no longer knows the code
        /// (it restarted and lost its in-memory rooms), it recreates the
        /// room from this under the same id and code, so every member
        /// lands back in the *same* room and live tunnels survive.
        /// Knowing the invite code is already what grants membership, so
        /// this lets a member do nothing it couldn't do before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        restore: Option<RoomRestore>,
    },
    /// Leave the current room (if any).
    LeaveRoom,
    /// Send our candidate list to another peer in the room for ICE.
    RelayCandidates {
        /// Destination peer.
        to: NodeId,
        /// Our candidate list.
        candidates: Vec<Candidate>,
    },
    /// Keepalive ping.
    Ping,
}

/// What a member remembers about its room, for [`ClientMessage::JoinRoom`]'s
/// `restore` field.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomRestore {
    /// The room's id.
    pub room_id: RoomId,
    /// Display name.
    pub name: String,
    /// Traffic mode.
    pub mode: RoomMode,
    /// Relay address (primary for relayed rooms, fallback for p2p rooms).
    pub relay_addr: Option<String>,
}

/// Messages sent from server → client.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Sent right after the WebSocket opens; contains a challenge the
    /// client must sign in its `Hello`.
    Challenge {
        /// Random 32-byte nonce the client signs.
        nonce: Vec<u8>,
    },
    /// Authentication accepted. Client may now send other messages.
    Welcome {
        /// Our server-assigned session id (used in logs).
        session_id: String,
    },
    /// A room was created for us.
    RoomCreated {
        /// The room's id.
        room_id: RoomId,
        /// The shareable invite code.
        invite_code: InviteCode,
        /// The room's traffic mode.
        mode: RoomMode,
        /// Relay address when the room is relayed.
        relay_addr: Option<String>,
        /// Our own IP salt in this room (always 0 for the creator).
        #[serde(default)]
        ip_salt: u32,
    },
    /// We successfully joined a room.
    RoomJoined {
        /// The room's id.
        room_id: RoomId,
        /// All other members currently present.
        members: Vec<PeerInfo>,
        /// The room's traffic mode.
        mode: RoomMode,
        /// Relay address when the room is relayed.
        relay_addr: Option<String>,
        /// Our own IP salt in this room — non-zero only if our default
        /// address would collide with an existing member's.
        #[serde(default)]
        ip_salt: u32,
    },
    /// A new peer joined our current room.
    PeerJoined {
        /// The peer's public info.
        peer: PeerInfo,
    },
    /// A peer left our room (or disconnected).
    PeerLeft {
        /// The departing peer.
        node_id: NodeId,
    },
    /// Candidate list relayed from another peer.
    PeerCandidates {
        /// The peer these candidates came from.
        from: NodeId,
        /// Their candidate list.
        candidates: Vec<Candidate>,
    },
    /// Error from the server.
    Error {
        /// Short machine-readable code (e.g. `invalid_code`).
        code: String,
        /// Human-readable message.
        message: String,
    },
    /// Keepalive pong.
    Pong,
}

impl PeerInfo {
    /// Does the peer's own signature vouch for the WireGuard key we were
    /// given? Peers failing this must not get a tunnel.
    #[must_use]
    pub fn key_binding_is_valid(&self) -> bool {
        crate::crypto::verify_wireguard_binding(
            &self.node_id,
            &self.wireguard_public,
            &self.wireguard_binding,
        )
    }
}

/// Publicly visible information about a peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The peer's identity.
    pub node_id: NodeId,
    /// Their WireGuard public key (X25519).
    pub wireguard_public: [u8; 32],
    /// The peer's own signature vouching for `wireguard_public`. Recipients
    /// must check it (`crypto::verify_wireguard_binding`) before building a
    /// tunnel: it is what stops the signaling server from substituting its
    /// own key and sitting in the middle.
    #[serde(default)]
    pub wireguard_binding: Vec<u8>,
    /// Self-chosen display name.
    pub alias: String,
    /// Which address in the peer's derivation sequence it uses in this
    /// room (see `VirtualIpv4::from_node_id_salted`). Assigned by the server
    /// so no two members share an IP; 0 for almost everyone.
    #[serde(default)]
    pub ip_salt: u32,
}
