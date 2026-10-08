//! IPC wire protocol between the Hermes daemon and its clients.
//!
//! The protocol is a request/response RPC with a side channel for
//! unsolicited events. Each message is a single JSON object prefixed by a
//! 4-byte little-endian length (see [`super::transport`]).
//!
//! Every [`Command`] carries an opaque `id` that the daemon echoes back
//! in the matching [`Response`], so clients can multiplex many in-flight
//! calls on a single connection. [`Event`] frames carry no id.

use serde::{Deserialize, Serialize};

use hermes_core::crypto::NodeId;
use hermes_core::directory::{ServerEntry, ServerKind};
use hermes_core::engine_pump::EngineEvent;
use hermes_core::mesh::LinkStats;
use hermes_core::room::{PeerRecord, PeerStatus, RoomId, RoomMode};

/// Current protocol version. Bumped on any incompatible wire change.
/// v2: room modes, relay assignment, server directory commands.
/// v3: reconnect + relay-health events, `relay_healthy` in the snapshot.
pub const IPC_PROTOCOL_VERSION: u16 = 3;

/// Envelope for every frame written on the wire.
///
/// Using a single tagged enum for commands, responses, and events keeps
/// the read loop trivial — there's one `decode -> match` rather than
/// three parallel state machines.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Frame {
    /// Client → daemon RPC request.
    Command(Command),
    /// Daemon → client reply to a matching [`Command`].
    Response(Response),
    /// Daemon → client unsolicited push.
    Event(Event),
}

/// A client-initiated command.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Command {
    /// Client-generated correlation id, echoed in the matching response.
    pub id: u64,
    /// The command payload.
    pub payload: CommandPayload,
}

/// The set of operations a client can request from the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CommandPayload {
    /// Handshake — must be the first command on a new connection.
    Hello {
        /// The protocol version the client speaks.
        protocol_version: u16,
    },
    /// Fetch our node identity as a base64 string.
    GetIdentity,
    /// Connect to a signaling server. With no URL, the daemon uses the
    /// directory's active selection.
    Connect {
        /// Explicit signaling URL override.
        #[serde(default)]
        signaling_url: Option<String>,
    },
    /// Create a new room. Daemon responds once the server acknowledges.
    CreateRoom {
        /// Display name.
        name: String,
        /// Traffic mode (peer-to-peer or relayed).
        #[serde(default)]
        mode: RoomMode,
        /// Relay address (`host:port`) — required for relayed rooms.
        #[serde(default)]
        relay_addr: Option<String>,
    },
    /// Join an existing room by its 12-character invite code.
    JoinRoom {
        /// The invite code (e.g. `WLFK-7X4K-QR2S`).
        code: String,
    },
    /// Leave the current room.
    LeaveRoom,
    /// Snapshot the current peer table.
    GetPeers,
    /// Snapshot the engine's overall state — connection status, current
    /// room, our virtual address, etc. Useful for UIs that just opened.
    GetState,
    /// Snapshot the server directory (signaling + relay lists).
    GetServers,
    /// Add a user-defined server to the directory.
    AddServer {
        /// Which fleet the server belongs to.
        kind: ServerKind,
        /// Display name (unique per fleet).
        name: String,
        /// `ws(s)://…` URL for signaling, `host:port` for relays.
        address: String,
    },
    /// Remove a user-defined server from the directory.
    RemoveServer {
        /// Which fleet the server belongs to.
        kind: ServerKind,
        /// Name of the entry to remove.
        name: String,
    },
    /// Select which signaling server `Connect` should use by default.
    SetActiveSignaling {
        /// Name of an existing signaling entry.
        name: String,
    },
    /// Set (or clear) the operator manifest URL.
    SetManifestUrl {
        /// New manifest URL; `None` disables manifest fetching.
        url: Option<String>,
    },
    /// Re-fetch the operator manifest now.
    RefreshServers,
    /// Graceful connection close.
    Goodbye,
}

/// Reply to a [`Command`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    /// The id echoed from the originating command.
    pub id: u64,
    /// The result body.
    pub result: ResponseBody,
}

/// Result of a command.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResponseBody {
    /// Welcome response to [`CommandPayload::Hello`].
    Welcome {
        /// Server protocol version.
        protocol_version: u16,
    },
    /// Identity as URL-safe base64.
    Identity {
        /// `NodeId` encoded as base64-url.
        node_id_base64: String,
    },
    /// Peer table snapshot.
    Peers {
        /// Cloned peer records.
        peers: Vec<PeerRecord>,
    },
    /// Engine state snapshot — see [`StateSnapshot`].
    State(StateSnapshot),
    /// Server directory snapshot.
    Servers(ServerListing),
    /// Operation succeeded with no payload.
    Ok,
    /// Operation failed.
    Error {
        /// Short machine-readable code.
        code: String,
        /// Human-readable message.
        message: String,
    },
}

/// A snapshot of the engine's high-level state, returned by
/// [`CommandPayload::GetState`]. Designed for a UI that's just opened
/// and needs to render its initial view without subscribing to events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Our node identity as URL-safe base64.
    pub node_id_base64: String,
    /// Have we connected to the signaling server?
    pub connected: bool,
    /// Local UDP endpoint we bound (host candidate). `None` until the
    /// engine has connected at least once.
    pub local_endpoint: Option<String>,
    /// Our reflexive (server-public) address learned via STUN. `None` if
    /// STUN hasn't run yet or it failed.
    pub reflexive_endpoint: Option<String>,
    /// The current room, if we're in one.
    pub room: Option<RoomSummary>,
    /// Current peer table.
    pub peers: Vec<PeerRecord>,
    /// Live per-peer link statistics, keyed by `node_id` in each entry.
    /// Empty until tunnels come up.
    pub links: Vec<LinkStats>,
    /// Health of the current relay session: `Some(healthy)` while a
    /// relay is configured for the room, `None` otherwise.
    pub relay_healthy: Option<bool>,
}

/// Lightweight summary of the current room (for [`StateSnapshot`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomSummary {
    /// Room id.
    pub id: RoomId,
    /// Display name.
    pub name: String,
    /// Two-byte subnet prefix (`10.42` for `10.42.0.0/16`).
    pub subnet_prefix: [u8; 2],
    /// Traffic mode.
    pub mode: RoomMode,
    /// Relay address when the room is relayed.
    pub relay_addr: Option<String>,
}

/// Snapshot of the server directory, returned by
/// [`CommandPayload::GetServers`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerListing {
    /// Merged signaling server list (built-in + manifest + custom).
    pub signaling: Vec<ServerEntry>,
    /// Merged relay server list.
    pub relays: Vec<ServerEntry>,
    /// Configured operator manifest URL.
    pub manifest_url: Option<String>,
    /// Name of the signaling server `Connect` uses by default.
    pub active_signaling: Option<String>,
}

impl ResponseBody {
    /// Construct a uniform `error` response.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Error {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Unsolicited push sent from daemon → client.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// We entered a room.
    RoomEntered {
        /// Room id.
        room_id: RoomId,
        /// Invite code (only present when we created the room).
        invite_code: Option<String>,
        /// The room's traffic mode.
        mode: RoomMode,
        /// Relay address when the room is relayed.
        relay_addr: Option<String>,
    },
    /// A peer appeared in our room.
    PeerAdded {
        /// Full peer record.
        peer: PeerRecord,
    },
    /// A peer's status changed.
    PeerStatusChanged {
        /// Which peer.
        node_id: NodeId,
        /// New status.
        status: PeerStatus,
    },
    /// A peer left.
    PeerRemoved {
        /// Which peer.
        node_id: NodeId,
    },
    /// Signaling server returned an error.
    SignalingError {
        /// Short code.
        code: String,
        /// Message.
        message: String,
    },
    /// The signaling WebSocket was closed. Tunnels keep running; the
    /// daemon reconnects automatically with backoff.
    SignalingDisconnected,
    /// A reconnect attempt is about to be made (1-based counter).
    SignalingReconnecting {
        /// Attempt number since the disconnect.
        attempt: u32,
    },
    /// The signaling connection was re-established (and any current room
    /// re-joined).
    SignalingReconnected,
    /// The room's relay stopped acknowledging registrations — relayed
    /// traffic is likely down until it recovers.
    RelayUnhealthy {
        /// Relay address, for display.
        relay: String,
    },
    /// The room's relay is acknowledging again.
    RelayRestored {
        /// Relay address, for display.
        relay: String,
    },
}

impl From<EngineEvent> for Event {
    fn from(e: EngineEvent) -> Self {
        match e {
            EngineEvent::RoomEntered {
                room_id,
                invite_code,
                mode,
                relay_addr,
            } => Event::RoomEntered {
                room_id,
                invite_code: invite_code.map(|c| c.to_string()),
                mode,
                relay_addr,
            },
            EngineEvent::PeerAdded(peer) => Event::PeerAdded { peer },
            EngineEvent::PeerStatusChanged { node_id, status } => {
                Event::PeerStatusChanged { node_id, status }
            }
            EngineEvent::PeerRemoved(node_id) => Event::PeerRemoved { node_id },
            EngineEvent::SignalingError { code, message } => {
                Event::SignalingError { code, message }
            }
            EngineEvent::SignalingDisconnected => Event::SignalingDisconnected,
            EngineEvent::SignalingReconnecting { attempt } => {
                Event::SignalingReconnecting { attempt }
            }
            EngineEvent::SignalingReconnected => Event::SignalingReconnected,
            EngineEvent::RelayUnhealthy { relay } => Event::RelayUnhealthy { relay },
            EngineEvent::RelayRestored { relay } => Event::RelayRestored { relay },
        }
    }
}
