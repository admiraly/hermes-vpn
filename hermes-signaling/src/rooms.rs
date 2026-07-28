//! In-memory room registry for the signaling server.

use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use uuid::Uuid;

use hermes_core::room::{InviteCode, RoomMode};
use hermes_core::signaling::ServerMessage;

/// A peer session on the server side.
pub struct Session {
    pub session_id: String,
    pub node_id: hermes_core::crypto::NodeId,
    pub alias: String,
    pub wireguard_public: [u8; 32],
    pub outgoing: mpsc::Sender<ServerMessage>,
}

/// A room as tracked by the signaling server.
pub struct ServerRoom {
    pub id: Uuid,
    pub name: String,
    pub invite: InviteCode,
    /// Traffic mode chosen by the creator — every joiner is told this.
    pub mode: RoomMode,
    /// Relay address (`host:port`) when `mode` is [`RoomMode::Relayed`].
    pub relay_addr: Option<String>,
    pub members: RwLock<Vec<Arc<Session>>>,
}

/// Thread-safe room registry, cloneable handle for Axum.
#[derive(Clone, Default)]
pub struct RoomRegistry {
    by_id: Arc<DashMap<Uuid, Arc<ServerRoom>>>,
    by_invite: Arc<DashMap<InviteCode, Uuid>>,
}

impl RoomRegistry {
    /// Construct a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a room and return it.
    pub fn create(&self, name: String, mode: RoomMode, relay_addr: Option<String>) -> Arc<ServerRoom> {
        let invite = InviteCode::generate();
        let id = Uuid::new_v4();
        let room = Arc::new(ServerRoom {
            id,
            name,
            invite,
            mode,
            relay_addr,
            members: RwLock::new(Vec::new()),
        });
        self.by_id.insert(id, room.clone());
        self.by_invite.insert(invite, id);
        room
    }

    /// Look up a room by invite code.
    #[must_use]
    pub fn find_by_invite(&self, code: &InviteCode) -> Option<Arc<ServerRoom>> {
        self.by_invite
            .get(code)
            .and_then(|id| self.by_id.get(&id).map(|r| r.clone()))
    }

    /// Remove a room (used when it becomes empty).
    pub fn remove(&self, id: Uuid) {
        if let Some((_, room)) = self.by_id.remove(&id) {
            self.by_invite.remove(&room.invite);
        }
    }
}
