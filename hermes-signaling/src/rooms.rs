//! In-memory room registry for the signaling server.

use std::sync::Arc;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use uuid::Uuid;

use hermes_core::room::{InviteCode, RoomMode};
use hermes_core::signaling::{RoomRestore, ServerMessage};

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

impl ServerRoom {
    /// Add `session` as a member. A node is in a room at most once: if an
    /// older session of the same node is still listed (its connection
    /// died but the server hasn't noticed yet, and the node reconnected),
    /// it is replaced and returned.
    pub fn insert_member(&self, session: Arc<Session>) -> Option<Arc<Session>> {
        let mut members = self.members.write();
        let replaced = members
            .iter()
            .position(|m| m.node_id == session.node_id)
            .map(|i| members.remove(i));
        members.push(session);
        replaced
    }

    /// Remove exactly this session (not merely any session of the same
    /// node). Returns `false` if it was no longer a member — e.g. it had
    /// already been replaced by a newer session of the same node.
    pub fn remove_member(&self, session: &Arc<Session>) -> bool {
        let mut members = self.members.write();
        let before = members.len();
        members.retain(|m| !Arc::ptr_eq(m, session));
        members.len() != before
    }

    /// Is this exact session a member?
    pub fn has_member(&self, session: &Arc<Session>) -> bool {
        self.members.read().iter().any(|m| Arc::ptr_eq(m, session))
    }
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
    pub fn create(
        &self,
        name: String,
        mode: RoomMode,
        relay_addr: Option<String>,
    ) -> Arc<ServerRoom> {
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

    /// Look up a room by invite code, or — if the code is unknown and the
    /// joiner supplied restore info — recreate it under the remembered id
    /// and code. Used when members re-join after a server restart wiped
    /// the in-memory registry. Atomic per code, so members racing to
    /// restore the same room all end up in one room.
    #[must_use]
    pub fn find_or_restore(
        &self,
        code: &InviteCode,
        restore: Option<RoomRestore>,
    ) -> Option<Arc<ServerRoom>> {
        if let Some(room) = self.find_by_invite(code) {
            return Some(room);
        }
        let r = restore?;
        if r.mode == RoomMode::Relayed && r.relay_addr.as_deref().map_or(true, str::is_empty) {
            return None;
        }
        let id = match self.by_invite.entry(*code) {
            // Someone restored it a moment ago.
            Entry::Occupied(e) => *e.get(),
            Entry::Vacant(slot) => {
                // A live room with a different code already has this id:
                // refuse instead of clobbering it.
                if self.by_id.contains_key(&r.room_id) {
                    return None;
                }
                let room = Arc::new(ServerRoom {
                    id: r.room_id,
                    name: r.name,
                    invite: *code,
                    mode: r.mode,
                    relay_addr: r.relay_addr,
                    members: RwLock::new(Vec::new()),
                });
                self.by_id.insert(room.id, room);
                *slot.insert(r.room_id)
            }
        };
        self.by_id.get(&id).map(|room| room.clone())
    }

    /// Remove a room if it has no members left.
    pub fn remove_if_empty(&self, room: &ServerRoom) {
        if room.members.read().is_empty() {
            self.remove(room.id);
        }
    }

    /// Remove a room (used when it becomes empty).
    pub fn remove(&self, id: Uuid) {
        if let Some((_, room)) = self.by_id.remove(&id) {
            self.by_invite.remove(&room.invite);
        }
    }
}
