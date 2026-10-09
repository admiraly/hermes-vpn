//! In-memory room registry for the signaling server.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use uuid::Uuid;

use hermes_core::crypto::VirtualIpv4;
use hermes_core::room::{InviteCode, RoomMode};
use hermes_core::signaling::{PeerInfo, RoomRestore, ServerMessage};

/// Every room's virtual subnet (10.42.0.0/16), as the clients use it.
const SUBNET_PREFIX: [u8; 2] = [10, 42];

/// A peer session on the server side.
pub struct Session {
    pub session_id: String,
    pub node_id: hermes_core::crypto::NodeId,
    pub alias: String,
    pub wireguard_public: [u8; 32],
    /// The node's signed key binding, relayed to peers verbatim.
    pub wireguard_binding: Vec<u8>,
    pub outgoing: mpsc::Sender<ServerMessage>,
    /// IP salt in the session's current room (see `insert_member`).
    pub ip_salt: AtomicU32,
}

impl Session {
    /// This member as other members see it.
    pub fn peer_info(&self) -> PeerInfo {
        PeerInfo {
            node_id: self.node_id,
            wireguard_public: self.wireguard_public,
            wireguard_binding: self.wireguard_binding.clone(),
            alias: self.alias.clone(),
            ip_salt: self.ip_salt.load(Ordering::Relaxed),
        }
    }
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
    ///
    /// The session is also given an IP salt: the smallest one under which
    /// its virtual address is free among the *current* members. Members
    /// already present never change address; only a newcomer whose
    /// default address would collide gets a different one.
    pub fn insert_member(&self, session: Arc<Session>) -> Option<Arc<Session>> {
        let mut members = self.members.write();
        let replaced = members
            .iter()
            .position(|m| m.node_id == session.node_id)
            .map(|i| members.remove(i));
        let taken: Vec<Ipv4Addr> = members
            .iter()
            .map(|m| {
                VirtualIpv4::from_node_id_salted(
                    &m.node_id,
                    SUBNET_PREFIX,
                    m.ip_salt.load(Ordering::Relaxed),
                )
                .0
            })
            .collect();
        let salt = VirtualIpv4::free_salt(&session.node_id, SUBNET_PREFIX, &taken);
        session.ip_salt.store(salt, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;
    use hermes_core::crypto::NodeId;
    use std::collections::HashMap;

    fn session(node_id: NodeId) -> Arc<Session> {
        let (outgoing, _rx) = mpsc::channel(1);
        Arc::new(Session {
            session_id: String::new(),
            node_id,
            alias: String::new(),
            wireguard_public: [0; 32],
            wireguard_binding: Vec::new(),
            outgoing,
            ip_salt: AtomicU32::new(0),
        })
    }

    /// Two node ids whose default (salt 0) addresses collide.
    fn colliding_pair() -> (NodeId, NodeId) {
        let mut seen: HashMap<Ipv4Addr, NodeId> = HashMap::new();
        for i in 0u32.. {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_le_bytes());
            let id = NodeId(bytes);
            let ip = VirtualIpv4::from_node_id(&id, SUBNET_PREFIX).0;
            if let Some(&first) = seen.get(&ip) {
                return (first, id);
            }
            seen.insert(ip, id);
        }
        unreachable!()
    }

    #[test]
    fn colliding_newcomer_gets_a_distinct_address_and_veterans_keep_theirs() {
        let (a, b) = colliding_pair();
        let registry = RoomRegistry::new();
        let room = registry.create("r".into(), RoomMode::PeerToPeer, None);

        let first = session(a);
        room.insert_member(first.clone());
        assert_eq!(first.ip_salt.load(Ordering::Relaxed), 0);

        let second = session(b);
        room.insert_member(second.clone());
        assert_eq!(second.ip_salt.load(Ordering::Relaxed), 1);

        let ip = |s: &Session| {
            let info = s.peer_info();
            VirtualIpv4::from_node_id_salted(&info.node_id, SUBNET_PREFIX, info.ip_salt).0
        };
        assert_ne!(ip(&first), ip(&second));
        assert_eq!(
            first.ip_salt.load(Ordering::Relaxed),
            0,
            "the earlier member never moves"
        );

        // Once the first member leaves, a later joiner of that id gets salt 0 again.
        room.remove_member(&first);
        let again = session(a);
        room.insert_member(again.clone());
        assert_ne!(ip(&again), ip(&second));
    }
}
