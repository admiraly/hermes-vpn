//! The MAC forwarding table.

use std::net::Ipv4Addr;

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::crypto::{NodeId, VirtualIpv4, VirtualMac};

/// What the mesh should do with an outbound frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDecision {
    /// Deliver to exactly one peer.
    Unicast(NodeId),
    /// Deliver to every peer in the room.
    ///
    /// Used for broadcast and multicast destinations, and — as a learning
    /// switch does — for unicast destinations we have no entry for. The
    /// alternative, dropping unknown unicast, would silently break any
    /// protocol whose first packet precedes the routing table entry.
    Flood,
    /// The frame is addressed to us. It should never have left the local
    /// stack; drop it rather than echo it onto the mesh.
    Local,
}

/// Maps virtual MACs and IPs to the peers that own them.
///
/// Entries are not learned from traffic the way a physical switch learns
/// them — every address in a Hermes room is *derived* from the owning
/// node's public key (see [`crate::crypto`]), so the engine can populate
/// the table the moment a peer is announced, before a single frame moves.
pub struct MacRouter {
    /// Our own MAC. Frames addressed here are [`RouteDecision::Local`].
    own_mac: VirtualMac,
    /// Our own virtual IPv4, once known. See [`MacRouter::set_own_ipv4`].
    own_ipv4: RwLock<Option<Ipv4Addr>>,
    /// Destination MAC → owning peer.
    by_mac: DashMap<VirtualMac, NodeId>,
    /// Destination IPv4 → its MAC. Used by the Layer-3 shim, which has to
    /// pick a destination MAC given only an IP packet.
    by_ipv4: DashMap<Ipv4Addr, VirtualMac>,
    /// Peer → the addresses registered for it, so a departing peer can be
    /// removed from both indexes.
    by_node: DashMap<NodeId, (VirtualMac, Ipv4Addr)>,
}

impl MacRouter {
    /// Build an empty table for a node whose own MAC is `own_mac`.
    #[must_use]
    pub fn new(own_mac: VirtualMac) -> Self {
        Self {
            own_mac,
            own_ipv4: RwLock::new(None),
            by_mac: DashMap::new(),
            by_ipv4: DashMap::new(),
            by_node: DashMap::new(),
        }
    }

    /// Our own MAC address.
    #[must_use]
    pub fn own_mac(&self) -> VirtualMac {
        self.own_mac
    }

    /// Our own virtual IPv4, if it has been set or observed.
    #[must_use]
    pub fn own_ipv4(&self) -> Option<Ipv4Addr> {
        *self.own_ipv4.read()
    }

    /// Record our own virtual IPv4.
    ///
    /// The Layer-3 shim needs this to know which ARP requests are asking
    /// about *us*: on wintun there is no local network stack to answer
    /// them. Callers that know the address up front (from the adapter
    /// config) should set it here; otherwise the shim learns it from the
    /// source address of the first packet we send.
    pub fn set_own_ipv4(&self, ip: Ipv4Addr) {
        *self.own_ipv4.write() = Some(ip);
    }

    /// Add or update the entry for a peer.
    pub fn register(&self, mac: VirtualMac, ipv4: VirtualIpv4, node: NodeId) {
        // Drop any addresses this peer held previously, so a re-registration
        // can't leave a stale MAC pointing at it.
        if let Some((_, (old_mac, old_ip))) = self.by_node.remove(&node) {
            if old_mac != mac {
                self.by_mac.remove(&old_mac);
            }
            if old_ip != ipv4.0 {
                self.by_ipv4.remove(&old_ip);
            }
        }
        self.by_mac.insert(mac, node);
        self.by_ipv4.insert(ipv4.0, mac);
        self.by_node.insert(node, (mac, ipv4.0));
    }

    /// Forget a peer that has left the room.
    pub fn unregister(&self, node: NodeId) {
        if let Some((_, (mac, ip))) = self.by_node.remove(&node) {
            self.by_mac.remove(&mac);
            self.by_ipv4.remove(&ip);
        }
    }

    /// Decide where a frame with destination MAC `dst` should go.
    #[must_use]
    pub fn route(&self, dst: VirtualMac) -> RouteDecision {
        if dst == self.own_mac {
            return RouteDecision::Local;
        }
        // Broadcast and multicast reach everyone — this is what carries
        // ARP, mDNS, SSDP, and game discovery across the room.
        if dst.is_multicast() {
            return RouteDecision::Flood;
        }
        match self.by_mac.get(&dst) {
            Some(node) => RouteDecision::Unicast(*node),
            None => RouteDecision::Flood,
        }
    }

    /// The MAC that owns `ip`, if we know it.
    #[must_use]
    pub fn mac_for_ipv4(&self, ip: Ipv4Addr) -> Option<VirtualMac> {
        self.by_ipv4.get(&ip).map(|m| *m)
    }

    /// The peer that owns `mac`, if we know it.
    #[must_use]
    pub fn node_for_mac(&self, mac: VirtualMac) -> Option<NodeId> {
        self.by_mac.get(&mac).map(|n| *n)
    }

    /// How many peers are currently in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_node.len()
    }

    /// Is the table empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_node.is_empty()
    }
}

impl std::fmt::Debug for MacRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacRouter")
            .field("own_mac", &self.own_mac)
            .field("own_ipv4", &self.own_ipv4())
            .field("peers", &self.by_node.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> (NodeId, VirtualMac, VirtualIpv4) {
        let id = NodeId([seed; 32]);
        (
            id,
            VirtualMac::from_node_id(&id),
            VirtualIpv4::from_node_id(&id, [10, 42]),
        )
    }

    #[test]
    fn unicast_resolves_to_the_owning_peer() {
        let (us, own_mac, _) = peer(1);
        let _ = us;
        let router = MacRouter::new(own_mac);

        let (node, mac, ip) = peer(2);
        router.register(mac, ip, node);

        assert_eq!(router.route(mac), RouteDecision::Unicast(node));
        assert_eq!(router.mac_for_ipv4(ip.0), Some(mac));
        assert_eq!(router.node_for_mac(mac), Some(node));
        assert_eq!(router.len(), 1);
    }

    #[test]
    fn our_own_mac_is_local() {
        let (_, own_mac, _) = peer(1);
        let router = MacRouter::new(own_mac);
        assert_eq!(router.route(own_mac), RouteDecision::Local);
    }

    #[test]
    fn broadcast_and_multicast_flood() {
        let (_, own_mac, _) = peer(1);
        let router = MacRouter::new(own_mac);

        assert_eq!(router.route(VirtualMac::broadcast()), RouteDecision::Flood);
        // IPv4 multicast MACs start 01:00:5e.
        let mdns = VirtualMac([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
        assert_eq!(router.route(mdns), RouteDecision::Flood);
    }

    #[test]
    fn unknown_unicast_floods_rather_than_dropping() {
        let (_, own_mac, _) = peer(1);
        let router = MacRouter::new(own_mac);
        let (_, stranger, _) = peer(9);
        assert_eq!(router.route(stranger), RouteDecision::Flood);
    }

    #[test]
    fn unregister_clears_both_indexes() {
        let (_, own_mac, _) = peer(1);
        let router = MacRouter::new(own_mac);
        let (node, mac, ip) = peer(2);

        router.register(mac, ip, node);
        router.unregister(node);

        assert_eq!(router.route(mac), RouteDecision::Flood);
        assert_eq!(router.mac_for_ipv4(ip.0), None);
        assert!(router.is_empty());
    }

    #[test]
    fn re_registration_does_not_leave_stale_entries() {
        let (_, own_mac, _) = peer(1);
        let router = MacRouter::new(own_mac);
        let (node, mac, ip) = peer(2);
        router.register(mac, ip, node);

        // Same peer announced with different addresses (shouldn't happen
        // with derived addressing, but the table must not be corrupted).
        let other_mac = VirtualMac([0x02, 9, 9, 9, 9, 9]);
        let other_ip = VirtualIpv4(Ipv4Addr::new(10, 42, 7, 7));
        router.register(other_mac, other_ip, node);

        assert_eq!(router.route(mac), RouteDecision::Flood, "old MAC dropped");
        assert_eq!(router.mac_for_ipv4(ip.0), None, "old IP dropped");
        assert_eq!(router.route(other_mac), RouteDecision::Unicast(node));
        assert_eq!(router.len(), 1);
    }

    #[test]
    fn own_ipv4_roundtrips() {
        let (_, own_mac, _) = peer(1);
        let router = MacRouter::new(own_mac);
        assert_eq!(router.own_ipv4(), None);
        router.set_own_ipv4(Ipv4Addr::new(10, 42, 1, 1));
        assert_eq!(router.own_ipv4(), Some(Ipv4Addr::new(10, 42, 1, 1)));
    }
}
