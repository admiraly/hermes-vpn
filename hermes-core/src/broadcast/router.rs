//! MAC routing table and frame classification.

use std::net::Ipv4Addr;

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::crypto::{NodeId, VirtualIpv4, VirtualMac};
use crate::tap::ETHERNET_HEADER;

/// How a frame is addressed at layer 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameClass {
    /// Addressed to a single station.
    Unicast,
    /// `ff:ff:ff:ff:ff:ff`.
    Broadcast,
    /// Any other group address (IPv4 `01:00:5e:…`, IPv6 `33:33:…`, …).
    Multicast,
}

/// Classify a frame by its destination MAC. `None` if it's too short to
/// be an Ethernet frame.
#[must_use]
pub fn classify(frame: &[u8]) -> Option<FrameClass> {
    if frame.len() < ETHERNET_HEADER {
        return None;
    }
    let dst = VirtualMac(frame[..6].try_into().ok()?);
    Some(if dst.is_broadcast() {
        FrameClass::Broadcast
    } else if dst.is_multicast() {
        FrameClass::Multicast
    } else {
        FrameClass::Unicast
    })
}

/// Where an outbound frame should go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDecision {
    /// Send to exactly this peer.
    Unicast(NodeId),
    /// Replicate to every peer in the room.
    Flood,
    /// Not deliverable (malformed, addressed to ourselves, or to a MAC
    /// that belongs to nobody in the room).
    Drop,
}

/// The room's MAC/IP → peer table.
///
/// Entries are registered when a peer joins (its MAC and IP are derived
/// from its node id, so no learning is needed) and removed when it leaves.
#[derive(Debug)]
pub struct MacRouter {
    own_mac: VirtualMac,
    own_ipv4: RwLock<Option<Ipv4Addr>>,
    by_mac: DashMap<VirtualMac, NodeId>,
    by_ip: DashMap<Ipv4Addr, VirtualMac>,
    by_node: DashMap<NodeId, (VirtualMac, Ipv4Addr)>,
}

impl MacRouter {
    /// A router for a node whose virtual MAC is `own_mac`.
    #[must_use]
    pub fn new(own_mac: VirtualMac) -> Self {
        Self {
            own_mac,
            own_ipv4: RwLock::new(None),
            by_mac: DashMap::new(),
            by_ip: DashMap::new(),
            by_node: DashMap::new(),
        }
    }

    /// Our own virtual MAC.
    #[must_use]
    pub fn own_mac(&self) -> VirtualMac {
        self.own_mac
    }

    /// Our virtual IPv4 in the current room (`None` outside a room).
    #[must_use]
    pub fn own_ipv4(&self) -> Option<Ipv4Addr> {
        *self.own_ipv4.read()
    }

    /// Set our virtual IPv4 (on room entry) or clear it (on leave).
    pub fn set_own_ipv4(&self, ip: Option<Ipv4Addr>) {
        *self.own_ipv4.write() = ip;
    }

    /// Register (or refresh) a peer's addresses.
    pub fn register(&self, mac: VirtualMac, ip: VirtualIpv4, node: NodeId) {
        self.unregister(node);
        self.by_mac.insert(mac, node);
        self.by_ip.insert(ip.0, mac);
        self.by_node.insert(node, (mac, ip.0));
    }

    /// Forget a peer.
    pub fn unregister(&self, node: NodeId) {
        if let Some((_, (mac, ip))) = self.by_node.remove(&node) {
            self.by_mac.remove(&mac);
            self.by_ip.remove(&ip);
        }
    }

    /// Forget every peer (room teardown).
    pub fn clear(&self) {
        self.by_mac.clear();
        self.by_ip.clear();
        self.by_node.clear();
    }

    /// The MAC of the peer holding virtual IPv4 `ip`.
    #[must_use]
    pub fn mac_for_ip(&self, ip: Ipv4Addr) -> Option<VirtualMac> {
        self.by_ip.get(&ip).map(|m| *m)
    }

    /// The MAC registered for `node`.
    #[must_use]
    pub fn mac_for_node(&self, node: NodeId) -> Option<VirtualMac> {
        self.by_node.get(&node).map(|e| e.0)
    }

    /// The peer owning `mac`.
    #[must_use]
    pub fn node_for_mac(&self, mac: VirtualMac) -> Option<NodeId> {
        self.by_mac.get(&mac).map(|n| *n)
    }

    /// Decide where an outbound frame goes.
    #[must_use]
    pub fn route(&self, frame: &[u8]) -> RouteDecision {
        match classify(frame) {
            None => RouteDecision::Drop,
            Some(FrameClass::Broadcast | FrameClass::Multicast) => RouteDecision::Flood,
            Some(FrameClass::Unicast) => {
                let dst = VirtualMac(frame[..6].try_into().expect("checked by classify"));
                if dst == self.own_mac {
                    return RouteDecision::Drop;
                }
                self.node_for_mac(dst)
                    .map_or(RouteDecision::Drop, RouteDecision::Unicast)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(dst: [u8; 6]) -> Vec<u8> {
        let mut f = dst.to_vec();
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
        f.extend_from_slice(&[0u8; 20]);
        f
    }

    #[test]
    fn routes_unicast_flood_and_drop() {
        let own = VirtualMac([0x02, 0, 0, 0, 0, 1]);
        let router = MacRouter::new(own);
        let peer = NodeId([5; 32]);
        let peer_mac = VirtualMac::from_node_id(&peer);
        let peer_ip = VirtualIpv4::from_node_id(&peer, [10, 42]);
        router.register(peer_mac, peer_ip, peer);

        assert_eq!(
            router.route(&frame(peer_mac.0)),
            RouteDecision::Unicast(peer)
        );
        assert_eq!(router.route(&frame([0xff; 6])), RouteDecision::Flood);
        assert_eq!(
            router.route(&frame([0x01, 0x00, 0x5e, 0, 0, 0xfb])),
            RouteDecision::Flood
        );
        assert_eq!(
            router.route(&frame([0x33, 0x33, 0, 0, 0, 1])),
            RouteDecision::Flood
        );
        assert_eq!(router.route(&frame(own.0)), RouteDecision::Drop);
        assert_eq!(
            router.route(&frame([0x02, 9, 9, 9, 9, 9])),
            RouteDecision::Drop
        );
        assert_eq!(router.route(&[0u8; 5]), RouteDecision::Drop);
        assert_eq!(router.mac_for_ip(peer_ip.0), Some(peer_mac));

        router.unregister(peer);
        assert_eq!(router.route(&frame(peer_mac.0)), RouteDecision::Drop);
        assert_eq!(router.mac_for_ip(peer_ip.0), None);
    }
}
