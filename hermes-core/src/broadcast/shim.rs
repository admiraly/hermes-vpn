//! L2/L3 shim for IP-only adapters (wintun on Windows).
//!
//! The mesh carries Ethernet frames, but wintun hands us — and accepts —
//! bare IP packets, and Windows never ARPs on a wintun interface. The shim
//! bridges the gap in both directions:
//!
//! - **Outbound** ([`wrap_outbound`]): prepend an Ethernet header. The
//!   destination MAC is resolved without ARP — peers' MACs are derived
//!   from their node ids and already sit in the [`MacRouter`] — and group
//!   IP addresses map to their standard group MACs, so broadcast and
//!   multicast discovery traffic floods the room.
//! - **Inbound** ([`unwrap_inbound`]): strip the Ethernet header and hand
//!   the IP packet to wintun, and answer ARP requests for our address on
//!   Windows' behalf (Linux peers *do* ARP before talking to us).
//!
//! IPv6 unicast is not supported yet (that needs neighbour-discovery
//! emulation); IPv6 multicast such as mDNS on `ff02::fb` is carried.

use std::net::Ipv4Addr;

use bytes::BytesMut;
use tracing::trace;

use super::{arp, ethertype, MacRouter, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use crate::crypto::VirtualMac;
use crate::tap::ETHERNET_HEADER;

/// What to do with a frame that arrived from the mesh.
#[derive(Debug, PartialEq, Eq)]
pub enum InboundAction {
    /// Write this IP packet to the adapter.
    WriteToAdapter(Vec<u8>),
    /// Send this Ethernet frame back across the mesh (an ARP reply).
    ReplyOnMesh(Vec<u8>),
    /// Nothing to do.
    Drop,
}

/// Group MAC for an IPv4 multicast address (RFC 1112: `01:00:5e` + low 23 bits).
fn ipv4_multicast_mac(ip: Ipv4Addr) -> VirtualMac {
    let o = ip.octets();
    VirtualMac([0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]])
}

/// Is `dst` a broadcast address from our point of view: the limited
/// broadcast, or the directed broadcast of our room's /16?
fn is_ipv4_broadcast(dst: Ipv4Addr, own: Option<Ipv4Addr>) -> bool {
    if dst.is_broadcast() {
        return true;
    }
    own.is_some_and(|own| {
        let (d, o) = (dst.octets(), own.octets());
        d[0] == o[0] && d[1] == o[1] && d[2] == 255 && d[3] == 255
    })
}

/// Wrap an IP packet from the adapter into an Ethernet frame addressed
/// to the right peer (or group). `None` if the packet is malformed or
/// its destination isn't in the room.
#[must_use]
pub fn wrap_outbound(packet: &[u8], own_mac: VirtualMac, router: &MacRouter) -> Option<BytesMut> {
    let (dst_mac, ethertype) = match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let mac = if is_ipv4_broadcast(dst, router.own_ipv4()) {
                VirtualMac::BROADCAST
            } else if dst.is_multicast() {
                ipv4_multicast_mac(dst)
            } else if let Some(mac) = router.mac_for_ip(dst) {
                mac
            } else {
                trace!(%dst, "no peer owns destination — dropping");
                return None;
            };
            (mac, ETHERTYPE_IPV4)
        }
        6 if packet.len() >= 40 => {
            // Only multicast (ff00::/8): RFC 2464 `33:33` + low 32 bits.
            if packet[24] != 0xff {
                trace!("IPv6 unicast not supported — dropping");
                return None;
            }
            let mac = VirtualMac([0x33, 0x33, packet[36], packet[37], packet[38], packet[39]]);
            (mac, ETHERTYPE_IPV6)
        }
        _ => return None,
    };

    let mut frame = BytesMut::with_capacity(ETHERNET_HEADER + packet.len());
    frame.extend_from_slice(&dst_mac.0);
    frame.extend_from_slice(&own_mac.0);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(packet);
    Some(frame)
}

/// Handle an Ethernet frame decrypted from the mesh on an IP-only adapter.
#[must_use]
pub fn unwrap_inbound(frame: &[u8], router: &MacRouter) -> InboundAction {
    let Some(et) = ethertype(frame) else {
        return InboundAction::Drop;
    };
    let dst = VirtualMac(frame[..6].try_into().expect("ethertype checked length"));
    if dst != router.own_mac() && !dst.is_multicast() {
        return InboundAction::Drop;
    }
    let payload = &frame[ETHERNET_HEADER..];
    match et {
        ETHERTYPE_IPV4 if payload.len() >= 20 => {
            // Trim Ethernet padding: some stacks pad short frames to 60 bytes.
            let total = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
            if total < 20 || total > payload.len() {
                return InboundAction::Drop;
            }
            InboundAction::WriteToAdapter(payload[..total].to_vec())
        }
        ETHERTYPE_IPV6 if payload.len() >= 40 => {
            let total = 40 + usize::from(u16::from_be_bytes([payload[4], payload[5]]));
            if total > payload.len() {
                return InboundAction::Drop;
            }
            InboundAction::WriteToAdapter(payload[..total].to_vec())
        }
        ETHERTYPE_ARP => {
            let (Some(req), Some(own_ip)) = (arp::parse_request(frame), router.own_ipv4()) else {
                return InboundAction::Drop;
            };
            if req.target_ip == own_ip {
                InboundAction::ReplyOnMesh(arp::build_reply(&req, router.own_mac(), own_ip))
            } else {
                InboundAction::Drop
            }
        }
        _ => InboundAction::Drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{NodeId, VirtualIpv4};

    fn ipv4_packet(dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 42, 0, 1];
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&[0u8; 8]);
        p
    }

    fn setup() -> (MacRouter, NodeId, VirtualMac, Ipv4Addr) {
        let own = VirtualMac([0x02, 0, 0, 0, 0, 1]);
        let router = MacRouter::new(own);
        router.set_own_ipv4(Some(Ipv4Addr::new(10, 42, 0, 1)));
        let peer = NodeId([4; 32]);
        let mac = VirtualMac::from_node_id(&peer);
        let ip = VirtualIpv4::from_node_id(&peer, [10, 42]);
        router.register(mac, ip, peer);
        (router, peer, mac, ip.0)
    }

    #[test]
    fn outbound_unicast_broadcast_multicast() {
        let (router, _, peer_mac, peer_ip) = setup();
        let own = router.own_mac();

        let f = wrap_outbound(&ipv4_packet(peer_ip), own, &router).unwrap();
        assert_eq!(&f[..6], &peer_mac.0);
        assert_eq!(&f[6..12], &own.0);
        assert_eq!(&f[12..14], &[0x08, 0x00]);

        for b in [Ipv4Addr::BROADCAST, Ipv4Addr::new(10, 42, 255, 255)] {
            let f = wrap_outbound(&ipv4_packet(b), own, &router).unwrap();
            assert_eq!(&f[..6], &[0xff; 6]);
        }

        let mdns =
            wrap_outbound(&ipv4_packet(Ipv4Addr::new(224, 0, 0, 251)), own, &router).unwrap();
        assert_eq!(&mdns[..6], &[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);

        assert!(wrap_outbound(&ipv4_packet(Ipv4Addr::new(10, 42, 9, 9)), own, &router).is_none());
        assert!(wrap_outbound(&[0x45], own, &router).is_none());
    }

    #[test]
    fn inbound_ip_is_unwrapped_and_padding_trimmed() {
        let (router, _, peer_mac, _) = setup();
        let own = router.own_mac();
        let packet = ipv4_packet(Ipv4Addr::new(10, 42, 0, 1));
        let mut frame = own.0.to_vec();
        frame.extend_from_slice(&peer_mac.0);
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&packet);
        frame.extend_from_slice(&[0u8; 18]); // Ethernet padding
        assert_eq!(
            unwrap_inbound(&frame, &router),
            InboundAction::WriteToAdapter(packet)
        );

        // Frames for somebody else's MAC are dropped.
        frame[..6].copy_from_slice(&[0x02, 7, 7, 7, 7, 7]);
        assert_eq!(unwrap_inbound(&frame, &router), InboundAction::Drop);
    }

    #[test]
    fn arp_for_our_ip_is_answered() {
        let (router, _, peer_mac, peer_ip) = setup();
        let req = arp::build_request(peer_mac, peer_ip, Ipv4Addr::new(10, 42, 0, 1));
        match unwrap_inbound(&req, &router) {
            InboundAction::ReplyOnMesh(reply) => {
                assert_eq!(&reply[..6], &peer_mac.0);
                assert_eq!(&reply[6..12], &router.own_mac().0);
            }
            other => panic!("expected ARP reply, got {other:?}"),
        }
        let other = arp::build_request(peer_mac, peer_ip, Ipv4Addr::new(10, 42, 3, 3));
        assert_eq!(unwrap_inbound(&other, &router), InboundAction::Drop);
    }
}
