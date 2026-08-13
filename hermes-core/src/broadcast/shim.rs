//! Layer-2 ↔ Layer-3 shim for adapters that don't speak Ethernet.
//!
//! Linux TAP gives us real Ethernet frames and needs none of this. wintun
//! on Windows is Layer 3 only: it hands over bare IP packets, and the
//! Windows networking stack behind it never sends or receives ARP for the
//! virtual interface. Left alone, such a node could not participate in a
//! room at all — its peers would ARP for it and hear nothing back.
//!
//! The shim closes that gap in both directions:
//!
//! - [`wrap_outbound`] takes an IP packet leaving wintun and grows an
//!   Ethernet header. The destination MAC comes from the routing table
//!   (or the standard multicast/broadcast mappings), so the frame looks
//!   exactly like one a TAP node would have emitted.
//!
//! - [`unwrap_inbound`] takes a frame arriving from the mesh. IP frames
//!   are stripped back down and written to the adapter. ARP requests are
//!   answered *here*, on behalf of the local stack that will never see
//!   them — that is what makes a Windows node discoverable.
//!
//! Everything in this module works on byte slices with explicit offsets
//! rather than a packet-parsing crate: the formats are fixed, ancient,
//! and small, and the frames are attacker-reachable, so bounds are
//! checked explicitly and anything unexpected is dropped.

use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use tracing::trace;

use super::MacRouter;
use crate::crypto::VirtualMac;

/// Bytes in an Ethernet II header: destination, source, EtherType.
pub const ETHERNET_HEADER_LEN: usize = 14;

/// EtherType for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// EtherType for IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Bytes in an ARP packet for IPv4-over-Ethernet.
const ARP_PACKET_LEN: usize = 28;
/// ARP hardware type for Ethernet.
const ARP_HTYPE_ETHERNET: u16 = 1;
/// ARP opcodes.
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;

/// What the driver should do with a frame that arrived from the mesh.
#[derive(Debug)]
pub enum InboundAction {
    /// Strip to an IP packet and hand it to the adapter.
    WriteToAdapter(BytesMut),
    /// Send this frame back out over the mesh — an ARP reply we generated
    /// on behalf of a local stack that cannot answer for itself.
    ReplyOnMesh(BytesMut),
    /// Not something this node can act on.
    Drop,
}

/// The Ethernet multicast MAC for an IPv4 multicast address: `01:00:5e`
/// followed by the low 23 bits of the group address (RFC 1112 §6.4).
fn ipv4_multicast_mac(dst: Ipv4Addr) -> VirtualMac {
    let o = dst.octets();
    VirtualMac([0x01, 0x00, 0x5e, o[1] & 0x7F, o[2], o[3]])
}

/// The Ethernet multicast MAC for an IPv6 multicast address: `33:33`
/// followed by the last four bytes of the group address (RFC 2464 §7).
fn ipv6_multicast_mac(dst: &[u8]) -> VirtualMac {
    VirtualMac([0x33, 0x33, dst[12], dst[13], dst[14], dst[15]])
}

/// Write an Ethernet II header followed by `payload`.
fn build_frame(dst: VirtualMac, src: VirtualMac, ethertype: u16, payload: &[u8]) -> BytesMut {
    let mut frame = BytesMut::with_capacity(ETHERNET_HEADER_LEN + payload.len());
    frame.put_slice(&dst.0);
    frame.put_slice(&src.0);
    frame.put_u16(ethertype);
    frame.put_slice(payload);
    frame
}

/// Grow an Ethernet header onto a bare IP packet leaving a Layer-3 adapter.
///
/// Returns `None` for packets the shim cannot address — a truncated
/// header, an IP version we don't carry, or an IPv6 unicast destination
/// (rooms are IPv4-only today; see CHECKLIST.md P6).
///
/// As a side effect this learns our own virtual IPv4 from the packet's
/// source address the first time we send anything, which is what lets
/// [`unwrap_inbound`] recognise ARP requests aimed at us.
#[must_use]
pub fn wrap_outbound(
    ip_packet: &[u8],
    own_mac: VirtualMac,
    router: &MacRouter,
) -> Option<BytesMut> {
    let version = ip_packet.first()? >> 4;

    match version {
        4 => {
            // Need at least a minimal IPv4 header to read the addresses.
            if ip_packet.len() < 20 {
                return None;
            }
            let src = Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
            let dst = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

            // Learn our own address from the first packet we emit, unless
            // a caller already told us. Ignore unspecified sources (DHCP
            // discovery and similar send from 0.0.0.0).
            if router.own_ipv4().is_none() && !src.is_unspecified() {
                router.set_own_ipv4(src);
            }

            let dst_mac = if dst.is_broadcast() {
                VirtualMac::broadcast()
            } else if dst.is_multicast() {
                ipv4_multicast_mac(dst)
            } else {
                // Unknown unicast floods, matching MacRouter::route — the
                // destination peer accepts it and discovery still works.
                router
                    .mac_for_ipv4(dst)
                    .unwrap_or_else(VirtualMac::broadcast)
            };

            trace!(%src, %dst, %dst_mac, "shim wrapped outbound IPv4");
            Some(build_frame(dst_mac, own_mac, ETHERTYPE_IPV4, ip_packet))
        }
        6 => {
            if ip_packet.len() < 40 {
                return None;
            }
            let dst = &ip_packet[24..40];
            // Only multicast is carried: link-local discovery (mDNS over
            // v6, SSDP) works, unicast v6 does not yet have addressing.
            if dst[0] == 0xFF {
                let dst_mac = ipv6_multicast_mac(dst);
                Some(build_frame(dst_mac, own_mac, ETHERTYPE_IPV6, ip_packet))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Decide what to do with an Ethernet frame that arrived from the mesh.
#[must_use]
pub fn unwrap_inbound(frame: &[u8], router: &MacRouter) -> InboundAction {
    if frame.len() < ETHERNET_HEADER_LEN {
        return InboundAction::Drop;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let payload = &frame[ETHERNET_HEADER_LEN..];

    match ethertype {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
            // The local stack wants the IP packet, not the frame.
            InboundAction::WriteToAdapter(BytesMut::from(payload))
        }
        ETHERTYPE_ARP => handle_arp(payload, router),
        // 802.1Q-tagged frames, LLDP, anything else: not ours to handle.
        _ => InboundAction::Drop,
    }
}

/// Answer an ARP request aimed at this node.
///
/// Only requests for *our* address get a reply. Answering for peers would
/// be proxy ARP, which would wrongly pull their traffic through us on a
/// mesh where every pair has a direct tunnel.
fn handle_arp(arp: &[u8], router: &MacRouter) -> InboundAction {
    if arp.len() < ARP_PACKET_LEN {
        return InboundAction::Drop;
    }

    let htype = u16::from_be_bytes([arp[0], arp[1]]);
    let ptype = u16::from_be_bytes([arp[2], arp[3]]);
    let hlen = arp[4];
    let plen = arp[5];
    let oper = u16::from_be_bytes([arp[6], arp[7]]);

    // Only IPv4-over-Ethernet requests are meaningful here.
    if htype != ARP_HTYPE_ETHERNET
        || ptype != ETHERTYPE_IPV4
        || hlen != 6
        || plen != 4
        || oper != ARP_OP_REQUEST
    {
        return InboundAction::Drop;
    }

    let sender_mac = VirtualMac([arp[8], arp[9], arp[10], arp[11], arp[12], arp[13]]);
    let sender_ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);

    // We can only answer once we know what our own address is.
    let Some(own_ip) = router.own_ipv4() else {
        trace!(%target_ip, "ARP request ignored — own IPv4 not yet known");
        return InboundAction::Drop;
    };
    if target_ip != own_ip {
        return InboundAction::Drop;
    }

    let own_mac = router.own_mac();
    trace!(%sender_ip, %target_ip, "answering ARP on behalf of the local stack");

    let mut arp_reply = BytesMut::with_capacity(ARP_PACKET_LEN);
    arp_reply.put_u16(ARP_HTYPE_ETHERNET);
    arp_reply.put_u16(ETHERTYPE_IPV4);
    arp_reply.put_u8(6);
    arp_reply.put_u8(4);
    arp_reply.put_u16(ARP_OP_REPLY);
    arp_reply.put_slice(&own_mac.0);
    arp_reply.put_slice(&own_ip.octets());
    arp_reply.put_slice(&sender_mac.0);
    arp_reply.put_slice(&sender_ip.octets());

    InboundAction::ReplyOnMesh(build_frame(sender_mac, own_mac, ETHERTYPE_ARP, &arp_reply))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{NodeId, VirtualIpv4};

    fn router_with_peer() -> (MacRouter, VirtualMac, Ipv4Addr) {
        let own = VirtualMac([0x02, 0, 0, 0, 0, 1]);
        let router = MacRouter::new(own);
        router.set_own_ipv4(Ipv4Addr::new(10, 42, 0, 1));

        let node = NodeId([5u8; 32]);
        let peer_mac = VirtualMac([0x02, 0, 0, 0, 0, 2]);
        let peer_ip = VirtualIpv4(Ipv4Addr::new(10, 42, 0, 2));
        router.register(peer_mac, peer_ip, node);
        (router, peer_mac, peer_ip.0)
    }

    /// Minimal IPv4 header with the given source and destination.
    fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    fn arp_request(sender_mac: VirtualMac, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&VirtualMac::broadcast().0);
        frame.extend_from_slice(&sender_mac.0);
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());

        frame.extend_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&ARP_OP_REQUEST.to_be_bytes());
        frame.extend_from_slice(&sender_mac.0);
        frame.extend_from_slice(&sender_ip.octets());
        frame.extend_from_slice(&[0u8; 6]); // target MAC unknown
        frame.extend_from_slice(&target_ip.octets());
        frame
    }

    #[test]
    fn outbound_unicast_uses_the_routing_table() {
        let (router, peer_mac, peer_ip) = router_with_peer();
        let own = router.own_mac();

        let packet = ipv4_packet(Ipv4Addr::new(10, 42, 0, 1), peer_ip);
        let frame = wrap_outbound(&packet, own, &router).expect("should wrap");

        assert_eq!(&frame[0..6], &peer_mac.0, "destination MAC");
        assert_eq!(&frame[6..12], &own.0, "source MAC");
        assert_eq!(&frame[12..14], &ETHERTYPE_IPV4.to_be_bytes());
        assert_eq!(&frame[14..], &packet[..], "payload preserved");
    }

    #[test]
    fn outbound_broadcast_and_multicast_map_correctly() {
        let (router, _, _) = router_with_peer();
        let own = router.own_mac();
        let src = Ipv4Addr::new(10, 42, 0, 1);

        let bcast = wrap_outbound(&ipv4_packet(src, Ipv4Addr::BROADCAST), own, &router).unwrap();
        assert_eq!(&bcast[0..6], &VirtualMac::broadcast().0);

        // mDNS: 224.0.0.251 → 01:00:5e:00:00:fb
        let mdns = Ipv4Addr::new(224, 0, 0, 251);
        let frame = wrap_outbound(&ipv4_packet(src, mdns), own, &router).unwrap();
        assert_eq!(&frame[0..6], &[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
    }

    #[test]
    fn outbound_unknown_unicast_floods() {
        let (router, _, _) = router_with_peer();
        let own = router.own_mac();
        let packet = ipv4_packet(Ipv4Addr::new(10, 42, 0, 1), Ipv4Addr::new(10, 42, 9, 9));
        let frame = wrap_outbound(&packet, own, &router).unwrap();
        assert_eq!(&frame[0..6], &VirtualMac::broadcast().0);
    }

    #[test]
    fn outbound_learns_our_own_address() {
        let router = MacRouter::new(VirtualMac([0x02, 0, 0, 0, 0, 1]));
        assert_eq!(router.own_ipv4(), None);

        let src = Ipv4Addr::new(10, 42, 3, 4);
        let packet = ipv4_packet(src, Ipv4Addr::new(10, 42, 0, 9));
        let _ = wrap_outbound(&packet, router.own_mac(), &router);

        assert_eq!(
            router.own_ipv4(),
            Some(src),
            "learned from the source address"
        );
    }

    #[test]
    fn outbound_ignores_unspecified_source_when_learning() {
        let router = MacRouter::new(VirtualMac([0x02, 0, 0, 0, 0, 1]));
        let packet = ipv4_packet(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST);
        let _ = wrap_outbound(&packet, router.own_mac(), &router);
        assert_eq!(router.own_ipv4(), None, "0.0.0.0 must not be learned");
    }

    #[test]
    fn outbound_rejects_malformed_and_unroutable() {
        let (router, _, _) = router_with_peer();
        let own = router.own_mac();

        assert!(wrap_outbound(&[], own, &router).is_none());
        assert!(
            wrap_outbound(&[0x45, 0, 0], own, &router).is_none(),
            "truncated v4"
        );
        // IPv6 unicast has no addressing yet.
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[24] = 0x20; // 2000::/3 unicast
        assert!(wrap_outbound(&v6, own, &router).is_none());
        // A version we don't carry at all.
        assert!(wrap_outbound(&[0x70; 40], own, &router).is_none());
    }

    #[test]
    fn outbound_carries_ipv6_multicast() {
        let (router, _, _) = router_with_peer();
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[24] = 0xFF; // multicast
        v6[36..40].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let frame = wrap_outbound(&v6, router.own_mac(), &router).expect("multicast is carried");
        assert_eq!(&frame[0..6], &[0x33, 0x33, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&frame[12..14], &ETHERTYPE_IPV6.to_be_bytes());
    }

    #[test]
    fn inbound_ip_frames_are_stripped() {
        let (router, peer_mac, _) = router_with_peer();
        let packet = ipv4_packet(Ipv4Addr::new(10, 42, 0, 2), Ipv4Addr::new(10, 42, 0, 1));
        let frame = build_frame(router.own_mac(), peer_mac, ETHERTYPE_IPV4, &packet);

        match unwrap_inbound(&frame, &router) {
            InboundAction::WriteToAdapter(ip) => assert_eq!(&ip[..], &packet[..]),
            other => panic!("expected WriteToAdapter, got {other:?}"),
        }
    }

    #[test]
    fn inbound_arp_for_us_is_answered() {
        let (router, peer_mac, peer_ip) = router_with_peer();
        let own_ip = router.own_ipv4().unwrap();
        let request = arp_request(peer_mac, peer_ip, own_ip);

        let InboundAction::ReplyOnMesh(reply) = unwrap_inbound(&request, &router) else {
            panic!("an ARP request for our address must be answered");
        };

        // Ethernet header: unicast back to the asker, from us.
        assert_eq!(&reply[0..6], &peer_mac.0);
        assert_eq!(&reply[6..12], &router.own_mac().0);
        assert_eq!(&reply[12..14], &ETHERTYPE_ARP.to_be_bytes());

        // ARP body: a reply claiming our MAC for our IP.
        let arp = &reply[ETHERNET_HEADER_LEN..];
        assert_eq!(u16::from_be_bytes([arp[6], arp[7]]), ARP_OP_REPLY);
        assert_eq!(&arp[8..14], &router.own_mac().0, "sender MAC is ours");
        assert_eq!(&arp[14..18], &own_ip.octets(), "sender IP is ours");
        assert_eq!(&arp[18..24], &peer_mac.0, "target MAC is the asker");
        assert_eq!(&arp[24..28], &peer_ip.octets(), "target IP is the asker");
    }

    #[test]
    fn inbound_arp_for_a_peer_is_not_proxied() {
        let (router, peer_mac, peer_ip) = router_with_peer();
        // Asking about a third party — answering would be proxy ARP.
        let request = arp_request(peer_mac, peer_ip, Ipv4Addr::new(10, 42, 0, 7));
        assert!(matches!(
            unwrap_inbound(&request, &router),
            InboundAction::Drop
        ));
    }

    #[test]
    fn inbound_arp_ignored_until_our_address_is_known() {
        let router = MacRouter::new(VirtualMac([0x02, 0, 0, 0, 0, 1]));
        let asker = VirtualMac([0x02, 0, 0, 0, 0, 2]);
        let request = arp_request(
            asker,
            Ipv4Addr::new(10, 42, 0, 2),
            Ipv4Addr::new(10, 42, 0, 1),
        );
        assert!(matches!(
            unwrap_inbound(&request, &router),
            InboundAction::Drop
        ));
    }

    #[test]
    fn inbound_garbage_is_dropped() {
        let (router, _, _) = router_with_peer();
        assert!(matches!(unwrap_inbound(&[], &router), InboundAction::Drop));
        assert!(matches!(
            unwrap_inbound(&[0u8; 10], &router),
            InboundAction::Drop
        ));
        // Truncated ARP body.
        let mut short_arp = vec![0u8; ETHERNET_HEADER_LEN + 10];
        short_arp[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        assert!(matches!(
            unwrap_inbound(&short_arp, &router),
            InboundAction::Drop
        ));
        // Unknown EtherType.
        let mut lldp = vec![0u8; 60];
        lldp[12..14].copy_from_slice(&0x88CCu16.to_be_bytes());
        assert!(matches!(
            unwrap_inbound(&lldp, &router),
            InboundAction::Drop
        ));
    }
}
