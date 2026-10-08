//! ARP (RFC 826) for IPv4 over Ethernet: parse requests, build replies.

use std::net::Ipv4Addr;

use super::{ethertype, ETHERTYPE_ARP};
use crate::crypto::VirtualMac;
use crate::tap::ETHERNET_HEADER;

/// Length of an IPv4-over-Ethernet ARP payload.
const ARP_LEN: usize = 28;
const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;

/// The interesting fields of an ARP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpRequest {
    /// Who is asking (sender hardware address).
    pub sender_mac: VirtualMac,
    /// The asker's IPv4.
    pub sender_ip: Ipv4Addr,
    /// The IPv4 being looked up.
    pub target_ip: Ipv4Addr,
}

/// Parse an Ethernet frame as an IPv4 ARP request.
#[must_use]
pub fn parse_request(frame: &[u8]) -> Option<ArpRequest> {
    if ethertype(frame)? != ETHERTYPE_ARP {
        return None;
    }
    let p = frame.get(ETHERNET_HEADER..ETHERNET_HEADER + ARP_LEN)?;
    // htype 1 (Ethernet), ptype IPv4, hlen 6, plen 4, op request.
    if p[0..2] != [0, 1] || p[2..4] != [0x08, 0x00] || p[4] != 6 || p[5] != 4 {
        return None;
    }
    if u16::from_be_bytes([p[6], p[7]]) != OP_REQUEST {
        return None;
    }
    Some(ArpRequest {
        sender_mac: VirtualMac(p[8..14].try_into().ok()?),
        sender_ip: Ipv4Addr::new(p[14], p[15], p[16], p[17]),
        target_ip: Ipv4Addr::new(p[24], p[25], p[26], p[27]),
    })
}

/// Build the complete Ethernet frame answering `req`: "`our_ip` is at
/// `our_mac`", unicast back to the requester.
#[must_use]
pub fn build_reply(req: &ArpRequest, our_mac: VirtualMac, our_ip: Ipv4Addr) -> Vec<u8> {
    let mut f = Vec::with_capacity(ETHERNET_HEADER + ARP_LEN);
    f.extend_from_slice(&req.sender_mac.0);
    f.extend_from_slice(&our_mac.0);
    f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    f.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);
    f.extend_from_slice(&OP_REPLY.to_be_bytes());
    f.extend_from_slice(&our_mac.0);
    f.extend_from_slice(&our_ip.octets());
    f.extend_from_slice(&req.sender_mac.0);
    f.extend_from_slice(&req.sender_ip.octets());
    f
}

/// Build an ARP request frame (used by tests to play the Linux side).
#[must_use]
pub fn build_request(sender_mac: VirtualMac, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut f = Vec::with_capacity(ETHERNET_HEADER + ARP_LEN);
    f.extend_from_slice(&VirtualMac::BROADCAST.0);
    f.extend_from_slice(&sender_mac.0);
    f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    f.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);
    f.extend_from_slice(&OP_REQUEST.to_be_bytes());
    f.extend_from_slice(&sender_mac.0);
    f.extend_from_slice(&sender_ip.octets());
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&target_ip.octets());
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_reply_roundtrip() {
        let asker = VirtualMac([0x02, 1, 2, 3, 4, 5]);
        let me = VirtualMac([0x02, 9, 9, 9, 9, 9]);
        let req_frame = build_request(
            asker,
            Ipv4Addr::new(10, 42, 0, 7),
            Ipv4Addr::new(10, 42, 0, 9),
        );
        let req = parse_request(&req_frame).unwrap();
        assert_eq!(req.sender_mac, asker);
        assert_eq!(req.target_ip, Ipv4Addr::new(10, 42, 0, 9));

        let reply = build_reply(&req, me, Ipv4Addr::new(10, 42, 0, 9));
        assert_eq!(&reply[..6], &asker.0);
        assert_eq!(&reply[6..12], &me.0);
        // A reply is not a request.
        assert!(parse_request(&reply).is_none());
    }
}
