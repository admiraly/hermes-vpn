//! Ethernet-over-WireGuard framing.
//!
//! WireGuard is an IP tunnel: `boringtun` expects the plaintext it
//! encrypts to be an IP packet, and on the way back it parses the IP
//! header to decide what to hand the caller. Hermes needs to carry raw
//! *Ethernet* frames instead — that is the whole point of the virtual
//! LAN, since ARP, mDNS, SSDP, and game discovery all live at Layer 2.
//!
//! The bridge is a synthetic 20-byte IPv4 header prepended to every
//! Ethernet frame before encapsulation and stripped after decapsulation:
//!
//! ```text
//! [ synthetic IPv4 header (20 B) ][ Ethernet frame (14 B header + payload) ]
//! ```
//!
//! The header is never routed and never leaves the tunnel — it exists
//! only to satisfy `boringtun`'s packet validation. Two fields make it
//! recognisable as ours: the IP protocol number is 253 (reserved for
//! experimentation by RFC 3692) and the identification field carries
//! [`HERMES_MAGIC`]. A decrypted packet that fails either check is not a
//! Hermes frame and is dropped rather than injected into the adapter.
//!
//! The `total_length` field matters for a subtler reason: ChaCha20-Poly1305
//! pads plaintext to a 16-byte boundary, so the buffer `boringtun` returns
//! is often *longer* than the frame we sent. `total_length` is what lets
//! [`decode_frame`] find the true end of the payload and discard the
//! padding.

use std::net::Ipv4Addr;

/// IPv4 header length we emit — always 20 bytes (IHL = 5, no options).
pub const IPV4_HEADER_LEN: usize = 20;

/// IP protocol number stamped into every Hermes frame. 253 is reserved
/// for experimentation and testing (RFC 3692), so it can never be
/// confused with real traffic.
pub const HERMES_IP_PROTOCOL: u8 = 253;

/// Value of the IPv4 identification field in a Hermes frame — `"HM"`.
pub const HERMES_MAGIC: u16 = 0x484D;

/// Placeholder addresses. The synthetic header is stripped before the
/// frame reaches the adapter, so these are never routed; they exist to
/// make the header well-formed.
const PLACEHOLDER_ADDR: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// A parsed Hermes framing header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Length of the Ethernet frame that follows the header, in bytes.
    pub payload_len: usize,
}

/// Standard RFC 1071 one's-complement checksum over the header.
fn header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = match chunk {
            [hi, lo] => u16::from_be_bytes([*hi, *lo]),
            [hi] => u16::from_be_bytes([*hi, 0]),
            _ => unreachable!("chunks(2) yields 1 or 2 elements"),
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Wrap an Ethernet frame in the synthetic IPv4 header.
///
/// The result is what gets handed to `Tunn::encapsulate`.
#[must_use]
pub fn encode_frame(eth_frame: &[u8]) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN + eth_frame.len();
    let mut buf = Vec::with_capacity(total_len);

    buf.push(0x45); // version 4, IHL 5
    buf.push(0x00); // DSCP / ECN
                    // `total_length` saturates rather than wrapping: the driver already
                    // refuses frames larger than FRAME_BUFFER_SIZE, so this can only be
                    // reached by a caller bypassing that check, and a saturated length is
                    // safer than a truncated one (decode_frame will reject it).
    buf.extend_from_slice(&u16::try_from(total_len).unwrap_or(u16::MAX).to_be_bytes());
    buf.extend_from_slice(&HERMES_MAGIC.to_be_bytes()); // identification
    buf.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    buf.push(64); // TTL
    buf.push(HERMES_IP_PROTOCOL);
    buf.extend_from_slice(&[0, 0]); // checksum placeholder
    buf.extend_from_slice(&PLACEHOLDER_ADDR.octets()); // source
    buf.extend_from_slice(&PLACEHOLDER_ADDR.octets()); // destination

    let checksum = header_checksum(&buf);
    buf[10..12].copy_from_slice(&checksum.to_be_bytes());

    buf.extend_from_slice(eth_frame);
    buf
}

/// Strip the synthetic header, returning it alongside the Ethernet frame.
///
/// Returns `None` if `packet` is not a Hermes frame — a foreign IP packet,
/// a truncated buffer, or a header whose `total_length` doesn't fit inside
/// what was actually decrypted.
#[must_use]
pub fn decode_frame(packet: &[u8]) -> Option<(FrameHeader, &[u8])> {
    if packet.len() < IPV4_HEADER_LEN {
        return None;
    }
    // Version 4, IHL exactly 5 (we never emit options).
    if packet[0] != 0x45 {
        return None;
    }
    if packet[9] != HERMES_IP_PROTOCOL {
        return None;
    }
    if u16::from_be_bytes([packet[4], packet[5]]) != HERMES_MAGIC {
        return None;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < IPV4_HEADER_LEN || total_len > packet.len() {
        return None;
    }

    let payload = &packet[IPV4_HEADER_LEN..total_len];
    Some((
        FrameHeader {
            payload_len: payload.len(),
        },
        payload,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let eth = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x01\x08\x06payload";
        let wrapped = encode_frame(eth);
        assert_eq!(wrapped.len(), IPV4_HEADER_LEN + eth.len());

        let (hdr, out) = decode_frame(&wrapped).expect("should decode");
        assert_eq!(out, eth);
        assert_eq!(hdr.payload_len, eth.len());
    }

    #[test]
    fn crypto_padding_is_stripped() {
        // ChaCha20-Poly1305 pads to a 16-byte boundary, so decapsulate can
        // hand back more bytes than we encoded. total_length must win.
        let eth = b"a short frame";
        let mut wrapped = encode_frame(eth);
        wrapped.extend_from_slice(&[0u8; 16]);

        let (hdr, out) = decode_frame(&wrapped).expect("should decode");
        assert_eq!(out, eth, "padding must not be delivered to the adapter");
        assert_eq!(hdr.payload_len, eth.len());
    }

    #[test]
    fn empty_frame_roundtrips() {
        let wrapped = encode_frame(&[]);
        let (hdr, out) = decode_frame(&wrapped).expect("should decode");
        assert_eq!(hdr.payload_len, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn foreign_packets_are_rejected() {
        // A real IPv4/UDP packet that happens to be decrypted from the
        // tunnel must not be mistaken for a Hermes frame.
        let mut udp = encode_frame(b"whatever");
        udp[9] = 17; // protocol = UDP
        assert!(decode_frame(&udp).is_none());

        // Right protocol, wrong magic.
        let mut bad_magic = encode_frame(b"whatever");
        bad_magic[4] = 0x00;
        assert!(decode_frame(&bad_magic).is_none());

        // IPv6.
        let mut v6 = encode_frame(b"whatever");
        v6[0] = 0x60;
        assert!(decode_frame(&v6).is_none());

        assert!(decode_frame(&[]).is_none());
        assert!(decode_frame(&[0x45; 10]).is_none());
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let wrapped = encode_frame(b"a reasonably long frame body");
        // total_length claims more than we actually have.
        assert!(decode_frame(&wrapped[..wrapped.len() - 1]).is_none());
    }

    #[test]
    fn checksum_is_valid() {
        let wrapped = encode_frame(b"body");
        // Checksumming a header that already contains its checksum yields 0.
        assert_eq!(header_checksum(&wrapped[..IPV4_HEADER_LEN]), 0);
    }
}
