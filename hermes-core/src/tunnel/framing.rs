//! Ethernet-in-WireGuard framing.
//!
//! WireGuard (and `boringtun`) only transports IP packets: after
//! decryption boringtun inspects the IP version nibble and the total-length
//! field, and refuses anything that doesn't look like IPv4/IPv6. Hermes
//! carries Ethernet frames, so each frame is prefixed with a fixed 20-byte
//! synthetic IPv4 header before encryption:
//!
//! ```text
//!  0      1      2      3
//! +------+------+------+------+
//! | 0x45 | 0x00 | total len   |   version 4, IHL 5; len = 20 + frame
//! | 'H'  | 'R'  | 0x00 | 0x00 |   identification = "HR" marker
//! | 0x40 | 0xFD | 0x00 | 0x00 |   TTL 64, protocol 253 (RFC 3692 experimental)
//! | 0.0.0.0 (src)             |
//! | 0.0.0.0 (dst)             |
//! +---------------------------+
//! | Ethernet frame ...        |
//! ```
//!
//! The same header with identification `"HC"` marks a **control** message
//! instead of an Ethernet frame — tunnel-internal signalling such as the
//! latency ping/pong, never handed to the adapter.
//!
//! The header never leaves the tunnel — it exists only inside the
//! encrypted payload — so it needs no checksum and no real addresses.
//! [`decode_frame`] checks the marker, protocol, and length, which rejects
//! a genuine IP packet a non-Hermes WireGuard peer might send.

use crate::tap::FRAMING_HEADER;

/// IP protocol number used in the synthetic header (RFC 3692 experimental).
const PROTOCOL_HERMES: u8 = 253;
/// Identification-field marker for Ethernet frames: ASCII "HR".
const MARKER: [u8; 2] = *b"HR";
/// Identification-field marker for control messages: ASCII "HC".
const CONTROL_MARKER: [u8; 2] = *b"HC";

/// What a decrypted tunnel packet carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payload<'a> {
    /// An Ethernet frame for the adapter.
    Frame(&'a [u8]),
    /// A tunnel control message.
    Control(&'a [u8]),
}

/// The decoded synthetic header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Length of the Ethernet frame that follows the header.
    pub frame_len: u16,
}

/// Wrap an Ethernet frame in the synthetic IPv4 header.
///
/// # Panics
/// Panics if the frame is larger than an IPv4 packet can describe
/// (65 515 bytes) — callers never get close (frames are capped at
/// [`crate::tap::FRAME_BUFFER_SIZE`]).
#[must_use]
pub fn encode_frame(eth_frame: &[u8]) -> Vec<u8> {
    encode(MARKER, eth_frame)
}

/// Wrap a control message in the synthetic header.
#[must_use]
pub fn encode_control(msg: &[u8]) -> Vec<u8> {
    encode(CONTROL_MARKER, msg)
}

fn encode(marker: [u8; 2], eth_frame: &[u8]) -> Vec<u8> {
    let total = u16::try_from(FRAMING_HEADER + eth_frame.len()).expect("frame fits in IPv4");
    let mut buf = Vec::with_capacity(usize::from(total));
    let len = total.to_be_bytes();
    buf.extend_from_slice(&[0x45, 0x00, len[0], len[1]]);
    buf.extend_from_slice(&[marker[0], marker[1], 0x00, 0x00]);
    buf.extend_from_slice(&[0x40, PROTOCOL_HERMES, 0x00, 0x00]);
    buf.extend_from_slice(&[0, 0, 0, 0]);
    buf.extend_from_slice(&[0, 0, 0, 0]);
    buf.extend_from_slice(eth_frame);
    buf
}

/// Strip the synthetic header from a decrypted packet, returning the
/// header and the Ethernet frame. `None` if the packet isn't a Hermes frame.
#[must_use]
pub fn decode_frame(packet: &[u8]) -> Option<(FrameHeader, &[u8])> {
    match decode_packet(packet)? {
        (hdr, Payload::Frame(frame)) => Some((hdr, frame)),
        (_, Payload::Control(_)) => None,
    }
}

/// Strip the synthetic header, telling Ethernet frames and control
/// messages apart. `None` if the packet isn't a Hermes packet at all.
#[must_use]
pub fn decode_packet(packet: &[u8]) -> Option<(FrameHeader, Payload<'_>)> {
    if packet.len() < FRAMING_HEADER || packet[0] != 0x45 || packet[9] != PROTOCOL_HERMES {
        return None;
    }
    let control = match [packet[4], packet[5]] {
        MARKER => false,
        CONTROL_MARKER => true,
        _ => return None,
    };
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total < FRAMING_HEADER || total > packet.len() {
        return None;
    }
    let body = &packet[FRAMING_HEADER..total];
    let frame_len = u16::try_from(body.len()).ok()?;
    let payload = if control {
        Payload::Control(body)
    } else {
        Payload::Frame(body)
    };
    Some((FrameHeader { frame_len }, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let frame: Vec<u8> = (0..200u8).collect();
        let wrapped = encode_frame(&frame);
        assert_eq!(wrapped.len(), FRAMING_HEADER + frame.len());
        let (hdr, out) = decode_frame(&wrapped).unwrap();
        assert_eq!(usize::from(hdr.frame_len), frame.len());
        assert_eq!(out, &frame[..]);
    }

    #[test]
    fn control_messages_are_distinguished() {
        let ctl = encode_control(&[1, 2, 3]);
        assert_eq!(decode_packet(&ctl).unwrap().1, Payload::Control(&[1, 2, 3]));
        assert!(
            decode_frame(&ctl).is_none(),
            "control must never reach the adapter"
        );
        let frame = encode_frame(&[9, 9]);
        assert_eq!(decode_packet(&frame).unwrap().1, Payload::Frame(&[9, 9]));
    }

    #[test]
    fn trailing_bytes_are_ignored() {
        let mut wrapped = encode_frame(b"abc");
        wrapped.extend_from_slice(b"junk");
        assert_eq!(decode_frame(&wrapped).unwrap().1, b"abc");
    }

    #[test]
    fn rejects_real_ip_and_garbage() {
        // A plain IPv4/UDP header (protocol 17, no marker).
        let mut ip = vec![0x45, 0, 0, 28, 0x12, 0x34, 0, 0, 64, 17, 0, 0];
        ip.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(decode_frame(&ip).is_none());
        assert!(decode_frame(&[]).is_none());
        // Length field claims more than we have.
        let mut bad = encode_frame(b"hello");
        bad.truncate(bad.len() - 2);
        assert!(decode_frame(&bad).is_none());
    }
}
