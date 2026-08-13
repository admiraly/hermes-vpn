//! Wire format spoken between Hermes nodes and a relay ("central") server.
//!
//! The relay protocol is deliberately tiny: four datagram types over the
//! same UDP socket the node already uses for WireGuard. Every packet
//! starts with a magic byte that can never collide with a WireGuard
//! message (WireGuard's first byte is always `0x01`–`0x04`), so the
//! inbound demultiplexer can tell relay frames from direct peer traffic
//! without per-packet state.
//!
//! ```text
//! REGISTER      client → relay   announce "I am <node> in <room>"
//! REGISTER_ACK  relay  → client  registration accepted
//! DATA          client → relay   "forward this ciphertext to <node>"
//! FORWARD       relay  → client  "ciphertext from <node>"
//! ```
//!
//! Registration is authenticated: the client signs
//! `context || room_id || node_id || timestamp` with its Ed25519 identity
//! key. The relay verifies the signature against the claimed node id (a
//! node id *is* an Ed25519 public key) and requires timestamps to be
//! strictly increasing per `(room, node)`, which makes captured REGISTER
//! packets useless for session hijacking.
//!
//! The relay never sees plaintext: DATA/FORWARD payloads are WireGuard
//! datagrams, end-to-end encrypted between the two peers.

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

use crate::crypto::{NodeId, NodeSecret};
use crate::room::RoomId;

/// First byte of every relay-protocol packet.
pub const RELAY_MAGIC: u8 = 0xC8;

/// Domain separator for registration signatures.
pub const REGISTER_CONTEXT: &[u8] = b"hermes-relay-register-v2";

const TYPE_REGISTER: u8 = 0x01;
const TYPE_REGISTER_ACK: u8 = 0x02;
const TYPE_DATA: u8 = 0x03;
const TYPE_FORWARD: u8 = 0x04;

/// Byte length of a REGISTER packet.
pub const REGISTER_LEN: usize = 2 + 16 + 32 + 8 + 64;
/// Byte length of the header preceding a DATA payload.
pub const DATA_HEADER_LEN: usize = 2 + 32;
/// Byte length of the header preceding a FORWARD payload.
pub const FORWARD_HEADER_LEN: usize = 2 + 32;

/// A parsed relay-protocol packet (borrowing payload bytes).
#[derive(Debug, PartialEq, Eq)]
pub enum RelayPacket<'a> {
    /// A node announces itself to the relay.
    Register {
        /// Room the node claims membership of.
        room_id: RoomId,
        /// The announcing node.
        node_id: NodeId,
        /// Unix milliseconds — must increase per (room, node).
        timestamp_ms: u64,
        /// Ed25519 signature over the registration fields.
        signature: [u8; 64],
    },
    /// Relay confirms a registration.
    RegisterAck {
        /// Echoed room id.
        room_id: RoomId,
    },
    /// Client asks the relay to forward `payload` to `dest`.
    Data {
        /// Destination node.
        dest: NodeId,
        /// WireGuard ciphertext.
        payload: &'a [u8],
    },
    /// Relay delivers `payload` sent by `src`.
    Forward {
        /// Originating node.
        src: NodeId,
        /// WireGuard ciphertext.
        payload: &'a [u8],
    },
}

/// Does this datagram look like a relay-protocol packet?
#[must_use]
pub fn is_relay_packet(buf: &[u8]) -> bool {
    buf.first() == Some(&RELAY_MAGIC)
}

/// The exact bytes a registration signature covers.
fn register_message(room_id: &RoomId, node_id: &NodeId, timestamp_ms: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(REGISTER_CONTEXT.len() + 16 + 32 + 8);
    msg.extend_from_slice(REGISTER_CONTEXT);
    msg.extend_from_slice(room_id.as_bytes());
    msg.extend_from_slice(&node_id.0);
    msg.extend_from_slice(&timestamp_ms.to_be_bytes());
    msg
}

/// Build a signed REGISTER packet.
#[must_use]
pub fn encode_register(room_id: &RoomId, secret: &NodeSecret, timestamp_ms: u64) -> Vec<u8> {
    let node_id = secret.public().node_id;
    let sig = secret
        .signing_key()
        .sign(&register_message(room_id, &node_id, timestamp_ms));

    let mut buf = Vec::with_capacity(REGISTER_LEN);
    buf.push(RELAY_MAGIC);
    buf.push(TYPE_REGISTER);
    buf.extend_from_slice(room_id.as_bytes());
    buf.extend_from_slice(&node_id.0);
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.extend_from_slice(&sig.to_bytes());
    buf
}

/// Build a REGISTER_ACK packet.
#[must_use]
pub fn encode_register_ack(room_id: &RoomId) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + 16);
    buf.push(RELAY_MAGIC);
    buf.push(TYPE_REGISTER_ACK);
    buf.extend_from_slice(room_id.as_bytes());
    buf
}

/// Build a DATA packet asking the relay to forward `payload` to `dest`.
#[must_use]
pub fn encode_data(dest: &NodeId, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DATA_HEADER_LEN + payload.len());
    buf.push(RELAY_MAGIC);
    buf.push(TYPE_DATA);
    buf.extend_from_slice(&dest.0);
    buf.extend_from_slice(payload);
    buf
}

/// Build a FORWARD packet delivering `payload` from `src`.
#[must_use]
pub fn encode_forward(src: &NodeId, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FORWARD_HEADER_LEN + payload.len());
    buf.push(RELAY_MAGIC);
    buf.push(TYPE_FORWARD);
    buf.extend_from_slice(&src.0);
    buf.extend_from_slice(payload);
    buf
}

/// Parse a relay-protocol packet. Returns `None` for anything malformed
/// or non-relay.
#[must_use]
pub fn parse_packet(buf: &[u8]) -> Option<RelayPacket<'_>> {
    if buf.len() < 2 || buf[0] != RELAY_MAGIC {
        return None;
    }
    match buf[1] {
        TYPE_REGISTER if buf.len() == REGISTER_LEN => {
            let room_id = RoomId::from_bytes(buf[2..18].try_into().ok()?);
            let node_id = NodeId(buf[18..50].try_into().ok()?);
            let timestamp_ms = u64::from_be_bytes(buf[50..58].try_into().ok()?);
            let signature: [u8; 64] = buf[58..122].try_into().ok()?;
            Some(RelayPacket::Register {
                room_id,
                node_id,
                timestamp_ms,
                signature,
            })
        }
        TYPE_REGISTER_ACK if buf.len() == 18 => {
            let room_id = RoomId::from_bytes(buf[2..18].try_into().ok()?);
            Some(RelayPacket::RegisterAck { room_id })
        }
        TYPE_DATA if buf.len() >= DATA_HEADER_LEN => Some(RelayPacket::Data {
            dest: NodeId(buf[2..34].try_into().ok()?),
            payload: &buf[DATA_HEADER_LEN..],
        }),
        TYPE_FORWARD if buf.len() >= FORWARD_HEADER_LEN => Some(RelayPacket::Forward {
            src: NodeId(buf[2..34].try_into().ok()?),
            payload: &buf[FORWARD_HEADER_LEN..],
        }),
        _ => None,
    }
}

/// Verify a REGISTER packet's signature. Used by the relay server.
#[must_use]
pub fn verify_register(
    room_id: &RoomId,
    node_id: &NodeId,
    timestamp_ms: u64,
    signature: &[u8; 64],
) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&node_id.0) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    key.verify(&register_message(room_id, node_id, timestamp_ms), &sig)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_roundtrip_and_verify() {
        let secret = NodeSecret::generate();
        let room = RoomId::new_v4();
        let buf = encode_register(&room, &secret, 1_700_000_000_000);
        assert_eq!(buf.len(), REGISTER_LEN);
        assert!(is_relay_packet(&buf));

        match parse_packet(&buf) {
            Some(RelayPacket::Register {
                room_id,
                node_id,
                timestamp_ms,
                signature,
            }) => {
                assert_eq!(room_id, room);
                assert_eq!(node_id, secret.public().node_id);
                assert_eq!(timestamp_ms, 1_700_000_000_000);
                assert!(verify_register(
                    &room_id,
                    &node_id,
                    timestamp_ms,
                    &signature
                ));
                // Tampered timestamp must fail verification.
                assert!(!verify_register(
                    &room_id,
                    &node_id,
                    timestamp_ms + 1,
                    &signature
                ));
            }
            other => panic!("unexpected parse: {other:?}"),
        }
    }

    #[test]
    fn data_forward_roundtrip() {
        let dest = NodeId([7u8; 32]);
        let payload = b"ciphertext bytes";
        let data = encode_data(&dest, payload);
        match parse_packet(&data) {
            Some(RelayPacket::Data {
                dest: d,
                payload: p,
            }) => {
                assert_eq!(d, dest);
                assert_eq!(p, payload);
            }
            other => panic!("unexpected parse: {other:?}"),
        }

        let fwd = encode_forward(&dest, payload);
        match parse_packet(&fwd) {
            Some(RelayPacket::Forward { src, payload: p }) => {
                assert_eq!(src, dest);
                assert_eq!(p, payload);
            }
            other => panic!("unexpected parse: {other:?}"),
        }
    }

    #[test]
    fn wireguard_bytes_are_not_relay_packets() {
        // WireGuard message types 1..=4 in byte 0.
        for first in 1u8..=4 {
            let pkt = [first, 0, 0, 0, 1, 2, 3];
            assert!(!is_relay_packet(&pkt));
            assert!(parse_packet(&pkt).is_none());
        }
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse_packet(&[]).is_none());
        assert!(parse_packet(&[RELAY_MAGIC]).is_none());
        assert!(parse_packet(&[RELAY_MAGIC, 0x09, 1, 2]).is_none());
        // Truncated register.
        let secret = NodeSecret::generate();
        let buf = encode_register(&RoomId::new_v4(), &secret, 5);
        assert!(parse_packet(&buf[..buf.len() - 1]).is_none());
    }
}
