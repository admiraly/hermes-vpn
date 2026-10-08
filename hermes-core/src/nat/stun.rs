//! Minimal STUN (RFC 5389) Binding client — just enough to learn our
//! server-reflexive address.
//!
//! The request goes out on the node's shared UDP socket (the reflexive
//! mapping is only useful if it belongs to the socket that carries
//! WireGuard), so responses arrive in the mesh's inbound demultiplexer
//! rather than here. This module is therefore pure codec: build a Binding
//! request, recognise a STUN datagram, and pull the
//! `XOR-MAPPED-ADDRESS` (or legacy `MAPPED-ADDRESS`) out of a response.
//! The round trip itself is [`crate::mesh::Mesh::stun_binding`].
//!
//! STUN datagrams never collide with the other traffic on the socket:
//! WireGuard messages are `0x01..=0x04` followed by three zero bytes (a
//! STUN Binding response starts `0x01 0x01`), relay packets start with
//! `0xC8`, and probes start with ASCII `H`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Default public STUN server (`host:port`, resolved at query time).
pub const DEFAULT_STUN_SERVER: &str = "stun.l.google.com:19302";

/// RFC 5389 magic cookie.
const MAGIC_COOKIE: u32 = 0x2112_A442;
const HEADER_LEN: usize = 20;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// A 96-bit STUN transaction id.
pub type TransactionId = [u8; 12];

/// Build a Binding request with the given transaction id.
#[must_use]
pub fn encode_binding_request(txid: &TransactionId) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN);
    buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // no attributes
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(txid);
    buf
}

/// Does this datagram look like a STUN message?
#[must_use]
pub fn is_stun_packet(buf: &[u8]) -> bool {
    if buf.len() < HEADER_LEN || buf[0] & 0xC0 != 0 {
        return false;
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    cookie == MAGIC_COOKIE && len % 4 == 0 && HEADER_LEN + len == buf.len()
}

/// Parse a Binding success response into its transaction id and the
/// reflexive address it reports. `None` for anything else.
#[must_use]
pub fn parse_binding_response(buf: &[u8]) -> Option<(TransactionId, SocketAddr)> {
    if !is_stun_packet(buf) || u16::from_be_bytes([buf[0], buf[1]]) != BINDING_SUCCESS {
        return None;
    }
    let txid: TransactionId = buf[8..20].try_into().ok()?;

    let mut mapped = None;
    let mut pos = HEADER_LEN;
    while pos + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = usize::from(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));
        let value = buf.get(pos + 4..pos + 4 + attr_len)?;
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                // Preferred — return immediately.
                return decode_address(value, Some(&txid)).map(|a| (txid, a));
            }
            ATTR_MAPPED_ADDRESS => mapped = decode_address(value, None),
            _ => {}
        }
        // Attributes are padded to a 4-byte boundary.
        pos += 4 + attr_len.div_ceil(4) * 4;
    }
    mapped.map(|a| (txid, a))
}

/// Decode a (XOR-)MAPPED-ADDRESS value. `xor_txid` selects XOR decoding.
fn decode_address(value: &[u8], xor_txid: Option<&TransactionId>) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    let cookie = MAGIC_COOKIE.to_be_bytes();
    if xor_txid.is_some() {
        port ^= u16::from_be_bytes([cookie[0], cookie[1]]);
    }
    let ip = match family {
        0x01 => {
            let mut octets: [u8; 4] = value.get(4..8)?.try_into().ok()?;
            if xor_txid.is_some() {
                for (o, c) in octets.iter_mut().zip(cookie) {
                    *o ^= c;
                }
            }
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        0x02 => {
            let mut octets: [u8; 16] = value.get(4..20)?.try_into().ok()?;
            if let Some(txid) = xor_txid {
                let key: Vec<u8> = cookie.iter().chain(txid.iter()).copied().collect();
                for (o, k) in octets.iter_mut().zip(key) {
                    *o ^= k;
                }
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
pub(crate) fn encode_binding_response(txid: &TransactionId, addr: SocketAddr) -> Vec<u8> {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let mut value = vec![0u8];
    let port = addr.port() ^ u16::from_be_bytes([cookie[0], cookie[1]]);
    match addr.ip() {
        IpAddr::V4(v4) => {
            value.push(0x01);
            value.extend_from_slice(&port.to_be_bytes());
            value.extend(v4.octets().iter().zip(cookie).map(|(o, c)| o ^ c));
        }
        IpAddr::V6(v6) => {
            value.push(0x02);
            value.extend_from_slice(&port.to_be_bytes());
            let key: Vec<u8> = cookie.iter().chain(txid.iter()).copied().collect();
            value.extend(v6.octets().iter().zip(key).map(|(o, k)| o ^ k));
        }
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    buf.extend_from_slice(&u16::try_from(4 + value.len()).unwrap().to_be_bytes());
    buf.extend_from_slice(&cookie);
    buf.extend_from_slice(txid);
    buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    buf.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    buf.extend_from_slice(&value);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shape() {
        let txid = [7u8; 12];
        let req = encode_binding_request(&txid);
        assert_eq!(req.len(), 20);
        assert!(is_stun_packet(&req));
        assert!(
            parse_binding_response(&req).is_none(),
            "request is not a response"
        );
    }

    #[test]
    fn xor_mapped_v4_and_v6_roundtrip() {
        let txid = [3u8; 12];
        for addr in ["203.0.113.7:54321", "[2001:db8::42]:3478"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let resp = encode_binding_response(&txid, addr);
            assert_eq!(parse_binding_response(&resp), Some((txid, addr)));
        }
    }

    #[test]
    fn rfc5769_sample_ipv4_response() {
        // RFC 5769 §2.2 sample response (XOR-MAPPED-ADDRESS 192.0.2.1:32853),
        // trimmed to header + that attribute with the length fixed up.
        let txid: TransactionId = [
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ];
        let mut msg = vec![0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42];
        msg.extend_from_slice(&txid);
        msg.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47]);
        msg.extend_from_slice(&[0xe1, 0x12, 0xa6, 0x43]);
        let (id, addr) = parse_binding_response(&msg).unwrap();
        assert_eq!(id, txid);
        assert_eq!(addr, "192.0.2.1:32853".parse().unwrap());
    }

    #[test]
    fn wireguard_and_relay_bytes_are_not_stun() {
        let mut wg = vec![1u8, 0, 0, 0];
        wg.resize(148, 0xAA);
        assert!(!is_stun_packet(&wg));
        assert!(!is_stun_packet(&[0xC8, 0x01, 0, 0]));
    }
}
