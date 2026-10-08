//! Deterministic virtual MAC and IPv4 addresses derived from a `NodeId`.
//!
//! Because the derivation is a pure hash of the 32-byte public key, two
//! nodes agree on each other's addresses without any central coordinator.
//! IPv4 host parts are 16 bits (minus a few reserved values), so a pair
//! of nodes collides with probability ~2^-16 — fine for LAN-party sized
//! rooms, and something room-level conflict detection should guard as
//! rooms grow. MAC collisions (46 random bits) are negligible.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use super::identity::NodeId;

/// A 6-byte Ethernet MAC address in the locally-administered, unicast range.
///
/// Serializes as a colon-separated hex string (`02:aa:bb:cc:dd:ee`) for
/// text formats and as a raw 6-byte array for binary formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VirtualMac(pub [u8; 6]);

impl Serialize for VirtualMac {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            self.0.serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for VirtualMac {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            let parts: std::result::Result<Vec<u8>, _> =
                s.split(':').map(|p| u8::from_str_radix(p, 16)).collect();
            let parts = parts.map_err(D::Error::custom)?;
            let arr: [u8; 6] = parts
                .try_into()
                .map_err(|_| D::Error::custom("MAC must be 6 bytes"))?;
            Ok(Self(arr))
        } else {
            Ok(Self(<[u8; 6]>::deserialize(d)?))
        }
    }
}

impl VirtualMac {
    /// Derive a stable virtual MAC from a node id.
    ///
    /// The first byte has the locally-administered bit set (0x02) and the
    /// multicast bit cleared (0x01) to make it a valid unicast MAC.
    #[must_use]
    pub fn from_node_id(id: &NodeId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hermes/virtual-mac/v1");
        hasher.update(&id.0);
        let digest = hasher.finalize();
        let d = digest.as_bytes();
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&d[..6]);
        mac[0] = (mac[0] | 0x02) & !0x01;
        Self(mac)
    }

    /// The Ethernet broadcast address `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// Is this the all-ones broadcast address?
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }

    /// Is this a group (multicast or broadcast) address? The I/G bit is
    /// the least-significant bit of the first octet.
    #[must_use]
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }
}

impl std::fmt::Display for VirtualMac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

/// A node's IPv4 address inside a room's `/16` virtual subnet.
///
/// Serializes as dotted-quad text for human-readable formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VirtualIpv4(pub Ipv4Addr);

impl Serialize for VirtualIpv4 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.0.to_string())
        } else {
            self.0.octets().serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for VirtualIpv4 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            s.parse().map(Self).map_err(D::Error::custom)
        } else {
            Ok(Self(Ipv4Addr::from(<[u8; 4]>::deserialize(d)?)))
        }
    }
}

impl VirtualIpv4 {
    /// Derive a stable host address within `prefix.0.0/16`.
    ///
    /// The two host octets come from a BLAKE3 hash of the node id. Host
    /// parts that are unusable on a real `/16` — the network address
    /// (`.0.0`), the subnet broadcast (`.255.255`) — and any last octet of
    /// `0` or `255` (which some stacks and games still treat as special)
    /// are avoided by re-hashing with a counter.
    #[must_use]
    pub fn from_node_id(id: &NodeId, prefix: [u8; 2]) -> Self {
        let mut counter: u32 = 0;
        loop {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"hermes/virtual-ipv4/v1");
            hasher.update(&id.0);
            hasher.update(&counter.to_le_bytes());
            let d = hasher.finalize();
            let (hi, lo) = (d.as_bytes()[0], d.as_bytes()[1]);
            if lo != 0 && lo != 255 {
                return Self(Ipv4Addr::new(prefix[0], prefix[1], hi, lo));
            }
            counter += 1;
        }
    }
}

impl std::fmt::Display for VirtualIpv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_is_unicast_and_locally_administered() {
        for i in 0..64u8 {
            let mac = VirtualMac::from_node_id(&NodeId([i; 32]));
            assert_eq!(mac.0[0] & 0x01, 0, "multicast bit set");
            assert_eq!(mac.0[0] & 0x02, 0x02, "local bit clear");
            assert!(!mac.is_multicast());
        }
    }

    #[test]
    fn ipv4_is_stable_and_in_subnet() {
        let id = NodeId([9; 32]);
        let a = VirtualIpv4::from_node_id(&id, [10, 42]);
        let b = VirtualIpv4::from_node_id(&id, [10, 42]);
        assert_eq!(a, b);
        assert_eq!(&a.0.octets()[..2], &[10, 42]);
        for i in 0..=255u8 {
            let ip = VirtualIpv4::from_node_id(&NodeId([i; 32]), [10, 42]).0;
            let last = ip.octets()[3];
            assert!(last != 0 && last != 255);
        }
    }

    #[test]
    fn serde_text_forms() {
        let mac = VirtualMac([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        let json = serde_json::to_string(&mac).unwrap();
        assert_eq!(json, "\"02:aa:bb:cc:dd:ee\"");
        assert_eq!(serde_json::from_str::<VirtualMac>(&json).unwrap(), mac);

        let ip = VirtualIpv4(Ipv4Addr::new(10, 42, 1, 2));
        let json = serde_json::to_string(&ip).unwrap();
        assert_eq!(json, "\"10.42.1.2\"");
        assert_eq!(serde_json::from_str::<VirtualIpv4>(&json).unwrap(), ip);
    }
}
