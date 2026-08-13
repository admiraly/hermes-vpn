//! Deterministic virtual MAC and IPv4 addresses derived from a `NodeId`.
//!
//! Because the derivation is a pure hash of the 32-byte public key, two
//! nodes agree on each other's addresses without any central coordinator.
//! Collisions for IPv4 within a /16 have probability ~2^-32 per pair;
//! MAC collisions are astronomically unlikely in practice.

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
        // Force locally-administered (0x02) and clear the multicast bit so
        // the result is always a valid unicast MAC.
        Self([d[0] & 0xFE | 0x02, d[1], d[2], d[3], d[4], d[5]])
    }

    /// The Ethernet broadcast address, `ff:ff:ff:ff:ff:ff`.
    #[must_use]
    pub const fn broadcast() -> Self {
        Self([0xFF; 6])
    }

    /// Is this the all-ones broadcast address?
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }

    /// Is the multicast bit set? Broadcast counts as multicast, as on a
    /// real Ethernet segment.
    #[must_use]
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }
}

impl std::fmt::Display for VirtualMac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// A node's virtual IPv4 address inside its room's subnet.
///
/// The room fixes the first two octets (`10.42.x.y` by default) and the
/// remaining 16 bits are hashed from the node id. Host parts `.0.0`
/// (network) and `.255.255` (broadcast) are avoided by folding them onto
/// neighbouring addresses, so every node gets a usable unicast address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VirtualIpv4(pub Ipv4Addr);

impl VirtualIpv4 {
    /// Derive the address a node holds within a room's `/16`.
    #[must_use]
    pub fn from_node_id(id: &NodeId, subnet_prefix: [u8; 2]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hermes/virtual-ipv4/v1");
        hasher.update(&id.0);
        let digest = hasher.finalize();
        let d = digest.as_bytes();

        let host = u16::from_be_bytes([d[0], d[1]]);
        // Fold the two reserved host values (network / broadcast) onto
        // addresses that are legal to assign.
        let host = match host {
            0 => 1,
            u16::MAX => u16::MAX - 1,
            other => other,
        };
        let [h1, h2] = host.to_be_bytes();
        Self(Ipv4Addr::new(subnet_prefix[0], subnet_prefix[1], h1, h2))
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
        let id = NodeId([9u8; 32]);
        let mac = VirtualMac::from_node_id(&id);
        assert_eq!(mac.0[0] & 0x01, 0, "multicast bit must be clear");
        assert_eq!(
            mac.0[0] & 0x02,
            0x02,
            "locally-administered bit must be set"
        );
        assert!(!mac.is_broadcast());
        assert!(!mac.is_multicast());
    }

    #[test]
    fn derivation_is_deterministic_and_distinct() {
        let a = NodeId([1u8; 32]);
        let b = NodeId([2u8; 32]);
        assert_eq!(VirtualMac::from_node_id(&a), VirtualMac::from_node_id(&a));
        assert_ne!(VirtualMac::from_node_id(&a), VirtualMac::from_node_id(&b));
        assert_eq!(
            VirtualIpv4::from_node_id(&a, [10, 42]),
            VirtualIpv4::from_node_id(&a, [10, 42])
        );
        assert_ne!(
            VirtualIpv4::from_node_id(&a, [10, 42]),
            VirtualIpv4::from_node_id(&b, [10, 42])
        );
    }

    #[test]
    fn ipv4_lands_inside_the_room_subnet() {
        let id = NodeId([3u8; 32]);
        let ip = VirtualIpv4::from_node_id(&id, [10, 42]).0.octets();
        assert_eq!([ip[0], ip[1]], [10, 42]);
        let host = u16::from_be_bytes([ip[2], ip[3]]);
        assert_ne!(host, 0, "must not be the network address");
        assert_ne!(host, u16::MAX, "must not be the broadcast address");
    }

    #[test]
    fn broadcast_helpers() {
        let b = VirtualMac::broadcast();
        assert!(b.is_broadcast());
        assert!(b.is_multicast());
        assert_eq!(b.to_string(), "ff:ff:ff:ff:ff:ff");
    }
}
