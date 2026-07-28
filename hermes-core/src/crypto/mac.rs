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