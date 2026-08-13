//! Cryptographic identity and the addresses derived from it.
//!
//! A Hermes node is defined by one long-term Ed25519 keypair
//! ([`NodeSecret`] / [`NodeId`]). Everything else a peer needs to know
//! about it is *derived* from that key rather than assigned:
//!
//! - the WireGuard X25519 keypair (BLAKE3 with a domain separator),
//! - the virtual MAC address ([`VirtualMac`]),
//! - the virtual IPv4 address within the room subnet ([`VirtualIpv4`]).
//!
//! Deriving instead of allocating is what lets a room work without any
//! authority handing out addresses: two nodes that know each other's
//! `NodeId` independently compute the same MAC and IP for that node, so
//! the ARP table and the routing table agree with no negotiation.

mod identity;
mod mac;

pub use identity::{NodeId, NodeIdentity, NodeSecret};
pub use mac::{VirtualIpv4, VirtualMac};
