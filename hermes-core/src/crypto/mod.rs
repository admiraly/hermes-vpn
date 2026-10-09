//! Cryptographic identity and the addresses derived from it.
//!
//! - [`identity`] — the permanent Ed25519 node keypair and the X25519
//!   WireGuard key derived from it.
//! - [`mac`] — deterministic virtual MAC / IPv4 addresses derived from a
//!   node's public key, so peers agree on addressing without a server.

pub mod admission;
pub mod identity;
pub mod mac;

pub use admission::RoomKeys;
pub use identity::{verify_wireguard_binding, NodeId, NodeIdentity, NodeSecret};
pub use mac::{VirtualIpv4, VirtualMac};
