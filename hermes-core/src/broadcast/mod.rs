//! Layer-2 forwarding: deciding where each Ethernet frame goes, and
//! making an L3-only adapter (wintun) look like Ethernet.
//!
//! A Hermes room is one virtual Ethernet segment. Every frame our adapter
//! emits is either addressed to one peer's virtual MAC (unicast → that
//! peer's tunnel) or to a group address (broadcast / multicast → every
//! peer's tunnel). Replicating group frames to all peers is what makes
//! ARP, mDNS/Bonjour, SSDP, NetBIOS, and LAN game discovery work exactly
//! as they would on a physical switch.
//!
//! - [`router`] — the MAC → peer table and the per-frame routing decision.
//! - [`arp`]    — ARP request parsing and reply synthesis.
//! - [`shim`]   — wraps wintun's IP packets in Ethernet headers and
//!   answers ARP on Windows' behalf.

pub mod arp;
pub mod router;
pub mod shim;

pub use router::{classify, FrameClass, MacRouter, RouteDecision};

/// EtherType for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// EtherType for IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Read the EtherType of an Ethernet II frame.
#[must_use]
pub fn ethertype(frame: &[u8]) -> Option<u16> {
    (frame.len() >= crate::tap::ETHERNET_HEADER).then(|| u16::from_be_bytes([frame[12], frame[13]]))
}
