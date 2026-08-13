//! Layer-2 forwarding: where a frame goes, and how to fake Ethernet on
//! platforms that don't have it.
//!
//! Hermes' whole reason for existing is that the virtual link behaves
//! like a real Ethernet segment — that is what makes ARP, mDNS/Bonjour,
//! SSDP, NetBIOS, and LAN game discovery work without any per-protocol
//! support. Two pieces make that true:
//!
//! - [`MacRouter`] is the forwarding table. It answers "which peer owns
//!   this destination MAC?" and, like a real switch, floods anything it
//!   can't answer for — which is exactly what broadcast and multicast
//!   discovery protocols depend on.
//!
//! - [`shim`] papers over the platforms that don't give us Ethernet.
//!   Linux TAP hands us real frames, but wintun on Windows is Layer 3
//!   only: it delivers bare IP packets and never speaks ARP. The shim
//!   synthesizes the Ethernet header on the way out and answers peers'
//!   ARP requests on the way in, so a Windows node looks like an ordinary
//!   Ethernet host to everyone else in the room.

mod router;
pub mod shim;

pub use router::{MacRouter, RouteDecision};
