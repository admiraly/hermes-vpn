//! The virtual network adapter.
//!
//! Each platform supplies its own backend behind the [`VirtualAdapter`]
//! trait, and they do not speak the same layer:
//!
//! - **Linux** opens `/dev/net/tun` in TAP mode, so it hands us real
//!   Ethernet frames ([`AdapterMode::Ethernet`]).
//! - **Windows** uses wintun, which is Layer 3 only ([`AdapterMode::Ip`]);
//!   the [`crate::broadcast::shim`] module synthesizes the Ethernet
//!   header on the way out and answers ARP on the way in.
//!
//! ## The MTU budget
//!
//! An application packet is wrapped several times before it reaches the
//! wire, and the total has to stay under the physical path MTU or every
//! full-size packet fragments:
//!
//! ```text
//!   [ outer IPv4 + UDP ]          UDP_IPV4_OVERHEAD   28
//!   [ relay DATA header ]         RELAY_HEADER        34   (relayed rooms only)
//!   [ WireGuard data header ]     WIREGUARD_OVERHEAD  32
//!   [ synthetic IPv4 header ]     FRAMING_HEADER      20   (see crate::tunnel::framing)
//!   [ Ethernet header ]           ETHERNET_HEADER     14
//!   [ application payload ]       VIRTUAL_MTU       1350
//! ```
//!
//! [`VIRTUAL_MTU`] is what we pin on the adapter, so applications do
//! path-MTU discovery against a number that already accounts for all of
//! the above. The `mtu_budget_fits_physical_path` test below is what
//! keeps these constants honest.

use async_trait::async_trait;
use bytes::BytesMut;

use crate::crypto::VirtualMac;
use crate::error::Result;

#[cfg(unix)]
pub mod linux;
#[cfg(windows)]
pub mod windows;

/// The platform's concrete [`VirtualAdapter`] implementation.
#[cfg(unix)]
pub type PlatformAdapter = linux::TunTapAdapter;
/// The platform's concrete [`VirtualAdapter`] implementation.
#[cfg(windows)]
pub type PlatformAdapter = windows::WintunAdapter;

/// The MTU we assume for the physical path between two nodes. 1500 is the
/// classic Ethernet MTU; paths with less (PPPoE, some VPNs) will still
/// work because WireGuard rides on UDP and the kernel fragments, but
/// throughput suffers.
pub const PHYSICAL_MTU: usize = 1500;

/// Bytes of Ethernet header in front of every frame on the virtual link
/// (destination MAC, source MAC, EtherType).
pub const ETHERNET_HEADER: usize = 14;

/// The synthetic IPv4 header [`crate::tunnel::framing`] puts in front of
/// each Ethernet frame so that WireGuard, which transports IP packets,
/// accepts it.
pub const FRAMING_HEADER: usize = 20;

/// WireGuard data-packet overhead: 4 B type/reserved, 4 B receiver index,
/// 8 B counter, 16 B Poly1305 tag.
pub const WIREGUARD_OVERHEAD: usize = 32;

/// The relay's DATA header: magic + type + 32-byte destination node id.
/// Only present in relayed rooms, but budgeted for unconditionally so a
/// room can fail over to a relay without renegotiating the MTU.
pub const RELAY_HEADER: usize = crate::relay::protocol::DATA_HEADER_LEN;

/// Outer IPv4 (20) + UDP (8) headers the kernel prepends on the wire.
pub const UDP_IPV4_OVERHEAD: usize = 28;

/// ChaCha20-Poly1305 pads plaintext to a 16-byte boundary; budget for a
/// full block of padding so the worst case still fits.
pub const CRYPTO_PADDING: usize = 16;

/// Everything wrapped around an application payload on the longest path
/// (a relayed room).
pub const MAX_ENCAP_OVERHEAD: usize = ETHERNET_HEADER
    + FRAMING_HEADER
    + WIREGUARD_OVERHEAD
    + RELAY_HEADER
    + UDP_IPV4_OVERHEAD
    + CRYPTO_PADDING;

/// MTU pinned on the virtual adapter. Chosen so that
/// `VIRTUAL_MTU + MAX_ENCAP_OVERHEAD <= PHYSICAL_MTU`.
pub const VIRTUAL_MTU: usize = 1350;

/// Buffer size for a single Ethernet frame read off the adapter. Larger
/// than `VIRTUAL_MTU + ETHERNET_HEADER` so an adapter that ignores the
/// MTU we set produces a *detectable* oversized frame (which the driver
/// drops with a warning) rather than a silently truncated one.
pub const FRAME_BUFFER_SIZE: usize = 1600;

/// Buffer size for a UDP datagram: big enough for the largest frame we
/// would ever encapsulate, with headroom.
pub const DATAGRAM_BUFFER_SIZE: usize = 2048;

/// Which layer an adapter speaks natively.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterMode {
    /// The adapter carries full Ethernet frames (Linux TAP).
    Ethernet,
    /// The adapter carries bare IP packets (wintun). Frames must go
    /// through [`crate::broadcast::shim`] in both directions.
    Ip,
}

/// How to bring the virtual adapter up.
#[derive(Clone, Debug)]
pub struct AdapterConfig {
    /// Interface name shown by the OS.
    pub name: String,
    /// Our virtual MAC on the link.
    pub mac: VirtualMac,
    /// Our virtual IPv4 address.
    pub ipv4: std::net::Ipv4Addr,
    /// Prefix length of the room subnet (16 for a `/16`).
    pub ipv4_prefix: u8,
    /// MTU to pin on the interface.
    pub mtu: u16,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            name: "Hermes".to_string(),
            mac: VirtualMac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ipv4: std::net::Ipv4Addr::new(10, 42, 0, 1),
            ipv4_prefix: 16,
            mtu: VIRTUAL_MTU as u16,
        }
    }
}

/// Platform-agnostic adapter interface.
#[async_trait]
pub trait VirtualAdapter: Send + Sync {
    /// Read the next packet from the adapter (Ethernet frame or raw IP,
    /// depending on [`Self::mode`]).
    async fn recv_frame(&self) -> Result<BytesMut>;

    /// Write a packet to the adapter. On [`AdapterMode::Ip`] platforms
    /// the caller must supply a raw IP packet; on [`AdapterMode::Ethernet`]
    /// the caller must supply an Ethernet frame.
    async fn send_frame(&self, frame: &[u8]) -> Result<()>;

    /// Tear down the adapter and release OS resources.
    async fn shutdown(&self) -> Result<()>;

    /// The config this adapter was brought up with.
    fn config(&self) -> &AdapterConfig;

    /// Which layer this adapter speaks natively.
    fn mode(&self) -> AdapterMode;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtu_budget_fits_physical_path() {
        // A full-size app packet, fully encapsulated for the relayed path,
        // must not exceed the physical MTU — otherwise it fragments.
        let on_wire = VIRTUAL_MTU + MAX_ENCAP_OVERHEAD;
        assert!(
            on_wire <= PHYSICAL_MTU,
            "VIRTUAL_MTU {VIRTUAL_MTU} + overhead {MAX_ENCAP_OVERHEAD} = {on_wire} \
             exceeds physical MTU {PHYSICAL_MTU}",
        );
    }

    #[test]
    fn datagram_buffer_holds_largest_datagram() {
        // The biggest thing we ever recv/encapsulate: a relayed frame
        // (everything except the outer UDP/IP headers, which the kernel
        // strips before we see the payload).
        let largest = FRAME_BUFFER_SIZE + FRAMING_HEADER + WIREGUARD_OVERHEAD + RELAY_HEADER;
        assert!(
            largest <= DATAGRAM_BUFFER_SIZE,
            "largest datagram {largest} exceeds buffer {DATAGRAM_BUFFER_SIZE}",
        );
    }
}
