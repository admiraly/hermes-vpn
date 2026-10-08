//! Virtual network adapter abstraction.
//!
//! Each platform exposes a different kind of virtual interface:
//!
//! - **Linux** — `/dev/net/tun` opened in TAP mode ([`linux`]). The kernel
//!   hands us complete Ethernet frames ([`AdapterMode::Ethernet`]).
//! - **Windows** — wintun ([`windows`]), which is Layer 3 only: it speaks
//!   raw IP packets ([`AdapterMode::Ip`]). The mesh carries Ethernet, so
//!   the driver passes wintun traffic through [`crate::broadcast::shim`].
//!
//! [`PlatformAdapter`] names the right implementation for the build
//! target; everything else talks to the [`VirtualAdapter`] trait.
//!
//! ## MTU budget
//!
//! A frame from the adapter is wrapped several times before it reaches
//! the physical network. The worst case is a relayed frame:
//!
//! ```text
//! app IP packet          VIRTUAL_MTU   1340
//! + Ethernet header      14
//! + framing header       20   (synthetic IPv4 header, see tunnel::framing)
//! + WireGuard data       32   (16 header + 16 Poly1305 tag)
//! + relay DATA header    34
//! + UDP header           8
//! + outer IPv4 header    20
//!                        ----
//!                        1468  <= PHYSICAL_MTU 1500
//! ```
//!
//! The 32-byte headroom covers PPPoE (8 bytes) and the 16-byte padding
//! the WireGuard spec permits (boringtun does not pad today). The
//! `mtu_budget_fits_physical_path` test pins the arithmetic.

use async_trait::async_trait;
use bytes::BytesMut;

use crate::crypto::VirtualMac;
use crate::error::Result;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod windows;

/// The adapter implementation for the current build target.
#[cfg(target_os = "linux")]
pub type PlatformAdapter = linux::TunTapAdapter;
/// The adapter implementation for the current build target.
#[cfg(windows)]
pub type PlatformAdapter = windows::WintunAdapter;

/// MTU of the virtual interface — the largest IP packet an application
/// may hand the adapter.
pub const VIRTUAL_MTU: usize = 1340;
/// MTU assumed for the physical path (standard Ethernet).
pub const PHYSICAL_MTU: usize = 1500;
/// Ethernet II header (dst MAC, src MAC, ethertype).
pub const ETHERNET_HEADER: usize = 14;
/// Synthetic IPv4 header that wraps every frame (see `tunnel::framing`).
pub const FRAMING_HEADER: usize = 20;
/// WireGuard transport-data overhead (16-byte header + 16-byte tag).
pub const WIREGUARD_OVERHEAD: usize = 32;
/// Relay `DATA`/`FORWARD` header (magic, type, node id).
pub const RELAY_HEADER: usize = 34;
/// Outer UDP header.
pub const UDP_HEADER: usize = 8;
/// Outer IPv4 header (relays are resolved to IPv4 only).
pub const OUTER_IP_HEADER: usize = 20;
/// Everything added on top of an application packet on the worst-case
/// (relayed) path.
pub const MAX_ENCAP_OVERHEAD: usize = ETHERNET_HEADER
    + FRAMING_HEADER
    + WIREGUARD_OVERHEAD
    + RELAY_HEADER
    + UDP_HEADER
    + OUTER_IP_HEADER;
/// Largest Ethernet frame the mesh carries (a full-MTU packet plus its
/// Ethernet header).
pub const FRAME_BUFFER_SIZE: usize = VIRTUAL_MTU + ETHERNET_HEADER;
/// Buffer size for any UDP datagram we send or receive. Comfortably
/// larger than the biggest datagram we ever produce so a slightly
/// oversized packet from a misconfigured peer is read whole (and then
/// rejected) rather than silently truncated.
pub const DATAGRAM_BUFFER_SIZE: usize = 2048;

/// Which layer an adapter speaks natively.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterMode {
    /// Full Ethernet frames (Linux TAP).
    Ethernet,
    /// Raw IP packets (wintun); needs the L2/L3 shim.
    Ip,
}

/// Settings an adapter is brought up with.
#[derive(Clone, Debug)]
pub struct AdapterConfig {
    /// Interface name (`Hermes`).
    pub name: String,
    /// Our virtual MAC — the adapter must use exactly this address, since
    /// peers route frames to it.
    pub mac: VirtualMac,
    /// Our virtual IPv4 address.
    pub ipv4: std::net::Ipv4Addr,
    /// Subnet prefix length (16).
    pub ipv4_prefix: u8,
    /// Interface MTU.
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
