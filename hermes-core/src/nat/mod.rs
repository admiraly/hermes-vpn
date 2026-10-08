//! NAT traversal stack for peer-to-peer rooms: UPnP, STUN, UDP hole punching.
//!
//! The traversal pipeline runs in this order:
//!
//! 1. [`upnp`] — try to request a port mapping from the local router. If
//!    this succeeds, we advertise the public port directly and the
//!    remaining steps are optional.
//! 2. [`stun`] — query a public STUN server to learn our reflexive
//!    address (external IP+port as seen from the Internet).
//! 3. [`ice`] — exchange candidate lists with the remote peer through
//!    the signaling server, then attempt simultaneous UDP opens.
//!
//! If traversal fails (e.g. symmetric NAT on both ends) and the room has
//! a fallback relay, the engine routes just that peer through the relay
//! (see `engine_pump::probe_and_tunnel` and [`crate::relay`]); otherwise
//! the peer is marked stale.
//!
//! The output of this pipeline is a [`TraversalResult`] containing the
//! `SocketAddr` boringtun should send to plus the classification of the
//! path (Direct vs `DirectUpnp`) which the UI surfaces.

pub mod ice;
pub mod stun;
pub mod upnp;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Classification of a NAT-traversal outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PathKind {
    /// Direct peer-to-peer UDP path (best latency).
    Direct,
    /// Peer reachable via UPnP-mapped port (still direct).
    DirectUpnp,
    /// Traffic is forwarded by a central relay server (a relayed room).
    Relayed,
}

/// Final result of a successful traversal attempt.
#[derive(Clone, Debug)]
pub struct TraversalResult {
    /// Where to send WireGuard UDP datagrams for this peer.
    pub endpoint: SocketAddr,
    /// Classification of the chosen path.
    pub kind: PathKind,
}

/// A candidate endpoint for a peer (gathered locally, sent via signaling).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    /// The `SocketAddr` that should be tried.
    pub address: SocketAddr,
    /// What kind of candidate this is.
    pub kind: CandidateKind,
    /// ICE-style priority (higher is preferred).
    pub priority: u32,
}

/// Candidate origin.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum CandidateKind {
    /// A local network interface address.
    Host,
    /// A reflexive address learned via STUN.
    ServerReflexive,
    /// A port mapped via UPnP.
    Upnp,
    /// A relay-forwarded address. Reserved for an automatic per-peer relay
    /// fallback; rooms select relaying explicitly today (see [`crate::relay`]).
    Relayed,
}

/// The IPv4 address of the interface that carries our default route —
/// what a LAN peer should use to reach us directly.
///
/// The engine's socket is bound to `0.0.0.0`, so its `local_addr()` says
/// nothing useful. Connecting a throwaway UDP socket to a public address
/// makes the OS pick the outbound interface without sending a packet.
#[must_use]
pub fn primary_local_ipv4() -> Option<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("192.0.2.1:9").ok()?; // TEST-NET-1; never actually sent to
    match probe.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() && !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

/// Turn the socket's bound address into a usable host candidate:
/// a wildcard bind is replaced by the primary LAN address.
#[must_use]
pub fn host_candidate_addr(bound: SocketAddr) -> Option<SocketAddr> {
    if bound.ip().is_unspecified() {
        primary_local_ipv4().map(|ip| SocketAddr::new(IpAddr::V4(ip), bound.port()))
    } else {
        Some(bound)
    }
}
