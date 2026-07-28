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
//! If traversal fails (e.g. symmetric NAT on both ends), the answer is to
//! create the room in **relayed** mode instead — see [`crate::relay`].
//! That central-server path is a deliberate, room-wide choice rather than
//! an automatic per-peer TURN fallback, so it lives outside this module.
//!
//! The output of this pipeline is a [`TraversalResult`] containing the
//! `SocketAddr` boringtun should send to plus the classification of the
//! path (Direct vs `DirectUpnp`) which the UI surfaces.

pub mod ice;
pub mod stun;
pub mod upnp;

use std::net::SocketAddr;

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
