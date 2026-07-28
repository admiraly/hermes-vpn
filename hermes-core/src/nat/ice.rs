//! Minimal ICE-lite candidate exchange + UDP hole punching.
//!
//! We don't implement full RFC 8445 ICE — that's a lot of machinery for a
//! LAN overlay. Instead we do "ICE-lite": each peer gathers a list of
//! candidates (host, server-reflexive, UPnP), swaps the list via the
//! signaling server, and both sides simultaneously open UDP sockets
//! to every candidate pair. The first pair that successfully round-trips
//! a handshake packet wins and is promoted to [`super::TraversalResult`].

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::debug;

use super::{Candidate, CandidateKind, PathKind, TraversalResult};
use crate::error::Result;

/// Probe each candidate by sending a small handshake datagram and waiting
/// for an echo. The first candidate that answers wins.
///
/// # Errors
/// Returns an error if none of the candidates respond within `budget`.
pub async fn probe_candidates(
    socket: &UdpSocket,
    candidates: &[Candidate],
    budget: Duration,
) -> Result<TraversalResult> {
    // Sort by ICE priority (higher first).
    let mut sorted: Vec<_> = candidates.iter().collect();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.priority));

    let deadline = tokio::time::Instant::now() + budget;

    for c in sorted {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        if let Ok(path) = probe_one(socket, c, remaining.min(Duration::from_millis(500))).await {
            return Ok(path);
        }
    }
    Err(crate::error::HermesError::Nat(
        "all candidates failed to respond".into(),
    ))
}

async fn probe_one(
    socket: &UdpSocket,
    candidate: &Candidate,
    budget: Duration,
) -> Result<TraversalResult> {
    // The handshake datagram is a fixed 4-byte magic. Peers looking for
    // the same room echo it back.
    const MAGIC: &[u8; 4] = b"HRM1";

    socket.send_to(MAGIC, candidate.address).await?;

    let mut buf = [0u8; 16];
    let result = tokio::time::timeout(budget, socket.recv_from(&mut buf)).await;
    match result {
        Ok(Ok((n, from))) if n >= 4 && &buf[..4] == MAGIC && from == candidate.address => {
            debug!(addr = %candidate.address, "candidate responded");
            Ok(TraversalResult {
                endpoint: candidate.address,
                kind: match candidate.kind {
                    CandidateKind::Host | CandidateKind::ServerReflexive => PathKind::Direct,
                    CandidateKind::Upnp => PathKind::DirectUpnp,
                    CandidateKind::Relayed => PathKind::Relayed,
                },
            })
        }
        _ => Err(crate::error::HermesError::Nat(format!(
            "no reply from {}",
            candidate.address
        ))),
    }
}

/// Priority for a candidate following RFC 8445's standard formula:
/// `2^24 * type_preference + 2^8 * local_preference + component_id`.
#[must_use]
pub fn priority_for(kind: CandidateKind) -> u32 {
    let type_pref: u32 = match kind {
        CandidateKind::Host => 126,
        CandidateKind::Upnp => 110,
        CandidateKind::ServerReflexive => 100,
        CandidateKind::Relayed => 0,
    };
    (type_pref << 24) | (65_535u32 << 8) | 1
}

/// Build the full candidate list from what we currently know.
#[must_use]
pub fn gather_candidates(
    host: Option<SocketAddr>,
    upnp: Option<SocketAddr>,
    reflexive: Option<SocketAddr>,
    relayed: Option<SocketAddr>,
) -> Vec<Candidate> {
    let mut v = Vec::new();
    if let Some(addr) = host {
        v.push(Candidate {
            address: addr,
            kind: CandidateKind::Host,
            priority: priority_for(CandidateKind::Host),
        });
    }
    if let Some(addr) = upnp {
        v.push(Candidate {
            address: addr,
            kind: CandidateKind::Upnp,
            priority: priority_for(CandidateKind::Upnp),
        });
    }
    if let Some(addr) = reflexive {
        v.push(Candidate {
            address: addr,
            kind: CandidateKind::ServerReflexive,
            priority: priority_for(CandidateKind::ServerReflexive),
        });
    }
    if let Some(addr) = relayed {
        v.push(Candidate {
            address: addr,
            kind: CandidateKind::Relayed,
            priority: priority_for(CandidateKind::Relayed),
        });
    }
    v
}
