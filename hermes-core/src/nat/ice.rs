//! Minimal ICE-lite candidate exchange + UDP hole punching.
//!
//! We don't implement full RFC 8445 ICE — that's a lot of machinery for a
//! LAN overlay. Instead we do "ICE-lite": each peer gathers a list of
//! candidates (host, server-reflexive, UPnP), swaps the list via the
//! signaling server, and both sides then fire probes at every one of the
//! other's candidates at once, re-sending every [`PROBE_INTERVAL`]. The
//! simultaneous outbound traffic is what opens each side's NAT for the
//! other ("hole punching"); the first candidate that answers wins.
//!
//! ## Probe wire format
//!
//! ```text
//! request  "HRM1" | nonce (8) | candidate index (1)
//! reply    "HRA1" | nonce (8) | candidate index (1)
//! ```
//!
//! Requests and replies use different magics so two peers probing each
//! other can never bounce a probe back and forth forever. Probes share
//! the node's single UDP socket with WireGuard (that's the socket whose
//! NAT mapping we're trying to open), so replies are delivered by the
//! mesh's inbound demultiplexer ([`Mesh::register_probe`]) rather than a
//! competing `recv_from` here. The address a reply *arrives from* becomes
//! the tunnel endpoint — if the peer's NAT rewrote its port, that
//! "peer-reflexive" address is the one that actually works.

use std::net::SocketAddr;
use std::time::Duration;

use rand::Rng;
use tracing::debug;

use super::{Candidate, CandidateKind, PathKind, TraversalResult};
use crate::error::{HermesError, Result};
use crate::mesh::Mesh;

/// How often probes are re-sent while waiting for an answer.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(250);

const REQUEST_MAGIC: &[u8; 4] = b"HRM1";
const REPLY_MAGIC: &[u8; 4] = b"HRA1";
const PROBE_LEN: usize = 4 + 8 + 1;

/// A parsed probe datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeMessage {
    /// "Are you there?" — answer with a [`ProbeMessage::Reply`].
    Request {
        /// Prober's nonce.
        nonce: u64,
        /// Which of the prober's targets this was sent to.
        index: u8,
    },
    /// Answer to one of our requests.
    Reply {
        /// Our nonce, echoed.
        nonce: u64,
        /// Our candidate index, echoed.
        index: u8,
    },
}

fn encode(magic: &[u8; 4], nonce: u64, index: u8) -> [u8; PROBE_LEN] {
    let mut buf = [0u8; PROBE_LEN];
    buf[..4].copy_from_slice(magic);
    buf[4..12].copy_from_slice(&nonce.to_be_bytes());
    buf[12] = index;
    buf
}

/// Build a probe request.
#[must_use]
pub fn encode_request(nonce: u64, index: u8) -> [u8; PROBE_LEN] {
    encode(REQUEST_MAGIC, nonce, index)
}

/// Build the reply to a request.
#[must_use]
pub fn encode_reply(nonce: u64, index: u8) -> [u8; PROBE_LEN] {
    encode(REPLY_MAGIC, nonce, index)
}

/// Parse a probe datagram; `None` if it isn't one.
#[must_use]
pub fn parse_probe(buf: &[u8]) -> Option<ProbeMessage> {
    if buf.len() != PROBE_LEN {
        return None;
    }
    let nonce = u64::from_be_bytes(buf[4..12].try_into().ok()?);
    let index = buf[12];
    match &buf[..4] {
        m if m == REQUEST_MAGIC => Some(ProbeMessage::Request { nonce, index }),
        m if m == REPLY_MAGIC => Some(ProbeMessage::Reply { nonce, index }),
        _ => None,
    }
}

/// Probe every candidate concurrently until one answers or `budget`
/// runs out.
///
/// Requires the mesh's inbound loop (the room driver) to be running, since
/// that is what delivers replies.
///
/// # Errors
/// Returns an error if none of the candidates respond within `budget`.
pub async fn probe_candidates(
    mesh: &Mesh,
    candidates: &[Candidate],
    budget: Duration,
) -> Result<TraversalResult> {
    // Highest priority first, so ties within one interval go to the best
    // candidate kind; cap at 256 so the index fits in a byte.
    let mut sorted: Vec<&Candidate> = candidates.iter().take(256).collect();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.priority));
    if sorted.is_empty() {
        return Err(HermesError::Nat("peer offered no candidates".into()));
    }

    let nonce: u64 = rand::thread_rng().gen();
    let mut replies = mesh.register_probe(nonce);
    let deadline = tokio::time::Instant::now() + budget;
    let mut ticker = tokio::time::interval(PROBE_INTERVAL);

    let outcome = loop {
        tokio::select! {
            _ = ticker.tick() => {
                if tokio::time::Instant::now() >= deadline {
                    break None;
                }
                for (i, c) in sorted.iter().enumerate() {
                    let index = u8::try_from(i).unwrap_or(u8::MAX);
                    if let Err(e) = mesh.socket.send_to(&encode_request(nonce, index), c.address).await {
                        debug!(addr = %c.address, ?e, "probe send failed");
                    }
                }
            }
            reply = replies.recv() => {
                match reply {
                    Some((index, from)) => {
                        if let Some(c) = sorted.get(usize::from(index)) {
                            break Some(((*c).clone(), from));
                        }
                    }
                    None => break None,
                }
            }
            () = tokio::time::sleep_until(deadline) => break None,
        }
    };
    mesh.unregister_probe(nonce);

    match outcome {
        Some((candidate, from)) => {
            debug!(candidate = %candidate.address, %from, "candidate responded");
            Ok(TraversalResult {
                endpoint: from,
                kind: path_kind(candidate.kind),
            })
        }
        None => Err(HermesError::Nat("all candidates failed to respond".into())),
    }
}

fn path_kind(kind: CandidateKind) -> PathKind {
    match kind {
        CandidateKind::Host | CandidateKind::ServerReflexive => PathKind::Direct,
        CandidateKind::Upnp => PathKind::DirectUpnp,
        CandidateKind::Relayed => PathKind::Relayed,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_codec_roundtrip() {
        let req = encode_request(0xDEAD_BEEF, 3);
        assert_eq!(
            parse_probe(&req),
            Some(ProbeMessage::Request {
                nonce: 0xDEAD_BEEF,
                index: 3
            })
        );
        let rep = encode_reply(7, 0);
        assert_eq!(
            parse_probe(&rep),
            Some(ProbeMessage::Reply { nonce: 7, index: 0 })
        );
        assert!(parse_probe(b"HRM1").is_none());
        assert!(parse_probe(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn priorities_order_host_first() {
        let c = gather_candidates(
            Some("192.168.1.2:1".parse().unwrap()),
            Some("1.2.3.4:1".parse().unwrap()),
            Some("1.2.3.4:2".parse().unwrap()),
            None,
        );
        assert!(c[0].priority > c[1].priority && c[1].priority > c[2].priority);
    }
}
