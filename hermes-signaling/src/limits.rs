//! Abuse limits for the signaling server.
//!
//! Generating an identity is free, so per-key limits are useless here —
//! limits are per **client IP**: how often it may open connections, and
//! how often it may create or join rooms (the latter is what makes
//! guessing invite codes impractical on top of their 55 bits of entropy).
//!
//! Behind a reverse proxy (the recommended TLS setup) every connection
//! comes from the proxy's address, so the client IP must be taken from
//! `X-Forwarded-For` instead — but only when the operator says a trusted
//! proxy is in front (`HERMES_SIGNALING_TRUST_PROXY=1`); otherwise any
//! client could forge the header to dodge its limits.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderMap;
use hermes_core::ratelimit::{Rate, RateLimiter};

/// Shared limiters plus the proxy-trust setting.
#[derive(Clone)]
pub struct Limits {
    /// New WebSocket connections per client IP.
    pub connections: Arc<RateLimiter<IpAddr>>,
    /// `create_room` / `join_room` attempts per client IP.
    pub room_ops: Arc<RateLimiter<IpAddr>>,
    trust_proxy: bool,
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
        .max(1)
}

impl Limits {
    /// Limits from the environment, with production defaults: 120
    /// connections/min and 60 room operations/min per IP. Generous on
    /// purpose — many users can share one address (CGNAT) and all
    /// reconnect at once after a server restart — while still making
    /// guessing a 55-bit invite code hopeless.
    #[must_use]
    pub fn from_env() -> Self {
        let per_min = |n: u32| Rate::new(n, Duration::from_secs(60), n);
        Self {
            connections: Arc::new(RateLimiter::new(per_min(env_u32(
                "HERMES_SIGNALING_CONNECTIONS_PER_MIN",
                120,
            )))),
            room_ops: Arc::new(RateLimiter::new(per_min(env_u32(
                "HERMES_SIGNALING_ROOM_OPS_PER_MIN",
                60,
            )))),
            trust_proxy: std::env::var("HERMES_SIGNALING_TRUST_PROXY")
                .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
        }
    }

    /// The client's IP: the TCP peer, or — behind a trusted proxy — the
    /// address the proxy appended to `X-Forwarded-For` (the rightmost
    /// entry; anything left of it was supplied by the client).
    #[must_use]
    pub fn client_ip(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        if self.trust_proxy {
            let forwarded = headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .last()
                .and_then(|ip| ip.trim().parse().ok());
            if let Some(ip) = forwarded {
                return ip;
            }
        }
        peer.ip()
    }

    /// Forget idle sources.
    pub fn prune(&self) {
        self.connections.prune();
        self.room_ops.prune();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(trust_proxy: bool) -> Limits {
        let rate = Rate::new(1, Duration::from_secs(1), 1);
        Limits {
            connections: Arc::new(RateLimiter::new(rate)),
            room_ops: Arc::new(RateLimiter::new(rate)),
            trust_proxy,
        }
    }

    #[test]
    fn forwarded_for_only_when_trusted() {
        let peer: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "6.6.6.6, 203.0.113.9".parse().unwrap());

        assert_eq!(limits(false).client_ip(peer, &headers), peer.ip());
        // Rightmost = what our proxy saw; "6.6.6.6" could be forged.
        assert_eq!(
            limits(true).client_ip(peer, &headers),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(limits(true).client_ip(peer, &HeaderMap::new()), peer.ip());
    }
}
