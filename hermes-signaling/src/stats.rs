//! Operational counters for the signaling server, exposed at `/metrics`
//! when `HERMES_SIGNALING_METRICS_BIND` is set. Aggregate only.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use hermes_core::metrics::Exposition;

use crate::rooms::RoomRegistry;

#[derive(Default)]
pub struct Stats {
    pub connections: AtomicU64,
    pub connections_rejected_rate: AtomicU64,
    pub sessions_active: AtomicU64,
    pub auth_failures: AtomicU64,
    pub rooms_created: AtomicU64,
    pub rooms_joined: AtomicU64,
    pub rooms_restored: AtomicU64,
    pub join_invalid_code: AtomicU64,
    pub room_ops_rate_limited: AtomicU64,
    pub idle_disconnects: AtomicU64,
}

/// `counter += 1`.
pub fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

impl Stats {
    pub fn render(&self, registry: &RoomRegistry, started: Instant) -> String {
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Exposition::new()
            .gauge(
                "hermes_signaling_sessions",
                "Authenticated connections right now.",
                get(&self.sessions_active),
            )
            .gauge(
                "hermes_signaling_rooms",
                "Rooms with at least one member.",
                registry.room_count() as u64,
            )
            .gauge(
                "hermes_signaling_uptime_seconds",
                "Seconds since start.",
                started.elapsed().as_secs(),
            )
            .counter(
                "hermes_signaling_connections_total",
                "WebSocket connections accepted.",
                get(&self.connections),
            )
            .counter(
                "hermes_signaling_connections_rate_limited_total",
                "Connections refused by the per-IP limit.",
                get(&self.connections_rejected_rate),
            )
            .counter(
                "hermes_signaling_auth_failures_total",
                "Handshakes that failed (bad signature, key binding or version).",
                get(&self.auth_failures),
            )
            .labeled_counter(
                "hermes_signaling_room_events_total",
                "Room operations by kind.",
                "kind",
                &[
                    ("created", get(&self.rooms_created)),
                    ("joined", get(&self.rooms_joined)),
                    ("restored", get(&self.rooms_restored)),
                    ("invalid_code", get(&self.join_invalid_code)),
                    ("rate_limited", get(&self.room_ops_rate_limited)),
                ],
            )
            .counter(
                "hermes_signaling_idle_disconnects_total",
                "Sessions dropped for silence.",
                get(&self.idle_disconnects),
            )
            .finish()
    }
}

/// Shared handle.
pub type SharedStats = Arc<Stats>;
