//! Client-side relay registration and relay health tracking.
//!
//! While a node is in a relayed room (or has failed over to a fallback
//! relay) it must keep a registration alive at the relay server: the
//! registration tells the relay where to forward packets addressed to
//! us, and the periodic re-send doubles as a NAT keepalive so our home
//! router keeps the UDP mapping open.
//!
//! The relay acks every registration, and we use those acks as a health
//! signal: if several consecutive registrations go unanswered the relay
//! is marked unhealthy on a [`RelayHealth`] watch channel the engine
//! translates into user-visible events. Recovery is automatic — the
//! keepalive never stops, so the moment the relay answers again the
//! session re-establishes and health flips back.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::protocol;
use crate::crypto::NodeSecret;
use crate::room::RoomId;

/// Tunables for the registration keepalive and health evaluation.
/// Defaults are production values; tests shrink them.
#[derive(Clone, Copy, Debug)]
pub struct RegistrationConfig {
    /// Steady-state re-registration interval. Must be comfortably below
    /// the relay's session expiry (60 s) and typical NAT UDP timeouts
    /// (~30 s).
    pub reregister_interval: Duration,
    /// Aggressive interval used for the first [`Self::initial_rounds`]
    /// registrations so a room comes up fast even if a packet is lost.
    pub initial_interval: Duration,
    /// How many aggressive rounds before settling into steady state.
    pub initial_rounds: u32,
    /// If no ack has been seen for this long while registering, the
    /// relay is declared unhealthy. Three missed steady-state cycles by
    /// default.
    pub ack_timeout: Duration,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        Self {
            reregister_interval: Duration::from_secs(15),
            initial_interval: Duration::from_secs(2),
            initial_rounds: 5,
            ack_timeout: Duration::from_secs(45),
        }
    }
}

/// Shared relay-health state.
///
/// The mesh's inbound demultiplexer calls [`RelayHealth::note_ack`] when
/// a `REGISTER_ACK` arrives from the relay; the registration loop calls
/// [`RelayHealth::evaluate`] on every tick. Consumers subscribe to the
/// watch channel and get edge-triggered healthy/unhealthy transitions.
#[derive(Debug)]
pub struct RelayHealth {
    last_ack: parking_lot::Mutex<Option<Instant>>,
    /// When the current registration loop started — gives a grace period
    /// before a relay that never acked at all is declared unhealthy.
    since: parking_lot::Mutex<Option<Instant>>,
    healthy_tx: watch::Sender<bool>,
}

impl Default for RelayHealth {
    fn default() -> Self {
        let (healthy_tx, _) = watch::channel(true);
        Self {
            last_ack: parking_lot::Mutex::new(None),
            since: parking_lot::Mutex::new(None),
            healthy_tx,
        }
    }
}

impl RelayHealth {
    /// Record that the relay acknowledged a registration.
    pub fn note_ack(&self) {
        *self.last_ack.lock() = Some(Instant::now());
    }

    /// Current health verdict.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        *self.healthy_tx.borrow()
    }

    /// Subscribe to health transitions. The receiver yields the current
    /// value first (watch semantics), then every change.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.healthy_tx.subscribe()
    }

    /// Reset for a new registration session (called when a registration
    /// loop starts, and on room teardown).
    pub fn reset(&self) {
        *self.last_ack.lock() = None;
        *self.since.lock() = Some(Instant::now());
        self.healthy_tx.send_if_modified(|h| {
            let changed = !*h;
            *h = true;
            changed
        });
    }

    /// Re-evaluate health based on how stale the last ack is. Called by
    /// the registration loop on every tick.
    fn evaluate(&self, ack_timeout: Duration) {
        let last_ack = *self.last_ack.lock();
        let since = *self.since.lock();
        let stale = match (last_ack, since) {
            // Acked at some point: stale if the ack is old.
            (Some(ack), _) => ack.elapsed() > ack_timeout,
            // Never acked: stale once the grace period expires.
            (None, Some(start)) => start.elapsed() > ack_timeout,
            // Not registering — nothing to judge.
            (None, None) => return,
        };
        let now_healthy = !stale;
        self.healthy_tx.send_if_modified(|h| {
            let changed = *h != now_healthy;
            *h = now_healthy;
            changed
        });
    }
}

/// Spawn the background task that keeps our relay registration fresh and
/// the health verdict current.
///
/// The task runs until aborted (the engine aborts it when leaving the
/// room). Send failures are logged and retried on the next tick — the
/// relay path self-heals as long as the relay is reachable.
#[must_use]
pub fn spawn_registration(
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
    room_id: RoomId,
    secret: Arc<NodeSecret>,
    health: Arc<RelayHealth>,
    cfg: RegistrationConfig,
) -> JoinHandle<()> {
    health.reset();
    tokio::spawn(async move {
        let mut rounds: u32 = 0;
        let mut was_healthy = true;
        loop {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0);
            let pkt = protocol::encode_register(&room_id, &secret, now_ms);
            match socket.send_to(&pkt, relay).await {
                Ok(_) => debug!(%relay, room = %room_id, "relay registration sent"),
                Err(e) => warn!(%relay, ?e, "relay registration send failed"),
            }

            health.evaluate(cfg.ack_timeout);
            let now_healthy = health.is_healthy();
            if was_healthy && !now_healthy {
                warn!(%relay, "relay stopped acking registrations — marked unhealthy");
            } else if !was_healthy && now_healthy {
                info!(%relay, "relay is acking again — healthy");
            }
            was_healthy = now_healthy;

            rounds = rounds.saturating_add(1);
            // Keep probing aggressively while unhealthy so recovery is
            // detected quickly.
            let interval = if rounds <= cfg.initial_rounds || !now_healthy {
                cfg.initial_interval
            } else {
                cfg.reregister_interval
            };
            tokio::time::sleep(interval).await;
        }
    })
}
