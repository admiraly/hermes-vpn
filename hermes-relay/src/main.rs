//! Hermes relay server — the "central server" behind relayed rooms.
//!
//! A single UDP socket. Clients `REGISTER` (Ed25519-signed) to announce
//! "I am node N in room R at this address"; afterwards their `DATA`
//! packets addressed to another member of the same room are rewritten to
//! `FORWARD` and delivered to that member's registered address.
//!
//! ## Multi-homed hosts
//!
//! A UDP reply must come from the address the client sent to — clients
//! ignore relay traffic from any other source, and so do most NATs. A
//! socket bound to `0.0.0.0` can't promise that: the kernel picks the
//! reply's source address by routing, which on a host with several IPs
//! may be a different one. So a wildcard bind (the default) opens **one
//! socket per local IPv4 address** instead, re-scanning periodically for
//! addresses that come and go, and each session remembers which socket
//! its client talks to. Binding a specific address uses just that one.
//!
//! The relay never sees plaintext — payloads are WireGuard ciphertext,
//! end-to-end encrypted between the two peers — and it never needs any
//! long-term secret of its own. See `docs/ARCHITECTURE.md` for the wire
//! format and the replay-protection rules implemented here.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use hermes_core::crypto::NodeId;
use hermes_core::metrics::{self, Exposition};
use hermes_core::ratelimit::{Rate, RateLimiter};
use hermes_core::relay::protocol::{self, RelayPacket};
use hermes_core::room::RoomId;
use hermes_core::tap::DATAGRAM_BUFFER_SIZE;

/// A registration goes stale if not refreshed within this window.
/// Clients re-register every 15 s.
const SESSION_TTL: Duration = Duration::from_secs(60);

/// How often the reaper sweeps stale sessions.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// How often a wildcard-bound relay re-scans the host's addresses.
const RESCAN_INTERVAL: Duration = Duration::from_secs(30);

/// Largest datagram we accept — the client's datagram buffer size, so the
/// relay can never truncate a frame a client could legitimately send.
const MAX_DATAGRAM: usize = DATAGRAM_BUFFER_SIZE;

/// One registered (room, node) endpoint.
struct Session {
    addr: SocketAddr,
    /// The local socket this client talks to — every reply to it must
    /// leave through the same socket (and therefore the same address).
    via: Arc<UdpSocket>,
    last_seen: Instant,
    /// Highest registration timestamp seen — replay guard.
    last_ts: u64,
}

/// Abuse limits. Defaults suit a public relay; each can be overridden by
/// an environment variable (see [`Limits::from_env`]).
#[derive(Clone, Copy, Debug)]
struct Limits {
    /// Sessions one source IP may hold (households and CGNAT put many
    /// clients behind one address, so this is generous).
    sessions_per_ip: usize,
    /// Sessions in total.
    max_sessions: usize,
    /// REGISTERs per second per source IP (each costs a signature check).
    /// Sized for CGNAT: a few hundred clients behind one address each
    /// register every 2 s while starting up.
    registers_per_sec: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            sessions_per_ip: 256,
            max_sessions: 100_000,
            registers_per_sec: 100,
        }
    }
}

impl Limits {
    fn from_env() -> Self {
        let get = |name: &str, default: usize| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        };
        let d = Self::default();
        Self {
            sessions_per_ip: get("HERMES_RELAY_MAX_SESSIONS_PER_IP", d.sessions_per_ip),
            max_sessions: get("HERMES_RELAY_MAX_SESSIONS", d.max_sessions),
            registers_per_sec: u32::try_from(get(
                "HERMES_RELAY_REGISTERS_PER_SEC",
                d.registers_per_sec as usize,
            ))
            .unwrap_or(d.registers_per_sec),
        }
    }
}

/// Operational counters, exposed at `/metrics` when `HERMES_RELAY_METRICS_BIND`
/// is set. All aggregate; nothing identifies a node or an address.
#[derive(Default)]
struct Counters {
    registers_accepted: AtomicU64,
    registers_bad_signature: AtomicU64,
    registers_replay: AtomicU64,
    registers_limited: AtomicU64,
    packets_forwarded: AtomicU64,
    bytes_forwarded: AtomicU64,
    dropped_unregistered_sender: AtomicU64,
    dropped_queue_full: AtomicU64,
    packets_queued: AtomicU64,
    packets_released_from_queue: AtomicU64,
    sessions_expired: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// How long a DATA packet for a not-yet-registered destination is held.
const PENDING_TTL: Duration = Duration::from_secs(3);
/// Packets held per destination (enough for a WireGuard handshake
/// initiation plus a retransmit or two).
const PENDING_PER_DEST: usize = 4;
/// Packets held in total — bounds memory however many bogus
/// destinations senders name.
const PENDING_TOTAL: usize = 4096;

/// A DATA packet waiting for its destination to register.
struct Pending {
    queued: Instant,
    src: NodeId,
    payload: Vec<u8>,
}

struct State {
    limits: Limits,
    /// (room, node) → session.
    sessions: DashMap<(RoomId, NodeId), Session>,
    /// Current source address → (room, node). Lets DATA packets identify
    /// their sender without carrying credentials.
    by_addr: DashMap<SocketAddr, (RoomId, NodeId)>,
    /// Sessions per source IP (for the per-IP cap).
    per_ip: DashMap<IpAddr, usize>,
    /// REGISTER rate limiter, keyed by source IP.
    register_limiter: RateLimiter<IpAddr>,
    /// Packets for destinations that haven't registered yet. Two peers
    /// join a relayed room at nearly the same moment; without this, the
    /// first WireGuard handshake initiation is dropped if it beats the
    /// peer's registration, costing a 5 s retransmit.
    pending: DashMap<(RoomId, NodeId), Vec<Pending>>,
    pending_total: AtomicUsize,
    counters: Counters,
    started: Instant,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

/// Outcome of processing a REGISTER.
#[derive(Debug, PartialEq, Eq)]
enum Registration {
    /// Accepted — ack it.
    Accepted,
    /// Bad signature.
    BadSignature,
    /// Stale timestamp from a new address — a replayed capture.
    Replay,
    /// Source exceeded its REGISTER rate or session quota.
    Limited,
}

/// What to do with a DATA packet.
enum Routed {
    /// Forward to `target` through `via`, stamped with sender `src`.
    Forward {
        target: SocketAddr,
        via: Arc<UdpSocket>,
        src: NodeId,
    },
    /// Held until the destination registers.
    Queued,
    /// Undeliverable.
    Dropped,
}

impl State {
    fn new(limits: Limits) -> Self {
        let rps = limits.registers_per_sec.max(1);
        Self {
            limits,
            sessions: DashMap::new(),
            by_addr: DashMap::new(),
            per_ip: DashMap::new(),
            register_limiter: RateLimiter::new(Rate::new(rps, Duration::from_secs(1), rps * 2)),
            pending: DashMap::new(),
            pending_total: AtomicUsize::new(0),
            counters: Counters::default(),
            started: Instant::now(),
        }
    }

    /// Snapshot in Prometheus text format.
    fn metrics(&self) -> String {
        let c = &self.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Exposition::new()
            .gauge(
                "hermes_relay_sessions",
                "Registered (room, node) sessions.",
                self.sessions.len() as u64,
            )
            .gauge(
                "hermes_relay_pending_packets",
                "Packets held for destinations that haven't registered.",
                self.pending_total.load(Ordering::Relaxed) as u64,
            )
            .gauge(
                "hermes_relay_uptime_seconds",
                "Seconds since start.",
                self.started.elapsed().as_secs(),
            )
            .labeled_counter(
                "hermes_relay_registers_total",
                "REGISTER packets by outcome.",
                "result",
                &[
                    ("accepted", get(&c.registers_accepted)),
                    ("bad_signature", get(&c.registers_bad_signature)),
                    ("replay", get(&c.registers_replay)),
                    ("limited", get(&c.registers_limited)),
                ],
            )
            .counter(
                "hermes_relay_forwarded_packets_total",
                "DATA packets forwarded.",
                get(&c.packets_forwarded),
            )
            .counter(
                "hermes_relay_forwarded_bytes_total",
                "Payload bytes forwarded.",
                get(&c.bytes_forwarded),
            )
            .counter(
                "hermes_relay_queued_packets_total",
                "Packets held for a not-yet-registered destination.",
                get(&c.packets_queued),
            )
            .counter(
                "hermes_relay_released_packets_total",
                "Held packets delivered after the destination registered.",
                get(&c.packets_released_from_queue),
            )
            .labeled_counter(
                "hermes_relay_dropped_packets_total",
                "DATA packets dropped, by reason.",
                "reason",
                &[
                    ("unregistered_sender", get(&c.dropped_unregistered_sender)),
                    ("queue_full", get(&c.dropped_queue_full)),
                ],
            )
            .counter(
                "hermes_relay_sessions_expired_total",
                "Sessions removed after going quiet.",
                get(&c.sessions_expired),
            )
            .finish()
    }

    fn ip_count(&self, ip: IpAddr) -> usize {
        self.per_ip.get(&ip).map_or(0, |c| *c)
    }

    fn ip_add(&self, ip: IpAddr) {
        *self.per_ip.entry(ip).or_insert(0) += 1;
    }

    fn ip_remove(&self, ip: IpAddr) {
        self.per_ip.remove_if_mut(&ip, |_, c| {
            *c = c.saturating_sub(1);
            *c == 0
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn register(
        &self,
        from: SocketAddr,
        via: &Arc<UdpSocket>,
        room_id: RoomId,
        node_id: NodeId,
        timestamp_ms: u64,
        signature: &[u8; 64],
    ) -> Registration {
        // Rate-limit before the (comparatively expensive) signature check.
        if !self.register_limiter.check(&from.ip()) {
            return Registration::Limited;
        }
        if !protocol::verify_register(&room_id, &node_id, timestamp_ms, signature) {
            return Registration::BadSignature;
        }
        let key = (room_id, node_id);
        let now = Instant::now();

        let previous_addr = match self.sessions.get_mut(&key) {
            Some(mut s) => {
                // Strictly newer timestamps may move the session anywhere
                // (the client's NAT mapping changed). An old or repeated
                // timestamp is only a harmless retransmit if it comes from
                // the address already registered; from anywhere else it's
                // someone replaying a captured packet to hijack the session.
                if timestamp_ms <= s.last_ts && s.addr != from {
                    return Registration::Replay;
                }
                if s.addr.ip() != from.ip()
                    && self.ip_count(from.ip()) >= self.limits.sessions_per_ip
                {
                    return Registration::Limited;
                }
                let prev = s.addr;
                s.addr = from;
                s.via = via.clone();
                s.last_seen = now;
                s.last_ts = s.last_ts.max(timestamp_ms);
                Some(prev)
            }
            None => {
                // A socket re-registering as something else (it left one
                // room for another) replaces its old session, so it doesn't
                // count against the caps twice.
                let replacing = self.by_addr.get(&from).is_some_and(|k| *k != key);
                if !replacing
                    && (self.sessions.len() >= self.limits.max_sessions
                        || self.ip_count(from.ip()) >= self.limits.sessions_per_ip)
                {
                    return Registration::Limited;
                }
                self.sessions.insert(
                    key,
                    Session {
                        addr: from,
                        via: via.clone(),
                        last_seen: now,
                        last_ts: timestamp_ms,
                    },
                );
                self.ip_add(from.ip());
                None
            }
        };

        if let Some(prev) = previous_addr {
            if prev != from {
                self.by_addr.remove(&prev);
                if prev.ip() != from.ip() {
                    self.ip_remove(prev.ip());
                    self.ip_add(from.ip());
                }
                info!(node = %node_id.short(), %prev, new = %from, "session moved");
            }
        } else {
            info!(node = %node_id.short(), room = %room_id, %from, "session registered");
        }

        // One address = one session: if this socket was registered as
        // something else (e.g. it left one room for another), drop that.
        if let Some(old) = self.by_addr.insert(from, key) {
            if old != key && self.sessions.remove(&old).is_some() {
                self.ip_remove(from.ip());
            }
        }
        Registration::Accepted
    }

    /// Decide what to do with a DATA packet from `from` to `dest`.
    fn route(&self, from: SocketAddr, dest: NodeId, payload: &[u8]) -> Routed {
        let Some((room, src)) = self.by_addr.get(&from).map(|k| *k) else {
            bump(&self.counters.dropped_unregistered_sender); // can't send until registered
            return Routed::Dropped;
        };
        if let Some(target) = self.sessions.get(&(room, dest)) {
            return Routed::Forward {
                target: target.addr,
                via: target.via.clone(),
                src,
            };
        }
        // Destination not registered (yet): hold a few packets briefly.
        if self.pending_total.load(Ordering::Relaxed) >= PENDING_TOTAL {
            bump(&self.counters.dropped_queue_full);
            return Routed::Dropped;
        }
        let mut queue = self.pending.entry((room, dest)).or_default();
        queue.retain(|p| p.queued.elapsed() < PENDING_TTL);
        if queue.len() >= PENDING_PER_DEST {
            bump(&self.counters.dropped_queue_full);
            return Routed::Dropped;
        }
        queue.push(Pending {
            queued: Instant::now(),
            src,
            payload: payload.to_vec(),
        });
        self.pending_total.fetch_add(1, Ordering::Relaxed);
        bump(&self.counters.packets_queued);
        Routed::Queued
    }

    /// Packets that were waiting for (room, node) to register, still fresh.
    fn take_pending(&self, room: RoomId, node: NodeId) -> Vec<Pending> {
        let Some((_, queue)) = self.pending.remove(&(room, node)) else {
            return Vec::new();
        };
        self.pending_total.fetch_sub(queue.len(), Ordering::Relaxed);
        queue
            .into_iter()
            .filter(|p| p.queued.elapsed() < PENDING_TTL)
            .collect()
    }

    fn sweep(&self) {
        let now = Instant::now();
        let mut expired = Vec::new();
        self.sessions.retain(|key, s| {
            let alive = now.duration_since(s.last_seen) < SESSION_TTL;
            if !alive {
                expired.push((*key, s.addr));
            }
            alive
        });
        for (key, addr) in expired {
            // Only drop the address mapping if it still points at the
            // expired session (the socket may have re-registered since).
            self.by_addr.remove_if(&addr, |_, v| *v == key);
            self.ip_remove(addr.ip());
            bump(&self.counters.sessions_expired);
            debug!(node = %key.1.short(), "session expired");
        }
        let mut dropped = 0;
        self.pending.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|p| now.duration_since(p.queued) < PENDING_TTL);
            dropped += before - queue.len();
            !queue.is_empty()
        });
        self.pending_total.fetch_sub(dropped, Ordering::Relaxed);
        self.register_limiter.prune();
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind: SocketAddr = std::env::var("HERMES_RELAY_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8788".into())
        .parse()?;
    let limits = Limits::from_env();
    info!(?limits, "abuse limits");
    let state = Arc::new(State::new(limits));

    // Stale-session reaper.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                ticker.tick().await;
                state.sweep();
            }
        });
    }

    // Optional metrics endpoint. Off unless asked for; bind it to localhost
    // or an internal interface.
    let _metrics = match metrics::bind_from_env("HERMES_RELAY_METRICS_BIND")? {
        Some(addr) => {
            let state = state.clone();
            let (bound, task) = metrics::serve(addr, Arc::new(move || state.metrics())).await?;
            info!(%bound, "metrics at /metrics");
            Some(task)
        }
        None => None,
    };

    tokio::select! {
        res = run_listeners(bind, state) => res,
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received");
            Ok(())
        }
    }
}

/// Bind and serve. A specific address gets one socket; a wildcard gets
/// one socket per local IPv4 address, kept in sync with the host.
async fn run_listeners(bind: SocketAddr, state: Arc<State>) -> anyhow::Result<()> {
    if !bind.ip().is_unspecified() {
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        info!(%bind, "hermes-relay listening");
        serve(socket, state).await;
        return Ok(());
    }

    let mut port = bind.port();
    let mut listeners: HashMap<IpAddr, JoinHandle<()>> = HashMap::new();
    loop {
        let wanted = local_ipv4_addrs();
        listeners.retain(|ip, task| {
            let keep = wanted.contains(ip) && !task.is_finished();
            if !keep {
                task.abort();
                info!(%ip, "address gone — stopped listening on it");
            }
            keep
        });
        for ip in wanted {
            if listeners.contains_key(&ip) {
                continue;
            }
            match UdpSocket::bind(SocketAddr::new(ip, port)).await {
                Ok(socket) => {
                    let local = socket.local_addr()?;
                    // With port 0, the first socket picks the port and the
                    // rest share it, so clients see one relay port.
                    port = local.port();
                    info!(bind = %local, "hermes-relay listening");
                    listeners.insert(ip, tokio::spawn(serve(Arc::new(socket), state.clone())));
                }
                Err(e) => warn!(%ip, port, ?e, "could not bind"),
            }
        }
        if listeners.is_empty() {
            anyhow::bail!("could not bind any local IPv4 address on port {port}");
        }
        tokio::time::sleep(RESCAN_INTERVAL).await;
    }
}

/// Every IPv4 address configured on this host, loopback included.
fn local_ipv4_addrs() -> Vec<IpAddr> {
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => {
            let mut ips: Vec<IpAddr> = ifaces
                .iter()
                .map(if_addrs::Interface::ip)
                .filter(IpAddr::is_ipv4)
                .collect();
            ips.sort_unstable();
            ips.dedup();
            ips
        }
        Err(e) => {
            warn!(?e, "could not enumerate interfaces");
            Vec::new()
        }
    }
}

/// Serve one socket until it fails.
async fn serve(socket: Arc<UdpSocket>, state: Arc<State>) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                // ICMP port-unreachable from a vanished client surfaces as
                // a recv error on some platforms (Windows WSAECONNRESET).
                // It's never fatal for a UDP server.
                debug!(?e, "recv_from error");
                continue;
            }
        };
        match protocol::parse_packet(&buf[..len]) {
            Some(RelayPacket::Register {
                room_id,
                node_id,
                timestamp_ms,
                signature,
            }) => match state.register(from, &socket, room_id, node_id, timestamp_ms, &signature) {
                Registration::Accepted => {
                    bump(&state.counters.registers_accepted);
                    let ack = protocol::encode_register_ack(&room_id);
                    if let Err(e) = socket.send_to(&ack, from).await {
                        debug!(%from, ?e, "ack send failed");
                    }
                    // Deliver anything that arrived for this node before it
                    // registered.
                    for p in state.take_pending(room_id, node_id) {
                        bump(&state.counters.packets_released_from_queue);
                        let fwd = protocol::encode_forward(&p.src, &p.payload);
                        if let Err(e) = socket.send_to(&fwd, from).await {
                            debug!(%from, ?e, "pending forward failed");
                        }
                    }
                }
                Registration::Limited => {
                    bump(&state.counters.registers_limited);
                    debug!(%from, "REGISTER over rate or session limit — dropped");
                }
                Registration::BadSignature => {
                    bump(&state.counters.registers_bad_signature);
                    warn!(%from, node = %node_id.short(), "REGISTER with bad signature");
                }
                Registration::Replay => {
                    bump(&state.counters.registers_replay);
                    warn!(%from, node = %node_id.short(), "replayed REGISTER rejected");
                }
            },
            Some(RelayPacket::Data { dest, payload }) => match state.route(from, dest, payload) {
                Routed::Forward { target, via, src } => {
                    let fwd = protocol::encode_forward(&src, payload);
                    match via.send_to(&fwd, target).await {
                        Ok(_) => {
                            bump(&state.counters.packets_forwarded);
                            state
                                .counters
                                .bytes_forwarded
                                .fetch_add(payload.len() as u64, Ordering::Relaxed);
                        }
                        Err(e) => debug!(%target, ?e, "forward send failed"),
                    }
                }
                Routed::Queued => {
                    debug!(%from, dest = %dest.short(), "DATA held for unregistered dest")
                }
                Routed::Dropped => {
                    debug!(%from, dest = %dest.short(), "undeliverable DATA dropped")
                }
            },
            // Clients never send ACK/FORWARD; anything else is noise.
            _ => debug!(%from, len, "ignoring non-relay datagram"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermes_core::crypto::NodeSecret;
    use hermes_core::relay::protocol::encode_register;

    async fn sock() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    /// The forward decision for DATA, as (target, via, src).
    fn fwd(
        state: &State,
        from: &str,
        dest: NodeId,
    ) -> Option<(SocketAddr, Arc<UdpSocket>, NodeId)> {
        match state.route(from.parse().unwrap(), dest, b"x") {
            Routed::Forward { target, via, src } => Some((target, via, src)),
            Routed::Queued | Routed::Dropped => None,
        }
    }

    fn register(
        state: &State,
        via: &Arc<UdpSocket>,
        from: &str,
        room: RoomId,
        secret: &NodeSecret,
        ts: u64,
    ) -> Registration {
        let pkt = encode_register(&room, secret, ts);
        let Some(RelayPacket::Register {
            room_id,
            node_id,
            timestamp_ms,
            signature,
        }) = protocol::parse_packet(&pkt)
        else {
            panic!("bad packet");
        };
        state.register(
            from.parse().unwrap(),
            via,
            room_id,
            node_id,
            timestamp_ms,
            &signature,
        )
    }

    #[tokio::test]
    async fn replay_from_new_address_is_rejected_but_retransmit_is_fine() {
        let state = State::default();
        let via = sock().await;
        let room = RoomId::new_v4();
        let alice = NodeSecret::generate();
        let reg = |from: &str, ts| register(&state, &via, from, room, &alice, ts);
        assert_eq!(reg("1.1.1.1:1000", 10), Registration::Accepted);
        // Same packet again from the same address: a retransmit.
        assert_eq!(reg("1.1.1.1:1000", 10), Registration::Accepted);
        // Same packet from an attacker's address: replay.
        assert_eq!(reg("6.6.6.6:666", 10), Registration::Replay);
        // A genuinely newer registration may move (NAT rebinding).
        assert_eq!(reg("2.2.2.2:2000", 11), Registration::Accepted);
        assert!(state
            .by_addr
            .get(&"1.1.1.1:1000".parse().unwrap())
            .is_none());
    }

    #[tokio::test]
    async fn routing_is_scoped_to_the_senders_room() {
        let state = State::default();
        let via = sock().await;
        let (room_a, room_b) = (RoomId::new_v4(), RoomId::new_v4());
        let (alice, bob, mallory) = (
            NodeSecret::generate(),
            NodeSecret::generate(),
            NodeSecret::generate(),
        );
        register(&state, &via, "1.1.1.1:1", room_a, &alice, 1);
        register(&state, &via, "2.2.2.2:2", room_a, &bob, 1);
        register(&state, &via, "3.3.3.3:3", room_b, &mallory, 1);

        let bob_id = bob.public().node_id;
        let (target, _, src) = fwd(&state, "1.1.1.1:1", bob_id).unwrap();
        assert_eq!(target, "2.2.2.2:2".parse().unwrap());
        assert_eq!(src, alice.public().node_id);
        // Mallory is in another room: can't reach Bob.
        assert!(matches!(
            state.route("3.3.3.3:3".parse().unwrap(), bob_id, b"x"),
            Routed::Dropped | Routed::Queued
        ));
        // Unregistered senders can't send at all.
        assert!(matches!(
            state.route("9.9.9.9:9".parse().unwrap(), bob_id, b"x"),
            Routed::Dropped | Routed::Queued
        ));
    }

    /// Two clients reaching the relay on different local addresses: a
    /// forward to each must leave through the socket *that* client uses.
    #[tokio::test]
    async fn forwards_leave_through_the_destinations_socket() {
        let state = State::default();
        let (sock_a, sock_b) = (sock().await, sock().await);
        let room = RoomId::new_v4();
        let (alice, bob) = (NodeSecret::generate(), NodeSecret::generate());
        register(&state, &sock_a, "1.1.1.1:1", room, &alice, 1);
        register(&state, &sock_b, "2.2.2.2:2", room, &bob, 1);

        let (_, via, _) = fwd(&state, "1.1.1.1:1", bob.public().node_id).unwrap();
        assert!(Arc::ptr_eq(&via, &sock_b));
        let (_, via, _) = fwd(&state, "2.2.2.2:2", alice.public().node_id).unwrap();
        assert!(Arc::ptr_eq(&via, &sock_a));

        // A newer registration through the other address moves the session.
        register(&state, &sock_a, "2.2.2.2:2", room, &bob, 2);
        let (_, via, _) = fwd(&state, "1.1.1.1:1", bob.public().node_id).unwrap();
        assert!(Arc::ptr_eq(&via, &sock_a));
    }

    #[tokio::test]
    async fn register_rate_and_session_caps() {
        let state = State::new(Limits {
            sessions_per_ip: 2,
            max_sessions: 3,
            registers_per_sec: 1000,
        });
        let via = sock().await;
        let room = RoomId::new_v4();
        let nodes: Vec<NodeSecret> = (0..4).map(|_| NodeSecret::generate()).collect();
        assert_eq!(
            register(&state, &via, "1.1.1.1:1", room, &nodes[0], 1),
            Registration::Accepted
        );
        assert_eq!(
            register(&state, &via, "1.1.1.1:2", room, &nodes[1], 1),
            Registration::Accepted
        );
        // Third session from the same IP: over the per-IP cap.
        assert_eq!(
            register(&state, &via, "1.1.1.1:3", room, &nodes[2], 1),
            Registration::Limited
        );
        // Refreshing an existing session is always fine.
        assert_eq!(
            register(&state, &via, "1.1.1.1:1", room, &nodes[0], 2),
            Registration::Accepted
        );
        // Another IP gets its own quota — until the global cap.
        assert_eq!(
            register(&state, &via, "2.2.2.2:1", room, &nodes[2], 1),
            Registration::Accepted
        );
        assert_eq!(
            register(&state, &via, "3.3.3.3:1", room, &nodes[3], 1),
            Registration::Limited
        );

        // REGISTER flood from one IP is cut off before signature checks.
        let slow = State::new(Limits {
            registers_per_sec: 2,
            ..Limits::default()
        });
        let results: Vec<_> = (0..10)
            .map(|i| register(&slow, &via, "9.9.9.9:9", room, &nodes[0], i + 1))
            .collect();
        assert!(
            results
                .iter()
                .filter(|r| **r == Registration::Accepted)
                .count()
                <= 4
        );
        assert!(results.contains(&Registration::Limited));
    }

    #[tokio::test]
    async fn data_for_unregistered_dest_is_held_then_released() {
        let state = State::default();
        let via = sock().await;
        let room = RoomId::new_v4();
        let (alice, bob) = (NodeSecret::generate(), NodeSecret::generate());
        register(&state, &via, "1.1.1.1:1", room, &alice, 1);
        let bob_id = bob.public().node_id;

        for _ in 0..PENDING_PER_DEST {
            assert!(matches!(
                state.route("1.1.1.1:1".parse().unwrap(), bob_id, b"hs"),
                Routed::Queued
            ));
        }
        // Per-destination cap.
        assert!(matches!(
            state.route("1.1.1.1:1".parse().unwrap(), bob_id, b"hs"),
            Routed::Dropped
        ));
        // Unregistered senders can't fill the queue.
        assert!(matches!(
            state.route("6.6.6.6:6".parse().unwrap(), bob_id, b"x"),
            Routed::Dropped
        ));

        register(&state, &via, "2.2.2.2:2", room, &bob, 1);
        let held = state.take_pending(room, bob_id);
        assert_eq!(held.len(), PENDING_PER_DEST);
        assert_eq!(held[0].src, alice.public().node_id);
        assert_eq!(state.pending_total.load(Ordering::Relaxed), 0);
        assert!(state.take_pending(room, bob_id).is_empty());
    }
}
