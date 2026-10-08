//! Per-peer WireGuard tunnel built on top of `boringtun`.
//!
//! Each [`PeerTunnel`] wraps a single `boringtun::noise::Tunn` state
//! machine plus a reference to the shared UDP socket that also carries
//! every other peer's traffic (one socket per Hermes node). A dedicated
//! timer task wakes every second to invoke `Tunn::update_timers`, which
//! is how `boringtun` drives keepalives, handshake retransmissions, and
//! session rekeys — if we skipped this, the tunnel would silently go
//! stale after the 180-second reject-after-time deadline.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::framing;
use crate::crypto::{NodeId, NodeSecret};
use crate::error::{HermesError, Result};
use crate::relay::protocol as relay_protocol;
use crate::tap::DATAGRAM_BUFFER_SIZE;

/// Where a tunnel's encrypted datagrams travel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerPath {
    /// Straight to the peer's UDP endpoint (found via NAT traversal).
    Direct(SocketAddr),
    /// Via a relay server which forwards to the destination node.
    Relayed {
        /// The relay server's UDP address.
        relay: SocketAddr,
        /// The destination node the relay should forward to.
        dest: NodeId,
    },
}

impl PeerPath {
    /// The direct endpoint, if this is a direct path.
    #[must_use]
    pub fn direct_endpoint(&self) -> Option<SocketAddr> {
        match self {
            Self::Direct(addr) => Some(*addr),
            Self::Relayed { .. } => None,
        }
    }
}

impl std::fmt::Display for PeerPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct(addr) => write!(f, "direct({addr})"),
            Self::Relayed { relay, dest } => write!(f, "relayed({relay} -> {})", dest.short()),
        }
    }
}

/// Source of per-tunnel WireGuard indices. boringtun puts `index << 8`
/// in the receiver-index field of every packet addressed to us, so unique
/// indices let the mesh map a datagram from an unknown address (a roaming
/// peer) back to its tunnel. Must stay below 2^24.
static NEXT_INDEX: AtomicU32 = AtomicU32::new(1);

fn allocate_index() -> u32 {
    NEXT_INDEX.fetch_add(1, Ordering::Relaxed) & 0x00FF_FFFF
}

/// Live traffic counters for a tunnel.
#[derive(Debug, Default)]
pub struct TunnelStats {
    /// Outbound Ethernet frames passed into the tunnel.
    pub frames_tx: AtomicU64,
    /// Inbound Ethernet frames received from the tunnel.
    pub frames_rx: AtomicU64,
    /// Encrypted bytes sent on the wire.
    pub bytes_tx: AtomicU64,
    /// Encrypted bytes received on the wire.
    pub bytes_rx: AtomicU64,
    /// Seconds since the most recent successful handshake (0 if none yet).
    /// Refreshed each time the timer task runs.
    pub last_handshake_secs: AtomicU64,
    /// Most recent round-trip time in microseconds, measured by the
    /// in-tunnel ping (0 = not measured yet).
    pub rtt_us: AtomicU64,
}

/// Seconds between latency pings (counted in timer ticks).
const PING_EVERY_TICKS: u32 = 5;
/// Control message types (first byte of a control payload).
const CTL_PING: u8 = 1;
const CTL_PONG: u8 = 2;

/// A WireGuard tunnel to a single peer.
///
/// Wraps `boringtun::noise::Tunn`. Access to the state machine is
/// serialised with a `parking_lot::Mutex` because WireGuard crypto is
/// stateful per packet.
pub struct PeerTunnel {
    /// The peer this tunnel connects to.
    pub peer: NodeId,
    /// The peer's WireGuard X25519 public key.
    peer_wg_pub: [u8; 32],
    /// Our WireGuard index for this tunnel (see [`NEXT_INDEX`]).
    local_index: u32,
    /// Current path our datagrams take. Updated when ICE finds a better
    /// route (direct mode) — fixed for the room's lifetime in relayed mode.
    path: Mutex<PeerPath>,
    /// Shared UDP socket used by the whole engine (one socket per node).
    socket: Arc<UdpSocket>,
    /// boringtun state machine.
    tunn: Mutex<boringtun::noise::Tunn>,
    /// Stats.
    stats: TunnelStats,
    /// Handle to the background timer task. Aborted on drop.
    timer_task: Mutex<Option<JoinHandle<()>>>,
    /// Time base for ping timestamps.
    created: Instant,
    /// Timer ticks since creation (paces the latency ping).
    ticks: AtomicU32,
}

impl PeerTunnel {
    /// Construct a new tunnel to `peer` and start its keepalive timer.
    ///
    /// # Errors
    /// Currently infallible (WireGuard key setup is in-memory), but returns
    /// a `Result` for forward compatibility with pre-shared-key support.
    pub fn new(
        peer: NodeId,
        peer_wg_pub: [u8; 32],
        our_secret: &NodeSecret,
        path: PeerPath,
        socket: Arc<UdpSocket>,
    ) -> Result<Arc<Self>> {
        let our_wg = our_secret.wireguard_secret();
        let our_wg_bytes: [u8; 32] = our_wg.to_bytes();
        let static_private: x25519_dalek::StaticSecret = our_wg_bytes.into();
        let peer_public: x25519_dalek::PublicKey = peer_wg_pub.into();

        let local_index = allocate_index();
        // Tunn::new() returns `Self` directly in boringtun 0.6+.
        let tunn = boringtun::noise::Tunn::new(
            static_private,
            peer_public,
            None,     // no pre-shared key in v1
            Some(25), // WireGuard keepalive every 25s
            local_index,
            None, // default per-tunnel handshake rate limiter
        );

        let this = Arc::new(Self {
            peer,
            peer_wg_pub,
            local_index,
            path: Mutex::new(path),
            socket,
            tunn: Mutex::new(tunn),
            stats: TunnelStats::default(),
            timer_task: Mutex::new(None),
            created: Instant::now(),
            ticks: AtomicU32::new(0),
        });

        // Spawn the timer task. It holds a weak reference so the tunnel
        // can be dropped cleanly when no one else holds a strong Arc.
        let weak = Arc::downgrade(&this);
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let Some(tunnel) = weak.upgrade() else {
                    break;
                };
                if let Err(e) = tunnel.tick().await {
                    debug!(peer = %tunnel.peer.short(), ?e, "tunnel tick error");
                }
            }
        });
        *this.timer_task.lock() = Some(handle);

        Ok(this)
    }

    /// Update the path (called when NAT traversal finds a better route).
    pub fn set_path(&self, path: PeerPath) {
        let mut guard = self.path.lock();
        if *guard != path {
            debug!(peer = %self.peer.short(), old = %*guard, new = %path, "path updated");
            *guard = path;
        }
    }

    /// Current path.
    #[must_use]
    pub fn path(&self) -> PeerPath {
        *self.path.lock()
    }

    /// The peer's WireGuard public key.
    #[must_use]
    pub fn peer_wireguard_public(&self) -> [u8; 32] {
        self.peer_wg_pub
    }

    /// Our WireGuard index for this tunnel — the upper 24 bits of the
    /// receiver index on every packet the peer sends us.
    #[must_use]
    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    /// Send an already-encrypted WireGuard datagram along the current
    /// path, wrapping it in a relay DATA header when the path is relayed.
    async fn send_raw(&self, packet: &[u8]) -> Result<usize> {
        match self.path() {
            PeerPath::Direct(addr) => Ok(self.socket.send_to(packet, addr).await?),
            PeerPath::Relayed { relay, dest } => {
                let framed = relay_protocol::encode_data(&dest, packet);
                self.socket.send_to(&framed, relay).await?;
                Ok(framed.len())
            }
        }
    }

    /// Statistics snapshot.
    #[must_use]
    pub fn stats(&self) -> &TunnelStats {
        &self.stats
    }

    /// Encrypt an Ethernet frame and send it on the wire to the remote peer.
    ///
    /// # Errors
    /// Fails if encryption or the socket write fails.
    pub async fn send(&self, eth_frame: &[u8]) -> Result<()> {
        // Wrap the Ethernet frame in our synthetic IPv4 header so boringtun
        // accepts the packet (WireGuard expects IP datagrams).
        if self
            .encrypt_and_send(&framing::encode_frame(eth_frame))
            .await?
        {
            self.stats.frames_tx.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Send a tunnel control message (not counted as a frame).
    async fn send_control(&self, msg: &[u8]) -> Result<()> {
        self.encrypt_and_send(&framing::encode_control(msg))
            .await
            .map(|_| ())
    }

    /// Encrypt a framed packet and put it on the wire. Returns `true` if a
    /// datagram was sent now (`false` if boringtun queued it pending a
    /// handshake).
    async fn encrypt_and_send(&self, wrapped: &[u8]) -> Result<bool> {
        let mut dst = [0u8; DATAGRAM_BUFFER_SIZE];
        let result = {
            let mut t = self.tunn.lock();
            t.encapsulate(wrapped, &mut dst)
        };

        use boringtun::noise::TunnResult;
        match result {
            TunnResult::WriteToNetwork(packet) => {
                let n = self.send_raw(packet).await?;
                self.stats.bytes_tx.fetch_add(n as u64, Ordering::Relaxed);
                Ok(true)
            }
            TunnResult::Done => Ok(false),
            TunnResult::Err(e) => Err(HermesError::Tunnel(format!("encap: {e:?}"))),
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                warn!("unexpected tunnel-write during encapsulate");
                Ok(false)
            }
        }
    }

    /// Microseconds since this tunnel was created (ping timestamps).
    fn now_us(&self) -> u64 {
        u64::try_from(self.created.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    /// Handle a decrypted control message from the peer.
    async fn on_control(&self, msg: &[u8]) -> Result<()> {
        let Some((&kind, rest)) = msg.split_first() else {
            return Ok(());
        };
        match kind {
            CTL_PING => {
                // Echo the peer's timestamp back unchanged.
                let mut pong = Vec::with_capacity(msg.len());
                pong.push(CTL_PONG);
                pong.extend_from_slice(rest);
                self.send_control(&pong).await
            }
            CTL_PONG => {
                if let Ok(sent) = <[u8; 8]>::try_from(rest) {
                    let rtt = self.now_us().saturating_sub(u64::from_be_bytes(sent));
                    // Never store 0: that means "unknown".
                    self.stats.rtt_us.store(rtt.max(1), Ordering::Relaxed);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Most recent measured round-trip time in milliseconds.
    #[must_use]
    pub fn rtt_ms(&self) -> Option<u32> {
        match self.stats.rtt_us.load(Ordering::Relaxed) {
            0 => None,
            us => Some(u32::try_from(us.div_ceil(1000)).unwrap_or(u32::MAX)),
        }
    }

    /// Handle a UDP datagram received from the network — runs it through
    /// boringtun and returns the decrypted Ethernet frame (if any).
    ///
    /// A single inbound datagram can trigger several boringtun actions:
    /// writing a handshake response back to the network, silently
    /// discarding a cookie, etc. We loop until the state machine is
    /// quiescent, per the `boringtun` API contract.
    ///
    /// # Errors
    /// Fails on decryption or socket write errors.
    pub async fn on_datagram(&self, datagram: &[u8]) -> Result<Option<BytesMut>> {
        self.process(datagram, None).await
    }

    /// Like [`Self::on_datagram`], but any packets boringtun wants to send
    /// in response go straight to `reply_to` instead of along the current
    /// path. Used when a peer roams: the mesh feeds the datagram from the
    /// peer's *new* address through here, and only switches the tunnel's
    /// path once WireGuard has authenticated it (i.e. this returns `Ok`).
    ///
    /// # Errors
    /// Fails on decryption or socket write errors.
    pub async fn on_datagram_from(
        &self,
        datagram: &[u8],
        reply_to: SocketAddr,
    ) -> Result<Option<BytesMut>> {
        self.process(datagram, Some(reply_to)).await
    }

    async fn process(
        &self,
        datagram: &[u8],
        reply_to: Option<SocketAddr>,
    ) -> Result<Option<BytesMut>> {
        self.stats
            .bytes_rx
            .fetch_add(datagram.len() as u64, Ordering::Relaxed);

        let mut dst = [0u8; DATAGRAM_BUFFER_SIZE];
        let mut eth_out: Option<BytesMut> = None;
        let mut control: Option<Vec<u8>> = None;

        // First call consumes the datagram; follow-up calls pass an empty
        // slice to drain any queued outbound handshake/keepalive packets,
        // as required by boringtun's API.
        let mut input: &[u8] = datagram;
        loop {
            let result = {
                let mut t = self.tunn.lock();
                t.decapsulate(None, input, &mut dst)
            };

            use boringtun::noise::TunnResult;
            match result {
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    return Err(HermesError::Tunnel(format!("decap: {e:?}")));
                }
                TunnResult::WriteToNetwork(packet) => {
                    let n = match reply_to {
                        Some(addr) => self.socket.send_to(packet, addr).await?,
                        None => self.send_raw(packet).await?,
                    };
                    self.stats.bytes_tx.fetch_add(n as u64, Ordering::Relaxed);
                    input = &[];
                    continue;
                }
                TunnResult::WriteToTunnelV4(inner, _) | TunnResult::WriteToTunnelV6(inner, _) => {
                    match framing::decode_packet(inner) {
                        Some((_, framing::Payload::Frame(eth))) => {
                            self.stats.frames_rx.fetch_add(1, Ordering::Relaxed);
                            let mut buf = BytesMut::with_capacity(eth.len());
                            buf.extend_from_slice(eth);
                            eth_out = Some(buf);
                        }
                        Some((_, framing::Payload::Control(msg))) => control = Some(msg.to_vec()),
                        None => {
                            warn!(peer = %self.peer.short(), "decrypted packet is not a Hermes frame");
                        }
                    }
                    break;
                }
            }
        }

        if let Some(msg) = control {
            self.on_control(&msg).await?;
        }
        Ok(eth_out)
    }

    /// Called once per second by the timer task. Drives keepalives and
    /// updates the handshake-age stat.
    async fn tick(&self) -> Result<()> {
        let mut dst = [0u8; DATAGRAM_BUFFER_SIZE];
        let result = {
            let mut t = self.tunn.lock();
            t.update_timers(&mut dst)
        };

        use boringtun::noise::TunnResult;
        match result {
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                return Err(HermesError::Tunnel(format!("timer: {e:?}")));
            }
            TunnResult::WriteToNetwork(packet) => {
                let n = self.send_raw(packet).await?;
                self.stats.bytes_tx.fetch_add(n as u64, Ordering::Relaxed);
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                // update_timers should never produce an inbound-bound packet.
                debug!("unexpected tunnel-write from update_timers");
            }
        }

        // Refresh handshake-age stat.
        let since = {
            let t = self.tunn.lock();
            t.time_since_last_handshake()
        };
        if let Some(d) = since {
            self.stats
                .last_handshake_secs
                .store(d.as_secs(), Ordering::Relaxed);
        }

        // Latency ping, once a session exists (pinging before that would
        // only queue packets behind the handshake).
        let tick = self.ticks.fetch_add(1, Ordering::Relaxed);
        if since.is_some() && tick % PING_EVERY_TICKS == 0 {
            self.send_ping().await?;
        }
        Ok(())
    }

    /// Send a latency ping now; the peer's pong updates [`Self::rtt_ms`].
    /// The timer task does this every few seconds on its own.
    ///
    /// # Errors
    /// Fails if encryption or the socket write fails.
    pub async fn send_ping(&self) -> Result<()> {
        let mut ping = Vec::with_capacity(9);
        ping.push(CTL_PING);
        ping.extend_from_slice(&self.now_us().to_be_bytes());
        self.send_control(&ping).await
    }
}

impl Drop for PeerTunnel {
    fn drop(&mut self) {
        if let Some(handle) = self.timer_task.lock().take() {
            handle.abort();
        }
    }
}
