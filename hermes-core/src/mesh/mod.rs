//! Full-mesh peer management.
//!
//! The mesh owns:
//! - The shared UDP socket used for all WireGuard + signaling NAT traffic.
//! - One [`PeerTunnel`] per peer in the current room.
//! - The demultiplexer that routes incoming UDP datagrams to the right tunnel.
//! - The [`MacRouter`] used to decide where outgoing frames (from our TAP
//!   adapter) go.
//! - Waiters for the other traffic that shares the socket: ICE probe
//!   replies and STUN responses. Everything that arrives on the socket is
//!   read by exactly one task (the driver's inbound loop), so anything
//!   that needs a reply registers here instead of calling `recv_from`.
//!
//! The [`driver`] submodule runs the two tasks that actually shuttle
//! packets at runtime.

pub mod driver;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use dashmap::DashMap;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, trace};

use crate::broadcast::{MacRouter, RouteDecision};
use crate::crypto::{NodeId, NodeSecret, VirtualMac};
use crate::error::{HermesError, Result};
use crate::nat::{ice, stun};
use crate::relay::{self, RelayHealth, RelayPacket};
use crate::tunnel::{PeerPath, PeerTunnel};

pub use driver::{spawn as spawn_driver, DriverHandle};

/// A live snapshot of one peer's tunnel — the running counters and the
/// path currently in use. Surfaced through the daemon so a UI can show
/// whether a peer went direct or fell back to a relay, and how much
/// traffic is flowing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkStats {
    /// Which peer this link reaches.
    pub node_id: NodeId,
    /// `true` if datagrams currently travel via a relay (relayed room, or
    /// a p2p peer that failed over to its fallback relay).
    pub relayed: bool,
    /// Encrypted bytes sent on the wire.
    pub bytes_tx: u64,
    /// Encrypted bytes received from the wire.
    pub bytes_rx: u64,
    /// Ethernet frames handed into the tunnel.
    pub frames_tx: u64,
    /// Ethernet frames received from the tunnel.
    pub frames_rx: u64,
    /// Seconds since the most recent successful WireGuard handshake. `0`
    /// means none has completed yet (the tunnel is still coming up).
    pub last_handshake_secs: u64,
}

/// The mesh coordinator.
pub struct Mesh {
    /// Shared UDP socket.
    pub socket: Arc<UdpSocket>,
    /// Our identity.
    pub secret: Arc<NodeSecret>,
    /// MAC → peer routing table.
    pub router: Arc<MacRouter>,
    /// Peer tunnels keyed by node id.
    tunnels: DashMap<NodeId, Arc<PeerTunnel>>,
    /// Secondary index: remote `SocketAddr` → node id. Used by the inbound
    /// demultiplexer for *direct* tunnels. Relayed tunnels are not in
    /// here — their datagrams arrive from the relay's address and carry
    /// the source node id in the relay framing instead. A relayed tunnel
    /// may gain an inbound-only alias here when its peer reaches us
    /// directly (asymmetric paths).
    by_addr: DashMap<SocketAddr, NodeId>,
    /// Our WireGuard tunnel index → node id (identifies roaming peers'
    /// transport packets).
    by_index: DashMap<u32, NodeId>,
    /// Peer WireGuard public key → node id (identifies roaming peers'
    /// handshake initiations).
    by_wg_pub: DashMap<[u8; 32], NodeId>,
    /// Our WireGuard static keypair, for anonymous handshake parsing.
    wg_static: (x25519_dalek::StaticSecret, x25519_dalek::PublicKey),
    /// The room's relay (primary in relayed rooms, fallback in p2p rooms).
    relay: parking_lot::RwLock<Option<SocketAddr>>,
    /// Ack-driven health of the relay registration.
    relay_health: Arc<RelayHealth>,
    /// In-flight ICE probes: nonce → (candidate index, reply source).
    probes: DashMap<u64, mpsc::UnboundedSender<(u8, SocketAddr)>>,
    /// In-flight STUN Binding requests by transaction id.
    stun_waiters: DashMap<stun::TransactionId, oneshot::Sender<SocketAddr>>,
}

impl Mesh {
    /// Build a mesh around an already-bound socket.
    #[must_use]
    pub fn new(socket: Arc<UdpSocket>, secret: Arc<NodeSecret>, router: Arc<MacRouter>) -> Self {
        let wg_secret = secret.wireguard_secret();
        let wg_public = x25519_dalek::PublicKey::from(&wg_secret);
        Self {
            socket,
            secret,
            router,
            tunnels: DashMap::new(),
            by_addr: DashMap::new(),
            by_index: DashMap::new(),
            by_wg_pub: DashMap::new(),
            wg_static: (wg_secret, wg_public),
            relay: parking_lot::RwLock::new(None),
            relay_health: Arc::new(RelayHealth::default()),
            probes: DashMap::new(),
            stun_waiters: DashMap::new(),
        }
    }

    // ----- peer table -------------------------------------------------

    /// Add (or replace) the tunnel for `tunnel.peer`.
    pub async fn add_peer(&self, tunnel: Arc<PeerTunnel>) {
        let node = tunnel.peer;
        self.forget_indexes(node);
        if let PeerPath::Direct(addr) = tunnel.path() {
            self.by_addr.insert(addr, node);
        }
        self.by_index.insert(tunnel.local_index(), node);
        self.by_wg_pub.insert(tunnel.peer_wireguard_public(), node);
        debug!(peer = %node.short(), path = %tunnel.path(), "tunnel added to mesh");
        self.tunnels.insert(node, tunnel);
    }

    /// Remove a peer's tunnel and routes.
    pub async fn remove_peer(&self, node: NodeId) {
        self.forget_indexes(node);
        self.tunnels.remove(&node);
        self.router.unregister(node);
    }

    fn forget_indexes(&self, node: NodeId) {
        self.by_addr.retain(|_, n| *n != node);
        self.by_index.retain(|_, n| *n != node);
        self.by_wg_pub.retain(|_, n| *n != node);
    }

    /// Node ids of every peer with a tunnel.
    #[must_use]
    pub fn peers(&self) -> Vec<NodeId> {
        self.tunnels.iter().map(|e| *e.key()).collect()
    }

    /// The tunnel to `node`, if any.
    #[must_use]
    pub fn tunnel(&self, node: NodeId) -> Option<Arc<PeerTunnel>> {
        self.tunnels.get(&node).map(|t| t.value().clone())
    }

    /// The path the tunnel to `node` currently uses.
    #[must_use]
    pub fn peer_path(&self, node: NodeId) -> Option<PeerPath> {
        self.tunnels.get(&node).map(|t| t.path())
    }

    /// Live counters for every tunnel.
    #[must_use]
    pub fn link_stats(&self) -> Vec<LinkStats> {
        self.tunnels
            .iter()
            .map(|e| {
                let t = e.value();
                let s = t.stats();
                LinkStats {
                    node_id: t.peer,
                    relayed: matches!(t.path(), PeerPath::Relayed { .. }),
                    bytes_tx: s.bytes_tx.load(Ordering::Relaxed),
                    bytes_rx: s.bytes_rx.load(Ordering::Relaxed),
                    frames_tx: s.frames_tx.load(Ordering::Relaxed),
                    frames_rx: s.frames_rx.load(Ordering::Relaxed),
                    last_handshake_secs: s.last_handshake_secs.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    // ----- relay ------------------------------------------------------

    /// Point the mesh at a relay (or clear it).
    pub fn set_relay(&self, relay: Option<SocketAddr>) {
        *self.relay.write() = relay;
    }

    /// The configured relay, if any.
    #[must_use]
    pub fn relay(&self) -> Option<SocketAddr> {
        *self.relay.read()
    }

    /// The relay health tracker (fed by this mesh's demux).
    #[must_use]
    pub fn relay_health(&self) -> Arc<RelayHealth> {
        self.relay_health.clone()
    }

    // ----- probes & STUN ----------------------------------------------

    /// Register interest in replies to the ICE probe with `nonce`.
    pub fn register_probe(&self, nonce: u64) -> mpsc::UnboundedReceiver<(u8, SocketAddr)> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.probes.insert(nonce, tx);
        rx
    }

    /// Stop listening for replies to probe `nonce`.
    pub fn unregister_probe(&self, nonce: u64) {
        self.probes.remove(&nonce);
    }

    /// Learn our server-reflexive address from the STUN server at
    /// `server`, using the shared socket. Retransmits per RFC 5389's
    /// spirit (0 ms, 500 ms, 1.5 s, …) until `budget` expires.
    ///
    /// Requires the inbound loop (room driver) to be running.
    ///
    /// # Errors
    /// Fails if the server never answers within `budget`.
    pub async fn stun_binding(&self, server: SocketAddr, budget: Duration) -> Result<SocketAddr> {
        let mut txid = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut txid);
        let (tx, mut rx) = oneshot::channel();
        self.stun_waiters.insert(txid, tx);
        let request = stun::encode_binding_request(&txid);

        let deadline = tokio::time::Instant::now() + budget;
        let mut wait = Duration::from_millis(500);
        let result = loop {
            if let Err(e) = self.socket.send_to(&request, server).await {
                break Err(HermesError::Nat(format!("STUN send to {server}: {e}")));
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break Err(HermesError::Nat(format!(
                    "STUN server {server} did not answer"
                )));
            }
            match tokio::time::timeout(wait.min(remaining), &mut rx).await {
                Ok(Ok(addr)) => break Ok(addr),
                Ok(Err(_)) => break Err(HermesError::Nat("STUN waiter dropped".into())),
                Err(_) => wait *= 2,
            }
        };
        self.stun_waiters.remove(&txid);
        result
    }

    // ----- data path --------------------------------------------------

    /// Route an Ethernet frame from our adapter to the right peer(s).
    ///
    /// # Errors
    /// Returns the first send error (a flood keeps going past failures).
    pub async fn dispatch_outbound(&self, frame: &[u8]) -> Result<()> {
        match self.router.route(frame) {
            RouteDecision::Unicast(node) => match self.tunnel(node) {
                Some(t) => t.send(frame).await,
                None => {
                    trace!(peer = %node.short(), "no tunnel yet — dropping frame");
                    Ok(())
                }
            },
            RouteDecision::Flood => {
                // Snapshot first: never hold a DashMap guard across .await.
                let tunnels: Vec<Arc<PeerTunnel>> =
                    self.tunnels.iter().map(|e| e.value().clone()).collect();
                let mut first_err = None;
                for t in tunnels {
                    if let Err(e) = t.send(frame).await {
                        first_err.get_or_insert(e);
                    }
                }
                first_err.map_or(Ok(()), Err)
            }
            RouteDecision::Drop => Ok(()),
        }
    }

    /// Handle one datagram read off the shared socket. Returns a decrypted
    /// Ethernet frame for the adapter, or `None` if the datagram was
    /// control traffic (relay acks, probes, STUN, WireGuard handshakes) or
    /// was rejected.
    ///
    /// # Errors
    /// Fails if a tunnel rejects the datagram (bad MAC, replay, …).
    pub async fn dispatch_inbound(&self, from: SocketAddr, buf: &[u8]) -> Result<Option<BytesMut>> {
        if relay::is_relay_packet(buf) {
            return self.dispatch_relay(from, buf).await;
        }
        if let Some(msg) = ice::parse_probe(buf) {
            self.handle_probe(from, msg).await;
            return Ok(None);
        }
        if stun::is_stun_packet(buf) {
            if let Some((txid, addr)) = stun::parse_binding_response(buf) {
                if let Some((_, waiter)) = self.stun_waiters.remove(&txid) {
                    let _ = waiter.send(addr);
                }
            }
            return Ok(None);
        }

        // WireGuard. Known direct endpoint?
        let known = self.by_addr.get(&from).map(|n| *n);
        if let Some(node) = known {
            if let Some(tunnel) = self.tunnel(node) {
                let frame = tunnel.on_datagram(buf).await?;
                return Ok(self.check_source(node, frame));
            }
        }
        self.dispatch_roaming(from, buf).await
    }

    async fn dispatch_relay(&self, from: SocketAddr, buf: &[u8]) -> Result<Option<BytesMut>> {
        if self.relay() != Some(from) {
            trace!(%from, "relay-framed datagram from a non-relay address — ignoring");
            return Ok(None);
        }
        match relay::parse_packet(buf) {
            Some(RelayPacket::RegisterAck { .. }) => {
                self.relay_health.note_ack();
                Ok(None)
            }
            Some(RelayPacket::Forward { src, payload }) => match self.tunnel(src) {
                Some(tunnel) => {
                    let frame = tunnel.on_datagram(payload).await?;
                    Ok(self.check_source(src, frame))
                }
                None => {
                    trace!(peer = %src.short(), "relayed datagram for unknown peer");
                    Ok(None)
                }
            },
            _ => Ok(None),
        }
    }

    async fn handle_probe(&self, from: SocketAddr, msg: ice::ProbeMessage) {
        match msg {
            ice::ProbeMessage::Request { nonce, index } => {
                let _ = self
                    .socket
                    .send_to(&ice::encode_reply(nonce, index), from)
                    .await;
            }
            ice::ProbeMessage::Reply { nonce, index } => {
                if let Some(tx) = self.probes.get(&nonce) {
                    let _ = tx.send((index, from));
                }
            }
        }
    }

    /// A WireGuard datagram from an address no tunnel is bound to: the
    /// peer's NAT mapping changed (Wi-Fi ↔ cellular, router reboot), or
    /// it reached us directly while our side of the pair is relayed.
    ///
    /// Identify the candidate tunnel from the packet itself — the receiver
    /// index for transport/response packets, the decrypted initiator key
    /// for handshake initiations — and let WireGuard authenticate it. Only
    /// if that succeeds is the address trusted, exactly like WireGuard's
    /// own roaming: a spoofed or replayed packet fails authentication and
    /// changes nothing.
    async fn dispatch_roaming(&self, from: SocketAddr, buf: &[u8]) -> Result<Option<BytesMut>> {
        let Some(node) = self.identify_wireguard_sender(buf) else {
            trace!(%from, "unattributable datagram — dropping");
            return Ok(None);
        };
        let Some(tunnel) = self.tunnel(node) else {
            return Ok(None);
        };
        match tunnel.path() {
            PeerPath::Direct(old) => {
                let frame = tunnel.on_datagram_from(buf, from).await?;
                // Authenticated: move the tunnel to the new endpoint.
                info!(peer = %node.short(), %old, new = %from, "peer roamed to a new endpoint");
                self.by_addr.remove(&old);
                self.by_addr.insert(from, node);
                tunnel.set_path(PeerPath::Direct(from));
                Ok(self.check_source(node, frame))
            }
            PeerPath::Relayed { .. } => {
                // We send via the relay, but the peer found a direct way
                // to us. Accept its direct traffic (inbound alias) while
                // keeping our outbound path unchanged.
                let frame = tunnel.on_datagram(buf).await?;
                debug!(peer = %node.short(), %from, "accepting direct inbound for relayed peer");
                self.by_addr.insert(from, node);
                Ok(self.check_source(node, frame))
            }
        }
    }

    fn identify_wireguard_sender(&self, buf: &[u8]) -> Option<NodeId> {
        let receiver_at = |off: usize| -> Option<NodeId> {
            let idx = u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?);
            self.by_index.get(&(idx >> 8)).map(|n| *n)
        };
        match buf.first()? {
            // Handshake initiation: decrypt the initiator's static key.
            1 => {
                let boringtun::noise::Packet::HandshakeInit(init) =
                    boringtun::noise::Tunn::parse_incoming_packet(buf).ok()?
                else {
                    return None;
                };
                let half = boringtun::noise::handshake::parse_handshake_anon(
                    &self.wg_static.0,
                    &self.wg_static.1,
                    &init,
                )
                .ok()?;
                self.by_wg_pub.get(&half.peer_static_public).map(|n| *n)
            }
            2 => receiver_at(8),     // handshake response
            3 | 4 => receiver_at(4), // cookie reply, transport data
            _ => None,
        }
    }

    /// Anti-spoofing: a frame decrypted from `node`'s tunnel must carry
    /// `node`'s virtual MAC as its source. Without this, any room member
    /// could forge frames that appear to come from another member.
    fn check_source(&self, node: NodeId, frame: Option<BytesMut>) -> Option<BytesMut> {
        let frame = frame?;
        let src = VirtualMac(frame.get(6..12)?.try_into().ok()?);
        let expected = self.router.mac_for_node(node)?;
        if src == expected {
            Some(frame)
        } else {
            debug!(peer = %node.short(), %src, %expected, "dropping frame with spoofed source MAC");
            None
        }
    }
}
