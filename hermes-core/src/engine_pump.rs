//! The engine's internal event loop.
//!
//! A background task owned by [`HermesEngine`] drains the signaling
//! server's inbox and drives the per-room state machine:
//!
//! - On `RoomCreated` / `RoomJoined`: create the virtual adapter for our
//!   assigned IP, spawn the mesh driver, begin gathering NAT candidates.
//! - On `PeerJoined`: record the peer, build the MAC route, initiate
//!   NAT traversal, and (once a path is found) spin up a [`PeerTunnel`]
//!   and register it with the mesh.
//! - On `PeerLeft`: tear down the tunnel and forget the route.
//! - On `PeerCandidates`: complete the ICE exchange by probing remote
//!   candidates and promoting the best one to the tunnel's endpoint.
//!
//! The event pump is deliberately a single task that owns the room-level
//! state machine — this keeps the concurrency story simple (no room-level
//! locks, no reordering bugs) and lets the rest of the code stay `Send`-
//! free for the per-peer hot paths.
//!
//! One pump exists per signaling *connection*, but the room state
//! ([`RoomRuntime`]) and network stack live on the engine and are shared
//! into each pump — that's what lets a signaling reconnect re-enter the
//! same room without tearing down the virtual adapter or live tunnels.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::broadcast::MacRouter;
use crate::crypto::{NodeSecret, VirtualIpv4, VirtualMac};
use crate::error::{HermesError, Result};
use crate::mesh::{self, Mesh};
use crate::nat::{self, Candidate, PathKind};
use crate::relay::{self, RegistrationConfig};
use crate::room::{InviteCode, PeerRecord, PeerStatus, Room, RoomId, RoomMode};
use crate::signaling::protocol::{ClientMessage, PeerInfo, RoomRestore, ServerMessage};
use crate::signaling::SignalingClient;
use crate::tap::{AdapterConfig, PlatformAdapter, VirtualAdapter, VIRTUAL_MTU};
use crate::tunnel::{PeerPath, PeerTunnel};

/// How long to keep probing a peer's candidates. Long enough for the
/// peer's own probes (started when *our* candidates reach it) to open its
/// NAT for ours.
const PROBE_BUDGET: Duration = Duration::from_secs(8);
/// Overall deadline for learning our reflexive address (DNS included).
const STUN_BUDGET: Duration = Duration::from_secs(3);
/// Overall deadline for gateway discovery + port mapping.
const UPNP_BUDGET: Duration = Duration::from_secs(3);

/// Events the pump emits to anyone watching (the UI, primarily).
#[derive(Clone, Debug)]
pub enum EngineEvent {
    /// We successfully joined or created a room.
    RoomEntered {
        /// Room id.
        room_id: RoomId,
        /// Invite code to share with others. Present only when we created
        /// the room; when joining via a known code, the UI already has it.
        invite_code: Option<InviteCode>,
        /// The room's traffic mode.
        mode: RoomMode,
        /// Relay address when the room is relayed.
        relay_addr: Option<String>,
    },
    /// A peer was added to our current room.
    PeerAdded(PeerRecord),
    /// A peer's status changed.
    PeerStatusChanged {
        /// Which peer.
        node_id: crate::crypto::NodeId,
        /// New status.
        status: PeerStatus,
    },
    /// A peer left.
    PeerRemoved(crate::crypto::NodeId),
    /// Protocol or transport error from the signaling server.
    SignalingError {
        /// Short machine-readable code.
        code: String,
        /// Human-readable message.
        message: String,
    },
    /// The signaling WebSocket has dropped. Existing tunnels keep
    /// running; the engine reconnects automatically with backoff.
    SignalingDisconnected,
    /// A reconnect attempt is about to be made.
    SignalingReconnecting {
        /// 1-based attempt counter since the disconnect.
        attempt: u32,
    },
    /// The signaling connection has been re-established (and, if we were
    /// in a room, a re-join has been requested).
    SignalingReconnected,
    /// The relay for the current room stopped acknowledging our
    /// registrations. Relayed traffic is likely blackholed until it
    /// recovers; the engine keeps retrying automatically.
    RelayUnhealthy {
        /// The relay's address, for display.
        relay: String,
    },
    /// The relay is acknowledging registrations again.
    RelayRestored {
        /// The relay's address, for display.
        relay: String,
    },
}

/// Handle to a running event pump.
pub struct PumpHandle {
    task: JoinHandle<()>,
}

impl PumpHandle {
    /// Abort the task (ungraceful).
    pub fn abort(self) {
        self.task.abort();
    }
}

/// Per-room runtime that must outlive any single signaling connection:
/// the room state, the TAP/mesh driver, and the relay keepalive tasks.
/// Owned by the engine, shared into every pump.
#[derive(Default)]
pub(crate) struct RoomRuntime {
    /// Currently-joined room; `None` until we get RoomCreated / RoomJoined.
    pub current_room: parking_lot::RwLock<Option<Arc<Room>>>,
    /// Driver handle for the currently-joined room. Dropped on leave.
    pub driver: parking_lot::Mutex<Option<mesh::DriverHandle>>,
    /// Relay keepalive + health-watcher tasks. Aborted on leave.
    pub relay_tasks: parking_lot::Mutex<Option<RelayTasks>>,
}

/// The two background tasks that exist while a relay session is active.
pub(crate) struct RelayTasks {
    registration: JoinHandle<()>,
    health_watcher: JoinHandle<()>,
}

impl RelayTasks {
    fn abort(self) {
        self.registration.abort();
        self.health_watcher.abort();
    }
}

/// Shared state the pump mutates as events arrive.
pub(crate) struct PumpState {
    pub secret: Arc<NodeSecret>,
    pub mesh: Arc<Mesh>,
    pub router: Arc<MacRouter>,
    pub signaling: SignalingClient,
    pub events: mpsc::Sender<EngineEvent>,
    /// Room state shared with the engine (survives reconnects).
    pub room_rt: Arc<RoomRuntime>,
    /// The invite code of the room we're in (or joining) — remembered so
    /// an automatic reconnect can re-join. Shared with the engine.
    pub invite: Arc<parking_lot::RwLock<Option<InviteCode>>>,
    /// Cached NAT candidates — populated on first use, reused for every
    /// peer. A property of our socket, so it survives reconnects too.
    pub cached_candidates: Arc<tokio::sync::Mutex<Option<Vec<Candidate>>>>,
    /// STUN server (`host:port`) used to learn our reflexive address.
    pub stun_server: String,
    /// Our UPnP port mapping, if we made one (engine-lifetime, renewed in
    /// the background, removed on shutdown).
    pub upnp: Arc<UpnpSlot>,
}

/// A UPnP mapping plus the task that keeps its lease alive.
pub(crate) struct UpnpLease {
    pub mapping: nat::upnp::UpnpMapping,
    renewer: Option<JoinHandle<()>>,
}

impl UpnpLease {
    fn new(mapping: nat::upnp::UpnpMapping) -> Self {
        let renewer = mapping.renew_interval().map(|every| {
            let m = mapping.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(every).await;
                    if let Err(e) = m.renew().await {
                        warn!(?e, "UPnP renewal failed — will retry");
                    }
                }
            })
        });
        Self { mapping, renewer }
    }

    /// Stop renewing and delete the mapping from the router.
    pub async fn release(mut self) {
        if let Some(task) = self.renewer.take() {
            task.abort();
        }
        match tokio::time::timeout(UPNP_BUDGET, self.mapping.remove()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => debug!(?e, "UPnP removal failed"),
            Err(_) => debug!("UPnP removal timed out"),
        }
    }
}

impl Drop for UpnpLease {
    fn drop(&mut self) {
        if let Some(task) = self.renewer.take() {
            task.abort();
        }
    }
}

/// Where the engine keeps its (at most one) UPnP lease.
pub(crate) type UpnpSlot = parking_lot::Mutex<Option<UpnpLease>>;

impl PumpState {
    fn current_room(&self) -> Option<Arc<Room>> {
        self.room_rt.current_room.read().clone()
    }
}

/// Spawn the pump. Drops and drains on its own when the signaling inbox
/// closes. On clean or unclean shutdown of the signaling socket we emit
/// a final [`EngineEvent::SignalingDisconnected`] so the UI can react.
pub(crate) fn spawn(state: Arc<PumpState>, mut inbox: mpsc::Receiver<ServerMessage>) -> PumpHandle {
    let task = tokio::spawn(async move {
        info!("engine event pump started");
        while let Some(msg) = inbox.recv().await {
            if let Err(e) = handle_message(&state, msg).await {
                warn!(?e, "pump handler error");
                // Don't fail silently: clients waiting on an outcome (the
                // CLI's `create`/`join`, the UI) need to hear about it.
                let _ = state
                    .events
                    .send(EngineEvent::SignalingError {
                        code: "engine_error".into(),
                        message: e.to_string(),
                    })
                    .await;
            }
        }
        info!("engine event pump exited");
        let _ = state.events.send(EngineEvent::SignalingDisconnected).await;
    });
    PumpHandle { task }
}

async fn handle_message(state: &Arc<PumpState>, msg: ServerMessage) -> Result<()> {
    match msg {
        ServerMessage::Challenge { .. } | ServerMessage::Welcome { .. } | ServerMessage::Pong => {
            // Already handled during connect() or not interesting here.
            Ok(())
        }
        ServerMessage::RoomCreated {
            room_id,
            invite_code,
            mode,
            relay_addr,
        } => {
            // Remember the code so an automatic reconnect can re-join.
            *state.invite.write() = Some(invite_code);
            if let Err(e) = enter_room(
                state,
                room_id,
                format!("room-{}", &invite_code.to_string()[..4]),
                mode,
                relay_addr.clone(),
            )
            .await
            {
                return abandon_room(state, &e).await;
            }
            let _ = state
                .events
                .send(EngineEvent::RoomEntered {
                    room_id,
                    invite_code: Some(invite_code),
                    mode,
                    relay_addr,
                })
                .await;
            Ok(())
        }
        ServerMessage::RoomJoined {
            room_id,
            members,
            mode,
            relay_addr,
        } => {
            if let Err(e) = enter_room(
                state,
                room_id,
                format!("room-{}", &room_id.to_string()[..8]),
                mode,
                relay_addr.clone(),
            )
            .await
            {
                return abandon_room(state, &e).await;
            }
            let _ = state
                .events
                .send(EngineEvent::RoomEntered {
                    room_id,
                    invite_code: None,
                    mode,
                    relay_addr,
                })
                .await;
            // Treat every pre-existing member as a fresh PeerJoined so the
            // same code path handles both cases.
            for peer in members {
                on_peer_joined(state, peer).await?;
            }
            Ok(())
        }
        ServerMessage::PeerJoined { peer } => on_peer_joined(state, peer).await,
        ServerMessage::PeerLeft { node_id } => {
            info!(node = %node_id.short(), "peer left");
            state.mesh.remove_peer(node_id).await;
            if let Some(room) = state.current_room() {
                room.set_status(node_id, PeerStatus::Gone);
                room.remove_peer(node_id);
            }
            let _ = state.events.send(EngineEvent::PeerRemoved(node_id)).await;
            Ok(())
        }
        ServerMessage::PeerCandidates { from, candidates } => {
            on_peer_candidates(state, from, candidates).await
        }
        ServerMessage::Error { code, message } => {
            warn!(%code, %message, "signaling server error");
            // A join we want (possibly the automatic re-join after a
            // reconnect, when many clients behind one address re-join at
            // once) was rate-limited: try again shortly instead of
            // silently staying out of the room.
            let pending_code = *state.invite.read();
            if code == "rate_limited" {
                if let Some(invite) = pending_code {
                    let state = state.clone();
                    tokio::spawn(async move {
                        let jitter = rand::random::<u64>() % 5_000;
                        tokio::time::sleep(Duration::from_millis(5_000 + jitter)).await;
                        // Still wanted, and still not in the room?
                        if *state.invite.read() == Some(invite) && !state.signaling.is_closed() {
                            let restore = restore_info(&state.room_rt);
                            let _ = state
                                .signaling
                                .send(ClientMessage::JoinRoom {
                                    code: invite,
                                    restore,
                                })
                                .await;
                        }
                    });
                }
            }
            let _ = state
                .events
                .send(EngineEvent::SignalingError { code, message })
                .await;
            Ok(())
        }
    }
}

/// The server placed us in a room but we couldn't set it up locally
/// (typically: no permission to create the virtual adapter). Tell the
/// server we're not there — otherwise peers would wait on us forever —
/// stop auto re-joining it, and report why.
async fn abandon_room(state: &Arc<PumpState>, error: &HermesError) -> Result<()> {
    warn!(?error, "could not enter room — leaving it");
    *state.invite.write() = None;
    tear_down_room(&state.room_rt, Some(&state.mesh)).await;
    let _ = state.signaling.send(ClientMessage::LeaveRoom).await;
    let _ = state
        .events
        .send(EngineEvent::SignalingError {
            code: "room_failed".into(),
            message: format!("could not enter the room: {error}"),
        })
        .await;
    Ok(())
}

/// Create/replace the current room, bring up the virtual adapter, spawn
/// the driver.
///
/// If we're re-entering the room we're already in (the reconnect path),
/// the virtual adapter, driver, and any live tunnels are kept — only the
/// room bookkeeping and relay session are refreshed.
///
/// The room's `relay_addr` plays two roles depending on `mode`:
/// - **Relayed**: it's the primary (and only) data path — a missing or
///   unresolvable relay is fatal, and we register eagerly.
/// - **`PeerToPeer`**: it's an optional *fallback* — we resolve it
///   best-effort and point the mesh at it, but don't register until a
///   peer's direct path actually fails (see [`probe_and_tunnel`]). If it
///   can't be resolved, the room still works, just without fallback.
async fn enter_room(
    state: &Arc<PumpState>,
    room_id: RoomId,
    name: String,
    mode: RoomMode,
    relay_addr: Option<String>,
) -> Result<()> {
    // Same room + running driver = a reconnect re-join. Keep the adapter
    // and tunnels; peers get refreshed by the RoomJoined member list.
    let rejoining = state.current_room().is_some_and(|r| r.id == room_id)
        && state.room_rt.driver.lock().is_some();
    info!(%room_id, %name, ?mode, rejoining, "entering room");

    // Clear any stale relay session from a previous room before we start.
    if let Some(old) = state.room_rt.relay_tasks.lock().take() {
        old.abort();
    }

    let resolved_relay = match relay_addr.as_deref() {
        Some(addr_str) => match resolve_relay(addr_str).await {
            Ok(sock) => Some(sock),
            Err(e) if mode == RoomMode::Relayed => return Err(e),
            Err(e) => {
                warn!(%addr_str, ?e, "fallback relay unresolvable — p2p room without fallback");
                None
            }
        },
        None if mode == RoomMode::Relayed => {
            return Err(HermesError::Room(
                "relayed room without a relay address".into(),
            ));
        }
        None => None,
    };
    state.mesh.set_relay(resolved_relay);

    // Relayed rooms register eagerly (it's the only path). P2P rooms
    // register lazily, the first time a direct path fails.
    if mode == RoomMode::Relayed {
        if let Some(relay) = resolved_relay {
            ensure_relay_registration(state, room_id, relay);
        }
    }

    // Keep the name the user already sees when re-joining the same room.
    let name = match state.current_room() {
        Some(r) if rejoining => r.name.clone(),
        _ => name,
    };
    let room = Arc::new(Room::new(room_id, name, mode, relay_addr));

    if !rejoining {
        // Our own virtual IP within the room.
        let our_node = state.secret.public().node_id;
        let our_ip = VirtualIpv4::from_node_id(&our_node, room.subnet_prefix).0;
        let our_mac = VirtualMac::from_node_id(&our_node);
        // The shim answers ARP for this address on IP-only adapters.
        state.router.set_own_ipv4(Some(our_ip));

        let adapter_cfg = AdapterConfig {
            name: "Hermes".to_string(),
            mac: our_mac,
            ipv4: our_ip,
            ipv4_prefix: 16,
            mtu: VIRTUAL_MTU as u16,
        };

        // Bring up the adapter. Failure here is fatal for the room but not
        // the engine overall.
        let adapter: Arc<dyn VirtualAdapter> =
            Arc::new(PlatformAdapter::create(adapter_cfg).await?);

        // Spawn the driver that pumps frames between TAP and mesh.
        let handle = mesh::spawn_driver(state.mesh.clone(), adapter);
        if let Some(old) = state.room_rt.driver.lock().replace(handle) {
            // Shouldn't happen — leave_room should have cleared it — but
            // be defensive.
            drop(old);
        }
    }

    *state.room_rt.current_room.write() = Some(room);
    Ok(())
}

/// A new peer showed up in our room. Record them, register routing, and
/// kick off NAT traversal in a background task so slow STUN queries don't
/// block the rest of the pump.
async fn on_peer_joined(state: &Arc<PumpState>, peer: PeerInfo) -> Result<()> {
    info!(node = %peer.node_id.short(), alias = %peer.alias, "peer joined");

    let Some(room) = state.current_room() else {
        warn!("PeerJoined before room entered — dropping");
        return Ok(());
    };

    let peer_mac = VirtualMac::from_node_id(&peer.node_id);
    let peer_ip = VirtualIpv4::from_node_id(&peer.node_id, room.subnet_prefix);

    // Reconnect path: if we already hold a live tunnel to this peer
    // (kept across the signaling blip), don't rebuild it — just refresh
    // the bookkeeping.
    if let Some(existing_path) = state.mesh.peer_path(peer.node_id) {
        let status = PeerStatus::Connected(match existing_path {
            PeerPath::Direct(_) => PathKind::Direct,
            PeerPath::Relayed { .. } => PathKind::Relayed,
        });
        let record = PeerRecord {
            node_id: peer.node_id,
            wireguard_public: peer.wireguard_public,
            alias: peer.alias.clone(),
            virtual_ipv4: peer_ip,
            virtual_mac: peer_mac,
            status,
            latency_ms: None,
        };
        room.upsert_peer(record.clone());
        state.router.register(peer_mac, peer_ip, peer.node_id);
        let _ = state.events.send(EngineEvent::PeerAdded(record)).await;
        debug!(node = %peer.node_id.short(), "kept existing tunnel across rejoin");
        return Ok(());
    }

    let record = PeerRecord {
        node_id: peer.node_id,
        wireguard_public: peer.wireguard_public,
        alias: peer.alias.clone(),
        virtual_ipv4: peer_ip,
        virtual_mac: peer_mac,
        status: PeerStatus::Discovered,
        latency_ms: None,
    };
    room.upsert_peer(record.clone());
    state.router.register(peer_mac, peer_ip, peer.node_id);
    let _ = state.events.send(EngineEvent::PeerAdded(record)).await;

    match room.mode {
        // Relayed room: no NAT traversal at all. Build the tunnel through
        // the relay immediately — WireGuard's own handshake retransmission
        // covers the window before both sides are registered.
        RoomMode::Relayed => {
            let Some(relay_sock) = state.mesh.relay() else {
                warn!("relayed room without resolved relay — dropping peer setup");
                return Ok(());
            };
            let tunnel = PeerTunnel::new(
                peer.node_id,
                peer.wireguard_public,
                &state.secret,
                PeerPath::Relayed {
                    relay: relay_sock,
                    dest: peer.node_id,
                },
                state.mesh.socket.clone(),
            )?;
            state.mesh.add_peer(tunnel).await;

            let status = PeerStatus::Connected(PathKind::Relayed);
            room.set_status(peer.node_id, status);
            let _ = state
                .events
                .send(EngineEvent::PeerStatusChanged {
                    node_id: peer.node_id,
                    status,
                })
                .await;
        }
        // P2P room: kick off NAT traversal in the background so slow STUN
        // queries don't block the rest of the pump. Cloning `state` is
        // cheap — everything inside is Arc.
        RoomMode::PeerToPeer => {
            let state_cloned = state.clone();
            tokio::spawn(async move {
                if let Err(e) = negotiate_candidates(&state_cloned, peer.node_id).await {
                    warn!(peer = %peer.node_id.short(), ?e, "candidate negotiation failed");
                }
            });
        }
    }

    Ok(())
}

/// Gather local NAT candidates and send them to the peer via the
/// signaling server. The matching task on the peer's side will do the
/// same, and both sides probe each other's lists in [`on_peer_candidates`].
///
/// Candidates are gathered once and cached — they're a property of our
/// node, not of the peer we're talking to, so there's no reason to hit
/// STUN or UPnP once per peer.
async fn negotiate_candidates(state: &Arc<PumpState>, peer: crate::crypto::NodeId) -> Result<()> {
    let candidates = get_or_gather_candidates(state).await;

    state
        .signaling
        .send(ClientMessage::RelayCandidates {
            to: peer,
            candidates,
        })
        .await?;

    if let Some(room) = state.current_room() {
        room.set_status(peer, PeerStatus::Connecting);
    }
    let _ = state
        .events
        .send(EngineEvent::PeerStatusChanged {
            node_id: peer,
            status: PeerStatus::Connecting,
        })
        .await;
    Ok(())
}

/// Return cached candidates if present, else gather them (host + STUN
/// reflexive + UPnP mapping) and cache the result.
async fn get_or_gather_candidates(state: &Arc<PumpState>) -> Vec<Candidate> {
    let mut guard = state.cached_candidates.lock().await;
    if let Some(existing) = guard.as_ref() {
        return existing.clone();
    }

    let socket = state.mesh.socket.clone();
    // The socket is bound to 0.0.0.0; advertise the LAN address instead.
    let host = socket.local_addr().ok().and_then(nat::host_candidate_addr);

    // STUN (our server-reflexive address) and UPnP (a router port mapping)
    // are independent and each may stall on an unreachable network — a
    // DNS lookup for the STUN host can hang for seconds on its own — so
    // run them concurrently, each under a hard overall deadline.
    let stun = async {
        let query = async {
            let server = resolve_ipv4(&state.stun_server).await?;
            // The request rides the shared socket; the response comes back
            // through the mesh demux.
            state.mesh.stun_binding(server, STUN_BUDGET).await
        };
        match tokio::time::timeout(STUN_BUDGET, query).await {
            Ok(Ok(addr)) => Some(addr),
            Ok(Err(e)) => {
                debug!(?e, server = %state.stun_server, "STUN failed");
                None
            }
            Err(_) => {
                debug!(server = %state.stun_server, "STUN timed out");
                None
            }
        }
    };
    // UPnP only targets IPv4. Reuse an existing mapping (gathering can
    // re-run if STUN failed earlier) rather than mapping again.
    let existing = state
        .upnp
        .lock()
        .as_ref()
        .map(|l| std::net::SocketAddr::V4(l.mapping.external));
    let upnp = async {
        if existing.is_some() {
            return existing;
        }
        let Some(std::net::SocketAddr::V4(v4)) = host else {
            return None;
        };
        let mapping = nat::upnp::map_udp_port(*v4.ip(), v4.port(), "Hermes");
        match tokio::time::timeout(UPNP_BUDGET, mapping).await {
            Ok(Ok(mapping)) => {
                let external = std::net::SocketAddr::V4(mapping.external);
                *state.upnp.lock() = Some(UpnpLease::new(mapping));
                Some(external)
            }
            Ok(Err(e)) => {
                debug!(?e, "UPnP mapping failed");
                None
            }
            Err(_) => {
                debug!("UPnP timed out");
                None
            }
        }
    };
    let (reflexive, upnp) = tokio::join!(stun, upnp);

    let candidates = nat::ice::gather_candidates(host, upnp, reflexive, None);
    debug!(count = candidates.len(), "gathered NAT candidates");
    // Only cache a complete set: if STUN failed (transient network
    // trouble), try again for the next peer rather than advertising a
    // host-only list for the rest of the session.
    if reflexive.is_some() {
        *guard = Some(candidates.clone());
    }
    candidates
}

/// A peer sent us their candidate list. Probe, pick the best path,
/// build a WireGuard tunnel, and add it to the mesh.
///
/// Runs in a spawned task because the probe may take up to several
/// seconds — blocking the main pump here would stall every other peer
/// in the room.
async fn on_peer_candidates(
    state: &Arc<PumpState>,
    from: crate::crypto::NodeId,
    candidates: Vec<Candidate>,
) -> Result<()> {
    debug!(
        peer = %from.short(),
        count = candidates.len(),
        "received peer candidates",
    );

    // Candidates are meaningless in a relayed room; a confused or
    // malicious peer must not be able to pull us off the relay path.
    if let Some(room) = state.current_room() {
        if room.mode == RoomMode::Relayed {
            debug!(peer = %from.short(), "ignoring candidates in relayed room");
            return Ok(());
        }
    }

    let state_cloned = state.clone();
    tokio::spawn(async move {
        if let Err(e) = probe_and_tunnel(&state_cloned, from, candidates).await {
            warn!(peer = %from.short(), ?e, "probe_and_tunnel failed");
        }
    });
    Ok(())
}

async fn probe_and_tunnel(
    state: &Arc<PumpState>,
    from: crate::crypto::NodeId,
    candidates: Vec<Candidate>,
) -> Result<()> {
    let Some(room) = state.current_room() else {
        return Ok(());
    };
    let Some(record) = room.peers().into_iter().find(|p| p.node_id == from) else {
        warn!(peer = %from.short(), "candidates for unknown peer");
        return Ok(());
    };

    let socket = state.mesh.socket.clone();
    let result = nat::ice::probe_candidates(&state.mesh, &candidates, PROBE_BUDGET).await;

    match result {
        Ok(path) => {
            info!(peer = %from.short(), endpoint = %path.endpoint, kind = ?path.kind, "path established");

            let tunnel = PeerTunnel::new(
                from,
                record.wireguard_public,
                &state.secret,
                PeerPath::Direct(path.endpoint),
                socket,
            )?;
            state.mesh.add_peer(tunnel).await;

            let status = PeerStatus::Connected(path.kind);
            room.set_status(from, status);
            let _ = state
                .events
                .send(EngineEvent::PeerStatusChanged {
                    node_id: from,
                    status,
                })
                .await;
        }
        Err(e) => {
            // Direct traversal failed. If this room has a relay configured
            // as a fallback (set in `enter_room`), route the peer through it
            // instead of giving up — this rescues symmetric-NAT pairs that
            // a pure-P2P room could never connect.
            if let Some(relay) = state.mesh.relay() {
                info!(peer = %from.short(), %relay, ?e, "direct path failed — falling back to relay");
                ensure_relay_registration(state, room.id, relay);

                let tunnel = PeerTunnel::new(
                    from,
                    record.wireguard_public,
                    &state.secret,
                    PeerPath::Relayed { relay, dest: from },
                    socket,
                )?;
                state.mesh.add_peer(tunnel).await;

                let status = PeerStatus::Connected(PathKind::Relayed);
                room.set_status(from, status);
                let _ = state
                    .events
                    .send(EngineEvent::PeerStatusChanged {
                        node_id: from,
                        status,
                    })
                    .await;
            } else {
                warn!(peer = %from.short(), ?e, "all candidates failed — peer stale");
                room.set_status(from, PeerStatus::Stale);
                let _ = state
                    .events
                    .send(EngineEvent::PeerStatusChanged {
                        node_id: from,
                        status: PeerStatus::Stale,
                    })
                    .await;
            }
        }
    }
    Ok(())
}

/// Resolve a relay `host:port` string to an IPv4 socket address.
async fn resolve_relay(addr_str: &str) -> Result<SocketAddr> {
    resolve_ipv4(addr_str)
        .await
        .map_err(|e| HermesError::Room(format!("relay: {e}")))
}

/// Resolve `host:port` to its first IPv4 address. The engine socket is
/// bound to `0.0.0.0`, so only IPv4 destinations are reachable from it.
async fn resolve_ipv4(addr_str: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(addr_str)
        .await
        .map_err(|e| HermesError::Nat(format!("resolve {addr_str}: {e}")))?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| HermesError::Nat(format!("{addr_str} has no IPv4 address")))
}

/// Start the relay registration keepalive and its health watcher if they
/// aren't already running.
///
/// Idempotent and safe to call from several peer tasks at once (they race
/// on `relay_tasks`; the first wins, the rest see `Some` and return). Used
/// both for relayed rooms (eagerly, at room entry) and for p2p rooms (the
/// first time a direct path fails over to the relay).
fn ensure_relay_registration(state: &Arc<PumpState>, room_id: RoomId, relay: SocketAddr) {
    let mut slot = state.room_rt.relay_tasks.lock();
    if slot.is_some() {
        return;
    }

    let health = state.mesh.relay_health();
    let registration = relay::spawn_registration(
        state.mesh.socket.clone(),
        relay,
        room_id,
        state.secret.clone(),
        health.clone(),
        RegistrationConfig::default(),
    );

    // Translate health transitions into user-visible events.
    let events = state.events.clone();
    let relay_display = relay.to_string();
    let mut rx = health.subscribe();
    let health_watcher = tokio::spawn(async move {
        // Skip the initial value; only report transitions.
        let mut last = *rx.borrow();
        while rx.changed().await.is_ok() {
            let healthy = *rx.borrow();
            if healthy == last {
                continue;
            }
            last = healthy;
            let event = if healthy {
                EngineEvent::RelayRestored {
                    relay: relay_display.clone(),
                }
            } else {
                EngineEvent::RelayUnhealthy {
                    relay: relay_display.clone(),
                }
            };
            if events.send(event).await.is_err() {
                break;
            }
        }
    });

    *slot = Some(RelayTasks {
        registration,
        health_watcher,
    });
}

/// What we remember about the current room, for a re-join that may need
/// to restore it on a restarted server.
pub(crate) fn restore_info(room_rt: &RoomRuntime) -> Option<RoomRestore> {
    room_rt.current_room.read().as_ref().map(|r| RoomRestore {
        room_id: r.id,
        name: r.name.clone(),
        mode: r.mode,
        relay_addr: r.relay_addr.clone(),
    })
}

/// Helper used by the engine when leaving a room: stops the driver and
/// clears per-room state.
pub(crate) async fn tear_down_room(room_rt: &RoomRuntime, mesh: Option<&Arc<Mesh>>) {
    // Take the handle out from under the lock so the parking_lot guard
    // (which is `!Send`) drops before we await on shutdown.
    let handle = room_rt.driver.lock().take();
    if let Some(handle) = handle {
        handle.shutdown().await;
    }
    if let Some(tasks) = room_rt.relay_tasks.lock().take() {
        tasks.abort();
    }
    *room_rt.current_room.write() = None;
    if let Some(mesh) = mesh {
        mesh.set_relay(None);
        for peer in mesh.peers() {
            mesh.remove_peer(peer).await;
        }
        mesh.router.clear();
        mesh.router.set_own_ipv4(None);
    }
}
