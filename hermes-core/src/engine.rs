//! The top-level Hermes engine — the public API of `hermes-core`.
//!
//! This module ties together identity, signaling, the NAT-traversal
//! stack, the mesh coordinator, and the virtual adapter into a single
//! `HermesEngine` that the daemon exposes over IPC and the Tauri app
//! drives via commands.
//!
//! The engine's lifecycle is:
//!
//! 1. [`HermesEngine::new`] loads or generates the permanent identity.
//! 2. [`HermesEngine::connect`] opens a WebSocket to the signaling server,
//!    spawns the event pump, and exposes an [`EngineEvent`] stream.
//! 3. [`HermesEngine::create_room`] / [`HermesEngine::join_room`] ask
//!    the server to place us in a room. Once the server confirms, the
//!    pump brings up the virtual adapter and starts the mesh driver.
//! 4. Per-peer tunnels come up asynchronously as peers arrive and their
//!    NAT candidates are exchanged.
//!
//! ## Reconnect model
//!
//! The network stack (UDP socket, mesh, tunnels) and the room runtime
//! (adapter, driver) are owned by the engine and **survive signaling
//! drops** — signaling is control plane only. A supervisor task watches
//! each signaling connection; when it dies unexpectedly the supervisor
//! reconnects with exponential backoff and re-joins the current room by
//! its remembered invite code. Live tunnels keep carrying traffic
//! throughout. An explicit [`HermesEngine::disconnect`] (or a fresh
//! `connect`) cancels the supervisor via a generation counter.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::broadcast::MacRouter;
use crate::crypto::{NodeSecret, VirtualMac};
use crate::engine_pump::{self, EngineEvent, PumpHandle, PumpState, RoomRuntime};
use crate::error::{HermesError, Result};
use crate::mesh::Mesh;
use crate::nat::Candidate;
use crate::room::{InviteCode, Room, RoomMode};
use crate::signaling::{ClientMessage, SignalingClient};

/// First reconnect delay; doubles per attempt up to [`RECONNECT_MAX_DELAY`].
const RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(1);
/// Ceiling for the reconnect backoff.
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);

/// Configuration for an engine instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineConfig {
    /// Path to persist identity and settings.
    pub data_dir: PathBuf,
    /// Signaling server URL (ws:// or wss://).
    pub signaling_url: String,
    /// Self-chosen display name.
    pub alias: String,
    /// Bind address for our UDP socket (`0.0.0.0:0` = random port).
    pub bind_addr: SocketAddr,
    /// STUN server for reflexive-address discovery.
    pub stun_server: String,
}

impl Default for EngineConfig {
    fn default() -> Self {
        let data_dir = directories::ProjectDirs::from("dev", "hermes", "Hermes")
            .map(|d| d.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            data_dir,
            signaling_url: crate::DEFAULT_SIGNALING_URL.to_string(),
            alias: "hermes-user".to_string(),
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            stun_server: crate::nat::stun::DEFAULT_STUN_SERVER.to_string(),
        }
    }
}

/// The long-lived network stack: one UDP socket (bound once, so tunnels
/// and relay sessions keep their port across signaling reconnects), the
/// MAC router, and the mesh.
struct NetRuntime {
    router: Arc<MacRouter>,
    mesh: Arc<Mesh>,
}

/// Everything a (re)connect attempt needs — cloneable so the supervisor
/// task can run without borrowing the engine.
#[derive(Clone)]
struct SessionCtx {
    url: String,
    alias: String,
    secret: Arc<NodeSecret>,
    events: mpsc::Sender<EngineEvent>,
    mesh: Arc<Mesh>,
    router: Arc<MacRouter>,
    room_rt: Arc<RoomRuntime>,
    invite: Arc<parking_lot::RwLock<Option<InviteCode>>>,
    cached_candidates: Arc<tokio::sync::Mutex<Option<Vec<Candidate>>>>,
    pump_state: Arc<RwLock<Option<Arc<PumpState>>>>,
    pump_handle: Arc<RwLock<Option<PumpHandle>>>,
    generation: Arc<AtomicU64>,
    my_generation: u64,
}

impl SessionCtx {
    fn superseded(&self) -> bool {
        self.generation.load(Ordering::SeqCst) != self.my_generation
    }
}

/// Open a signaling connection and spawn a pump wired to the shared
/// runtimes. Used by both the initial `connect()` and the supervisor.
async fn establish(ctx: &SessionCtx) -> Result<SignalingClient> {
    let client = SignalingClient::connect(&ctx.url, &ctx.secret, ctx.alias.clone()).await?;
    let inbox = client
        .take_inbox()
        .ok_or_else(|| HermesError::Signaling("inbox already taken".into()))?;

    let state = Arc::new(PumpState {
        secret: ctx.secret.clone(),
        mesh: ctx.mesh.clone(),
        router: ctx.router.clone(),
        signaling: client.clone(),
        events: ctx.events.clone(),
        room_rt: ctx.room_rt.clone(),
        invite: ctx.invite.clone(),
        cached_candidates: ctx.cached_candidates.clone(),
    });
    let handle = engine_pump::spawn(state.clone(), inbox);

    *ctx.pump_state.write() = Some(state);
    if let Some(old) = ctx.pump_handle.write().replace(handle) {
        old.abort();
    }
    Ok(client)
}

/// Watch a signaling connection; when it drops (and we weren't superseded
/// by an explicit disconnect or a fresh connect), reconnect with backoff
/// and re-join the room we were in.
async fn supervise(ctx: SessionCtx, mut client: SignalingClient) {
    loop {
        client.closed().await;
        if ctx.superseded() {
            return;
        }
        info!("signaling connection lost — starting reconnect loop");

        let mut attempt: u32 = 0;
        let mut delay = RECONNECT_INITIAL_DELAY;
        let new_client = loop {
            attempt += 1;
            let _ = ctx
                .events
                .send(EngineEvent::SignalingReconnecting { attempt })
                .await;
            tokio::time::sleep(delay).await;
            if ctx.superseded() {
                return;
            }
            match establish(&ctx).await {
                Ok(c) => break c,
                Err(e) => {
                    warn!(attempt, ?e, "reconnect attempt failed");
                    delay = (delay * 2).min(RECONNECT_MAX_DELAY);
                }
            }
        };
        if ctx.superseded() {
            return;
        }
        info!(attempt, "signaling reconnected");
        let _ = ctx.events.send(EngineEvent::SignalingReconnected).await;

        // Re-join the room we were in. The pump's enter_room recognizes a
        // re-join of the same room and keeps the adapter and live tunnels.
        let invite = ctx.invite.read().clone();
        if let Some(code) = invite {
            if let Err(e) = new_client.send(ClientMessage::JoinRoom { code }).await {
                warn!(?e, "re-join request failed");
            }
        }
        client = new_client;
    }
}

/// The Hermes engine.
pub struct HermesEngine {
    config: EngineConfig,
    secret: Arc<NodeSecret>,
    /// Bound lazily on first connect, then reused for the engine's whole
    /// life — the stable UDP port is what lets tunnels survive signaling
    /// reconnects.
    net: tokio::sync::OnceCell<NetRuntime>,
    /// Room state shared with every pump (survives reconnects).
    room_rt: Arc<RoomRuntime>,
    /// Invite code of the current room — remembered for auto re-join.
    invite: Arc<parking_lot::RwLock<Option<InviteCode>>>,
    cached_candidates: Arc<tokio::sync::Mutex<Option<Vec<Candidate>>>>,
    pump_state: Arc<RwLock<Option<Arc<PumpState>>>>,
    pump_handle: Arc<RwLock<Option<PumpHandle>>>,
    supervisor: RwLock<Option<tokio::task::JoinHandle<()>>>,
    /// Bumped by every connect()/disconnect(); supervisors from older
    /// generations exit instead of fighting the new session.
    generation: Arc<AtomicU64>,
    events_rx: parking_lot::Mutex<Option<mpsc::Receiver<EngineEvent>>>,
    /// Cloned into every pump we spawn — keeping the sender here (rather
    /// than handing it off) is what lets the engine reconnect.
    events_tx: mpsc::Sender<EngineEvent>,
}

impl HermesEngine {
    /// Construct an engine, loading or generating the persistent identity.
    ///
    /// # Errors
    /// Fails if the data directory cannot be accessed or identity cannot
    /// be read/written.
    pub fn new(config: EngineConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)?;
        let identity_path = config.data_dir.join("identity.key");

        let secret = if identity_path.exists() {
            let bytes = std::fs::read(&identity_path)?;
            bincode::deserialize::<NodeSecret>(&bytes)
                .map_err(|e| HermesError::Crypto(format!("load identity: {e}")))?
        } else {
            let s = NodeSecret::generate();
            let bytes = bincode::serialize(&s)
                .map_err(|e| HermesError::Crypto(format!("save identity: {e}")))?;
            std::fs::write(&identity_path, &bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &identity_path,
                    std::fs::Permissions::from_mode(0o600),
                );
            }
            s
        };

        info!(node_id = %secret.public().node_id, "engine identity loaded");

        let (events_tx, events_rx) = mpsc::channel(128);

        Ok(Self {
            config,
            secret: Arc::new(secret),
            net: tokio::sync::OnceCell::new(),
            room_rt: Arc::new(RoomRuntime::default()),
            invite: Arc::new(parking_lot::RwLock::new(None)),
            cached_candidates: Arc::new(tokio::sync::Mutex::new(None)),
            pump_state: Arc::new(RwLock::new(None)),
            pump_handle: Arc::new(RwLock::new(None)),
            supervisor: RwLock::new(None),
            generation: Arc::new(AtomicU64::new(0)),
            events_rx: parking_lot::Mutex::new(Some(events_rx)),
            events_tx,
        })
    }

    /// Our identity.
    #[must_use]
    pub fn identity(&self) -> crate::crypto::NodeIdentity {
        self.secret.public()
    }

    /// Take ownership of the events channel. Can only be called once per
    /// engine instance.
    pub fn take_events(&self) -> Option<mpsc::Receiver<EngineEvent>> {
        self.events_rx.lock().take()
    }

    /// Bind the UDP socket and build the mesh on first use.
    async fn net_runtime(&self) -> Result<&NetRuntime> {
        self.net
            .get_or_try_init(|| async {
                let socket = Arc::new(tokio::net::UdpSocket::bind(self.config.bind_addr).await?);
                let own_mac = VirtualMac::from_node_id(&self.secret.public().node_id);
                let router = Arc::new(MacRouter::new(own_mac));
                let mesh = Arc::new(Mesh::new(socket, self.secret.clone(), router.clone()));
                Ok::<_, HermesError>(NetRuntime { router, mesh })
            })
            .await
    }

    /// Connect to a signaling server, start the event pump, and arm the
    /// auto-reconnect supervisor.
    ///
    /// `signaling_url` overrides the URL from [`EngineConfig`] when given
    /// (this is how the daemon points the engine at whichever server the
    /// user selected in the directory). If we're already connected, the
    /// previous session is torn down first.
    ///
    /// # Errors
    /// Fails on connection, authentication, or UDP bind error.
    pub async fn connect(&self, signaling_url: Option<&str>) -> Result<()> {
        // Tear down any previous session so reconnect / server switching
        // works. This also bumps the generation, cancelling any old
        // supervisor.
        self.disconnect().await;

        let net = self.net_runtime().await?;
        let my_generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;

        let ctx = SessionCtx {
            url: signaling_url
                .unwrap_or(&self.config.signaling_url)
                .to_string(),
            alias: self.config.alias.clone(),
            secret: self.secret.clone(),
            events: self.events_tx.clone(),
            mesh: net.mesh.clone(),
            router: net.router.clone(),
            room_rt: self.room_rt.clone(),
            invite: self.invite.clone(),
            cached_candidates: self.cached_candidates.clone(),
            pump_state: self.pump_state.clone(),
            pump_handle: self.pump_handle.clone(),
            generation: self.generation.clone(),
            my_generation,
        };

        let client = establish(&ctx).await?;

        let supervisor = tokio::spawn(supervise(ctx, client));
        if let Some(old) = self.supervisor.write().replace(supervisor) {
            old.abort();
        }
        Ok(())
    }

    /// Tear down the current signaling session, room, and tunnels (no-op
    /// when not connected).
    pub async fn disconnect(&self) {
        // Invalidate any running supervisor first so it can't reconnect
        // while we tear down.
        self.generation.fetch_add(1, Ordering::SeqCst);
        if let Some(sup) = self.supervisor.write().take() {
            sup.abort();
        }
        if let Some(handle) = self.pump_handle.write().take() {
            handle.abort();
        }
        *self.pump_state.write() = None;
        *self.invite.write() = None;
        engine_pump::tear_down_room(&self.room_rt, self.net.get().map(|n| &n.mesh)).await;
    }

    /// Create a new room.
    ///
    /// `relay_addr` (`host:port`) means different things per mode:
    /// - [`RoomMode::Relayed`]: the required primary relay for all traffic.
    /// - [`RoomMode::PeerToPeer`]: an optional *fallback* relay used only
    ///   when a peer's direct path can't be established.
    ///
    /// # Errors
    /// Fails if we're not connected, or if a relayed room is requested
    /// without a relay address.
    pub async fn create_room(
        &self,
        name: String,
        mode: RoomMode,
        relay_addr: Option<String>,
    ) -> Result<()> {
        if mode == RoomMode::Relayed && relay_addr.is_none() {
            return Err(HermesError::Room(
                "relayed room requires a relay address".into(),
            ));
        }
        let state = self.pump_state()?;
        state
            .signaling
            .send(ClientMessage::CreateRoom {
                name,
                mode,
                relay_addr,
            })
            .await
    }

    /// Join a room by invite code.
    ///
    /// # Errors
    /// Fails if we're not connected.
    pub async fn join_room(&self, code: InviteCode) -> Result<()> {
        let state = self.pump_state()?;
        // Remember the code so an automatic reconnect can re-join.
        *self.invite.write() = Some(code);
        state.signaling.send(ClientMessage::JoinRoom { code }).await
    }

    /// Leave the current room, tearing down the TAP adapter and tunnels.
    ///
    /// # Errors
    /// Fails if we're not connected.
    pub async fn leave_room(&self) -> Result<()> {
        let state = self.pump_state()?;
        // Deliberate leave — a later reconnect must not re-join.
        *self.invite.write() = None;
        state.signaling.send(ClientMessage::LeaveRoom).await?;
        engine_pump::tear_down_room(&self.room_rt, self.net.get().map(|n| &n.mesh)).await;
        Ok(())
    }

    /// Get the current room (if joined).
    #[must_use]
    pub fn current_room(&self) -> Option<Arc<Room>> {
        self.room_rt.current_room.read().clone()
    }

    /// Live per-peer link statistics (empty when not connected or no
    /// tunnels are up).
    #[must_use]
    pub fn peer_links(&self) -> Vec<crate::mesh::LinkStats> {
        self.net
            .get()
            .map(|n| n.mesh.link_stats())
            .unwrap_or_default()
    }

    /// Health of the current relay session: `Some(healthy)` while a relay
    /// is configured for the room, `None` otherwise.
    #[must_use]
    pub fn relay_healthy(&self) -> Option<bool> {
        let net = self.net.get()?;
        net.mesh.relay()?;
        Some(net.mesh.relay_health().is_healthy())
    }

    /// Are we connected to the signaling server right now? Detects
    /// mid-session drops (returns `false` while the supervisor is
    /// reconnecting).
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.pump_state
            .read()
            .as_ref()
            .is_some_and(|s| !s.signaling.is_closed())
    }

    /// Local UDP socket address we're bound to, or `None` if we haven't
    /// connected yet.
    #[must_use]
    pub fn local_endpoint(&self) -> Option<SocketAddr> {
        self.net.get().and_then(|n| n.mesh.socket.local_addr().ok())
    }

    /// Our reflexive (server-public) address as last learned via STUN, or
    /// `None` if we haven't gathered candidates yet.
    pub async fn reflexive_endpoint(&self) -> Option<SocketAddr> {
        let cands = self.cached_candidates.lock().await;
        cands.as_ref().and_then(|cs| {
            cs.iter()
                .find(|c| matches!(c.kind, crate::nat::CandidateKind::ServerReflexive))
                .map(|c| c.address)
        })
    }

    fn pump_state(&self) -> Result<Arc<PumpState>> {
        self.pump_state
            .read()
            .clone()
            .ok_or_else(|| HermesError::Signaling("not connected".into()))
    }
}

impl Drop for HermesEngine {
    fn drop(&mut self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        if let Some(sup) = self.supervisor.write().take() {
            sup.abort();
        }
        if let Some(handle) = self.pump_handle.write().take() {
            handle.abort();
        }
        info!("engine shutting down");
    }
}
