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
use crate::engine_pump::{self, EngineEvent, PumpHandle, PumpState, RoomRuntime, UpnpSlot};
use crate::error::{HermesError, Result};
use crate::mesh::Mesh;
use crate::nat::Candidate;
use crate::room::{InviteCode, Room, RoomMode};
use crate::signaling::{ClientMessage, SignalingClient};
use crate::tap::AdapterFactory;

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
    /// Display name used when none has been saved with
    /// [`HermesEngine::set_alias`]. Defaults to the machine's hostname.
    pub alias: String,
    /// Bind address for our UDP socket (`0.0.0.0:0` = random port).
    pub bind_addr: SocketAddr,
    /// STUN server for reflexive-address discovery.
    pub stun_server: String,
    /// Ask the home router for a UPnP port mapping (on by default; turn it
    /// off on networks where opening router ports isn't wanted).
    #[serde(default = "default_true")]
    pub upnp: bool,
}

fn default_true() -> bool {
    true
}

impl Default for EngineConfig {
    fn default() -> Self {
        let data_dir = directories::ProjectDirs::from("dev", "hermes", "Hermes")
            .map(|d| d.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            data_dir,
            signaling_url: crate::DEFAULT_SIGNALING_URL.to_string(),
            alias: default_alias(),
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            stun_server: crate::nat::stun::DEFAULT_STUN_SERVER.to_string(),
            upnp: true,
        }
    }
}

/// Longest accepted display name, in characters.
pub const MAX_ALIAS_CHARS: usize = 32;
/// File in the data directory holding a user-chosen alias.
const ALIAS_FILE: &str = "alias.txt";

/// The machine's hostname, as a sensible default display name.
fn default_alias() -> String {
    let from_os = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| std::env::var("HOSTNAME").ok());
    from_os
        .and_then(|h| normalize_alias(&h).ok())
        .unwrap_or_else(|| "hermes-user".to_string())
}

/// Validate and tidy a display name: trimmed, 1–32 characters, no
/// control characters.
///
/// # Errors
/// Returns a message describing what's wrong with the name.
pub fn normalize_alias(alias: &str) -> std::result::Result<String, String> {
    let alias = alias.trim();
    if alias.is_empty() {
        return Err("display name can't be empty".into());
    }
    if alias.chars().any(char::is_control) {
        return Err("display name can't contain control characters".into());
    }
    if alias.chars().count() > MAX_ALIAS_CHARS {
        return Err(format!(
            "display name is limited to {MAX_ALIAS_CHARS} characters"
        ));
    }
    Ok(alias.to_string())
}

/// Create `path` readable by its owner only — from the moment it exists,
/// not after a later `chmod` — and write `contents` to it. Refuses to
/// overwrite an existing file.
fn write_private_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents)
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
    stun_server: String,
    upnp_enabled: bool,
    adapter_factory: AdapterFactory,
    upnp: Arc<UpnpSlot>,
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
        stun_server: ctx.stun_server.clone(),
        upnp_enabled: ctx.upnp_enabled,
        adapter_factory: ctx.adapter_factory.clone(),
        upnp: ctx.upnp.clone(),
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
        // The restore info lets a restarted server recreate the room.
        let invite = *ctx.invite.read();
        if let Some(code) = invite {
            let restore = engine_pump::restore_info(&ctx.room_rt);
            let password = ctx.room_rt.password.read().clone();
            if let Err(e) = new_client
                .send(ClientMessage::JoinRoom {
                    code,
                    restore,
                    password,
                })
                .await
            {
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
    /// The signaling URL of the current session (for status display).
    signaling_url: RwLock<Option<String>>,
    /// Our UPnP port mapping (lives as long as the UDP socket).
    upnp: Arc<UpnpSlot>,
    /// Creates the virtual adapter on room entry.
    adapter_factory: AdapterFactory,
    /// Current display name (saved alias, else the configured default).
    alias: RwLock<String>,
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
            NodeSecret::from_bytes(&bytes).map_err(|e| {
                HermesError::Crypto(format!("load {}: {e}", identity_path.display()))
            })?
        } else {
            let s = NodeSecret::generate();
            write_private_file(&identity_path, &s.to_bytes())?;
            s
        };

        info!(node_id = %secret.public().node_id, "engine identity loaded");

        let alias = std::fs::read_to_string(config.data_dir.join(ALIAS_FILE))
            .ok()
            .and_then(|a| normalize_alias(&a).ok())
            .or_else(|| normalize_alias(&config.alias).ok())
            .unwrap_or_else(default_alias);

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
            signaling_url: RwLock::new(None),
            upnp: Arc::new(parking_lot::Mutex::new(None)),
            adapter_factory: crate::tap::platform_adapter_factory(),
            alias: RwLock::new(alias),
        })
    }

    /// Use `factory` instead of the OS adapter when entering rooms — for
    /// tests (see [`crate::tap::mock::MockAdapter`]) and headless embedding.
    /// Call before connecting.
    #[must_use]
    pub fn with_adapter_factory(mut self, factory: AdapterFactory) -> Self {
        self.adapter_factory = factory;
        self
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
            alias: self.alias(),
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
            stun_server: self.config.stun_server.clone(),
            upnp_enabled: self.config.upnp,
            adapter_factory: self.adapter_factory.clone(),
            upnp: self.upnp.clone(),
        };

        *self.signaling_url.write() = Some(ctx.url.clone());
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
        *self.room_rt.password.write() = None;
        *self.room_rt.owner.write() = None;
        *self.signaling_url.write() = None;
        engine_pump::tear_down_room(&self.room_rt, self.net.get().map(|n| &n.mesh)).await;
    }

    /// Graceful shutdown: leave the room (tearing down the adapter and
    /// tunnels), disconnect from signaling, and remove our UPnP port
    /// mapping from the router. Call before exiting; `Drop` can't do the
    /// async parts.
    pub async fn shutdown(&self) {
        if self.current_room().is_some() {
            if let Ok(state) = self.pump_state() {
                let _ = state.signaling.send(ClientMessage::LeaveRoom).await;
            }
        }
        self.disconnect().await;
        let lease = self.upnp.lock().take();
        if let Some(lease) = lease {
            lease.release().await;
        }
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
        self.create_room_with_password(name, mode, relay_addr, None)
            .await
    }

    /// [`create_room`](Self::create_room) with an optional password that
    /// joiners must present as well as the invite code.
    ///
    /// # Errors
    /// As for `create_room`.
    pub async fn create_room_with_password(
        &self,
        name: String,
        mode: RoomMode,
        relay_addr: Option<String>,
        password: Option<String>,
    ) -> Result<()> {
        if mode == RoomMode::Relayed && relay_addr.is_none() {
            return Err(HermesError::Room(
                "relayed room requires a relay address".into(),
            ));
        }
        let state = self.pump_state()?;
        let password = password.filter(|p| !p.is_empty());
        *self.room_rt.password.write() = password.clone();
        state
            .signaling
            .send(ClientMessage::CreateRoom {
                name,
                mode,
                relay_addr,
                password,
            })
            .await
    }

    /// Join a room by invite code.
    ///
    /// # Errors
    /// Fails if we're not connected.
    pub async fn join_room(&self, code: InviteCode) -> Result<()> {
        self.join_room_with_password(code, None).await
    }

    /// [`join_room`](Self::join_room) for a password-protected room.
    ///
    /// # Errors
    /// Fails if we're not connected.
    pub async fn join_room_with_password(
        &self,
        code: InviteCode,
        password: Option<String>,
    ) -> Result<()> {
        let state = self.pump_state()?;
        let password = password.filter(|p| !p.is_empty());
        // Remember the code so an automatic reconnect can re-join.
        *self.invite.write() = Some(code);
        *self.room_rt.password.write() = password.clone();
        state
            .signaling
            .send(ClientMessage::JoinRoom {
                code,
                restore: None,
                password,
            })
            .await
    }

    /// Owner only: remove `node_id` from the room, and with `ban` keep
    /// them out until the room ends. The server enforces ownership; a
    /// non-owner gets a `not_owner` signaling error.
    ///
    /// # Errors
    /// Fails if we're not connected.
    pub async fn kick_member(&self, node_id: crate::crypto::NodeId, ban: bool) -> Result<()> {
        self.pump_state()?
            .signaling
            .send(ClientMessage::KickMember { node_id, ban })
            .await
    }

    /// Owner only: replace the room's invite code. Members stay; the old
    /// code stops working. The new code arrives as
    /// [`EngineEvent::InviteRotated`].
    ///
    /// # Errors
    /// Fails if we're not connected.
    pub async fn rotate_invite(&self) -> Result<()> {
        self.pump_state()?
            .signaling
            .send(ClientMessage::RotateInvite)
            .await
    }

    /// Are we the current room's owner?
    #[must_use]
    pub fn is_room_owner(&self) -> bool {
        *self.room_rt.owner.read() == Some(self.secret.public().node_id)
    }

    /// Leave the current room, tearing down the TAP adapter and tunnels.
    ///
    /// # Errors
    /// Fails if we're not connected.
    pub async fn leave_room(&self) -> Result<()> {
        let state = self.pump_state()?;
        // Deliberate leave — a later reconnect must not re-join.
        *self.invite.write() = None;
        *self.room_rt.password.write() = None;
        *self.room_rt.owner.write() = None;
        state.signaling.send(ClientMessage::LeaveRoom).await?;
        engine_pump::tear_down_room(&self.room_rt, self.net.get().map(|n| &n.mesh)).await;
        Ok(())
    }

    /// Get the current room (if joined).
    #[must_use]
    pub fn current_room(&self) -> Option<Arc<Room>> {
        self.room_rt.current_room.read().clone()
    }

    /// The current room's peers, with `latency_ms` filled in from each
    /// tunnel's latency ping. Empty outside a room.
    #[must_use]
    pub fn peers(&self) -> Vec<crate::room::PeerRecord> {
        let Some(room) = self.current_room() else {
            return Vec::new();
        };
        let mesh = self.net.get().map(|n| &n.mesh);
        room.peers()
            .into_iter()
            .map(|mut p| {
                if let Some(rtt) = mesh
                    .and_then(|m| m.tunnel(p.node_id))
                    .and_then(|t| t.rtt_ms())
                {
                    p.latency_ms = Some(rtt);
                }
                p
            })
            .collect()
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

    /// Our display name, as peers see it.
    #[must_use]
    pub fn alias(&self) -> String {
        self.alias.read().clone()
    }

    /// Change and persist our display name. Peers learn the new name the
    /// next time we connect to signaling (it travels in the `Hello`).
    ///
    /// # Errors
    /// Fails if the name is invalid (see [`normalize_alias`]) or can't be
    /// saved.
    pub fn set_alias(&self, alias: &str) -> Result<String> {
        let alias = normalize_alias(alias).map_err(HermesError::Room)?;
        std::fs::write(self.config.data_dir.join(ALIAS_FILE), &alias)?;
        *self.alias.write() = alias.clone();
        Ok(alias)
    }

    /// The invite code of the room we're in (or joining), if any.
    #[must_use]
    pub fn current_invite(&self) -> Option<InviteCode> {
        *self.invite.read()
    }

    /// The current room's password, if it has one (for remembering it
    /// across restarts).
    #[must_use]
    pub fn room_password(&self) -> Option<String> {
        self.room_rt.password.read().clone()
    }

    /// The signaling server URL of the current session, if any.
    #[must_use]
    pub fn signaling_url(&self) -> Option<String> {
        self.signaling_url.read().clone()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn new_identity_file_is_private_and_reloads() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("hermes-id-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = EngineConfig {
            data_dir: dir.clone(),
            ..EngineConfig::default()
        };
        let first = HermesEngine::new(config.clone())
            .unwrap()
            .identity()
            .node_id;
        let file = dir.join("identity.key");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::metadata(&file).unwrap().len(), 32);
        assert_eq!(
            HermesEngine::new(config.clone())
                .unwrap()
                .identity()
                .node_id,
            first
        );
        // A damaged file is an error, never silently replaced by a new identity.
        std::fs::write(&file, b"short").unwrap();
        assert!(HermesEngine::new(config).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn alias_validation() {
        assert_eq!(normalize_alias("  Lisa's PC  ").unwrap(), "Lisa's PC");
        assert!(normalize_alias("   ").is_err());
        assert!(normalize_alias("bad\nname").is_err());
        assert!(normalize_alias(&"x".repeat(33)).is_err());
        assert!(
            normalize_alias(&"é".repeat(32)).is_ok(),
            "limit counts characters, not bytes"
        );
        assert!(normalize_alias(&default_alias()).is_ok());
    }

    #[test]
    fn alias_persists_across_restarts() {
        let dir = std::env::temp_dir().join(format!("hermes-alias-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = EngineConfig {
            data_dir: dir.clone(),
            alias: "configured".into(),
            ..EngineConfig::default()
        };
        let engine = HermesEngine::new(config.clone()).unwrap();
        assert_eq!(engine.alias(), "configured");
        engine.set_alias(" renamed ").unwrap();
        assert!(engine.set_alias("").is_err());
        drop(engine);
        assert_eq!(HermesEngine::new(config).unwrap().alias(), "renamed");
        let _ = std::fs::remove_dir_all(dir);
    }
}
