//! Daemon-side IPC server.
//!
//! The server owns a single [`HermesEngine`] instance and multiplexes
//! every connected client onto it. Each accepted connection spawns a
//! dedicated task that:
//!
//! 1. Validates the client's `Hello`.
//! 2. Reads [`Command`]s on a loop, dispatches them to the engine, and
//!    writes [`Response`]s back.
//! 3. In parallel, forwards every [`EngineEvent`] broadcast from the
//!    engine to the client as an [`Event`] frame.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, info, warn};

use hermes_core::crypto::NodeId;
use hermes_core::directory::ServerDirectory;
use hermes_core::room::InviteCode;
use hermes_core::EngineEvent;
use hermes_core::{EngineConfig, HermesEngine};

use crate::protocol::{
    CommandPayload, Event, Frame, Response, ResponseBody, RoomSummary, ServerListing,
    StateSnapshot, IPC_PROTOCOL_VERSION,
};
use crate::resume::{Resume, ResumeStore};
use crate::transport::{self, FramedIpc};

/// Capacity of the broadcast channel used to fan events out to all
/// connected clients. If a client is slow to drain its receiver it will
/// start missing events (tokio broadcast is lossy on lag) — which is
/// acceptable for status events and preferable to unbounded buffering.
const EVENT_FANOUT_CAPACITY: usize = 256;

/// The IPC server.
pub struct Server {
    engine: Arc<HermesEngine>,
    events: broadcast::Sender<Event>,
    /// Server directory — shared because RefreshServers mutates it from
    /// any client connection.
    directory: Mutex<ServerDirectory>,
    /// Where the directory persists itself.
    data_dir: PathBuf,
    /// The last room, so a restart rejoins it.
    resume: ResumeStore,
}

impl Server {
    /// Build a new server from the given engine config and spawn the
    /// background task that pumps engine events into the fan-out channel.
    ///
    /// # Errors
    /// Fails if the engine cannot be initialised.
    pub fn new(config: EngineConfig) -> anyhow::Result<Arc<Self>> {
        let data_dir = config.data_dir.clone();
        Ok(Self::from_engine(HermesEngine::new(config)?, data_dir))
    }

    /// Like [`Self::new`] around an engine you built yourself — e.g. one
    /// using a different adapter factory in tests. `data_dir` should be the
    /// engine's data directory.
    #[must_use]
    pub fn from_engine(engine: HermesEngine, data_dir: PathBuf) -> Arc<Self> {
        let engine = Arc::new(engine);
        let resume = ResumeStore::new(&data_dir);
        let (events_tx, _) = broadcast::channel(EVENT_FANOUT_CAPACITY);

        // Drain the engine's event receiver into our broadcast channel so
        // every connected client gets a copy — and remember which room we
        // are in, so a restart can rejoin it.
        if let Some(mut rx) = engine.take_events() {
            let tx = events_tx.clone();
            let (engine, resume) = (engine.clone(), resume.clone());
            tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match &event {
                        EngineEvent::RoomEntered { .. } | EngineEvent::InviteRotated { .. } => {
                            if let (Some(url), Some(code)) =
                                (engine.signaling_url(), engine.current_invite())
                            {
                                let saved = Resume {
                                    signaling_url: url,
                                    invite_code: code.to_string(),
                                    password: engine.room_password(),
                                };
                                if let Err(e) = resume.save(&saved) {
                                    warn!(?e, "could not save the room for resume");
                                }
                            }
                        }
                        // We couldn't set the room up locally: don't try
                        // the same thing again on every start.
                        EngineEvent::SignalingError { code, .. } if code == "room_failed" => {
                            resume.clear();
                        }
                        // Removed by the owner: don't keep knocking.
                        EngineEvent::Kicked { .. } => resume.clear(),
                        _ => {}
                    }
                    let _ = tx.send(Event::from(event));
                }
                debug!("engine event stream closed");
            });
        }

        let directory = ServerDirectory::load(&data_dir);

        let server = Arc::new(Self {
            engine,
            events: events_tx,
            directory: Mutex::new(directory),
            data_dir,
            resume,
        });

        // Rejoin the room we were in before we stopped (unless disabled).
        if !resume_disabled() {
            if let Some(saved) = server.resume.load() {
                tokio::spawn(resume_room(server.clone(), saved));
            }
        }

        // Refresh the operator manifest in the background — best effort,
        // the cached copy keeps working offline.
        {
            let server = server.clone();
            tokio::spawn(async move {
                let mut dir = server.directory.lock().await;
                match dir.refresh_manifest().await {
                    Ok(true) => {
                        if let Err(e) = dir.save(&server.data_dir) {
                            warn!(?e, "saving refreshed directory failed");
                        }
                    }
                    Ok(false) => {}
                    Err(e) => warn!(?e, "manifest refresh failed — using cached copy"),
                }
            });
        }

        server
    }

    /// Serve one client on the given stream until it disconnects.
    ///
    /// This is generic over any async duplex stream so the same code path
    /// handles both Windows named pipes and Unix domain sockets.
    pub async fn serve_client<T>(self: Arc<Self>, stream: T)
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut framed = transport::wrap(stream);

        // Handshake.
        match transport::recv_frame(&mut framed).await {
            Ok(Some(Frame::Command(cmd))) => match cmd.payload {
                CommandPayload::Hello { protocol_version } => {
                    if protocol_version != IPC_PROTOCOL_VERSION {
                        send_response(
                            &mut framed,
                            cmd.id,
                            ResponseBody::error(
                                "version_mismatch",
                                format!("daemon speaks v{IPC_PROTOCOL_VERSION}"),
                            ),
                        )
                        .await
                        .ok();
                        return;
                    }
                    if send_response(
                        &mut framed,
                        cmd.id,
                        ResponseBody::Welcome {
                            protocol_version: IPC_PROTOCOL_VERSION,
                        },
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                }
                _ => {
                    warn!("client sent non-Hello as first command");
                    return;
                }
            },
            Ok(Some(_)) => {
                warn!("client sent a non-command frame first");
                return;
            }
            Ok(None) | Err(_) => return,
        }

        self.run_client_loop(framed).await;
    }

    async fn run_client_loop<T>(&self, mut framed: FramedIpc<T>)
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut event_rx = self.events.subscribe();

        loop {
            tokio::select! {
                biased;
                // Inbound client frames.
                frame = transport::recv_frame(&mut framed) => {
                    match frame {
                        Ok(None) => break, // clean close
                        Err(e) => {
                            warn!(?e, "IPC recv error");
                            break;
                        }
                        Ok(Some(Frame::Command(cmd))) => {
                            let body = self.dispatch(cmd.payload).await;
                            if send_response(&mut framed, cmd.id, body).await.is_err() {
                                break;
                            }
                        }
                        Ok(Some(other)) => {
                            debug!(?other, "ignoring non-command frame from client");
                        }
                    }
                }
                // Outbound engine events.
                event = event_rx.recv() => {
                    match event {
                        Ok(ev) => {
                            if transport::send_frame(&mut framed, &Frame::Event(ev))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(skipped = n, "client lagged on event channel");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }

        info!("client disconnected");
    }

    async fn dispatch(&self, cmd: CommandPayload) -> ResponseBody {
        match cmd {
            CommandPayload::Hello { .. } => {
                ResponseBody::error("protocol", "Hello after handshake")
            }
            CommandPayload::GetIdentity => ResponseBody::Identity {
                node_id_base64: self.engine.identity().node_id.to_base64(),
            },
            CommandPayload::Connect { signaling_url } => {
                // Connecting is a deliberate (re)start: whatever room we
                // remembered no longer applies.
                self.resume.clear();
                let url = match signaling_url {
                    Some(u) => u,
                    None => match self.directory.lock().await.resolve_signaling_url() {
                        Some(u) => u,
                        None => {
                            return ResponseBody::error(
                                "no_signaling_server",
                                "the server directory has no signaling servers",
                            )
                        }
                    },
                };
                match self.engine.connect(Some(&url)).await {
                    Ok(()) => ResponseBody::Ok,
                    Err(e) => ResponseBody::error("connect", e.to_string()),
                }
            }
            CommandPayload::CreateRoom {
                name,
                mode,
                relay_addr,
                password,
            } => match self
                .engine
                .create_room_with_password(name, mode, relay_addr, password)
                .await
            {
                Ok(()) => ResponseBody::Ok,
                Err(e) => ResponseBody::error("create_room", e.to_string()),
            },
            CommandPayload::KickMember { node_id, ban } => {
                let Ok(node_id) = NodeId::from_base64(&node_id) else {
                    return ResponseBody::error("bad_node_id", "node id did not parse");
                };
                match self.engine.kick_member(node_id, ban).await {
                    Ok(()) => ResponseBody::Ok,
                    Err(e) => ResponseBody::error("kick_member", e.to_string()),
                }
            }
            CommandPayload::RotateInvite => match self.engine.rotate_invite().await {
                Ok(()) => ResponseBody::Ok,
                Err(e) => ResponseBody::error("rotate_invite", e.to_string()),
            },
            CommandPayload::JoinRoom { code, password } => {
                let parsed: InviteCode = match code.parse() {
                    Ok(c) => c,
                    Err(_) => {
                        return ResponseBody::error("invalid_code", "invite code did not parse")
                    }
                };
                match self.engine.join_room_with_password(parsed, password).await {
                    Ok(()) => ResponseBody::Ok,
                    Err(e) => ResponseBody::error("join_room", e.to_string()),
                }
            }
            CommandPayload::LeaveRoom => match self.engine.leave_room().await {
                Ok(()) => {
                    // An explicit leave: don't rejoin on the next start.
                    self.resume.clear();
                    ResponseBody::Ok
                }
                Err(e) => ResponseBody::error("leave_room", e.to_string()),
            },
            CommandPayload::GetPeers => ResponseBody::Peers {
                peers: self.engine.peers(),
            },
            CommandPayload::GetState => {
                let room = self.engine.current_room();
                let signaling_url = self.engine.signaling_url();
                let snap = StateSnapshot {
                    node_id_base64: self.engine.identity().node_id.to_base64(),
                    alias: self.engine.alias(),
                    connected: self.engine.is_connected(),
                    local_endpoint: self.engine.local_endpoint().map(|a| a.to_string()),
                    reflexive_endpoint: self
                        .engine
                        .reflexive_endpoint()
                        .await
                        .map(|a| a.to_string()),
                    room: room.as_ref().map(|r| RoomSummary {
                        id: r.id,
                        name: r.name.clone(),
                        subnet_prefix: r.subnet_prefix,
                        mode: r.mode,
                        relay_addr: r.relay_addr.clone(),
                        is_owner: self.engine.is_room_owner(),
                    }),
                    peers: self.engine.peers(),
                    links: self.engine.peer_links(),
                    relay_healthy: self.engine.relay_healthy(),
                    signaling_insecure: signaling_url
                        .as_deref()
                        .is_some_and(hermes_core::signaling::is_insecure_url),
                    signaling_url,
                };
                ResponseBody::State(snap)
            }
            CommandPayload::GetServers => self.server_listing().await,
            CommandPayload::AddServer {
                kind,
                name,
                address,
            } => {
                let mut dir = self.directory.lock().await;
                match dir.add_custom(kind, name, address) {
                    Ok(()) => self.save_directory(&dir),
                    Err(e) => ResponseBody::error("add_server", e.to_string()),
                }
            }
            CommandPayload::RemoveServer { kind, name } => {
                let mut dir = self.directory.lock().await;
                match dir.remove_custom(kind, &name) {
                    Ok(()) => self.save_directory(&dir),
                    Err(e) => ResponseBody::error("remove_server", e.to_string()),
                }
            }
            CommandPayload::SetActiveSignaling { name } => {
                let mut dir = self.directory.lock().await;
                match dir.set_active_signaling(&name) {
                    Ok(()) => self.save_directory(&dir),
                    Err(e) => ResponseBody::error("set_active_signaling", e.to_string()),
                }
            }
            CommandPayload::SetManifestUrl { url } => {
                let mut dir = self.directory.lock().await;
                dir.set_manifest_url(url);
                self.save_directory(&dir)
            }
            CommandPayload::RefreshServers => {
                let mut dir = self.directory.lock().await;
                match dir.refresh_manifest().await {
                    Ok(_) => self.save_directory(&dir),
                    Err(e) => ResponseBody::error("refresh_servers", e.to_string()),
                }
            }
            CommandPayload::SetAlias { alias } => match self.engine.set_alias(&alias) {
                Ok(_) => ResponseBody::Ok,
                Err(e) => ResponseBody::error("set_alias", e.to_string()),
            },
            CommandPayload::Goodbye => ResponseBody::Ok,
        }
    }

    /// Snapshot the directory as a [`ResponseBody::Servers`].
    async fn server_listing(&self) -> ResponseBody {
        let dir = self.directory.lock().await;
        ResponseBody::Servers(ServerListing {
            signaling: dir.signaling_servers(),
            relays: dir.relay_servers(),
            manifest_url: dir.manifest_url().map(str::to_string),
            active_signaling: dir.active_signaling().map(str::to_string),
        })
    }

    /// Persist the directory; collapse errors into a response.
    fn save_directory(&self, dir: &ServerDirectory) -> ResponseBody {
        match dir.save(&self.data_dir) {
            Ok(()) => ResponseBody::Ok,
            Err(e) => ResponseBody::error("save_directory", e.to_string()),
        }
    }

    /// Expose the current identity for non-IPC callers (tests, CLI).
    #[must_use]
    pub fn engine(&self) -> &HermesEngine {
        &self.engine
    }

    /// Subscribe to the event broadcast (for callers that embed the daemon
    /// library instead of going through IPC).
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }
}

async fn send_response<T>(
    framed: &mut FramedIpc<T>,
    id: u64,
    result: ResponseBody,
) -> anyhow::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    transport::send_frame(framed, &Frame::Response(Response { id, result })).await
}

/// Is automatic rejoin turned off (`HERMES_RESUME=0`)?
fn resume_disabled() -> bool {
    std::env::var("HERMES_RESUME").is_ok_and(|v| v == "0" || v.eq_ignore_ascii_case("false"))
}

/// How long to keep trying to reach the signaling server after startup.
/// At boot the network is often not up yet when the service starts.
const RESUME_PATIENCE: Duration = Duration::from_secs(15 * 60);

/// Reconnect to the saved signaling server and rejoin the saved room.
async fn resume_room(server: Arc<Server>, saved: Resume) {
    let Ok(code) = saved.invite_code.parse::<InviteCode>() else {
        warn!("saved invite code is invalid — forgetting it");
        server.resume.clear();
        return;
    };
    // Watch for the outcome of the join before we start it.
    let mut events = server.events.subscribe();
    info!(url = %saved.signaling_url, "rejoining the room from before the restart");

    let started = tokio::time::Instant::now();
    let mut delay = Duration::from_secs(2);
    loop {
        // A user who got in first (connected or joined by hand) wins.
        if server.engine.is_connected() || server.engine.current_room().is_some() {
            debug!("already connected — not resuming");
            return;
        }
        match server.engine.connect(Some(&saved.signaling_url)).await {
            Ok(()) => break,
            Err(e) => {
                if started.elapsed() > RESUME_PATIENCE {
                    warn!(
                        ?e,
                        "gave up reaching the signaling server; the saved room is kept"
                    );
                    return;
                }
                debug!(?e, ?delay, "signaling not reachable yet");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(60));
            }
        }
    }
    if let Err(e) = server
        .engine
        .join_room_with_password(code, saved.password.clone())
        .await
    {
        warn!(?e, "rejoin request failed");
        return;
    }

    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match events.recv().await {
                Ok(Event::RoomEntered { .. }) => return Some(true),
                Ok(Event::SignalingError { code, .. })
                    if matches!(
                        code.as_str(),
                        "invalid_code"
                            | "room_failed"
                            | "bad_password"
                            | "password_required"
                            | "banned"
                    ) =>
                {
                    return Some(false)
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
    .await;
    match outcome {
        Ok(Some(true)) => info!("rejoined the room"),
        Ok(Some(false)) => {
            warn!("the saved room is gone — forgetting it");
            server.resume.clear();
        }
        _ => debug!("rejoin outcome unknown (timed out); keeping the saved room"),
    }
}
