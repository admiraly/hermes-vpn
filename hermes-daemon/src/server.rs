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

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, info, warn};

use hermes_core::directory::ServerDirectory;
use hermes_core::room::InviteCode;
use hermes_core::{EngineConfig, HermesEngine};

use crate::protocol::{
    CommandPayload, Event, Frame, Response, ResponseBody, RoomSummary, ServerListing,
    StateSnapshot, IPC_PROTOCOL_VERSION,
};
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
}

impl Server {
    /// Build a new server from the given engine config and spawn the
    /// background task that pumps engine events into the fan-out channel.
    ///
    /// # Errors
    /// Fails if the engine cannot be initialised.
    pub fn new(config: EngineConfig) -> anyhow::Result<Arc<Self>> {
        let data_dir = config.data_dir.clone();
        let engine = Arc::new(HermesEngine::new(config)?);
        let (events_tx, _) = broadcast::channel(EVENT_FANOUT_CAPACITY);

        // Drain the engine's event receiver into our broadcast channel so
        // every connected client gets a copy.
        if let Some(mut rx) = engine.take_events() {
            let tx = events_tx.clone();
            tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
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
        });

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

        Ok(server)
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
            } => match self.engine.create_room(name, mode, relay_addr).await {
                Ok(()) => ResponseBody::Ok,
                Err(e) => ResponseBody::error("create_room", e.to_string()),
            },
            CommandPayload::JoinRoom { code } => {
                let parsed: InviteCode = match code.parse() {
                    Ok(c) => c,
                    Err(_) => {
                        return ResponseBody::error("invalid_code", "invite code did not parse")
                    }
                };
                match self.engine.join_room(parsed).await {
                    Ok(()) => ResponseBody::Ok,
                    Err(e) => ResponseBody::error("join_room", e.to_string()),
                }
            }
            CommandPayload::LeaveRoom => match self.engine.leave_room().await {
                Ok(()) => ResponseBody::Ok,
                Err(e) => ResponseBody::error("leave_room", e.to_string()),
            },
            CommandPayload::GetPeers => {
                let peers = self
                    .engine
                    .current_room()
                    .map(|r| r.peers())
                    .unwrap_or_default();
                ResponseBody::Peers { peers }
            }
            CommandPayload::GetState => {
                let room = self.engine.current_room();
                let snap = StateSnapshot {
                    node_id_base64: self.engine.identity().node_id.to_base64(),
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
                    }),
                    peers: room.map(|r| r.peers()).unwrap_or_default(),
                    links: self.engine.peer_links(),
                    relay_healthy: self.engine.relay_healthy(),
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
