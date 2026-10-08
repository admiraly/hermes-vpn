//! Tauri entrypoint for the Hermes desktop UI.
//!
//! This process runs as the logged-in user and drives the Hermes engine
//! through the daemon IPC. Commands exposed to the frontend are declared
//! with `#[tauri::command]` and forwarded to the daemon via
//! [`hermes_daemon::DaemonClient`]. Engine events arrive on the client's
//! event channel and are re-emitted as Tauri events for the webview.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::sync::Arc;

use hermes_core::directory::ServerKind;
use hermes_core::room::RoomMode;
use hermes_daemon::protocol::{CommandPayload, ResponseBody, ServerListing};
use hermes_daemon::DaemonClient;
use tauri::{AppHandle, Emitter, Manager, State};
use tracing::warn;

struct AppState {
    client: tokio::sync::Mutex<Option<Arc<DaemonClient>>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            client: tokio::sync::Mutex::new(None),
        }
    }

    /// Lazily connect to the daemon, retrying on every call until we
    /// succeed once. After that we cache the client. (If the daemon dies
    /// later, the client's read loop notices and the next IPC call will
    /// fail, prompting the user to restart the daemon and reload the UI.)
    async fn client(&self) -> Result<Arc<DaemonClient>, String> {
        let mut slot = self.client.lock().await;
        if let Some(c) = slot.as_ref() {
            return Ok(c.clone());
        }
        match DaemonClient::connect_default().await {
            Ok(c) => {
                let arc = Arc::new(c);
                *slot = Some(arc.clone());
                Ok(arc)
            }
            Err(e) => Err(format!(
                "Cannot reach the Hermes daemon. Start it as a service \
                 (Linux: `sudo packaging/linux/install.sh`, then log in \
                 again so you're in the `hermes` group; Windows: \
                 `hermes-daemon.exe service install` from an elevated \
                 prompt) or run `hermes-daemon` by hand. Details: {e}"
            )),
        }
    }
}

/// Translate an IPC response body into a Tauri command result, flattening
/// error bodies into rejected promises on the JS side.
fn flatten(body: ResponseBody) -> Result<ResponseBody, String> {
    match body {
        ResponseBody::Error { code, message } => Err(format!("{code}: {message}")),
        other => Ok(other),
    }
}

#[tauri::command]
async fn get_identity(state: State<'_, AppState>) -> Result<String, String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::GetIdentity)
        .await
        .map_err(|e| e.to_string())?;
    match flatten(body)? {
        ResponseBody::Identity { node_id_base64 } => Ok(node_id_base64),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn connect(signaling_url: Option<String>, state: State<'_, AppState>) -> Result<(), String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::Connect { signaling_url })
        .await
        .map_err(|e| e.to_string())?;
    flatten(body).map(|_| ())
}

#[tauri::command]
async fn create_room(
    name: String,
    mode: RoomMode,
    relay_addr: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::CreateRoom {
            name,
            mode,
            relay_addr,
        })
        .await
        .map_err(|e| e.to_string())?;
    flatten(body).map(|_| ())
}

#[tauri::command]
async fn join_room(code: String, state: State<'_, AppState>) -> Result<(), String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::JoinRoom { code })
        .await
        .map_err(|e| e.to_string())?;
    flatten(body).map(|_| ())
}

#[tauri::command]
async fn leave_room(state: State<'_, AppState>) -> Result<(), String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::LeaveRoom)
        .await
        .map_err(|e| e.to_string())?;
    flatten(body).map(|_| ())
}

#[tauri::command]
async fn get_peers(
    state: State<'_, AppState>,
) -> Result<Vec<hermes_core::room::PeerRecord>, String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::GetPeers)
        .await
        .map_err(|e| e.to_string())?;
    match flatten(body)? {
        ResponseBody::Peers { peers } => Ok(peers),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn get_state(
    state: State<'_, AppState>,
) -> Result<hermes_daemon::protocol::StateSnapshot, String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::GetState)
        .await
        .map_err(|e| e.to_string())?;
    match flatten(body)? {
        ResponseBody::State(snap) => Ok(snap),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn get_servers(state: State<'_, AppState>) -> Result<ServerListing, String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::GetServers)
        .await
        .map_err(|e| e.to_string())?;
    match flatten(body)? {
        ResponseBody::Servers(listing) => Ok(listing),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn add_server(
    kind: ServerKind,
    name: String,
    address: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::AddServer {
            kind,
            name,
            address,
        })
        .await
        .map_err(|e| e.to_string())?;
    flatten(body).map(|_| ())
}

#[tauri::command]
async fn remove_server(
    kind: ServerKind,
    name: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::RemoveServer { kind, name })
        .await
        .map_err(|e| e.to_string())?;
    flatten(body).map(|_| ())
}

#[tauri::command]
async fn set_active_signaling(name: String, state: State<'_, AppState>) -> Result<(), String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::SetActiveSignaling { name })
        .await
        .map_err(|e| e.to_string())?;
    flatten(body).map(|_| ())
}

#[tauri::command]
async fn set_manifest_url(url: Option<String>, state: State<'_, AppState>) -> Result<(), String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::SetManifestUrl { url })
        .await
        .map_err(|e| e.to_string())?;
    flatten(body).map(|_| ())
}

#[tauri::command]
async fn refresh_servers(state: State<'_, AppState>) -> Result<(), String> {
    let client = state.client().await?;
    let body = client
        .call(CommandPayload::RefreshServers)
        .await
        .map_err(|e| e.to_string())?;
    flatten(body).map(|_| ())
}

/// Pump events from the daemon into Tauri's event bus so the webview
/// can subscribe with `listen('hermes://event', …)`.
async fn pump_events(app: AppHandle, client: Arc<DaemonClient>) {
    let Some(mut rx) = client.take_events().await else {
        warn!("event receiver already taken; not pumping events");
        return;
    };
    while let Some(event) = rx.recv().await {
        if let Err(e) = app.emit("hermes://event", &event) {
            warn!(?e, "failed to emit tauri event");
        }
    }
}

fn main() {
    tracing_subscriber::fmt::init();

    tauri::Builder::default()
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            get_identity,
            get_state,
            connect,
            create_room,
            join_room,
            leave_room,
            get_peers,
            get_servers,
            add_server,
            remove_server,
            set_active_signaling,
            set_manifest_url,
            refresh_servers
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            // Connect to the daemon lazily in a background task; if it
            // isn't running yet the UI stays usable for identity-free
            // flows and will retry on demand.
            tauri::async_runtime::spawn(async move {
                let state = handle.state::<AppState>();
                if let Ok(client) = state.client().await {
                    pump_events(handle.clone(), client).await;
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("tauri run");
}
