//! Hermes signaling server.
//!
//! A lightweight WebSocket rendezvous server. Peers authenticate with an
//! Ed25519 signature over a server-provided nonce, then create/join rooms
//! by invite code. The server relays ICE candidate lists but never
//! touches user data or long-term secrets.

mod limits;
mod rooms;
mod session;

use std::net::SocketAddr;

use axum::{extract::State, routing::get, Router};
use tokio::signal;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use limits::Limits;
use rooms::RoomRegistry;

/// Shared server state handed to every handler.
#[derive(Clone)]
pub struct AppState {
    /// Live rooms.
    pub registry: RoomRegistry,
    /// Per-IP abuse limits.
    pub limits: Limits,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let bind: SocketAddr = std::env::var("HERMES_SIGNALING_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8787".to_string())
        .parse()?;

    let state = AppState {
        registry: RoomRegistry::new(),
        limits: Limits::from_env(),
    };
    {
        let limits = state.limits.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                ticker.tick().await;
                limits.prune();
            }
        });
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1", get(session::ws_handler))
        .with_state(state);

    info!(%bind, "hermes-signaling listening");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn health(State(_): State<AppState>) -> &'static str {
    "ok"
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install ctrl+c");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    info!("shutdown signal received");
}
