//! `hermes-daemon` entrypoint.
//!
//! Binds the platform-specific IPC socket, constructs the shared
//! [`hermes_daemon::Server`], and accepts clients in a loop until a
//! shutdown signal arrives.

use std::sync::Arc;

use hermes_core::EngineConfig;
use hermes_daemon::{transport, Server};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = EngineConfig::default();
    let server = Server::new(config)?;

    info!(
        node = %server.engine().identity().node_id.short(),
        "hermes-daemon started",
    );

    tokio::select! {
        res = accept_loop(server.clone()) => {
            if let Err(e) = res {
                error!(?e, "accept loop exited with error");
            }
        }
        _ = shutdown_signal() => {
            info!("shutdown signal received");
        }
    }

    // Drop the server, which drops the engine.
    drop(server);
    Ok(())
}

#[cfg(unix)]
async fn accept_loop(server: Arc<Server>) -> anyhow::Result<()> {
    use tokio::net::UnixListener;

    let path = transport::unix_socket_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Remove any stale socket from a previous run. Ignore ENOENT.
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)?;

    // Lock down permissions to the owner only — /tmp is a shared space.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!(path = %path.display(), "listening for IPC clients");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let server = server.clone();
        tokio::spawn(async move {
            server.serve_client(stream).await;
        });
    }
}

#[cfg(windows)]
async fn accept_loop(server: Arc<Server>) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    info!(pipe = %transport::PIPE_PATH, "listening for IPC clients");

    loop {
        // Named pipe semantics: we always keep one "first" instance
        // listening; after it accepts, we immediately create the next one
        // so there's never a window where a client would hit ERROR_PIPE_BUSY.
        let server_pipe = ServerOptions::new()
            .first_pipe_instance(false)
            .create(transport::PIPE_PATH)?;
        server_pipe.connect().await?;

        let srv = server.clone();
        tokio::spawn(async move {
            srv.serve_client(server_pipe).await;
        });
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("install ctrl+c");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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
}
