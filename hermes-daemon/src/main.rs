//! `hermes-daemon` entrypoint.
//!
//! Binds the platform-specific IPC endpoint, constructs the shared
//! [`hermes_daemon::Server`], and accepts clients until a shutdown signal
//! arrives — then leaves the room and removes UPnP mappings cleanly.
//!
//! ```text
//! hermes-daemon                    per-user daemon (Linux: run with
//!                                  CAP_NET_ADMIN via setcap; Windows: as
//!                                  Administrator)
//! hermes-daemon --system           system service mode (Linux systemd
//!                                  unit): socket /run/hermes/daemon.sock
//!                                  for the `hermes` group, state in
//!                                  /var/lib/hermes
//! hermes-daemon service install    Windows: register + start the service
//! hermes-daemon service uninstall  Windows: stop + remove it
//! ```
//!
//! Overrides: `HERMES_DATA_DIR` (state directory), `HERMES_SOCKET` (Unix
//! socket path).

#[cfg(windows)]
mod windows_service;

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use hermes_core::EngineConfig;
use hermes_daemon::{transport, Server};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const USAGE: &str = "usage: hermes-daemon [--system]
       hermes-daemon service <install|uninstall>   (Windows)";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => run_foreground(false),
        ["--system"] => run_foreground(true),
        #[cfg(windows)]
        ["service", cmd] => windows_service::command(cmd),
        ["--help" | "-h"] => {
            println!("{USAGE}");
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}

fn init_logging() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn run_foreground(system: bool) -> anyhow::Result<()> {
    init_logging();
    tokio::runtime::Runtime::new()?.block_on(run(system, shutdown_signal()))
}

/// Engine configuration for this run mode.
pub(crate) fn engine_config(system: bool) -> EngineConfig {
    let mut config = EngineConfig::default();
    if let Some(dir) = std::env::var_os("HERMES_DATA_DIR").filter(|d| !d.is_empty()) {
        config.data_dir = PathBuf::from(dir);
    } else if system {
        config.data_dir = system_data_dir();
    }
    config
}

/// State directory of the system service: systemd's `StateDirectory=` if
/// set, else the platform's conventional machine-wide location.
fn system_data_dir() -> PathBuf {
    #[cfg(unix)]
    {
        std::env::var_os("STATE_DIRECTORY")
            .and_then(|d| std::env::split_paths(&d).next())
            .unwrap_or_else(|| PathBuf::from("/var/lib/hermes"))
    }
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
            .join("Hermes")
    }
}

/// Serve until `shutdown` resolves, then shut the engine down gracefully.
pub(crate) async fn run(system: bool, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
    let config = engine_config(system);
    info!(data_dir = %config.data_dir.display(), system, "starting");
    let server = Server::new(config)?;

    info!(
        node = %server.engine().identity().node_id.short(),
        "hermes-daemon started",
    );

    tokio::select! {
        res = accept_loop(server.clone(), system) => {
            if let Err(e) = &res {
                error!(?e, "accept loop exited with error");
            }
            server.engine().shutdown().await;
            return res;
        }
        () = shutdown => {
            info!("shutdown signal received");
        }
    }

    // Leave the room cleanly (peers see us go immediately, the adapter is
    // torn down) and remove our UPnP port mapping from the router.
    server.engine().shutdown().await;
    Ok(())
}

#[cfg(unix)]
async fn accept_loop(server: Arc<Server>, system: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    let path = transport::listen_path(system);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Remove any stale socket from a previous run. Ignore ENOENT.
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)?;

    // A per-user daemon's socket is for its owner only. The system
    // service's socket is also open to its group (`hermes`): membership in
    // that group is what authorizes a user to drive the daemon.
    let mode = if system { 0o660 } else { 0o600 };
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;

    info!(path = %path.display(), mode = format!("{mode:o}"), "listening for IPC clients");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let server = server.clone();
        tokio::spawn(async move {
            server.serve_client(stream).await;
        });
    }
}

#[cfg(windows)]
async fn accept_loop(server: Arc<Server>, _system: bool) -> anyhow::Result<()> {
    info!(pipe = %transport::PIPE_PATH, "listening for IPC clients");

    // The first instance claims the name (fails if anyone else holds it);
    // after each connection we immediately create the next instance so
    // there's never a window where a client would hit ERROR_PIPE_BUSY.
    let mut next = transport::create_pipe_instance(true)?;
    loop {
        next.connect().await?;
        let connected = std::mem::replace(&mut next, transport::create_pipe_instance(false)?);
        let srv = server.clone();
        tokio::spawn(async move {
            srv.serve_client(connected).await;
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
