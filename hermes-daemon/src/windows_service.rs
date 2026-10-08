//! Running the daemon as a Windows service.
//!
//! `hermes-daemon service install` registers an auto-start service running
//! as LocalSystem (it needs administrator rights to create the wintun
//! adapter) and starts it; `service uninstall` stops and removes it. The
//! Service Control Manager launches the binary as `hermes-daemon service
//! run`, which hands control to [`service_main`].
//!
//! The service stores its state under `%ProgramData%\Hermes` and logs to
//! `daemon.log` there. Its named pipe admits authenticated local users
//! (see `transport::PIPE_SDDL`), so the desktop app works without
//! elevation.

use std::ffi::OsString;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_NAME: &str = "HermesDaemon";
const DISPLAY_NAME: &str = "Hermes virtual LAN";
const DESCRIPTION: &str = "Hosts the Hermes engine and virtual network adapter; \
                           the Hermes app and CLI control it.";

/// `hermes-daemon service <cmd>`.
pub fn command(cmd: &str) -> anyhow::Result<()> {
    match cmd {
        "install" => install(),
        "uninstall" => uninstall(),
        "run" => {
            // Called by the SCM. Blocks until the service stops.
            service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
            Ok(())
        }
        other => anyhow::bail!("unknown service command {other:?} (install | uninstall)"),
    }
}

fn install() -> anyhow::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec![OsString::from("service"), OsString::from("run")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager.create_service(
        &info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
    )?;
    service.set_description(DESCRIPTION)?;
    service.start::<&str>(&[])?;
    println!("installed and started the {DISPLAY_NAME} service ({SERVICE_NAME})");
    println!("keep wintun.dll next to {}", info.executable_path.display());
    Ok(())
}

fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        // Give the engine time to leave its room and remove UPnP mappings.
        for _ in 0..50 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    service.delete()?;
    println!("removed the {DISPLAY_NAME} service");
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(?e, "service failed");
    }
}

fn status(state: ServiceState, accept: ServiceControlAccept, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn run_service() -> anyhow::Result<()> {
    init_file_logging();

    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;

    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    ))?;

    let result = tokio::runtime::Runtime::new()?.block_on(crate::run(true, async move {
        let _ = stop_rx.wait_for(|stop| *stop).await;
    }));

    let exit = u32::from(result.is_err());
    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
    ))?;
    result
}

/// Services have no console: log to `%ProgramData%\Hermes\daemon.log`.
fn init_file_logging() {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let dir = crate::engine_config(true).data_dir;
    let _ = std::fs::create_dir_all(&dir);
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("daemon.log"))
    else {
        return;
    };
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(file)),
        )
        .init();
}
