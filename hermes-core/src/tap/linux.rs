//! Linux virtual adapter backed by `/dev/net/tun` in TAP mode via `tokio-tun`.
//!
//! Linux's built-in `tun` module supports both Layer 3 (TUN) and Layer 2
//! (TAP) operation. We open the device in TAP mode so the adapter speaks
//! raw Ethernet frames natively — no L2/L3 shim required.
//!
//! `tokio-tun` gives us an async file descriptor that integrates with
//! the tokio runtime, so the single-threaded driver loop can read/write
//! without needing a dedicated OS thread the way wintun on Windows does.
//!
//! Requires `CAP_NET_ADMIN` (run as root or give the binary the
//! capability via `setcap`).

#![cfg(unix)]

use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio_tun::Tun;
use tracing::{debug, info};

use super::{AdapterConfig, VirtualAdapter, FRAME_BUFFER_SIZE};
use crate::error::{HermesError, Result};

/// Linux TAP-mode virtual adapter.
pub struct TunTapAdapter {
    config: AdapterConfig,
    /// Wrapped in `Arc` because both `recv` and `send` take `&self` and
    /// we want to allow concurrent reads and writes. `tokio-tun::Tun`
    /// internally uses a file descriptor which is safe for concurrent I/O.
    tun: Arc<Tun>,
}

impl TunTapAdapter {
    /// Bring up the TAP adapter. Requires `CAP_NET_ADMIN`.
    ///
    /// # Errors
    /// Fails if the kernel module is missing, permissions are
    /// insufficient, or the device name is already in use.
    pub async fn create(config: AdapterConfig) -> Result<Self> {
        info!(
            adapter.name = %config.name,
            adapter.ipv4 = %config.ipv4,
            adapter.mac = %config.mac,
            "bringing up tun/tap adapter",
        );

        // Build the TAP device. `name("")` lets the kernel pick a name if
        // the user didn't set one — but for Hermes we always want a
        // predictable name so the same adapter is reused across restarts.
        //
        // `try_build()` returns a single Tun in 0.12; multi-queue support
        // is via the separate `try_build_mq` method which we don't need.
        // Deliberately built *down*: the MAC must be set before the
        // interface starts carrying traffic, and some drivers refuse an
        // address change on a live link. `configure_interface` brings it
        // up once addressing is in place.
        let tun = Tun::builder()
            .name(&config.name)
            .tap() // L2 mode
            .mtu(i32::from(config.mtu))
            .try_build()
            .map_err(|e| HermesError::Tap(format!("tokio-tun build: {e}")))?;
        let tun = Arc::new(tun);

        // Configure MAC, IPv4, and link state over netlink, in-process.
        // This must not shell out to `ip`: file capabilities are not
        // inherited across `exec`, so a daemon granted CAP_NET_ADMIN via
        // setcap would create the device successfully and then fail to
        // configure it with EPERM.
        configure_interface(&config).await?;

        debug!(iface = %tun.name(), "TAP adapter up");

        Ok(Self { config, tun })
    }
}

/// Bring the interface up with its derived MAC and IPv4 address, over netlink.
///
/// The obvious implementation is `Command::new("ip").args(["addr", "add", ...])`,
/// and that is what this used to be. It cannot work for an unprivileged
/// daemon: capabilities granted to a binary with `setcap` live in the
/// file's permitted/effective sets and are **not** inherited by processes
/// it `exec`s. The `ip` child therefore runs with no capabilities at all
/// and the kernel rejects the address with `EPERM`, even though the very
/// same process just created the TUN device successfully.
///
/// Talking to netlink in-process keeps the operation inside the daemon,
/// where `CAP_NET_ADMIN` actually applies, so `setcap` works as documented
/// in BUILDING.md and running as root becomes optional rather than required.
///
/// # Errors
/// Fails if the netlink socket cannot be opened, the interface cannot be
/// found, or the kernel rejects the address (most often `EPERM` for a
/// missing `CAP_NET_ADMIN`, or `EEXIST` if it is already assigned).
async fn configure_interface(config: &AdapterConfig) -> Result<()> {
    use futures::TryStreamExt;

    let iface = config.name.as_str();
    let ip = config.ipv4;
    let prefix = config.ipv4_prefix;

    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|e| HermesError::Tap(format!("netlink socket: {e}")))?;
    // The connection drives the socket; it ends when `handle` is dropped.
    let conn_task = tokio::spawn(connection);

    let result = async {
        let link = handle
            .link()
            .get()
            .match_name(iface.to_string())
            .execute()
            .try_next()
            .await
            .map_err(|e| HermesError::Tap(format!("netlink link lookup: {e}")))?
            .ok_or_else(|| HermesError::Tap(format!("interface {iface} not found")))?;

        // The MAC is not cosmetic. Every peer derives this node's MAC from
        // its public key and addresses unicast frames to it; if the kernel's
        // randomly-generated MAC were left in place, those frames would be
        // dropped as "not for me" and only broadcast traffic would work.
        handle
            .link()
            .set(link.header.index)
            .address(config.mac.0.to_vec())
            .execute()
            .await
            .map_err(|e| HermesError::Tap(format!("set MAC {} on {iface}: {e}", config.mac)))?;

        handle
            .address()
            .add(link.header.index, std::net::IpAddr::V4(ip), prefix)
            .execute()
            .await
            .map_err(|e| {
                HermesError::Tap(format!(
                    "assign {ip}/{prefix} to {iface}: {e} \
                     (needs CAP_NET_ADMIN — see BUILDING.md)"
                ))
            })?;

        handle
            .link()
            .set(link.header.index)
            .up()
            .execute()
            .await
            .map_err(|e| HermesError::Tap(format!("bring {iface} up: {e}")))
    }
    .await;

    drop(handle);
    conn_task.abort();
    result
}

#[async_trait]
impl VirtualAdapter for TunTapAdapter {
    async fn recv_frame(&self) -> Result<BytesMut> {
        let mut buf = vec![0u8; FRAME_BUFFER_SIZE];
        let n = self
            .tun
            .recv(&mut buf)
            .await
            .map_err(|e| HermesError::Tap(format!("tun recv: {e}")))?;
        buf.truncate(n);
        Ok(BytesMut::from(&buf[..]))
    }

    async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        if frame.len() > FRAME_BUFFER_SIZE {
            return Err(HermesError::Tap(format!(
                "oversized frame: {} bytes",
                frame.len()
            )));
        }
        self.tun
            .send_all(frame)
            .await
            .map_err(|e| HermesError::Tap(format!("tun send: {e}")))
    }

    async fn shutdown(&self) -> Result<()> {
        // Nothing explicit — the device closes when the last Arc drops.
        Ok(())
    }

    fn config(&self) -> &AdapterConfig {
        &self.config
    }

    fn mode(&self) -> super::AdapterMode {
        super::AdapterMode::Ethernet
    }
}
