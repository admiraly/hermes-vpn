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
            "bringing up tun/tap adapter",
        );

        // Build the TAP device. `name("")` lets the kernel pick a name if
        // the user didn't set one — but for Hermes we always want a
        // predictable name so the same adapter is reused across restarts.
        //
        // `try_build()` returns a single Tun in 0.12; multi-queue support
        // is via the separate `try_build_mq` method which we don't need.
        let tun = Tun::builder()
            .name(&config.name)
            .tap() // L2 mode
            .mtu(i32::from(config.mtu))
            .up()
            .try_build()
            .map_err(|e| {
                let hint = if e.to_string().contains("Permission denied")
                    || e.to_string().contains("Operation not permitted")
                {
                    " — the daemon needs CAP_NET_ADMIN (setcap, or the systemd unit) \
                     and read/write access to /dev/net/tun (normally mode 0666)"
                } else {
                    ""
                };
                HermesError::Tap(format!("creating the TAP adapter: {e}{hint}"))
            })?;
        let tun = Arc::new(tun);

        // The kernel gives a fresh TAP device a random MAC, but peers
        // address frames to our *derived* virtual MAC (and the Windows
        // shim synthesizes frames with it). Without this the kernel
        // drops every unicast frame sent to us as "not for this host".
        // TAP devices allow live MAC changes, so this works while up.
        set_mac_address(&config.name, &config.mac.to_string())?;

        // Configure IPv4. Use `ip` rather than the libc netlink API to
        // keep the implementation short; if you want to avoid the fork,
        // swap this for `rtnetlink`.
        set_ipv4_address(&config.name, config.ipv4, config.ipv4_prefix)?;

        debug!(iface = %tun.name(), "TAP adapter up");

        Ok(Self { config, tun })
    }
}

fn run_ip(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("ip")
        .args(args)
        .status()
        .map_err(|e| HermesError::Tap(format!("spawn ip: {e}")))?;
    if !status.success() {
        return Err(HermesError::Tap(format!(
            "`ip {}` exited with {status}",
            args.join(" ")
        )));
    }
    Ok(())
}

fn set_mac_address(iface: &str, mac: &str) -> Result<()> {
    run_ip(&["link", "set", "dev", iface, "address", mac])
}

fn set_ipv4_address(iface: &str, ip: std::net::Ipv4Addr, prefix: u8) -> Result<()> {
    // `replace` rather than `add` so re-entering a room (or a leftover
    // address from a crashed run) is not an error.
    run_ip(&["addr", "replace", &format!("{ip}/{prefix}"), "dev", iface])
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
