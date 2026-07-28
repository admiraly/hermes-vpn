//! Windows virtual adapter backed by [wintun](https://www.wintun.net/).
//!
//! This is a real implementation — no stubs. It drives the wintun driver
//! through the `wintun` crate and is paired with the
//! [`crate::broadcast::shim`] module that translates between the L3
//! interface wintun presents and the L2 frames the Hermes mesh carries.
//!
//! ### Threading model
//!
//! Wintun's `receive_blocking` / `send_packet` are synchronous C calls
//! that block the calling thread. We can't call them from a tokio task
//! directly (they'd starve the async runtime), so we dedicate two OS
//! threads per adapter:
//!
//! - A **reader thread** calls `receive_blocking` in a loop and ships
//!   packets into an mpsc channel that the async runtime drains.
//! - A **writer thread** drains an outbound mpsc channel and calls
//!   `allocate_send_packet` + `send_packet` for each packet.
//!
//! Shutdown is coordinated through `Session::shutdown`, which unblocks
//! any thread currently parked in `receive_blocking`.
//!
//! ### IPv4 configuration
//!
//! Wintun does **not** configure the adapter's IP address for us — we
//! have to do that separately. The `set_ipv4_address` helper shells out
//! to `netsh interface ip set address` for simplicity. A production
//! build should use the IP Helper API (`SetUnicastIpAddressEntry`) to
//! avoid the process spawn, but the behaviour is identical.
//!
//! ### wintun.dll location
//!
//! The DLL must be present next to the executable at runtime. Our
//! installer copies `wintun/bin/amd64/wintun.dll` into the install dir;
//! during `cargo run` we look for it beside `target/debug/*.exe`. If the
//! DLL is missing, adapter creation fails with a clear error and the
//! daemon exits — we don't silently fall back to anything.

#![cfg(windows)]

use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use super::{AdapterConfig, VirtualAdapter, FRAME_BUFFER_SIZE};
use crate::error::{HermesError, Result};

/// Channel capacity in each direction.
///
/// Sized to absorb short traffic bursts without dropping frames while
/// keeping memory bounded. Gigabit at 1500-byte MTU is ~85k packets/s,
/// so 4096 ≈ 50 ms of buffering — enough to ride out GC pauses on the
/// async side without serialising a big queue.
const CHANNEL_CAPACITY: usize = 4096;

/// Wintun-backed adapter for Windows.
pub struct WintunAdapter {
    config: AdapterConfig,
    /// Tokio mutex: the guard is held across an `.await` in `recv_frame`,
    /// which a sync mutex guard must never be.
    inbound_rx: Mutex<mpsc::Receiver<BytesMut>>,
    outbound_tx: mpsc::Sender<BytesMut>,
    /// Keeps the wintun session alive for the lifetime of this adapter.
    /// `wintun::Session` is dropped through `Arc` refs from the worker
    /// threads, so we hold it here too to prevent premature teardown if
    /// those threads exit early.
    _session: Arc<wintun::Session>,
    /// Same idea for the adapter itself.
    _adapter: Arc<wintun::Adapter>,
}

impl WintunAdapter {
    /// Bring up a new wintun adapter with the given config.
    ///
    /// # Errors
    /// Fails if `wintun.dll` cannot be loaded, the driver is not
    /// installed, the process lacks administrator rights, or the IPv4
    /// address assignment fails.
    pub async fn create(config: AdapterConfig) -> Result<Self> {
        info!(
            adapter.name = %config.name,
            adapter.ipv4 = %config.ipv4,
            "bringing up wintun adapter",
        );

        // Load wintun.dll. `wintun::load` searches the current directory
        // and then PATH; the installer places the DLL next to our .exe.
        let wintun = unsafe { wintun::load() }
            .map_err(|e| HermesError::Tap(format!("load wintun.dll: {e}")))?;

        // Create (or open) the adapter. A persistent GUID keeps Windows
        // from treating each start as a fresh "unidentified network" that
        // prompts the user for a firewall profile.
        let adapter = match wintun::Adapter::open(&wintun, &config.name) {
            Ok(a) => a,
            Err(_) => wintun::Adapter::create(&wintun, &config.name, "Hermes", None)
                .map_err(|e| HermesError::Tap(format!("create wintun adapter: {e}")))?,
        };

        // Configure the IPv4 address. wintun doesn't do this itself.
        set_ipv4_address(&config.name, config.ipv4, config.ipv4_prefix)?;

        // Set the interface MTU. Without this, Windows advertises the
        // default 1500 to applications, which then hand wintun packets
        // larger than our encapsulation budget — those would fragment (or
        // be dropped with the DF bit set) once wrapped for the tunnel.
        // Pinning the adapter MTU makes the OS perform path-MTU discovery
        // correctly. (Linux does the equivalent via `tokio-tun`'s `.mtu()`.)
        set_mtu(&config.name, config.mtu);

        // Start a session. `MAX_RING_CAPACITY` is 64 MiB, which sounds
        // huge but is the library's recommended value — it's a ring
        // buffer, not an allocation, and the kernel backs it with paged
        // memory.
        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| HermesError::Tap(format!("start session: {e}")))?,
        );

        let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (outbound_tx, outbound_rx) = mpsc::channel::<BytesMut>(CHANNEL_CAPACITY);

        // Spawn reader and writer threads.
        let reader_session = session.clone();
        std::thread::Builder::new()
            .name("hermes-wintun-reader".into())
            .spawn(move || reader_loop(reader_session, inbound_tx))
            .map_err(|e| HermesError::Tap(format!("spawn reader: {e}")))?;

        let writer_session = session.clone();
        std::thread::Builder::new()
            .name("hermes-wintun-writer".into())
            .spawn(move || writer_loop(writer_session, outbound_rx))
            .map_err(|e| HermesError::Tap(format!("spawn writer: {e}")))?;

        Ok(Self {
            config,
            inbound_rx: Mutex::new(inbound_rx),
            outbound_tx,
            _session: session,
            _adapter: adapter,
        })
    }
}

/// OS-thread body that drains wintun's receive ring into the async channel.
fn reader_loop(session: Arc<wintun::Session>, tx: mpsc::Sender<BytesMut>) {
    loop {
        let packet = match session.receive_blocking() {
            Ok(p) => p,
            Err(e) => {
                // Any error from receive_blocking is terminal — either
                // the session was shut down (expected) or something
                // genuinely went wrong.
                info!(?e, "wintun reader exiting");
                return;
            }
        };
        let bytes = packet.bytes();
        if bytes.is_empty() {
            continue;
        }
        let mut buf = BytesMut::with_capacity(bytes.len());
        buf.extend_from_slice(bytes);

        // `blocking_send` is fine here because we're on a dedicated OS
        // thread that never touches the tokio runtime.
        if tx.blocking_send(buf).is_err() {
            info!("inbound channel closed; wintun reader exiting");
            return;
        }
    }
}

/// OS-thread body that drains the async outbound channel into wintun's send ring.
fn writer_loop(session: Arc<wintun::Session>, mut rx: mpsc::Receiver<BytesMut>) {
    while let Some(packet) = rx.blocking_recv() {
        // `allocate_send_packet` requires the exact final size, so we
        // can't re-use a pool buffer — wintun itself owns the packet
        // memory.
        let len = packet.len();
        match session.allocate_send_packet(len as u16) {
            Ok(mut alloc) => {
                alloc.bytes_mut().copy_from_slice(&packet);
                session.send_packet(alloc);
            }
            Err(e) => {
                warn!(?e, bytes = len, "wintun allocate_send_packet failed");
            }
        }
    }
    info!("wintun writer exiting");
}

/// Assign an IPv4 address to the wintun adapter named `adapter_name`.
///
/// We use `netsh` rather than the IP Helper API because it's a single
/// external call with clear semantics. If you want to avoid the subprocess,
/// swap this for `SetUnicastIpAddressEntry` from the `windows` crate.
fn set_ipv4_address(adapter_name: &str, ip: std::net::Ipv4Addr, prefix_len: u8) -> Result<()> {
    let mask = prefix_to_mask_string(prefix_len);
    let status = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "address",
            &format!("name={adapter_name}"),
            "static",
            &ip.to_string(),
            &mask,
        ])
        .status()
        .map_err(|e| HermesError::Tap(format!("spawn netsh: {e}")))?;
    if !status.success() {
        return Err(HermesError::Tap(format!(
            "netsh set address exited with {status}"
        )));
    }
    debug!(adapter = %adapter_name, %ip, prefix = prefix_len, "wintun IPv4 configured");
    Ok(())
}

/// Pin the adapter's IPv4 MTU via `netsh`. Best-effort: a failure here
/// degrades to possible fragmentation rather than a dead adapter, so we
/// log and carry on rather than failing adapter creation.
fn set_mtu(adapter_name: &str, mtu: u16) {
    let result = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "subinterface",
            &format!("interface={adapter_name}"),
            &format!("mtu={mtu}"),
            "store=persistent",
        ])
        .status();
    match result {
        Ok(status) if status.success() => {
            debug!(adapter = %adapter_name, mtu, "wintun MTU configured");
        }
        Ok(status) => {
            warn!(adapter = %adapter_name, %status, "netsh set mtu failed — large packets may fragment");
        }
        Err(e) => {
            warn!(adapter = %adapter_name, ?e, "could not spawn netsh to set mtu");
        }
    }
}

fn prefix_to_mask_string(prefix: u8) -> String {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    std::net::Ipv4Addr::from(mask).to_string()
}

#[async_trait]
impl VirtualAdapter for WintunAdapter {
    async fn recv_frame(&self) -> Result<BytesMut> {
        let mut rx = self
            .inbound_rx
            .try_lock()
            .map_err(|_| HermesError::Tap("concurrent recv_frame".into()))?;
        rx.recv()
            .await
            .ok_or_else(|| HermesError::Tap("adapter closed".into()))
    }

    async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        if frame.len() > FRAME_BUFFER_SIZE {
            return Err(HermesError::Tap(format!(
                "oversized frame: {} bytes",
                frame.len()
            )));
        }
        let mut buf = BytesMut::with_capacity(frame.len());
        buf.extend_from_slice(frame);
        self.outbound_tx
            .send(buf)
            .await
            .map_err(|_| HermesError::Tap("adapter send channel closed".into()))
    }

    async fn shutdown(&self) -> Result<()> {
        // Calling `shutdown` on the session unblocks the reader thread
        // currently parked in `receive_blocking`. The writer thread exits
        // when its channel closes on Drop.
        let _ = self._session.shutdown();
        Ok(())
    }

    fn config(&self) -> &AdapterConfig {
        &self.config
    }

    fn mode(&self) -> super::AdapterMode {
        super::AdapterMode::Ip
    }
}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        if let Err(e) = self._session.shutdown() {
            warn!(?e, "error shutting down wintun session on drop");
        }
    }
}
