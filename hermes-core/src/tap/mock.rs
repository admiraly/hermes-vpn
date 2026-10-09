//! An in-memory [`VirtualAdapter`] for tests and headless use.
//!
//! It behaves like an OS adapter without touching the OS, so the engine's
//! whole data path — driver loops, shim, mesh, tunnels — can run in an
//! ordinary unprivileged process. Frames the "operating system" sends are
//! pushed with [`MockHandle::inject`]; frames the engine delivers to the
//! OS come out of [`MockHandle::written`].
//!
//! It can pose as either kind of adapter: [`AdapterMode::Ethernet`] like
//! Linux TAP, or [`AdapterMode::Ip`] like Windows wintun — which exercises
//! the L2/L3 shim on any platform.

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::sync::{mpsc, Mutex};

use super::{AdapterConfig, AdapterMode, VirtualAdapter};
use crate::error::{HermesError, Result};

/// A factory making [`MockAdapter`]s of the given kind, for
/// [`crate::HermesEngine::with_adapter_factory`]. Each adapter the engine
/// creates (one per room entry) delivers its [`MockHandle`] on the returned
/// channel.
#[must_use]
pub fn mock_adapter_factory(
    mode: AdapterMode,
) -> (super::AdapterFactory, mpsc::UnboundedReceiver<MockHandle>) {
    let (handles_tx, handles_rx) = mpsc::unbounded_channel();
    let factory: super::AdapterFactory = std::sync::Arc::new(move |config| {
        let handles_tx = handles_tx.clone();
        Box::pin(async move {
            let (adapter, handle) = MockAdapter::new(config, mode);
            let _ = handles_tx.send(handle);
            let adapter: std::sync::Arc<dyn VirtualAdapter> = std::sync::Arc::new(adapter);
            Ok(adapter)
        })
    });
    (factory, handles_rx)
}

/// The test's side of a [`MockAdapter`].
pub struct MockHandle {
    /// What the engine brought the adapter up with (our MAC and IP).
    pub config: AdapterConfig,
    to_engine: mpsc::UnboundedSender<BytesMut>,
    /// Frames the engine wrote to the adapter (the "OS" side).
    pub written: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl MockHandle {
    /// Send a packet from the "OS" into the engine, as an application
    /// writing to the adapter would (Ethernet frame or IP packet,
    /// depending on the adapter's mode).
    pub fn inject(&self, packet: &[u8]) {
        let _ = self.to_engine.send(BytesMut::from(packet));
    }
}

/// See the [module docs](self).
pub struct MockAdapter {
    config: AdapterConfig,
    mode: AdapterMode,
    from_os: Mutex<mpsc::UnboundedReceiver<BytesMut>>,
    to_os: mpsc::UnboundedSender<Vec<u8>>,
}

impl MockAdapter {
    /// A mock adapter plus the handle that drives it.
    #[must_use]
    pub fn new(config: AdapterConfig, mode: AdapterMode) -> (Self, MockHandle) {
        let (to_engine, from_os) = mpsc::unbounded_channel();
        let (to_os, written) = mpsc::unbounded_channel();
        let config_for_handle = config.clone();
        (
            Self {
                config,
                mode,
                from_os: Mutex::new(from_os),
                to_os,
            },
            MockHandle {
                config: config_for_handle,
                to_engine,
                written,
            },
        )
    }
}

#[async_trait]
impl VirtualAdapter for MockAdapter {
    async fn recv_frame(&self) -> Result<BytesMut> {
        self.from_os
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| HermesError::Tap("mock adapter closed".into()))
    }

    async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        self.to_os
            .send(frame.to_vec())
            .map_err(|_| HermesError::Tap("mock adapter handle dropped".into()))
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    fn config(&self) -> &AdapterConfig {
        &self.config
    }

    fn mode(&self) -> AdapterMode {
        self.mode
    }
}
