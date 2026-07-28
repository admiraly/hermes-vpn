//! Runtime driver that wires the virtual adapter and the mesh together.
//!
//! Two long-lived tasks run per engine:
//!
//! - The **tap→mesh** task pulls packets off the virtual adapter and
//!   hands them to [`Mesh::dispatch_outbound`], which routes each frame
//!   to the right peer (unicast) or every peer (broadcast / multicast).
//!   If the adapter operates in [`AdapterMode::Ip`] (wintun on Windows)
//!   packets go through [`shim::wrap_outbound`] first to grow an
//!   Ethernet header.
//!
//! - The **udp→mesh→tap** task reads UDP datagrams off the shared socket
//!   and asks the mesh to decrypt them. Decrypted Ethernet frames go
//!   back to the adapter via `send_frame` — or, if the adapter is
//!   Ip-mode and the frame is an ARP request, we synthesize a reply and
//!   loop it back into the mesh so the remote peer sees an answer.

use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::broadcast::{shim, MacRouter};
use crate::mesh::Mesh;
use crate::tap::{AdapterMode, VirtualAdapter, DATAGRAM_BUFFER_SIZE, FRAME_BUFFER_SIZE};

/// A running driver. Dropping this cancels both tasks.
pub struct DriverHandle {
    shutdown_tx: watch::Sender<bool>,
    tap_task: Option<JoinHandle<()>>,
    udp_task: Option<JoinHandle<()>>,
}

impl DriverHandle {
    /// Signal the driver to stop and wait for the tasks to finish.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(h) = self.tap_task.take() {
            let _ = h.await;
        }
        if let Some(h) = self.udp_task.take() {
            let _ = h.await;
        }
    }
}

impl Drop for DriverHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Start the driver.
pub fn spawn(mesh: Arc<Mesh>, adapter: Arc<dyn VirtualAdapter>) -> DriverHandle {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mode = adapter.mode();
    let own_mac = adapter.config().mac;
    let router = mesh.router.clone();

    let tap_task = tokio::spawn(tap_to_mesh_loop(
        mesh.clone(),
        adapter.clone(),
        router.clone(),
        own_mac,
        mode,
        shutdown_rx.clone(),
    ));
    let udp_task = tokio::spawn(udp_to_tap_loop(mesh, adapter, router, mode, shutdown_rx));

    DriverHandle {
        shutdown_tx,
        tap_task: Some(tap_task),
        udp_task: Some(udp_task),
    }
}

/// Pull packets from the virtual adapter and hand them to the mesh.
async fn tap_to_mesh_loop(
    mesh: Arc<Mesh>,
    adapter: Arc<dyn VirtualAdapter>,
    router: Arc<MacRouter>,
    own_mac: crate::crypto::VirtualMac,
    mode: AdapterMode,
    mut shutdown: watch::Receiver<bool>,
) {
    info!(?mode, "tap→mesh loop started");
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            packet = adapter.recv_frame() => {
                match packet {
                    Ok(raw) => {
                        let frame = match mode {
                            AdapterMode::Ethernet => raw,
                            AdapterMode::Ip => match shim::wrap_outbound(&raw, own_mac, &router) {
                                Some(f) => f,
                                None => continue, // malformed or undeliverable
                            },
                        };
                        // Defense in depth: if the adapter MTU wasn't honored
                        // and an app handed us a jumbo frame, drop it rather
                        // than emit a datagram that fragments (or is dropped
                        // with DF set) once encapsulated. The adapter MTU
                        // should prevent this from ever firing.
                        if frame.len() > FRAME_BUFFER_SIZE {
                            warn!(
                                bytes = frame.len(),
                                max = FRAME_BUFFER_SIZE,
                                "dropping oversized outbound frame (check adapter MTU)",
                            );
                            continue;
                        }
                        if let Err(e) = mesh.dispatch_outbound(&frame).await {
                            debug!(?e, "outbound dispatch error");
                        }
                    }
                    Err(e) => {
                        warn!(?e, "recv_frame failed; exiting tap loop");
                        break;
                    }
                }
            }
        }
    }
    info!("tap→mesh loop exited");
}

/// Pull UDP datagrams off the shared socket, decrypt, and inject into TAP.
async fn udp_to_tap_loop(
    mesh: Arc<Mesh>,
    adapter: Arc<dyn VirtualAdapter>,
    router: Arc<MacRouter>,
    mode: AdapterMode,
    mut shutdown: watch::Receiver<bool>,
) {
    info!(?mode, "udp→mesh→tap loop started");
    let socket = mesh.socket.clone();
    let mut buf = [0u8; DATAGRAM_BUFFER_SIZE];
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            recvd = socket.recv_from(&mut buf) => {
                match recvd {
                    Ok((n, from)) => {
                        match mesh.dispatch_inbound(from, &buf[..n]).await {
                            Ok(Some(eth_frame)) => {
                                handle_inbound_frame(
                                    &mesh,
                                    &adapter,
                                    &router,
                                    mode,
                                    &eth_frame,
                                )
                                .await;
                            }
                            Ok(None) => {}
                            Err(e) => debug!(?e, "inbound dispatch error"),
                        }
                    }
                    Err(e) => {
                        warn!(?e, "recv_from failed; exiting udp loop");
                        break;
                    }
                }
            }
        }
    }
    info!("udp→mesh→tap loop exited");
}

/// Decide what to do with an Ethernet frame decrypted from the mesh.
///
/// On Ethernet-mode platforms it goes straight into the adapter. On
/// Ip-mode platforms it passes through the shim, which may unwrap it
/// into an IP packet for wintun, bounce an ARP reply back across the
/// mesh, or drop the frame entirely.
async fn handle_inbound_frame(
    mesh: &Arc<Mesh>,
    adapter: &Arc<dyn VirtualAdapter>,
    router: &Arc<MacRouter>,
    mode: AdapterMode,
    frame: &[u8],
) {
    match mode {
        AdapterMode::Ethernet => {
            if let Err(e) = adapter.send_frame(frame).await {
                warn!(?e, "tap send_frame failed");
            }
        }
        AdapterMode::Ip => match shim::unwrap_inbound(frame, router) {
            shim::InboundAction::WriteToAdapter(ip) => {
                if let Err(e) = adapter.send_frame(&ip).await {
                    warn!(?e, "tap send_frame failed");
                }
            }
            shim::InboundAction::ReplyOnMesh(reply) => {
                if let Err(e) = mesh.dispatch_outbound(&reply).await {
                    debug!(?e, "shim reply outbound failed");
                }
            }
            shim::InboundAction::Drop => {}
        },
    }
}
