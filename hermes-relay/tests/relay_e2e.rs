//! End-to-end tests against the real `hermes-relay` binary.
//!
//! Each test spawns the compiled relay server (cargo exposes the path via
//! `CARGO_BIN_EXE_hermes-relay`), registers nodes over real UDP, and
//! verifies forwarding, room isolation, replay protection — and finally a
//! complete WireGuard handshake + encrypted frame delivery through the
//! relay using the same `PeerTunnel` code the engine uses.

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use hermes_core::crypto::NodeSecret;
use hermes_core::relay::protocol::{self, RelayPacket};
use hermes_core::room::RoomId;
use hermes_core::tunnel::{PeerPath, PeerTunnel};

struct RelayProcess {
    child: Child,
    addr: SocketAddr,
}