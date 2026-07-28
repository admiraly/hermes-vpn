//! Relay ("central server") support.
//!
//! A Hermes room can run in one of two modes (see
//! [`crate::room::RoomMode`]):
//!
//! - **Peer-to-peer** — peers exchange NAT candidates via the signaling
//!   server and talk directly. The classic Hermes path.
//! - **Relayed** — every peer sends its WireGuard ciphertext to one
//!   relay server, which forwards it to the addressed room member. No
//!   NAT traversal is attempted at all; the only thing a peer needs is
//!   outbound UDP to the relay. Traffic remains end-to-end encrypted —
//!   the relay sees ciphertext and metadata only.
//!
//! [`protocol`] defines the datagram format shared with the
//! `hermes-relay` server binary; [`client`] hosts the client-side
//! registration keepalive.

pub mod client;
pub mod protocol;

pub use client::{spawn_registration, RegistrationConfig, RelayHealth};
pub use protocol::{is_relay_packet, parse_packet, RelayPacket};
