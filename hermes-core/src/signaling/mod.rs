//! Client side of the signaling (rendezvous) protocol.
//!
//! - [`protocol`] — the JSON message types shared with `hermes-signaling`.
//! - [`client`]   — the WebSocket driver: challenge/response auth, then a
//!   send handle plus an inbox of server messages.

pub mod client;
pub mod protocol;

pub use client::{is_insecure_url, Keepalive, SignalingClient};
pub use protocol::{ClientMessage, PeerInfo, RoomRestore, ServerMessage};
