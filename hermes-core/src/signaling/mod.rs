//! The signaling (rendezvous) client.
//!
//! Signaling is how two Hermes nodes find each other. It is a WebSocket
//! connection to a small, self-hostable server that does exactly three
//! things: authenticate a node by challenging it to sign a nonce with its
//! Ed25519 identity key, track which nodes are in which room, and pass
//! NAT candidate lists between them.
//!
//! It deliberately does *not* touch room traffic. Once peers have each
//! other's candidates the data path is direct (or via a relay), and the
//! signaling connection can drop without interrupting a single frame —
//! the engine reconnects in the background and re-joins by remembered
//! invite code.
//!
//! [`protocol`] holds the message types shared with the `hermes-signaling`
//! server binary; [`SignalingClient`] is the client half.

pub mod client;
pub mod protocol;

pub use client::SignalingClient;
pub use protocol::{ClientMessage, PeerInfo, ServerMessage};
