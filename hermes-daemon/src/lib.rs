//! # hermes-daemon
//!
//! The privileged half of a Hermes node. The daemon owns the virtual
//! network adapter — the one resource that needs elevation — and exposes
//! everything else over a local IPC socket so that unprivileged clients
//! (the desktop UI, `hermes-cli`) can drive it.
//!
//! - [`protocol`]  — the JSON request/response wire format and its events
//! - [`transport`] — length-prefixed framing over a named pipe / Unix socket
//! - [`Server`]    — daemon side: owns the engine, serves many clients
//! - [`DaemonClient`] — client side: handshake, RPC, and an event stream
//!
//! The binary in `main.rs` is a thin wrapper: it builds a [`Server`] and
//! accepts connections until it is signalled to stop.

#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

pub mod client;
pub mod protocol;
pub mod server;
pub mod transport;

pub use client::DaemonClient;
pub use server::Server;
