//! # hermes-daemon
//!
//! The privileged Hermes background service. It owns one
//! [`hermes_core::HermesEngine`] (and therefore the virtual adapter) and
//! exposes it to unprivileged clients — the Tauri UI and the `hermes`
//! CLI — over a local IPC socket (a named pipe on Windows, a Unix domain
//! socket elsewhere).
//!
//! - [`protocol`]  — the JSON wire types (commands, responses, events).
//! - [`transport`] — length-prefixed framing and the platform socket path.
//! - [`server`]    — the engine host that serves any number of clients.
//! - [`client`]    — the client library used by the UI and CLI.

#![warn(missing_docs)]

pub mod client;
pub mod protocol;
pub mod server;
pub mod transport;

pub use client::DaemonClient;
pub use server::Server;
