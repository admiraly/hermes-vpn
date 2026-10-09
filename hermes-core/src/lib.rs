//! # hermes-core
//!
//! The core engine for Hermes — a P2P virtual LAN application.
//!
//! This crate is organized into focused submodules that each handle
//! one architectural concern:
//!
//! - [`crypto`]    — Ed25519/X25519 identity keypairs, derivation
//! - [`tap`]       — Virtual network adapter (wintun on Windows, tun on Linux)
//! - [`tunnel`]    — WireGuard encrypted tunnels between peer pairs
//! - [`nat`]       — NAT traversal (UPnP, STUN, ICE)
//! - [`relay`]     — Relay ("central server") wire protocol + client
//! - [`signaling`] — WebSocket client to the rendezvous server
//! - [`room`]      — Room state, modes, invite codes, peer registry
//! - [`mesh`]      — Full-mesh topology management
//! - [`broadcast`] — L2 frame forwarding, broadcast/multicast replication
//! - [`directory`] — Signaling/relay server directory + remote manifest
//! - [`ratelimit`] — Per-source token buckets for the servers
//!
//! The top-level [`HermesEngine`] ties these together behind one API.

#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

pub mod broadcast;
pub mod crypto;
pub mod directory;
pub mod engine;
pub mod engine_pump;
pub mod error;
pub mod mesh;
pub mod nat;
pub mod ratelimit;
pub mod relay;
pub mod room;
pub mod signaling;
pub mod tap;
pub mod tunnel;

pub use directory::{ServerDirectory, ServerEntry, ServerKind, ServerSource};
pub use engine::{EngineConfig, HermesEngine};
pub use engine_pump::EngineEvent;
pub use error::{HermesError, Result};
pub use room::RoomMode;

/// Protocol version — bumped on any wire-format change.
/// v2: room modes (p2p / relayed) + relay assignment.
/// v3: signed WireGuard-key bindings (`wireguard_binding`); peers without a
/// valid one are refused, so a hostile signaling server can't substitute keys.
pub const PROTOCOL_VERSION: u16 = 3;

/// Default virtual subnet assigned to rooms.
pub const DEFAULT_VIRTUAL_SUBNET: &str = "10.42.0.0/16";

/// Default signaling server URL (override via config).
pub const DEFAULT_SIGNALING_URL: &str = "wss://signal.hermes.example/v1";
