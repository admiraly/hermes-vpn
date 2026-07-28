//! Error types for hermes-core.

use thiserror::Error;

/// Result alias used throughout hermes-core.
pub type Result<T> = std::result::Result<T, HermesError>;

/// The top-level error type.
#[derive(Debug, Error)]
pub enum HermesError {
    /// I/O error (sockets, files, adapters).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic failure.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// TAP/virtual adapter error.
    #[error("tap adapter error: {0}")]
    Tap(String),

    /// WireGuard tunnel error.
    #[error("tunnel error: {0}")]
    Tunnel(String),

    /// Signaling server error.
    #[error("signaling error: {0}")]
    Signaling(String),

    /// NAT traversal failure.
    #[error("NAT traversal error: {0}")]
    Nat(String),

    /// Room/membership error.
    #[error("room error: {0}")]
    Room(String),

    /// Peer not found / disconnected.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Serialization failure.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Invalid invite code.
    #[error("invalid invite code")]
    InvalidInviteCode,

    /// Protocol version mismatch with remote peer.
    #[error("protocol version mismatch (ours: {ours}, theirs: {theirs})")]
    VersionMismatch {
        /// Our protocol version.
        ours: u16,
        /// Their protocol version.
        theirs: u16,
    },

    /// Catch-all wrapping `anyhow::Error`.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<serde_json::Error> for HermesError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<bincode::Error> for HermesError {
    fn from(e: bincode::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}
