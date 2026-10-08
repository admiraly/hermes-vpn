//! WireGuard tunnels between peer pairs.
//!
//! Each established peer relationship owns one [`PeerTunnel`]. The tunnel
//! wraps a `boringtun` `Tunn` state machine and a UDP socket, and provides
//! an Ethernet-frame in / Ethernet-frame out async interface.
//!
//! Frames are wrapped in a tiny framing header before being handed to
//! boringtun, because WireGuard natively expects IP packets. See
//! [`framing`] for details.

mod framing;
mod peer_tunnel;

pub use framing::{
    decode_frame, decode_packet, encode_control, encode_frame, FrameHeader, Payload,
};
pub use peer_tunnel::{PeerPath, PeerTunnel, TunnelStats};
