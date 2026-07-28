//! Length-prefixed JSON framing and the platform-specific local socket
//! used to carry it.
//!
//! Framing is deliberately simple: a 4-byte little-endian length followed
//! by exactly that many UTF-8 JSON bytes. Messages up to [`MAX_FRAME_LEN`]
//! are accepted; larger frames cause the stream to be dropped. The cap is
//! intentional — local IPC should never need multi-megabyte messages, and
//! a low cap limits the blast radius of a misbehaving client.
//!
//! On Windows the stream type is a named pipe (`NamedPipeServer` /
//! `NamedPipeClient`) and on Unix it's a `UnixStream`. Both satisfy the
//! `AsyncRead + AsyncWrite` bounds we need.

use std::path::PathBuf;

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::protocol::Frame;

/// The named pipe path used on Windows.
#[cfg(windows)]
pub const PIPE_PATH: &str = r"\\.\pipe\hermes-daemon";

/// Maximum IPC frame length (1 MiB). Frames larger than this tear the
/// connection down.
pub const MAX_FRAME_LEN: usize = 1_048_576;

/// Type-erased framed IPC connection.
pub type FramedIpc<T> = Framed<T, LengthDelimitedCodec>;

/// Construct a length-delimited codec with our standard limits.
#[must_use]
pub fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .little_endian()
        .length_field_length(4)
        .max_frame_length(MAX_FRAME_LEN)
        .new_codec()
}

/// Wrap a raw byte stream into a framed JSON transport.
pub fn wrap<T>(stream: T) -> FramedIpc<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    Framed::new(stream, codec())
}

/// Return the canonical Unix domain socket path for the daemon.
///
/// Prefers `$XDG_RUNTIME_DIR/hermes/daemon.sock` (cleared on logout) and
/// falls back to the user's data dir if the runtime dir is unavailable.
#[cfg(unix)]
#[must_use]
pub fn unix_socket_path() -> PathBuf {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime.is_empty() {
            return PathBuf::from(runtime).join("hermes").join("daemon.sock");
        }
    }
    let data = directories::ProjectDirs::from("dev", "hermes", "Hermes")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    data.join("daemon.sock")
}

/// Stub to keep the path function cross-platform where callers need one.
#[cfg(windows)]
#[must_use]
pub fn unix_socket_path() -> PathBuf {
    PathBuf::from(PIPE_PATH)
}

/// Send a frame over a framed transport.
///
/// # Errors
/// Fails on serialization error or write error.
pub async fn send_frame<T>(framed: &mut FramedIpc<T>, frame: &Frame) -> anyhow::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let bytes = serde_json::to_vec(frame)?;
    framed.send(bytes.into()).await?;
    Ok(())
}

/// Receive the next frame from a framed transport.
///
/// Returns `Ok(None)` on clean EOF.
///
/// # Errors
/// Fails on framing error or invalid JSON.
pub async fn recv_frame<T>(framed: &mut FramedIpc<T>) -> anyhow::Result<Option<Frame>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match framed.next().await {
        None => Ok(None),
        Some(Err(e)) => Err(e.into()),
        Some(Ok(bytes)) => {
            let frame: Frame = serde_json::from_slice(&bytes)?;
            Ok(Some(frame))
        }
    }
}
