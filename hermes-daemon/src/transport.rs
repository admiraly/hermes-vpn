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

/// Socket of a daemon running as a system service (`hermes-daemon
/// --system`, e.g. via the bundled systemd unit). Group-accessible: users
/// in the `hermes` group may drive it.
#[cfg(unix)]
pub const SYSTEM_SOCKET: &str = "/run/hermes/daemon.sock";

/// Environment variable overriding the socket path on both sides.
#[cfg(unix)]
pub const SOCKET_ENV: &str = "HERMES_SOCKET";

/// Where a daemon should listen: `$HERMES_SOCKET` if set, else the system
/// socket in `--system` mode, else the per-user socket.
#[cfg(unix)]
#[must_use]
pub fn listen_path(system: bool) -> PathBuf {
    if let Some(p) = std::env::var_os(SOCKET_ENV).filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    if system {
        PathBuf::from(SYSTEM_SOCKET)
    } else {
        unix_socket_path()
    }
}

/// Where a client should look, in order: `$HERMES_SOCKET`, the per-user
/// daemon's socket, then the system service's socket.
#[cfg(unix)]
#[must_use]
pub fn client_paths() -> Vec<PathBuf> {
    if let Some(p) = std::env::var_os(SOCKET_ENV).filter(|p| !p.is_empty()) {
        return vec![PathBuf::from(p)];
    }
    let mut paths = vec![unix_socket_path(), PathBuf::from(SYSTEM_SOCKET)];
    paths.dedup();
    paths
}

/// The per-user Unix domain socket path.
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

/// Who may open the daemon's pipe, as an SDDL string: full control for
/// SYSTEM and Administrators, read/write for authenticated users (so a
/// non-elevated UI can drive an elevated daemon or the service). The `P`
/// flag stops inherited ACEs from widening it. Remote (SMB) clients are
/// refused separately, via `reject_remote_clients`.
#[cfg(windows)]
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

/// Create one instance of the daemon's named pipe with [`PIPE_SDDL`].
///
/// `first` must be `true` for the very first instance: Windows then fails
/// if the name already exists, so another process can't squat the pipe
/// name ahead of the daemon and impersonate it to clients.
///
/// # Errors
/// Fails if the security descriptor can't be built or the pipe can't be
/// created (e.g. another daemon already owns the name).
#[cfg(windows)]
pub fn create_pipe_instance(
    first: bool,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    const SDDL_REVISION_1: u32 = 1;

    let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is a NUL-terminated UTF-16 string that outlives the
    // call; `descriptor` receives a LocalAlloc'd buffer we free below.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut opts = tokio::net::windows::named_pipe::ServerOptions::new();
    opts.first_pipe_instance(first).reject_remote_clients(true);
    // SAFETY: `attrs` points at a valid SECURITY_ATTRIBUTES whose
    // descriptor stays alive until after the call returns.
    let result = unsafe {
        opts.create_with_security_attributes_raw(PIPE_PATH, std::ptr::from_mut(&mut attrs).cast())
    };
    // SAFETY: `descriptor` was allocated by the conversion call above.
    unsafe {
        LocalFree(descriptor);
    }
    result
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
