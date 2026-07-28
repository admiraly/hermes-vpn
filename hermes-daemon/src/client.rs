//! Client-side IPC helper for talking to a running `hermes-daemon`.
//!
//! The client is intended to be embedded in processes that need to
//! drive the daemon — primarily the Tauri UI. It:
//!
//! - Opens the local socket (named pipe on Windows, Unix stream elsewhere).
//! - Performs the [`CommandPayload::Hello`] handshake.
//! - Spawns a read task that sorts inbound frames into either an
//!   in-flight-commands map (matched by `id`) or an events channel.
//! - Exposes a small request/response API plus an event receiver.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::SinkExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;
use tracing::{debug, warn};

use crate::protocol::{Command, CommandPayload, Event, Frame, ResponseBody, IPC_PROTOCOL_VERSION};
use crate::transport::{self, FramedIpc};

/// How long to wait for a response before timing out.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// A connected daemon client.
#[derive(Clone)]
pub struct DaemonClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    next_id: AtomicU64,
    tx: Mutex<mpsc::Sender<OutgoingFrame>>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<ResponseBody>>>>,
    events_rx: Mutex<Option<mpsc::Receiver<Event>>>,
}

struct OutgoingFrame(Frame);

impl DaemonClient {
    /// Connect to the daemon at the platform-default address.
    ///
    /// # Errors
    /// Fails if the socket cannot be opened, the handshake is rejected,
    /// or the daemon speaks a different protocol version.
    #[cfg(unix)]
    pub async fn connect_default() -> anyhow::Result<Self> {
        let path = transport::unix_socket_path();
        let stream = tokio::net::UnixStream::connect(&path)
            .await
            .map_err(|e| anyhow::anyhow!("connect {}: {e}", path.display()))?;
        Self::from_stream(stream).await
    }

    /// Connect to the daemon via the Windows named pipe.
    ///
    /// # Errors
    /// Fails if the pipe can't be opened.
    #[cfg(windows)]
    pub async fn connect_default() -> anyhow::Result<Self> {
        use tokio::net::windows::named_pipe::ClientOptions;
        let stream = ClientOptions::new().open(transport::PIPE_PATH)?;
        Self::from_stream(stream).await
    }

    /// Build a client on top of an already-opened duplex stream.
    pub async fn from_stream<T>(stream: T) -> anyhow::Result<Self>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let framed = transport::wrap(stream);
        Self::spawn_with_framed(framed).await
    }

    async fn spawn_with_framed<T>(mut framed: FramedIpc<T>) -> anyhow::Result<Self>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Send Hello and wait for Welcome inline.
        let hello_id = 0;
        let hello = Frame::Command(Command {
            id: hello_id,
            payload: CommandPayload::Hello {
                protocol_version: IPC_PROTOCOL_VERSION,
            },
        });
        transport::send_frame(&mut framed, &hello).await?;

        match transport::recv_frame(&mut framed).await? {
            Some(Frame::Response(resp)) if resp.id == hello_id => match resp.result {
                ResponseBody::Welcome { protocol_version } => {
                    if protocol_version != IPC_PROTOCOL_VERSION {
                        anyhow::bail!(
                            "protocol version mismatch: daemon speaks v{protocol_version}"
                        );
                    }
                }
                ResponseBody::Error { code, message } => {
                    anyhow::bail!("handshake rejected ({code}): {message}")
                }
                other => anyhow::bail!("expected Welcome, got {other:?}"),
            },
            other => anyhow::bail!("expected Welcome response, got {other:?}"),
        }

        // Handshake done — spawn the I/O tasks.
        let (out_tx, mut out_rx) = mpsc::channel::<OutgoingFrame>(64);
        let (events_tx, events_rx) = mpsc::channel::<Event>(256);
        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<ResponseBody>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_reader = pending.clone();

        // Split the framed stream into reader/writer halves via a local
        // mpsc — simpler than juggling `split` on a generic Framed.
        let (sink, stream) = split_framed(framed);

        // Writer task.
        tokio::spawn(async move {
            let mut sink = sink;
            while let Some(OutgoingFrame(frame)) = out_rx.recv().await {
                let bytes = match serde_json::to_vec(&frame) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(?e, "serialize IPC frame");
                        continue;
                    }
                };
                if sink.send(bytes.into()).await.is_err() {
                    break;
                }
            }
            debug!("IPC writer exiting");
        });

        // Reader task.
        tokio::spawn(async move {
            let mut stream = stream;
            while let Some(result) = futures::StreamExt::next(&mut stream).await {
                let bytes = match result {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(?e, "IPC read error");
                        break;
                    }
                };
                let frame: Frame = match serde_json::from_slice(&bytes) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(?e, "IPC frame parse error");
                        continue;
                    }
                };
                match frame {
                    Frame::Response(resp) => {
                        if let Some(tx) = pending_reader.lock().await.remove(&resp.id) {
                            let _ = tx.send(resp.result);
                        } else {
                            warn!(id = resp.id, "response for unknown id");
                        }
                    }
                    Frame::Event(ev) => {
                        if events_tx.send(ev).await.is_err() {
                            break;
                        }
                    }
                    Frame::Command(_) => {
                        warn!("daemon sent a command frame — ignoring");
                    }
                }
            }
            debug!("IPC reader exiting");
        });

        Ok(Self {
            inner: Arc::new(ClientInner {
                next_id: AtomicU64::new(1), // 0 reserved for Hello
                tx: Mutex::new(out_tx),
                pending,
                events_rx: Mutex::new(Some(events_rx)),
            }),
        })
    }

    /// Send a command and wait for the matching response.
    ///
    /// # Errors
    /// Fails on transport error or response timeout.
    pub async fn call(&self, payload: CommandPayload) -> anyhow::Result<ResponseBody> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.inner.pending.lock().await.insert(id, tx);

        let frame = Frame::Command(Command { id, payload });
        self.inner
            .tx
            .lock()
            .await
            .send(OutgoingFrame(frame))
            .await
            .map_err(|_| anyhow::anyhow!("daemon connection closed"))?;

        match tokio::time::timeout(RESPONSE_TIMEOUT, rx).await {
            Ok(Ok(body)) => Ok(body),
            Ok(Err(_)) => anyhow::bail!("daemon dropped the response"),
            Err(_) => {
                // Clean up the pending entry on timeout.
                self.inner.pending.lock().await.remove(&id);
                anyhow::bail!("timed out waiting for daemon response")
            }
        }
    }

    /// Take ownership of the events receiver. Can only be called once.
    pub async fn take_events(&self) -> Option<mpsc::Receiver<Event>> {
        self.inner.events_rx.lock().await.take()
    }
}

/// Split a `Framed` stream into sink and stream halves. Tokio-util's
/// `SplitSink`/`SplitStream` from `futures` works on any `Stream + Sink`,
/// so we reach for that.
fn split_framed<T>(
    framed: Framed<T, LengthDelimitedCodec>,
) -> (
    futures::stream::SplitSink<Framed<T, LengthDelimitedCodec>, bytes::Bytes>,
    futures::stream::SplitStream<Framed<T, LengthDelimitedCodec>>,
)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    use futures::StreamExt;
    framed.split()
}
