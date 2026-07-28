//! Client-side WebSocket driver for the signaling server.

use std::sync::Arc;

use ed25519_dalek::Signer;
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{debug, error, info, warn};

use super::protocol::{ClientMessage, ServerMessage};
use crate::crypto::NodeSecret;
use crate::error::{HermesError, Result};

/// Handle to an active signaling session. Clone is cheap.
#[derive(Clone)]
pub struct SignalingClient {
    outgoing: mpsc::Sender<ClientMessage>,
    /// Inbox of server messages. The engine drains this.
    incoming: Arc<parking_lot::Mutex<Option<mpsc::Receiver<ServerMessage>>>>,
    /// Shared flag flipped when either the read or write loop detects
    /// the connection is gone. `closed()` resolves once this is set.
    closed_rx: tokio::sync::watch::Receiver<bool>,
}

impl SignalingClient {
    /// Wait until the connection to the signaling server is known to be
    /// dead. Resolves immediately if it's already dead.
    pub async fn closed(&self) {
        let mut rx = self.closed_rx.clone();
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Is the connection known to be dead right now?
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.closed_rx.borrow()
    }
}

impl SignalingClient {
    /// Connect to `url`, perform the challenge/response handshake, and
    /// return a client ready to send further requests.
    ///
    /// # Errors
    /// Fails on connection error, protocol mismatch, or signature rejection.
    pub async fn connect(url: &str, secret: &NodeSecret, alias: String) -> Result<Self> {
        info!(%url, "connecting to signaling server");

        let (ws_stream, _) = connect_async(url)
            .await
            .map_err(|e| HermesError::Signaling(format!("connect: {e}")))?;
        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        // Step 1: wait for the challenge.
        let challenge = match ws_rx.next().await {
            Some(Ok(WsMessage::Text(t))) => {
                let msg: ServerMessage = serde_json::from_str(&t)
                    .map_err(|e| HermesError::Signaling(format!("parse challenge: {e}")))?;
                match msg {
                    ServerMessage::Challenge { nonce } => nonce,
                    other => {
                        return Err(HermesError::Signaling(format!(
                            "expected Challenge, got {other:?}"
                        )))
                    }
                }
            }
            other => {
                return Err(HermesError::Signaling(format!(
                    "expected Challenge frame, got {other:?}"
                )))
            }
        };

        // Step 2: sign the challenge and send Hello.
        let signing = secret.signing_key();
        let signature = signing.sign(&challenge).to_bytes().to_vec();
        let identity = secret.public();
        let hello = ClientMessage::Hello {
            node_id: identity.node_id,
            wireguard_public: identity.wireguard_public,
            signature,
            alias,
            protocol_version: crate::PROTOCOL_VERSION,
        };
        ws_tx
            .send(WsMessage::Text(serde_json::to_string(&hello)?))
            .await
            .map_err(|e| HermesError::Signaling(format!("send hello: {e}")))?;

        // Step 3: wait for Welcome.
        match ws_rx.next().await {
            Some(Ok(WsMessage::Text(t))) => match serde_json::from_str::<ServerMessage>(&t)? {
                ServerMessage::Welcome { session_id } => {
                    info!(%session_id, "signaling welcomed");
                }
                ServerMessage::Error { code, message } => {
                    return Err(HermesError::Signaling(format!(
                        "auth rejected: {code} — {message}"
                    )));
                }
                other => {
                    return Err(HermesError::Signaling(format!(
                        "expected Welcome, got {other:?}"
                    )))
                }
            },
            other => {
                return Err(HermesError::Signaling(format!(
                    "expected Welcome frame, got {other:?}"
                )))
            }
        }

        // Channels for the engine to interact with the connection.
        let (out_tx, mut out_rx) = mpsc::channel::<ClientMessage>(64);
        let (in_tx, in_rx) = mpsc::channel::<ServerMessage>(64);
        let (closed_tx, closed_rx) = tokio::sync::watch::channel(false);

        // Write loop.
        let closed_tx_w = closed_tx.clone();
        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                let payload = match serde_json::to_string(&msg) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(?e, "signaling outbound serialize failed");
                        continue;
                    }
                };
                if let Err(e) = ws_tx.send(WsMessage::Text(payload)).await {
                    warn!(?e, "signaling send failed — closing");
                    break;
                }
            }
            let _ = closed_tx_w.send(true);
        });

        // Read loop.
        let closed_tx_r = closed_tx;
        tokio::spawn(async move {
            while let Some(frame) = ws_rx.next().await {
                match frame {
                    Ok(WsMessage::Text(t)) => match serde_json::from_str::<ServerMessage>(&t) {
                        Ok(msg) => {
                            if in_tx.send(msg).await.is_err() {
                                debug!("signaling inbox closed");
                                break;
                            }
                        }
                        Err(e) => warn!(?e, "signaling parse error"),
                    },
                    Ok(WsMessage::Close(_)) => {
                        info!("signaling server closed");
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!(?e, "signaling read error — closing");
                        break;
                    }
                }
            }
            let _ = closed_tx_r.send(true);
        });

        Ok(Self {
            outgoing: out_tx,
            incoming: Arc::new(parking_lot::Mutex::new(Some(in_rx))),
            closed_rx,
        })
    }

    /// Send a message to the server.
    ///
    /// # Errors
    /// Fails if the write loop has exited.
    pub async fn send(&self, msg: ClientMessage) -> Result<()> {
        self.outgoing
            .send(msg)
            .await
            .map_err(|_| HermesError::Signaling("outbound channel closed".into()))
    }

    /// Take ownership of the inbox receiver. Can only be called once.
    pub fn take_inbox(&self) -> Option<mpsc::Receiver<ServerMessage>> {
        self.incoming.lock().take()
    }
}
