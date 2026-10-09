//! Client-side WebSocket driver for the signaling server.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::Signer;
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{debug, error, info, warn};

use super::protocol::{ClientMessage, ServerMessage};
use crate::crypto::NodeSecret;
use crate::error::{HermesError, Result};

/// Liveness settings for a signaling connection.
///
/// TCP alone can't tell a quiet connection from a dead one: after a NAT
/// timeout, Wi-Fi switch, or server crash without a FIN, reads simply
/// block forever. So the client sends an application-level `Ping` every
/// [`Self::ping_interval`] (the server answers `Pong`, and also drops
/// clients it doesn't hear from) and treats [`Self::idle_timeout`] of
/// silence as a dead connection — which hands control to the engine's
/// reconnect supervisor.
#[derive(Clone, Copy, Debug)]
pub struct Keepalive {
    /// How often to ping the server.
    pub ping_interval: Duration,
    /// Silence after which the connection is declared dead.
    pub idle_timeout: Duration,
}

impl Default for Keepalive {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(45),
        }
    }
}

/// Is `url` a plaintext (`ws://`) connection to a host other than this
/// machine?
///
/// The signaling channel carries invite codes and NAT candidates. Its
/// authentication can't be forged, but on a plaintext connection anyone
/// on the path can *read* an invite code — which is all it takes to join
/// the room. Loopback is exempt (the traffic never leaves the machine).
#[must_use]
pub fn is_insecure_url(url: &str) -> bool {
    let url = url.trim();
    let Some(rest) = url
        .get(..5)
        .filter(|scheme| scheme.eq_ignore_ascii_case("ws://"))
        .map(|_| &url[5..])
    else {
        return false; // wss:// (or not a WebSocket URL at all)
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    !loopback
}

/// Resolve once the closed flag is set (or its sender is gone). The
/// borrowed value is dropped right away: `watch::Ref` is not `Send`.
async fn wait_closed(rx: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|closed| *closed).await;
}

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
        Self::connect_with(url, secret, alias, Keepalive::default()).await
    }

    /// [`Self::connect`] with explicit keepalive settings.
    ///
    /// # Errors
    /// Fails on connection error, protocol mismatch, or signature rejection.
    pub async fn connect_with(
        url: &str,
        secret: &NodeSecret,
        alias: String,
        keepalive: Keepalive,
    ) -> Result<Self> {
        info!(%url, "connecting to signaling server");
        if is_insecure_url(url) {
            warn!(
                %url,
                "signaling over plaintext ws:// to a remote host — invite codes can be \
                 read on the network path; use wss://"
            );
        }

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
            wireguard_binding: secret.sign_wireguard_binding(),
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

        // Write loop. Exits when every sender is gone (the engine dropped
        // this client) or the read loop declared the connection dead, and
        // closes the WebSocket either way so the TCP connection is freed.
        let closed_tx_w = closed_tx.clone();
        let mut closed_w = closed_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = out_rx.recv() => {
                        let Some(msg) = msg else { break };
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
                    () = wait_closed(&mut closed_w) => break,
                }
            }
            let _ = ws_tx.close().await;
            let _ = closed_tx_w.send(true);
        });

        // Ping loop. Holds only a weak sender so it never keeps the write
        // loop (and the connection) alive on its own.
        {
            let weak = out_tx.downgrade();
            let mut closed_p = closed_rx.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(keepalive.ping_interval);
                ticker.tick().await; // the first tick is immediate
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {}
                        () = wait_closed(&mut closed_p) => break,
                    }
                    let Some(tx) = weak.upgrade() else { break };
                    if tx.send(ClientMessage::Ping).await.is_err() {
                        break;
                    }
                }
            });
        }

        // Read loop. Any frame — a reply, an event, a Pong — proves the
        // connection is alive; `idle_timeout` of silence means it isn't.
        let closed_tx_r = closed_tx;
        tokio::spawn(async move {
            loop {
                let frame = match tokio::time::timeout(keepalive.idle_timeout, ws_rx.next()).await {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(_) => {
                        warn!(
                            timeout = ?keepalive.idle_timeout,
                            "signaling server silent — treating connection as dead"
                        );
                        break;
                    }
                };
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

#[cfg(test)]
mod tests {
    use super::is_insecure_url;

    #[test]
    fn plaintext_to_remote_hosts_is_insecure() {
        for url in [
            "ws://signal.example.net/v1",
            "ws://10.0.0.5:8787/v1",
            "ws://[2001:db8::1]:8787/v1",
            "ws://user@host.example/v1",
            "WS://Signal.Example.NET/v1",
        ] {
            assert!(is_insecure_url(url), "{url}");
        }
        for url in [
            "wss://signal.example.net/v1",
            "ws://127.0.0.1:8787/v1",
            "ws://localhost:8787/v1",
            "ws://[::1]:8787/v1",
            "WSS://x/v1",
        ] {
            assert!(!is_insecure_url(url), "{url}");
        }
    }
}
