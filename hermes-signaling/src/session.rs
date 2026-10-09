//! Per-connection WebSocket session state machine.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::extract::{
    ws::{Message, WebSocket, WebSocketUpgrade},
    State,
};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use hermes_core::signaling::protocol::{ClientMessage, ServerMessage};

use hermes_core::room::RoomMode;

use crate::rooms::{JoinDenied, RoomRegistry, ServerRoom, Session};
use crate::stats;
use crate::AppState;

/// Default silence after which a client is considered gone: three missed
/// client pings (every 15 s).
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

/// Axum handler: upgrade to WebSocket and run the session loop.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = app.limits.client_ip(peer, &headers);
    if !app.limits.connections.check(&ip) {
        stats::bump(&app.stats.connections_rejected_rate);
        debug!(%ip, "connection rate limit hit");
        return (StatusCode::TOO_MANY_REQUESTS, "too many connections").into_response();
    }
    stats::bump(&app.stats.connections);
    ws.on_upgrade(move |socket| run_session(socket, app, ip))
}

async fn run_session(socket: WebSocket, app: AppState, ip: IpAddr) {
    let registry = app.registry.clone();
    let (mut ws_tx, mut ws_rx) = socket.split();

    // Step 1: send challenge.
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let challenge = ServerMessage::Challenge {
        nonce: nonce.to_vec(),
    };
    if ws_tx
        .send(Message::Text(serde_json::to_string(&challenge).unwrap()))
        .await
        .is_err()
    {
        return;
    }

    // Step 2: await Hello.
    let hello = match ws_rx.next().await {
        Some(Ok(Message::Text(t))) => match serde_json::from_str::<ClientMessage>(&t) {
            Ok(ClientMessage::Hello {
                node_id,
                wireguard_public,
                signature,
                wireguard_binding,
                alias,
                protocol_version,
            }) => {
                if protocol_version != hermes_core::PROTOCOL_VERSION {
                    let _ = ws_tx
                        .send(Message::Text(
                            serde_json::to_string(&ServerMessage::Error {
                                code: "version_mismatch".into(),
                                message: format!(
                                    "server speaks v{}",
                                    hermes_core::PROTOCOL_VERSION
                                ),
                            })
                            .unwrap(),
                        ))
                        .await;
                    stats::bump(&app.stats.auth_failures);
                    return;
                }
                (
                    node_id,
                    wireguard_public,
                    signature,
                    wireguard_binding,
                    alias,
                )
            }
            _ => return,
        },
        _ => return,
    };
    let (node_id, wireguard_public, signature, wireguard_binding, alias) = hello;

    // Verify the Ed25519 signature over the nonce.
    let verifying = match VerifyingKey::from_bytes(&node_id.0) {
        Ok(v) => v,
        Err(e) => {
            warn!(?e, "bad node_id in Hello");
            stats::bump(&app.stats.auth_failures);
            return;
        }
    };
    let sig = match Signature::from_slice(&signature) {
        Ok(s) => s,
        Err(_) => {
            stats::bump(&app.stats.auth_failures);
            return;
        }
    };
    if verifying.verify(&nonce, &sig).is_err() {
        let _ = ws_tx
            .send(Message::Text(
                serde_json::to_string(&ServerMessage::Error {
                    code: "bad_signature".into(),
                    message: "signature did not verify".into(),
                })
                .unwrap(),
            ))
            .await;
        stats::bump(&app.stats.auth_failures);
        return;
    }

    // The node must also vouch for the WireGuard key it advertises. Peers
    // re-check this themselves (that is what makes it trustworthy — we
    // only relay it), but refusing a bad one here keeps junk out of rooms.
    if !hermes_core::crypto::verify_wireguard_binding(
        &node_id,
        &wireguard_public,
        &wireguard_binding,
    ) {
        let _ = ws_tx
            .send(Message::Text(
                serde_json::to_string(&ServerMessage::Error {
                    code: "bad_key_binding".into(),
                    message: "wireguard_binding does not match node_id and wireguard_public".into(),
                })
                .unwrap(),
            ))
            .await;
        stats::bump(&app.stats.auth_failures);
        return;
    }

    // Auth OK. Issue Welcome.
    app.stats
        .sessions_active
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let session_id = Uuid::new_v4().to_string();
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<ServerMessage>(64);
    let welcome = ServerMessage::Welcome {
        session_id: session_id.clone(),
    };
    let _ = ws_tx
        .send(Message::Text(serde_json::to_string(&welcome).unwrap()))
        .await;

    let session = Arc::new(Session {
        session_id,
        node_id,
        alias,
        wireguard_public,
        wireguard_binding,
        outgoing: outgoing_tx,
        ip_salt: std::sync::atomic::AtomicU32::new(0),
    });
    info!(node = %node_id.short(), session = %session.session_id, "session authenticated");

    // Outbound writer task.
    let writer = tokio::spawn(async move {
        while let Some(msg) = outgoing_rx.recv().await {
            if ws_tx
                .send(Message::Text(serde_json::to_string(&msg).unwrap()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut current_room: Option<Arc<ServerRoom>> = None;
    let idle_timeout = idle_timeout();

    // Main request loop. Clients ping every 15 s; a connection silent for
    // longer than `idle_timeout` is dead (half-open TCP after a NAT
    // timeout or network switch) and is dropped so the room learns the
    // member is gone instead of waiting for TCP to time out.
    loop {
        let frame = match tokio::time::timeout(idle_timeout, ws_rx.next()).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(_) => {
                stats::bump(&app.stats.idle_disconnects);
                info!(node = %node_id.short(), "client silent — dropping session");
                break;
            }
        };
        let msg = match frame {
            Ok(Message::Text(t)) => match serde_json::from_str::<ClientMessage>(&t) {
                Ok(m) => m,
                Err(e) => {
                    warn!(?e, "bad client msg");
                    continue;
                }
            },
            Ok(Message::Close(_)) | Err(_) => break,
            _ => continue,
        };

        match msg {
            ClientMessage::Hello { .. } => {
                // Illegal after initial Hello.
                warn!("duplicate Hello");
            }
            ClientMessage::CreateRoom {
                name,
                mode,
                relay_addr,
                password,
            } => {
                // A relayed room is meaningless without a relay address —
                // reject early instead of letting every member fail to
                // resolve `None` later.
                if mode == RoomMode::Relayed
                    && relay_addr.as_deref().map_or(true, |a| a.trim().is_empty())
                {
                    send(
                        &session,
                        error("relay_required", "relayed rooms need a relay address"),
                    )
                    .await;
                    continue;
                }
                if !app.limits.room_ops.check(&ip) {
                    stats::bump(&app.stats.room_ops_rate_limited);
                    send(&session, rate_limited()).await;
                    continue;
                }
                // Creating a room implicitly leaves the current one.
                if let Some(old) = current_room.take() {
                    leave(&registry, &old, &session).await;
                }
                stats::bump(&app.stats.rooms_created);
                let room =
                    registry.create(name, mode, relay_addr, session.node_id, password.as_deref());
                info!(room = %room.id, name = %room.name, mode = ?room.mode, "room created");
                room.insert_member(session.clone());
                current_room = Some(room.clone());
                send(
                    &session,
                    ServerMessage::RoomCreated {
                        room_id: room.id,
                        invite_code: room.invite(),
                        mode: room.mode,
                        relay_addr: room.relay_addr.clone(),
                        ip_salt: 0,
                    },
                )
                .await;
            }
            ClientMessage::JoinRoom {
                code,
                restore,
                password,
            } => {
                // Every attempt counts, so guessing invite codes is capped
                // at a few dozen tries per minute per address.
                if !app.limits.room_ops.check(&ip) {
                    stats::bump(&app.stats.room_ops_rate_limited);
                    send(&session, rate_limited()).await;
                    continue;
                }
                let restoring = restore.is_some();
                let Some(room) = registry.find_or_restore(&code, restore, session.node_id) else {
                    stats::bump(&app.stats.join_invalid_code);
                    send(
                        &session,
                        error("invalid_code", "invite code not recognised"),
                    )
                    .await;
                    continue;
                };
                if let Err(denied) = room.admit(&session.node_id, password.as_deref()) {
                    stats::bump(&app.stats.join_denied);
                    // A room we just recreated for this joiner and then
                    // refused them would linger empty; drop it.
                    registry.remove_if_empty(&room);
                    send(&session, denied_message(&denied)).await;
                    continue;
                }
                stats::bump(&app.stats.rooms_joined);
                // Joining another room implicitly leaves the current one;
                // re-joining the same room is just a refresh.
                if let Some(old) = current_room.take() {
                    if old.id != room.id {
                        leave(&registry, &old, &session).await;
                    }
                }
                if restoring && room.members.read().is_empty() {
                    stats::bump(&app.stats.rooms_restored);
                    info!(room = %room.id, "room restored after server restart");
                }

                // Join first: that assigns our IP salt (a fresh address if
                // our default one is taken), which the others must learn.
                if let Some(stale) = room.insert_member(session.clone()) {
                    if !Arc::ptr_eq(&stale, &session) {
                        info!(
                            node = %session.node_id.short(),
                            stale = %stale.session_id,
                            "replaced stale session of a reconnecting node"
                        );
                    }
                }
                let ip_salt = session.ip_salt.load(std::sync::atomic::Ordering::Relaxed);
                if ip_salt > 0 {
                    info!(node = %session.node_id.short(), ip_salt, "virtual IP collision avoided");
                }
                let peer_info = session.peer_info();
                let others: Vec<Arc<Session>> = room
                    .members
                    .read()
                    .iter()
                    .filter(|m| !Arc::ptr_eq(m, &session))
                    .cloned()
                    .collect();
                for m in &others {
                    let _ = m
                        .outgoing
                        .send(ServerMessage::PeerJoined {
                            peer: peer_info.clone(),
                        })
                        .await;
                }
                current_room = Some(room.clone());
                let owner = *room.owner.read();
                send(
                    &session,
                    ServerMessage::RoomJoined {
                        room_id: room.id,
                        members: others.iter().map(|m| m.peer_info()).collect(),
                        mode: room.mode,
                        relay_addr: room.relay_addr.clone(),
                        ip_salt,
                        owner,
                    },
                )
                .await;
            }
            ClientMessage::KickMember { node_id, ban } => {
                let Some(room) = current_room.as_ref().filter(|r| r.has_member(&session)) else {
                    continue;
                };
                if !room.is_owner(&session.node_id) {
                    send(
                        &session,
                        error("not_owner", "only the room owner can do that"),
                    )
                    .await;
                    continue;
                }
                if node_id == session.node_id {
                    send(&session, error("bad_request", "you can't remove yourself")).await;
                    continue;
                }
                if ban {
                    room.ban(node_id);
                }
                if let Some(target) = room.member(&node_id) {
                    stats::bump(&app.stats.members_kicked);
                    info!(room = %room.id, node = %node_id.short(), ban, "member removed by owner");
                    if room.remove_member(&target) {
                        let _ = target
                            .outgoing
                            .send(ServerMessage::Kicked { banned: ban })
                            .await;
                        let others = room.members.read().clone();
                        for m in others {
                            let _ = m.outgoing.send(ServerMessage::PeerLeft { node_id }).await;
                        }
                    }
                }
            }
            ClientMessage::RotateInvite => {
                let Some(room) = current_room.as_ref().filter(|r| r.has_member(&session)) else {
                    continue;
                };
                if !room.is_owner(&session.node_id) {
                    send(
                        &session,
                        error("not_owner", "only the room owner can do that"),
                    )
                    .await;
                    continue;
                }
                let fresh = registry.rotate_invite(room);
                stats::bump(&app.stats.invites_rotated);
                info!(room = %room.id, "invite code rotated");
                let members = room.members.read().clone();
                for m in members {
                    let _ = m
                        .outgoing
                        .send(ServerMessage::InviteRotated { invite_code: fresh })
                        .await;
                }
            }
            ClientMessage::LeaveRoom => {
                if let Some(room) = current_room.take() {
                    leave(&registry, &room, &session).await;
                }
            }
            ClientMessage::RelayCandidates { to, candidates } => {
                // A session that was replaced by a newer one of the same
                // node no longer speaks for that node.
                let Some(room) = current_room.as_ref().filter(|r| r.has_member(&session)) else {
                    continue;
                };
                // Resolve and clone the target session in a scope that
                // drops the read lock before we await on the send.
                let target = {
                    let members = room.members.read();
                    members.iter().find(|m| m.node_id == to).cloned()
                };
                if let Some(target) = target {
                    let _ = target
                        .outgoing
                        .send(ServerMessage::PeerCandidates {
                            from: session.node_id,
                            candidates,
                        })
                        .await;
                }
            }
            ClientMessage::Ping => send(&session, ServerMessage::Pong).await,
        }
    }

    // Cleanup on disconnect.
    if let Some(room) = current_room.take() {
        leave(&registry, &room, &session).await;
    }
    app.stats
        .sessions_active
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    drop(session);
    let _ = writer.await;
}

/// Silence after which a client is considered gone. Overridable via
/// `HERMES_SIGNALING_IDLE_TIMEOUT_SECS` (tests use a short one).
fn idle_timeout() -> Duration {
    std::env::var("HERMES_SIGNALING_IDLE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map_or(DEFAULT_IDLE_TIMEOUT, Duration::from_secs)
}

async fn send(session: &Session, msg: ServerMessage) {
    let _ = session.outgoing.send(msg).await;
}

fn denied_message(denied: &JoinDenied) -> ServerMessage {
    match denied {
        JoinDenied::Banned => error("banned", "you were removed from this room"),
        JoinDenied::PasswordRequired => error("password_required", "this room needs a password"),
        JoinDenied::BadPassword => error("bad_password", "wrong room password"),
    }
}

fn rate_limited() -> ServerMessage {
    error(
        "rate_limited",
        "too many room requests — slow down and retry",
    )
}

fn error(code: &str, message: &str) -> ServerMessage {
    ServerMessage::Error {
        code: code.into(),
        message: message.into(),
    }
}

/// Take `session` out of `room`. Only if it was still a member — not
/// already superseded by a newer session of the same node — do the other
/// members hear `PeerLeft`; otherwise the node is still present and
/// telling peers it left would tear down working tunnels.
async fn leave(registry: &RoomRegistry, room: &Arc<ServerRoom>, session: &Arc<Session>) {
    if room.remove_member(session) {
        let departing = session.node_id;
        let members = room.members.read().clone();
        for m in members {
            if m.node_id != departing {
                let _ = m
                    .outgoing
                    .send(ServerMessage::PeerLeft { node_id: departing })
                    .await;
            }
        }
    } else {
        debug!(node = %session.node_id.short(), "superseded session left — no PeerLeft");
    }
    registry.remove_if_empty(room);
}
