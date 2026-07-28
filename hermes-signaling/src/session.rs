//! Per-connection WebSocket session state machine.

use std::sync::Arc;

use axum::extract::{
    ws::{Message, WebSocket, WebSocketUpgrade},
    State,
};
use axum::response::Response;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use hermes_core::signaling::protocol::{ClientMessage, PeerInfo, ServerMessage};

use crate::rooms::{RoomRegistry, Session};

/// Axum handler: upgrade to WebSocket and run the session loop.
pub async fn ws_handler(ws: WebSocketUpgrade, State(registry): State<RoomRegistry>) -> Response {
    ws.on_upgrade(|socket| run_session(socket, registry))
}

async fn run_session(socket: WebSocket, registry: RoomRegistry) {
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
                    return;
                }
                (node_id, wireguard_public, signature, alias)
            }
            _ => return,
        },
        _ => return,
    };
    let (node_id, wireguard_public, signature, alias) = hello;

    // Verify the Ed25519 signature over the nonce.
    let verifying = match VerifyingKey::from_bytes(&node_id.0) {
        Ok(v) => v,
        Err(e) => {
            warn!(?e, "bad node_id in Hello");
            return;
        }
    };
    let sig = match Signature::from_slice(&signature) {
        Ok(s) => s,
        Err(_) => return,
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
        return;
    }

    // Auth OK. Issue Welcome.
    let session_id = Uuid::new_v4().to_string();
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<ServerMessage>(64);
    let welcome = ServerMessage::Welcome {
        session_id: session_id.clone(),
    };
    let _ = ws_tx
        .send(Message::Text(serde_json::to_string(&welcome).unwrap()))
        .await;

    // The WireGuard public key the client advertised in its Hello. We
    // accept this as-is; it's derived client-side from the Ed25519
    // identity so any mismatch only harms the misbehaving client (they
    // won't be able to complete a handshake with their own peers).
    let _ = wireguard_public; // captured into Session below

    let session = Arc::new(Session {
        session_id,
        node_id,
        alias,
        wireguard_public,
        outgoing: outgoing_tx,
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

    let mut current_room: Option<Arc<crate::rooms::ServerRoom>> = None;

    // Main request loop.
    while let Some(frame) = ws_rx.next().await {
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
            } => {
                // A relayed room is meaningless without a relay address —
                // reject early instead of letting every member fail to
                // resolve `None` later.
                if mode == hermes_core::room::RoomMode::Relayed
                    && relay_addr.as_deref().map_or(true, |a| a.trim().is_empty())
                {
                    let _ = session
                        .outgoing
                        .send(ServerMessage::Error {
                            code: "relay_required".into(),
                            message: "relayed rooms need a relay address".into(),
                        })
                        .await;
                    continue;
                }
                let room = registry.create(name, mode, relay_addr);
                info!(room = %room.id, name = %room.name, mode = ?room.mode, "room created");
                room.members.write().push(session.clone());
                current_room = Some(room.clone());
                let _ = session
                    .outgoing
                    .send(ServerMessage::RoomCreated {
                        room_id: room.id,
                        invite_code: room.invite,
                        mode: room.mode,
                        relay_addr: room.relay_addr.clone(),
                    })
                    .await;
            }
            ClientMessage::JoinRoom { code } => match registry.find_by_invite(&code) {
                Some(room) => {
                    // Notify existing members of the new peer.
                    let peer_info = PeerInfo {
                        node_id: session.node_id,
                        wireguard_public: session.wireguard_public,
                        alias: session.alias.clone(),
                    };
                    let (snapshot, members_clone): (Vec<PeerInfo>, Vec<Arc<Session>>) = {
                        let members = room.members.read();
                        let snap = members
                            .iter()
                            .filter(|m| m.node_id != session.node_id)
                            .map(|m| PeerInfo {
                                node_id: m.node_id,
                                wireguard_public: m.wireguard_public,
                                alias: m.alias.clone(),
                            })
                            .collect();
                        let cloned = members.clone();
                        (snap, cloned)
                    };
                    // Broadcast PeerJoined to existing members.
                    for m in &members_clone {
                        let _ = m
                            .outgoing
                            .send(ServerMessage::PeerJoined {
                                peer: peer_info.clone(),
                            })
                            .await;
                    }
                    room.members.write().push(session.clone());
                    current_room = Some(room.clone());
                    let _ = session
                        .outgoing
                        .send(ServerMessage::RoomJoined {
                            room_id: room.id,
                            members: snapshot,
                            mode: room.mode,
                            relay_addr: room.relay_addr.clone(),
                        })
                        .await;
                }
                None => {
                    let _ = session
                        .outgoing
                        .send(ServerMessage::Error {
                            code: "invalid_code".into(),
                            message: "invite code not recognised".into(),
                        })
                        .await;
                }
            },
            ClientMessage::LeaveRoom => {
                if let Some(room) = current_room.take() {
                    notify_left(&room, session.node_id).await;
                    prune_room(&registry, &room, session.node_id);
                }
            }
            ClientMessage::RelayCandidates { to, candidates } => {
                let Some(room) = current_room.as_ref() else {
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
            ClientMessage::Ping => {
                let _ = session.outgoing.send(ServerMessage::Pong).await;
            }
        }
    }

    // Cleanup on disconnect.
    if let Some(room) = current_room.take() {
        notify_left(&room, session.node_id).await;
        prune_room(&registry, &room, session.node_id);
    }
    drop(session);
    let _ = writer.await;
}

async fn notify_left(room: &crate::rooms::ServerRoom, departing: hermes_core::crypto::NodeId) {
    let members = room.members.read().clone();
    for m in members {
        if m.node_id != departing {
            let _ = m
                .outgoing
                .send(ServerMessage::PeerLeft { node_id: departing })
                .await;
        }
    }
}

fn prune_room(
    registry: &RoomRegistry,
    room: &Arc<crate::rooms::ServerRoom>,
    departing: hermes_core::crypto::NodeId,
) {
    let mut members = room.members.write();
    members.retain(|m| m.node_id != departing);
    if members.is_empty() {
        let id = room.id;
        drop(members);
        registry.remove(id);
    }
}
