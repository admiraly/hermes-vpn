//! Room access control on the real `hermes-signaling` binary: passwords,
//! owner-only kick/ban, invite rotation, and that none of it can be
//! claimed by a non-owner.

use std::process::{Child, Command};
use std::time::Duration;

use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

use hermes_core::crypto::{NodeId, NodeSecret, RoomKeys};
use hermes_core::room::{InviteCode, RoomMode};
use hermes_core::signaling::protocol::{ClientMessage, RoomRestore, ServerMessage};
use hermes_core::signaling::SignalingClient;

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn spawn(port: u16) -> Server {
    let server = Server(
        Command::new(env!("CARGO_BIN_EXE_hermes-signaling"))
            .env("HERMES_SIGNALING_BIND", format!("127.0.0.1:{port}"))
            .env("RUST_LOG", "warn")
            .spawn()
            .expect("spawn hermes-signaling"),
    );
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return server;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("signaling server never came up");
}

struct Client {
    id: NodeId,
    secret: NodeSecret,
    tx: SignalingClient,
    rx: Receiver<ServerMessage>,
}

async fn client(port: u16, name: &str) -> Client {
    let secret = NodeSecret::generate();
    let tx = SignalingClient::connect(&format!("ws://127.0.0.1:{port}/v1"), &secret, name.into())
        .await
        .unwrap();
    let rx = tx.take_inbox().unwrap();
    Client {
        id: secret.public().node_id,
        secret,
        tx,
        rx,
    }
}

/// A fresh invite code and its keys.
fn room(password: Option<&str>) -> (InviteCode, RoomKeys) {
    let code = InviteCode::generate();
    let keys = RoomKeys::derive(&code, password);
    (code, keys)
}

impl Client {
    async fn send(&self, m: ClientMessage) {
        self.tx.send(m).await.unwrap();
    }

    /// Next message matching `pred` (others are skipped).
    async fn expect<T>(
        &mut self,
        what: &str,
        mut pred: impl FnMut(&ServerMessage) -> Option<T>,
    ) -> T {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match timeout(left, self.rx.recv()).await {
                Ok(Some(m)) => {
                    if let Some(v) = pred(&m) {
                        return v;
                    }
                }
                _ => panic!("timed out waiting for {what}"),
            }
        }
    }

    async fn error_code(&mut self) -> String {
        self.expect("an error", |m| match m {
            ServerMessage::Error { code, .. } => Some(code.clone()),
            _ => None,
        })
        .await
    }

    async fn create(&mut self, keys: &RoomKeys) {
        self.send(ClientMessage::create_room(
            "r".into(),
            RoomMode::PeerToPeer,
            None,
            keys,
            &self.secret,
        ))
        .await;
        self.expect("RoomCreated", |m| {
            matches!(m, ServerMessage::RoomCreated { .. }).then_some(())
        })
        .await;
    }

    async fn join(&mut self, keys: &RoomKeys) {
        self.send(ClientMessage::join_room(keys, &self.secret, None))
            .await;
    }

    async fn joined(&mut self) -> Vec<hermes_core::signaling::PeerInfo> {
        self.expect("RoomJoined", |m| match m {
            ServerMessage::RoomJoined { members, .. } => Some(members.clone()),
            _ => None,
        })
        .await
    }
}

#[tokio::test]
async fn the_password_is_part_of_the_secret() {
    let port = 39851;
    let _s = spawn(port).await;
    let mut owner = client(port, "owner").await;
    let code = InviteCode::generate();
    owner.create(&RoomKeys::derive(&code, Some("s3cret"))).await;

    // The code alone, or with the wrong password, finds no room: to the
    // server it is just another unknown token.
    let mut guest = client(port, "guest").await;
    guest.join(&RoomKeys::derive(&code, None)).await;
    assert_eq!(guest.error_code().await, "invalid_code");
    guest.join(&RoomKeys::derive(&code, Some("wrong"))).await;
    assert_eq!(guest.error_code().await, "invalid_code");
    guest.join(&RoomKeys::derive(&code, Some("s3cret"))).await;
    guest.joined().await;
}

/// What the server holds is enough to find a room but not to vouch for
/// anyone in it: it sees a token and proofs, never the code or the key.
#[tokio::test]
async fn members_receive_each_others_proofs_which_verify_only_under_the_room_key() {
    let port = 39855;
    let _s = spawn(port).await;
    let (_, keys) = room(None);
    let (_, other_keys) = room(None);
    let mut owner = client(port, "owner").await;
    owner.create(&keys).await;
    let mut guest = client(port, "guest").await;
    guest.join(&keys).await;
    let members = guest.joined().await;
    let peer = members.iter().find(|p| p.node_id == owner.id).unwrap();
    let wg = owner.secret.public().wireguard_public;
    assert!(keys.verify(&peer.node_id, &peer.wireguard_public, &peer.admission));
    assert_eq!(peer.wireguard_public, wg);
    assert!(
        !other_keys.verify(&peer.node_id, &peer.wireguard_public, &peer.admission),
        "another room's key must not accept it"
    );

    // The owner is shown the guest's proof as well.
    let guest_id = guest.id;
    let seen = owner
        .expect("PeerJoined", |m| match m {
            ServerMessage::PeerJoined { peer } if peer.node_id == guest_id => Some(peer.clone()),
            _ => None,
        })
        .await;
    assert!(keys.verify(&seen.node_id, &seen.wireguard_public, &seen.admission));
}

#[tokio::test]
async fn only_the_owner_can_kick_ban_or_rotate() {
    let port = 39852;
    let _s = spawn(port).await;
    let (_, keys) = room(None);
    let mut owner = client(port, "owner").await;
    owner.create(&keys).await;
    let mut a = client(port, "a").await;
    let mut b = client(port, "b").await;
    a.join(&keys).await;
    a.joined().await;
    b.join(&keys).await;
    b.joined().await;

    // A member can't remove anyone or replace the code.
    a.send(ClientMessage::KickMember {
        node_id: b.id,
        ban: true,
    })
    .await;
    assert_eq!(a.error_code().await, "not_owner");
    let (next, next_keys) = room(None);
    a.send(ClientMessage::RotateInvite {
        new_lookup: next_keys.lookup(),
        admission: Vec::new(),
        sealed: keys.seal_code(&next),
    })
    .await;
    assert_eq!(a.error_code().await, "not_owner");

    // The owner can't remove themselves.
    owner
        .send(ClientMessage::KickMember {
            node_id: owner.id,
            ban: false,
        })
        .await;
    assert_eq!(owner.error_code().await, "bad_request");

    // Kick (no ban): b is told, a hears PeerLeft, and b may come back.
    owner
        .send(ClientMessage::KickMember {
            node_id: b.id,
            ban: false,
        })
        .await;
    b.expect("Kicked", |m| {
        matches!(m, ServerMessage::Kicked { banned: false }).then_some(())
    })
    .await;
    let b_id = b.id;
    a.expect("PeerLeft for b", |m| {
        matches!(m, ServerMessage::PeerLeft { node_id } if *node_id == b_id).then_some(())
    })
    .await;
    b.join(&keys).await;
    b.joined().await;

    // Kick with ban: b can't return with the code.
    owner
        .send(ClientMessage::KickMember {
            node_id: b.id,
            ban: true,
        })
        .await;
    b.expect("Kicked (banned)", |m| {
        matches!(m, ServerMessage::Kicked { banned: true }).then_some(())
    })
    .await;
    b.join(&keys).await;
    assert_eq!(b.error_code().await, "banned");
}

#[tokio::test]
async fn rotation_revokes_the_old_code_and_hands_the_new_one_over_sealed() {
    let port = 39853;
    let _s = spawn(port).await;
    let (_, old) = room(None);
    let mut owner = client(port, "owner").await;
    owner.create(&old).await;
    let mut member = client(port, "member").await;
    member.join(&old).await;
    member.joined().await;

    let (fresh_code, fresh) = room(None);
    owner
        .send(ClientMessage::RotateInvite {
            new_lookup: fresh.lookup(),
            admission: fresh.prove(&owner.id, &owner.secret.public().wireguard_public),
            sealed: old.seal_code(&fresh_code),
        })
        .await;

    // Everyone in the room, the owner included, is sent the sealed code;
    // only holders of the old key can read it.
    for who in [&mut owner, &mut member] {
        let sealed = who
            .expect("InviteRotated", |m| match m {
                ServerMessage::InviteRotated { sealed } => Some(sealed.clone()),
                _ => None,
            })
            .await;
        assert_eq!(old.open_code(&sealed), Some(fresh_code));
        assert!(fresh.open_code(&sealed).is_none());
    }

    // The member re-proves under the new key; the owner is told.
    member
        .send(ClientMessage::Reprove {
            admission: fresh.prove(&member.id, &member.secret.public().wireguard_public),
        })
        .await;
    let member_id = member.id;
    let updated = owner
        .expect("PeerUpdated", |m| match m {
            ServerMessage::PeerUpdated { peer } if peer.node_id == member_id => Some(peer.clone()),
            _ => None,
        })
        .await;
    assert!(fresh.verify(
        &updated.node_id,
        &updated.wireguard_public,
        &updated.admission
    ));

    // The old code is dead; the new one works and sees verifiable members.
    let mut late = client(port, "late").await;
    late.join(&old).await;
    assert_eq!(late.error_code().await, "invalid_code");
    late.join(&fresh).await;
    let members = late.joined().await;
    assert_eq!(members.len(), 2);
    for p in members {
        assert!(fresh.verify(&p.node_id, &p.wireguard_public, &p.admission));
    }
}

/// After a server restart the first member back recreates the room under
/// its token. Ownership is only ever claimed for oneself.
#[tokio::test]
async fn restored_room_grants_ownership_only_to_the_claimant() {
    let port = 39854;
    let _s = spawn(port).await;
    let mut owner = client(port, "owner").await;
    let mut member = client(port, "member").await;
    let (_, keys) = room(None);
    let restore = |claimed_owner: NodeId| RoomRestore {
        room_id: uuid::Uuid::new_v4(),
        name: "restored".into(),
        mode: RoomMode::PeerToPeer,
        relay_addr: None,
        owner: Some(claimed_owner),
    };

    // The member returns first and tries to claim the owner's seat.
    member
        .send(ClientMessage::join_room(
            &keys,
            &member.secret,
            Some(restore(owner.id)),
        ))
        .await;
    member.joined().await;

    owner.join(&keys).await;
    owner.joined().await;
    member
        .send(ClientMessage::KickMember {
            node_id: owner.id,
            ban: false,
        })
        .await;
    assert_eq!(member.error_code().await, "not_owner");
    owner
        .send(ClientMessage::KickMember {
            node_id: member.id,
            ban: false,
        })
        .await;
    assert_eq!(
        owner.error_code().await,
        "not_owner",
        "ownership claimed for someone else is dropped, not granted"
    );
}
