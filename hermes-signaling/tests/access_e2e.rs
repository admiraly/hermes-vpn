//! Room access control on the real `hermes-signaling` binary: passwords,
//! owner-only kick/ban, invite rotation, and that none of it can be
//! claimed by a non-owner.

use std::process::{Child, Command};
use std::time::Duration;

use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

use hermes_core::crypto::{NodeId, NodeSecret};
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
        tx,
        rx,
    }
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

    async fn create(&mut self, password: Option<&str>) -> InviteCode {
        self.send(ClientMessage::CreateRoom {
            name: "r".into(),
            mode: RoomMode::PeerToPeer,
            relay_addr: None,
            password: password.map(str::to_string),
        })
        .await;
        self.expect("RoomCreated", |m| match m {
            ServerMessage::RoomCreated { invite_code, .. } => Some(*invite_code),
            _ => None,
        })
        .await
    }

    async fn join(&mut self, code: InviteCode, password: Option<&str>) {
        self.send(ClientMessage::JoinRoom {
            code,
            restore: None,
            password: password.map(str::to_string),
        })
        .await;
    }

    async fn joined(&mut self) {
        self.expect("RoomJoined", |m| {
            matches!(m, ServerMessage::RoomJoined { .. }).then_some(())
        })
        .await;
    }
}

#[tokio::test]
async fn password_protects_the_room() {
    let port = 39851;
    let _s = spawn(port).await;
    let mut owner = client(port, "owner").await;
    let code = owner.create(Some("s3cret")).await;

    let mut guest = client(port, "guest").await;
    guest.join(code, None).await;
    assert_eq!(guest.error_code().await, "password_required");
    guest.join(code, Some("wrong")).await;
    assert_eq!(guest.error_code().await, "bad_password");
    guest.join(code, Some("s3cret")).await;
    guest.joined().await;

    // A room without a password is unaffected by a password offered anyway.
    let mut open_owner = client(port, "open").await;
    let open_code = open_owner.create(None).await;
    let mut other = client(port, "other").await;
    other.join(open_code, Some("ignored")).await;
    other.joined().await;
}

#[tokio::test]
async fn only_the_owner_can_kick_ban_or_rotate() {
    let port = 39852;
    let _s = spawn(port).await;
    let mut owner = client(port, "owner").await;
    let code = owner.create(None).await;
    let mut a = client(port, "a").await;
    let mut b = client(port, "b").await;
    a.join(code, None).await;
    a.joined().await;
    b.join(code, None).await;
    b.joined().await;

    // A member can't remove anyone or replace the code.
    a.send(ClientMessage::KickMember {
        node_id: b.id,
        ban: true,
    })
    .await;
    assert_eq!(a.error_code().await, "not_owner");
    a.send(ClientMessage::RotateInvite).await;
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
    b.join(code, None).await;
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
    b.join(code, None).await;
    assert_eq!(b.error_code().await, "banned");
}

#[tokio::test]
async fn rotating_the_invite_revokes_the_old_code() {
    let port = 39853;
    let _s = spawn(port).await;
    let mut owner = client(port, "owner").await;
    let old = owner.create(None).await;
    let mut member = client(port, "member").await;
    member.join(old, None).await;
    member.joined().await;

    owner.send(ClientMessage::RotateInvite).await;
    let fresh = owner
        .expect("InviteRotated", |m| match m {
            ServerMessage::InviteRotated { invite_code } => Some(*invite_code),
            _ => None,
        })
        .await;
    // Existing members are told, too, so their re-joins use the new code.
    let told = member
        .expect("InviteRotated at member", |m| match m {
            ServerMessage::InviteRotated { invite_code } => Some(*invite_code),
            _ => None,
        })
        .await;
    assert_eq!(told, fresh);
    assert_ne!(old, fresh);

    let mut late = client(port, "late").await;
    late.join(old, None).await;
    assert_eq!(late.error_code().await, "invalid_code");
    late.join(fresh, None).await;
    late.joined().await;
}

/// After a server restart the first member to return recreates the room.
/// Their password comes back with them; ownership is only ever claimed
/// for oneself.
#[tokio::test]
async fn restored_room_keeps_its_password_and_owner_only_for_the_claimant() {
    let port = 39854;
    let _s = spawn(port).await;
    let mut owner = client(port, "owner").await;
    let mut member = client(port, "member").await;
    let code = InviteCode::generate();
    let restore = |claimed_owner: NodeId| RoomRestore {
        room_id: uuid_for_test(),
        name: "restored".into(),
        mode: RoomMode::PeerToPeer,
        relay_addr: None,
        password: Some("pw".into()),
        owner: Some(claimed_owner),
    };

    // The member returns first and tries to claim the owner's seat.
    member
        .send(ClientMessage::JoinRoom {
            code,
            restore: Some(restore(owner.id)),
            password: Some("pw".into()),
        })
        .await;
    member.joined().await;

    // The password survived the restore.
    let mut stranger = client(port, "stranger").await;
    stranger.join(code, None).await;
    assert_eq!(stranger.error_code().await, "password_required");

    // The claim was not honoured: nobody but the claimant can hold it.
    owner.join(code, Some("pw")).await;
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

fn uuid_for_test() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}
