//! Robustness of everything that parses bytes an attacker controls.
//!
//! Every datagram on the shared UDP socket, every frame out of a tunnel,
//! and every control message is untrusted input. For each parser: arbitrary
//! bytes must never panic (and never make it read out of bounds), and the
//! codecs must round-trip. These run on stable in normal CI; they are the
//! cheap cousin of a coverage-guided fuzzer. Raise the effort locally with
//! `PROPTEST_CASES=100000 cargo test -p hermes-core --test parsers_proptest`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use proptest::prelude::*;
use tokio::net::UdpSocket;

use hermes_core::broadcast::{arp, classify, ethertype, shim, MacRouter};
use hermes_core::crypto::{NodeId, NodeSecret, VirtualIpv4, VirtualMac};
use hermes_core::mesh::Mesh;
use hermes_core::nat::{ice, stun};
use hermes_core::relay::protocol as relay;
use hermes_core::room::InviteCode;
use hermes_core::signaling::{ClientMessage, ServerMessage};
use hermes_core::tunnel::{
    decode_frame, decode_packet, encode_control, encode_frame, PeerPath, PeerTunnel,
};

/// Cases per property: 1000 by default, or `PROPTEST_CASES` if set.
fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

/// Bytes that start like a real packet of some kind, so the fuzzer gets past
/// the first magic-number check instead of bouncing off it.
fn almost_packet() -> impl Strategy<Value = Vec<u8>> {
    let heads: Vec<Vec<u8>> = vec![
        vec![0xC8, 1],          // relay REGISTER
        vec![0xC8, 2],          // relay ACK
        vec![0xC8, 3],          // relay DATA
        vec![0xC8, 4],          // relay FORWARD
        b"HRM1".to_vec(),       // ICE probe request
        b"HRA1".to_vec(),       // ICE probe reply
        vec![0x01, 0x01, 0, 0], // STUN-ish
        vec![1, 0, 0, 0],       // WireGuard initiation
        vec![2, 0, 0, 0],       // WireGuard response
        vec![4, 0, 0, 0],       // WireGuard data
        vec![0x45, 0],          // IPv4
        vec![0x08, 0x06],       // ARP ethertype
    ];
    (prop::sample::select(heads), bytes(200)).prop_map(|(mut head, tail)| {
        head.extend(tail);
        head
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    // ---- relay wire protocol -------------------------------------------
    #[test]
    fn relay_parse_never_panics(buf in prop_oneof![bytes(300), almost_packet()]) {
        let _ = relay::parse_packet(&buf);
        let _ = relay::is_relay_packet(&buf);
    }

    #[test]
    fn relay_data_and_forward_roundtrip(
        id in any::<[u8; 32]>(),
        payload in bytes(1500),
    ) {
        let node = NodeId(id);
        match relay::parse_packet(&relay::encode_data(&node, &payload)) {
            Some(relay::RelayPacket::Data { dest, payload: p }) => {
                prop_assert_eq!(dest, node);
                prop_assert_eq!(p, &payload[..]);
            }
            other => prop_assert!(false, "data: {other:?}"),
        }
        match relay::parse_packet(&relay::encode_forward(&node, &payload)) {
            Some(relay::RelayPacket::Forward { src, payload: p }) => {
                prop_assert_eq!(src, node);
                prop_assert_eq!(p, &payload[..]);
            }
            other => prop_assert!(false, "forward: {other:?}"),
        }
    }

    /// A REGISTER with any single byte flipped must not verify (the
    /// signature covers room, node and timestamp).
    #[test]
    fn relay_register_rejects_any_bit_flip(ts in any::<u64>(), pos in 0usize..relay::REGISTER_LEN, bit in 0u8..8) {
        let secret = NodeSecret::generate();
        let room = uuid::Uuid::new_v4();
        let mut pkt = relay::encode_register(&room, &secret, ts);
        pkt[pos] ^= 1 << bit;
        if let Some(relay::RelayPacket::Register { room_id, node_id, timestamp_ms, signature }) = relay::parse_packet(&pkt) {
            // Flipping the magic/type byte makes it unparseable; anything
            // that still parses as REGISTER must fail verification.
            prop_assert!(!relay::verify_register(&room_id, &node_id, timestamp_ms, &signature));
        }
    }

    // ---- tunnel framing --------------------------------------------------
    #[test]
    fn framing_decode_never_panics(buf in prop_oneof![bytes(400), almost_packet()]) {
        let _ = decode_packet(&buf);
        let _ = decode_frame(&buf);
    }

    #[test]
    fn framing_roundtrip(frame in bytes(1500), ctl in bytes(64)) {
        let wrapped = encode_frame(&frame);
        let (hdr, out) = decode_frame(&wrapped).expect("frame decodes");
        prop_assert_eq!(usize::from(hdr.frame_len), frame.len());
        prop_assert_eq!(out, &frame[..]);
        // A control message is never mistaken for an Ethernet frame.
        prop_assert!(decode_frame(&encode_control(&ctl)).is_none());
    }

    // ---- L2 helpers -----------------------------------------------------
    #[test]
    fn l2_helpers_never_panic(buf in prop_oneof![bytes(200), almost_packet()]) {
        let _ = classify(&buf);
        let _ = ethertype(&buf);
        let _ = arp::parse_request(&buf);
    }

    #[test]
    fn shim_never_panics_on_garbage(buf in prop_oneof![bytes(300), almost_packet()]) {
        let own = VirtualMac([0x02, 1, 2, 3, 4, 5]);
        let router = MacRouter::new(own);
        router.set_own_ipv4(Some(Ipv4Addr::new(10, 42, 0, 1)));
        let peer = NodeId([9; 32]);
        router.register(
            VirtualMac::from_node_id(&peer),
            VirtualIpv4::from_node_id(&peer, [10, 42]),
            peer,
        );
        let _ = shim::wrap_outbound(&buf, own, &router);
        let _ = shim::unwrap_inbound(&buf, &router);
        let _ = router.route(&buf);
    }

    /// What the shim wraps for the mesh must route to a peer or flood —
    /// never come out as a frame the router can't classify.
    #[test]
    fn shim_output_is_always_routable(dst in any::<[u8; 4]>(), payload in bytes(100)) {
        let own = VirtualMac([0x02, 1, 2, 3, 4, 5]);
        let router = MacRouter::new(own);
        router.set_own_ipv4(Some(Ipv4Addr::new(10, 42, 0, 1)));
        let mut pkt = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 42, 0, 1];
        pkt.extend_from_slice(&dst);
        pkt.extend_from_slice(&payload);
        let total = u16::try_from(pkt.len()).unwrap();
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        if let Some(frame) = shim::wrap_outbound(&pkt, own, &router) {
            prop_assert!(classify(&frame).is_some());
        }
    }

    // ---- STUN and ICE probes ---------------------------------------------
    #[test]
    fn stun_parse_never_panics(buf in prop_oneof![bytes(200), almost_packet()]) {
        let _ = stun::is_stun_packet(&buf);
        let _ = stun::parse_binding_response(&buf);
    }

    #[test]
    fn ice_probe_codec(buf in prop_oneof![bytes(40), almost_packet()], nonce in any::<u64>(), index in any::<u8>()) {
        let _ = ice::parse_probe(&buf);
        prop_assert_eq!(
            ice::parse_probe(&ice::encode_request(nonce, index)),
            Some(ice::ProbeMessage::Request { nonce, index })
        );
        prop_assert_eq!(
            ice::parse_probe(&ice::encode_reply(nonce, index)),
            Some(ice::ProbeMessage::Reply { nonce, index })
        );
    }

    // ---- text formats ---------------------------------------------------
    #[test]
    fn json_messages_never_panic(buf in bytes(400)) {
        let text = String::from_utf8_lossy(&buf);
        let _ = serde_json::from_str::<ClientMessage>(&text);
        let _ = serde_json::from_str::<ServerMessage>(&text);
    }

    #[test]
    fn invite_code_parse_never_panics(s in "\\PC{0,40}") {
        let _ = s.parse::<InviteCode>();
    }
}

/// The big one: arbitrary datagrams from arbitrary addresses into a live
/// mesh holding a real tunnel. Whatever arrives — relay frames, probes,
/// STUN, WireGuard-shaped junk, truncated handshakes — must be handled
/// without panicking, and must never produce a frame for the adapter.
#[test]
fn mesh_dispatch_inbound_survives_arbitrary_datagrams() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let secret = Arc::new(NodeSecret::generate());
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let router = Arc::new(MacRouter::new(VirtualMac::from_node_id(
            &secret.public().node_id,
        )));
        let mesh = Arc::new(Mesh::new(socket.clone(), secret.clone(), router.clone()));
        let relay_addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        mesh.set_relay(Some(relay_addr));

        let peer = NodeSecret::generate().public();
        router.register(
            VirtualMac::from_node_id(&peer.node_id),
            VirtualIpv4::from_node_id(&peer.node_id, [10, 42]),
            peer.node_id,
        );
        let direct: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        mesh.add_peer(
            PeerTunnel::new(
                peer.node_id,
                peer.wireguard_public,
                &secret,
                PeerPath::Direct(direct),
                socket,
            )
            .unwrap(),
        )
        .await;

        let mut runner =
            proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(cases()));
        let strat = (
            prop_oneof![bytes(300), almost_packet()],
            prop_oneof![
                Just(direct),
                Just(relay_addr),
                Just("127.0.0.1:40001".parse().unwrap())
            ],
        );
        let accepted_frames = std::sync::atomic::AtomicUsize::new(0);
        runner
            .run(&strat, |(datagram, from)| {
                let result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(mesh.dispatch_inbound(from, &datagram))
                });
                if let Ok(Some(_)) = result {
                    accepted_frames.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(
            accepted_frames.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "random bytes must never decrypt into a frame"
        );
    });
}
