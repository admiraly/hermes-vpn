//! Cryptographic room admission.
//!
//! The invite code (plus the room password, if any) is the room's shared
//! secret, and the signaling server is never given it. From the secret we
//! derive, with a deliberately slow KDF:
//!
//! - a **lookup token** — all the server sees; it finds the room by it and
//!   cannot reverse it short of guessing the 55-bit code against Argon2id;
//! - an **admission key** — never leaves the members. Every member
//!   publishes a MAC, under that key, over its `(node_id, wireguard_public)`.
//!   Peers check the MAC before building a tunnel, so a server that wants to
//!   slip itself (or anyone) into the room has nothing that verifies.
//!
//! A wrong password derives a different token, so it looks to the server
//! exactly like a wrong code.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

use crate::crypto::NodeId;
use crate::room::InviteCode;

/// Fixed salt: the server can't supply a per-room one before lookup, and
/// the code itself carries the entropy.
const SALT: &[u8] = b"hermes-room-admission-v1";
/// OWASP's minimum Argon2id profile (19 MiB, 2 passes).
const MEMORY_KIB: u32 = 19 * 1024;
const PASSES: u32 = 2;

/// Length of a lookup token / admission proof.
pub const TAG_LEN: usize = 32;

/// The keys derived from a room's invite code and password.
#[derive(Clone)]
pub struct RoomKeys {
    lookup: [u8; 32],
    admission: [u8; 32],
}

impl std::fmt::Debug for RoomKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomKeys(..)")
    }
}

impl RoomKeys {
    /// Derive the keys. Slow (tens of milliseconds): call from
    /// `spawn_blocking` in async code.
    ///
    /// # Panics
    /// Never in practice: the Argon2 parameters are constants.
    #[must_use]
    pub fn derive(code: &InviteCode, password: Option<&str>) -> Self {
        let mut material = code.to_string().into_bytes();
        material.push(0);
        material.extend_from_slice(password.unwrap_or("").as_bytes());

        let params = Params::new(MEMORY_KIB, PASSES, 1, Some(32)).expect("valid argon2 params");
        let mut root = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(&material, SALT, &mut root)
            .expect("argon2 with fixed parameters");
        Self {
            lookup: blake3::derive_key("hermes room lookup v1", &root),
            admission: blake3::derive_key("hermes room admission v1", &root),
        }
    }

    /// What the server is told in place of the code.
    #[must_use]
    pub fn lookup(&self) -> [u8; TAG_LEN] {
        self.lookup
    }

    fn member_tag(&self, node_id: &NodeId, wireguard_public: &[u8; 32]) -> blake3::Hash {
        let mut h = blake3::Hasher::new_keyed(&self.admission);
        h.update(b"hermes member v1");
        h.update(&node_id.0);
        h.update(wireguard_public);
        h.finalize()
    }

    /// Our proof of belonging, for the server to hand to the other members.
    #[must_use]
    pub fn prove(&self, node_id: &NodeId, wireguard_public: &[u8; 32]) -> Vec<u8> {
        self.member_tag(node_id, wireguard_public)
            .as_bytes()
            .to_vec()
    }

    /// Does `proof` show that its sender holds the room secret?
    #[must_use]
    pub fn verify(&self, node_id: &NodeId, wireguard_public: &[u8; 32], proof: &[u8]) -> bool {
        let Ok(proof) = <[u8; TAG_LEN]>::try_from(proof) else {
            return false;
        };
        // `blake3::Hash` equality is constant-time.
        self.member_tag(node_id, wireguard_public) == blake3::Hash::from(proof)
    }

    /// Encrypt a replacement invite code for the other members, under
    /// *this* (the old) room's key, so the server can pass it on without
    /// reading it.
    #[must_use]
    pub fn seal_code(&self, new_code: &InviteCode) -> Vec<u8> {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut body = new_code.to_string().into_bytes();
        self.keystream(&nonce, &mut body);
        let mut out = nonce.to_vec();
        out.extend_from_slice(&body);
        let tag = self.seal_tag(&out);
        out.extend_from_slice(tag.as_bytes());
        out
    }

    /// Open a code sealed by [`seal_code`](Self::seal_code); `None` if it
    /// wasn't sealed under this room's key or was altered.
    #[must_use]
    pub fn open_code(&self, sealed: &[u8]) -> Option<InviteCode> {
        let split = sealed.len().checked_sub(TAG_LEN)?;
        let (head, tag) = sealed.split_at(split);
        let tag = <[u8; TAG_LEN]>::try_from(tag).ok()?;
        if self.seal_tag(head) != blake3::Hash::from(tag) {
            return None;
        }
        let (nonce, body) = head.split_at(16.min(head.len()));
        let mut body = body.to_vec();
        self.keystream(nonce, &mut body);
        String::from_utf8(body).ok()?.parse().ok()
    }

    fn keystream(&self, nonce: &[u8], data: &mut [u8]) {
        let key = blake3::derive_key("hermes seal enc v1", &self.admission);
        let mut stream = vec![0u8; data.len()];
        blake3::Hasher::new_keyed(&key)
            .update(nonce)
            .finalize_xof()
            .fill(&mut stream);
        for (d, k) in data.iter_mut().zip(stream) {
            *d ^= k;
        }
    }

    fn seal_tag(&self, data: &[u8]) -> blake3::Hash {
        let key = blake3::derive_key("hermes seal mac v1", &self.admission);
        blake3::keyed_hash(&key, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(b: u8) -> NodeId {
        NodeId([b; 32])
    }

    #[test]
    fn same_secret_same_keys_different_secret_nothing_shared() {
        let code = InviteCode::generate();
        let a = RoomKeys::derive(&code, Some("pw"));
        let b = RoomKeys::derive(&code, Some("pw"));
        assert_eq!(a.lookup(), b.lookup());
        // The password is part of the secret.
        assert_ne!(a.lookup(), RoomKeys::derive(&code, None).lookup());
        assert_ne!(a.lookup(), RoomKeys::derive(&code, Some("PW")).lookup());
        assert_ne!(
            a.lookup(),
            RoomKeys::derive(&InviteCode::generate(), Some("pw")).lookup()
        );
        // The token reveals neither the admission key nor the code.
        assert_ne!(a.lookup(), a.admission);
    }

    #[test]
    fn proofs_verify_only_for_the_same_member_and_room() {
        let keys = RoomKeys::derive(&InviteCode::generate(), None);
        let other = RoomKeys::derive(&InviteCode::generate(), None);
        let (n, wg) = (node(1), [7u8; 32]);
        let proof = keys.prove(&n, &wg);
        assert!(keys.verify(&n, &wg, &proof));
        assert!(!other.verify(&n, &wg, &proof), "another room's key");
        assert!(!keys.verify(&node(2), &wg, &proof), "another node");
        assert!(!keys.verify(&n, &[8u8; 32], &proof), "another wg key");
        assert!(!keys.verify(&n, &wg, &[]), "empty");
        assert!(!keys.verify(&n, &wg, &proof[..31]), "short");
        let mut flipped = proof.clone();
        flipped[0] ^= 1;
        assert!(!keys.verify(&n, &wg, &flipped));
    }

    #[test]
    fn sealed_codes_open_only_with_the_room_key_and_resist_tampering() {
        let keys = RoomKeys::derive(&InviteCode::generate(), Some("pw"));
        let next = InviteCode::generate();
        let sealed = keys.seal_code(&next);
        assert_eq!(keys.open_code(&sealed), Some(next));
        assert_ne!(
            keys.seal_code(&next),
            sealed,
            "fresh nonce each time (no deterministic ciphertext)"
        );

        let stranger = RoomKeys::derive(&InviteCode::generate(), Some("pw"));
        assert_eq!(stranger.open_code(&sealed), None);
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert_eq!(keys.open_code(&bad), None, "byte {i}");
        }
        assert_eq!(keys.open_code(&[]), None);
        assert_eq!(keys.open_code(&sealed[..sealed.len() - 1]), None);
    }
}
