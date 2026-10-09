//! Node identity — long-term Ed25519 keypair, derived X25519 for WireGuard.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::error::{HermesError, Result};

/// 32-byte Ed25519 public key — the canonical identifier for a node.
///
/// Serializes as a URL-safe base64 string for text formats (JSON) and as
/// a raw 32-byte array for compact binary formats (bincode). This keeps
/// on-disk identity files small while letting the IPC protocol use the
/// string form that TypeScript clients expect.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 32]);

impl serde::Serialize for NodeId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_base64())
        } else {
            self.0.serialize(s)
        }
    }
}

impl<'de> serde::Deserialize<'de> for NodeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            Self::from_base64(&s).map_err(D::Error::custom)
        } else {
            let bytes = <[u8; 32]>::deserialize(d)?;
            Ok(Self(bytes))
        }
    }
}

impl NodeId {
    /// Render as short hex prefix for logs (first 8 bytes).
    #[must_use]
    pub fn short(&self) -> String {
        hex::encode(&self.0[..8])
    }

    /// Render full identifier as URL-safe base64 (no padding).
    #[must_use]
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// Parse from URL-safe base64.
    ///
    /// # Errors
    /// Returns an error if the string is not valid base64 or not 32 bytes.
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| HermesError::Crypto(format!("bad base64: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| HermesError::Crypto("NodeId must be 32 bytes".into()))?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}

/// Private half of a node identity. Never leaves the local machine.
///
/// Stored as the bare 32-byte Ed25519 seed (see [`NodeSecret::to_bytes`]).
/// The X25519 secret used for WireGuard is derived via BLAKE3 rather than
/// stored separately.
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeSecret {
    ed25519_seed: [u8; 32],
}

impl NodeSecret {
    /// The seed as stored on disk: exactly 32 raw bytes.
    ///
    /// (Earlier versions wrote the same bytes via `bincode`, which encodes
    /// a fixed-size array without any framing — so existing `identity.key`
    /// files load unchanged.)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.ed25519_seed
    }

    /// Load a seed written by [`Self::to_bytes`].
    ///
    /// # Errors
    /// Fails unless `bytes` is exactly 32 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let ed25519_seed: [u8; 32] = bytes.try_into().map_err(|_| {
            HermesError::Crypto(format!(
                "identity file must be 32 bytes, found {}",
                bytes.len()
            ))
        })?;
        Ok(Self { ed25519_seed })
    }

    /// Generate a fresh, cryptographically random node identity.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self {
            ed25519_seed: signing.to_bytes(),
        }
    }

    /// The Ed25519 signing key used to sign outgoing control messages.
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.ed25519_seed)
    }

    /// Sign "this WireGuard key is mine" (see [`verify_wireguard_binding`]).
    #[must_use]
    pub fn sign_wireguard_binding(&self) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let identity = self.public();
        self.signing_key()
            .sign(&wg_binding_message(
                &identity.node_id,
                &identity.wireguard_public,
            ))
            .to_bytes()
            .to_vec()
    }

    /// The X25519 static secret used for WireGuard handshakes.
    ///
    /// Derived from the Ed25519 seed via BLAKE3 with a domain separator so
    /// the two key spaces remain cryptographically independent.
    #[must_use]
    pub fn wireguard_secret(&self) -> XStaticSecret {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hermes/wireguard/x25519/v1");
        hasher.update(&self.ed25519_seed);
        let digest = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest.as_bytes()[..32]);
        XStaticSecret::from(seed)
    }

    /// Derive the public identity.
    #[must_use]
    pub fn public(&self) -> NodeIdentity {
        let signing = self.signing_key();
        let verifying: VerifyingKey = signing.verifying_key();
        let wg_pub = XPublicKey::from(&self.wireguard_secret());
        NodeIdentity {
            node_id: NodeId(verifying.to_bytes()),
            wireguard_public: wg_pub.to_bytes(),
        }
    }
}

impl fmt::Debug for NodeSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print private material.
        f.debug_struct("NodeSecret").finish_non_exhaustive()
    }
}

/// Domain separator for [`NodeSecret::sign_wireguard_binding`].
const WG_BINDING_CONTEXT: &[u8] = b"hermes-wireguard-binding-v1";

fn wg_binding_message(node_id: &NodeId, wireguard_public: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(WG_BINDING_CONTEXT.len() + 64);
    msg.extend_from_slice(WG_BINDING_CONTEXT);
    msg.extend_from_slice(&node_id.0);
    msg.extend_from_slice(wireguard_public);
    msg
}

/// Check that `node_id` vouches for `wireguard_public`: `signature` must be
/// the node's Ed25519 signature from [`NodeSecret::sign_wireguard_binding`].
///
/// A node's WireGuard key is *derived* from its identity seed, but nobody
/// else can recompute that derivation (it needs the secret), so peers
/// would otherwise have to take whatever key the signaling server hands
/// them on trust — and a hostile server could substitute its own and sit
/// in the middle of the "end-to-end" tunnel. This signature closes that
/// gap: only the holder of the identity key can produce it, and the
/// server can relay it but not forge it.
#[must_use]
pub fn verify_wireguard_binding(
    node_id: &NodeId,
    wireguard_public: &[u8; 32],
    signature: &[u8],
) -> bool {
    use ed25519_dalek::{Signature, Verifier};
    let Ok(key) = VerifyingKey::from_bytes(&node_id.0) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(&wg_binding_message(node_id, wireguard_public), &sig)
        .is_ok()
}

/// Public identity of a node: what you advertise to peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// Canonical node identifier.
    pub node_id: NodeId,
    /// WireGuard X25519 public key (derived deterministically from `node_id`).
    pub wireguard_public: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_unique() {
        let a = NodeSecret::generate();
        let b = NodeSecret::generate();
        assert_ne!(a.public().node_id, b.public().node_id);
    }

    #[test]
    fn wireguard_secret_is_deterministic() {
        let s = NodeSecret::generate();
        let wg1 = XPublicKey::from(&s.wireguard_secret());
        let wg2 = XPublicKey::from(&s.wireguard_secret());
        assert_eq!(wg1.as_bytes(), wg2.as_bytes());
    }

    #[test]
    fn wireguard_binding_accepts_only_the_owner_and_the_right_key() {
        let (alice, mallory) = (NodeSecret::generate(), NodeSecret::generate());
        let a = alice.public();
        let sig = alice.sign_wireguard_binding();
        assert!(verify_wireguard_binding(
            &a.node_id,
            &a.wireguard_public,
            &sig
        ));

        // A substituted key (what a hostile signaling server would try).
        let m = mallory.public();
        assert!(!verify_wireguard_binding(
            &a.node_id,
            &m.wireguard_public,
            &sig
        ));
        // Someone else's signature over someone else's key, under Alice's id.
        let forged = mallory.sign_wireguard_binding();
        assert!(!verify_wireguard_binding(
            &a.node_id,
            &m.wireguard_public,
            &forged
        ));
        // Garbage / empty / truncated.
        assert!(!verify_wireguard_binding(
            &a.node_id,
            &a.wireguard_public,
            &[]
        ));
        assert!(!verify_wireguard_binding(
            &a.node_id,
            &a.wireguard_public,
            &sig[..63]
        ));
        // Context separation: a relay-registration signature isn't a binding.
        assert!(!verify_wireguard_binding(
            &a.node_id,
            &a.wireguard_public,
            &[0u8; 64]
        ));
    }

    #[test]
    fn seed_bytes_roundtrip_and_validation() {
        let s = NodeSecret::generate();
        let loaded = NodeSecret::from_bytes(&s.to_bytes()).unwrap();
        assert_eq!(loaded.public().node_id, s.public().node_id);
        assert!(NodeSecret::from_bytes(&[0u8; 31]).is_err());
        assert!(NodeSecret::from_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn legacy_bincode_identity_files_load_unchanged() {
        // Version <= 0.2 stored `bincode::serialize(&NodeSecret)`; for a
        // struct holding one [u8; 32] that is the bare 32 bytes.
        let legacy = [7u8; 32];
        assert_eq!(NodeSecret::from_bytes(&legacy).unwrap().to_bytes(), legacy);
    }

    #[test]
    fn base64_roundtrip() {
        let s = NodeSecret::generate();
        let id = s.public().node_id;
        let encoded = id.to_base64();
        let decoded = NodeId::from_base64(&encoded).unwrap();
        assert_eq!(id, decoded);
    }
}
