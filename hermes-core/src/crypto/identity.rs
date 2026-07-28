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
/// Serialized form is a bincode-encoded Ed25519 seed. The X25519 secret
/// used for WireGuard is derived via BLAKE3 rather than stored separately.
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeSecret {
    ed25519_seed: [u8; 32],
}

impl NodeSecret {
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
    fn base64_roundtrip() {
        let s = NodeSecret::generate();
        let id = s.public().node_id;
        let encoded = id.to_base64();
        let decoded = NodeId::from_base64(&encoded).unwrap();
        assert_eq!(id, decoded);
    }
}
