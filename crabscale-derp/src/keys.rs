//! DERP key types.
//!
//! A DERP node is addressed by a Curve25519 public key (the same key family
//! used for the control plane), and the login handshake seals payloads with
//! the NaCl `crypto_box` construction (Curve25519 + XSalsa20-Poly1305)
//! described in Spec-DERP-STUN §3.

use std::fmt;

use crypto_box::aead::OsRng;
use crypto_box::{PublicKey as BoxPublicKey, SecretKey as BoxSecretKey};

/// Number of bytes in a DERP public or secret key.
pub const KEY_LEN: usize = 32;

/// A DERP node public key.
///
/// This is the routing address used in `SendPacket`/`RecvPacket` and the
/// `key` field of `ClientInfo`, `PeerGone`, and `PeerPresent` frames. On the
/// wire it is always 32 raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeKey([u8; KEY_LEN]);

impl NodeKey {
    /// Build a key from its raw 32-byte representation.
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Return the raw 32-byte representation.
    pub const fn to_bytes(self) -> [u8; KEY_LEN] {
        self.0
    }

    /// Convert into the underlying `crypto_box` public key.
    pub fn to_crypto_public(self) -> BoxPublicKey {
        BoxPublicKey::from(self.0)
    }
}

impl From<[u8; KEY_LEN]> for NodeKey {
    fn from(bytes: [u8; KEY_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<NodeKey> for [u8; KEY_LEN] {
    fn from(key: NodeKey) -> Self {
        key.to_bytes()
    }
}

impl AsRef<[u8]> for NodeKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        write!(f, "node:{}", &hex[..16])
    }
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A DERP secret key (the private half of a `crypto_box` keypair).
///
/// Secret material is never logged, serialized, or displayed.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// Generate a fresh random secret key.
    pub fn random() -> Self {
        let secret = BoxSecretKey::generate(&mut OsRng);
        Self(secret.to_bytes())
    }

    /// Build a secret key from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Return the raw secret bytes.
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    /// Derive this key's public half as a [`NodeKey`].
    pub fn public(&self) -> NodeKey {
        let secret = BoxSecretKey::from(self.0);
        NodeKey::from_bytes(BoxPublicKey::from(&secret).to_bytes())
    }

    /// Convert into the underlying `crypto_box` secret key.
    pub fn to_crypto_secret(&self) -> BoxSecretKey {
        BoxSecretKey::from(self.0)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose secret material through Debug output.
        f.write_str("SecretKey([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn public_key_round_trips_through_bytes() {
        let secret = SecretKey::random();
        let public = secret.public();
        let restored = NodeKey::from_bytes(public.to_bytes());
        assert_eq!(restored, public);
    }

    #[test]
    fn node_key_is_usable_as_a_hash_key() {
        let key = NodeKey::from_bytes([1; KEY_LEN]);
        let mut map = HashMap::new();
        map.insert(key, 42);
        assert_eq!(map[&NodeKey::from_bytes([1; KEY_LEN])], 42);
    }

    #[test]
    fn secret_key_debug_never_leaks_bytes() {
        let secret = SecretKey::from_bytes([0xab; KEY_LEN]);
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("abab"));
        assert!(rendered.contains("redacted"));
    }
}
