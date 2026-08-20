//! DERP login handshake (Spec-DERP-STUN §3).
//!
//! The handshake is:
//!
//! 1. Server -> client `ServerKey` (magic + server public key).
//! 2. Client -> server `ClientInfo` (client key + nonce + encrypted JSON).
//! 3. Server decrypts, validates, and replies with `ServerInfo`
//!    (nonce + encrypted JSON) carrying the wire protocol version.
//!
//! Encryption uses the NaCl `crypto_box` construction (Curve25519 +
//! XSalsa20-Poly1305) provided by the `crypto_box` crate.

use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{Nonce, SalsaBox};
use serde::{Deserialize, Serialize};

use crate::frame::{FrameError, PROTOCOL_VERSION};
use crate::frames::NONCE_LEN;
use crate::keys::{NodeKey, SecretKey};

/// Errors returned by the DERP handshake helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// The encrypted payload could not be opened (bad key or tampering).
    DecryptionFailed,
    /// The client's capability version is not supported.
    UnsupportedVersion, // reserved for future capability gating
    /// The sealed JSON payload is invalid UTF-8 or malformed JSON.
    InvalidPayload(String),
    /// The client's node key in `ClientInfo` does not match its identity.
    KeyMismatch,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecryptionFailed => write!(f, "failed to open crypto_box payload"),
            Self::UnsupportedVersion => write!(f, "unsupported DERP protocol version"),
            Self::InvalidPayload(e) => write!(f, "invalid DERP handshake JSON: {e}"),
            Self::KeyMismatch => write!(f, "DERP client key does not match"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// The JSON payload a client seals inside `ClientInfo`.
///
/// The wire field names follow the reference client: `CanAckPings`,
/// `IsProber` (Go fields without tags) and `meshKey` (tagged). Renames make
/// serialization match the wire; aliases keep decoding tolerant of both the
/// PascalCase and camelCase forms seen in the wild.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfoPayload {
    /// Whether the client answers DERP pings with pongs.
    #[serde(rename = "CanAckPings", alias = "canAckPings", default)]
    pub can_ack_pings: bool,
    /// Whether the connection belongs to a connectivity prober.
    #[serde(rename = "IsProber", alias = "isProber", default)]
    pub is_prober: bool,
    /// Optional mesh key; empty for regular clients. Stub-only in this
    /// milestone (multi-node mesh is out of scope).
    #[serde(rename = "meshKey", alias = "mesh_key", default)]
    pub mesh_key: String,
    /// The DERP protocol version the client was built with.
    #[serde(rename = "version", alias = "Version", default)]
    pub version: u32,
}

impl Default for ClientInfoPayload {
    fn default() -> Self {
        Self {
            can_ack_pings: false,
            is_prober: false,
            mesh_key: String::new(),
            version: PROTOCOL_VERSION,
        }
    }
}

/// The JSON payload a server seals inside `ServerInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfoPayload {
    /// The wire protocol version; always [`PROTOCOL_VERSION`] on output.
    ///
    /// The wire field is lowercase `"version"` (JSON tag
    /// `json:"version,omitempty"`); decoding also accepts the PascalCase
    /// `"Version"` variant.
    #[serde(rename = "version", alias = "Version")]
    pub version: u32,
    /// Sustained token-bucket refill rate in bytes per second, when limited.
    #[serde(
        rename = "TokenBucketBytesPerSecond",
        alias = "tokenBucketBytesPerSecond",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_bucket_bytes_per_second: Option<u32>,
    /// Token-bucket burst size in bytes, when limited.
    #[serde(
        rename = "TokenBucketBytesBurst",
        alias = "tokenBucketBytesBurst",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_bucket_bytes_burst: Option<u32>,
}

impl Default for ServerInfoPayload {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            token_bucket_bytes_per_second: None,
            token_bucket_bytes_burst: None,
        }
    }
}

/// Seal `plaintext` to `recipient_public` using `sender_secret` and `nonce`.
///
/// Both endpoints of the connection construct the same `crypto_box` shared
/// key from their own secret and the peer's public key. Callers must pass a
/// unique nonce for every message sent in one direction.
pub fn seal_to(
    recipient_public: &NodeKey,
    sender_secret: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, FrameError> {
    let boxx = SalsaBox::new(
        &recipient_public.to_crypto_public(),
        &sender_secret.to_crypto_secret(),
    );
    boxx.encrypt(&Nonce::from(*nonce), plaintext)
        .map_err(|_| FrameError::CryptoFailed)
}

/// Open a payload sealed by `sender_public` for `recipient_secret`.
pub fn open_from(
    sender_public: &NodeKey,
    recipient_secret: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, FrameError> {
    let boxx = SalsaBox::new(
        &sender_public.to_crypto_public(),
        &recipient_secret.to_crypto_secret(),
    );
    boxx.decrypt(&Nonce::from(*nonce), ciphertext)
        .map_err(|_| FrameError::CryptoFailed)
}

/// Encode and seal a [`ClientInfoPayload`] with a freshly generated nonce.
pub fn make_client_info(
    client_secret: &SecretKey,
    server_public: &NodeKey,
    payload: &ClientInfoPayload,
) -> Result<(NodeKey, [u8; NONCE_LEN], Vec<u8>), HandshakeError> {
    let json =
        serde_json::to_vec(payload).map_err(|e| HandshakeError::InvalidPayload(e.to_string()))?;
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ciphertext = seal_to(server_public, client_secret, &nonce.into(), &json)
        .map_err(|_| HandshakeError::DecryptionFailed)?;
    Ok((client_secret.public(), nonce.into(), ciphertext))
}

/// Decrypt and parse a [`ClientInfoPayload`].
pub fn open_client_info(
    client_public: &NodeKey,
    server_secret: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<ClientInfoPayload, HandshakeError> {
    let plaintext = open_from(client_public, server_secret, nonce, ciphertext)
        .map_err(|_| HandshakeError::DecryptionFailed)?;
    serde_json::from_slice(&plaintext).map_err(|e| HandshakeError::InvalidPayload(e.to_string()))
}

/// Encode and seal a [`ServerInfoPayload`] with a freshly generated nonce.
pub fn make_server_info(
    server_secret: &SecretKey,
    client_public: &NodeKey,
    payload: &ServerInfoPayload,
) -> Result<([u8; NONCE_LEN], Vec<u8>), HandshakeError> {
    let json =
        serde_json::to_vec(payload).map_err(|e| HandshakeError::InvalidPayload(e.to_string()))?;
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ciphertext = seal_to(client_public, server_secret, &nonce.into(), &json)
        .map_err(|_| HandshakeError::DecryptionFailed)?;
    Ok((nonce.into(), ciphertext))
}

/// Decrypt and parse a [`ServerInfoPayload`] from the server.
pub fn open_server_info(
    server_public: &NodeKey,
    client_secret: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<ServerInfoPayload, HandshakeError> {
    let plaintext = open_from(server_public, client_secret, nonce, ciphertext)
        .map_err(|_| HandshakeError::DecryptionFailed)?;
    serde_json::from_slice(&plaintext).map_err(|e| HandshakeError::InvalidPayload(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::{ClientInfoBody, ServerInfoBody};

    #[test]
    fn client_info_and_server_info_round_trip() {
        let server_secret = SecretKey::random();
        let server_public = server_secret.public();
        let client_secret = SecretKey::random();
        let client_public = client_secret.public();

        // Client -> server: build the exact ClientInfo wire body.
        let client_payload = ClientInfoPayload {
            can_ack_pings: true,
            version: PROTOCOL_VERSION,
            ..Default::default()
        };
        let (sent_key, nonce, ciphertext) =
            make_client_info(&client_secret, &server_public, &client_payload).unwrap();
        assert_eq!(sent_key, client_public);

        let mut wire = ClientInfoBody {
            key: sent_key,
            nonce,
        }
        .encode_prefix()
        .to_vec();
        wire.extend_from_slice(&ciphertext);
        let prefix = ClientInfoBody::decode_prefix(&wire).unwrap();
        let encrypted = &wire[ClientInfoBody::PREFIX_LEN..];
        let opened =
            open_client_info(&prefix.key, &server_secret, &prefix.nonce, encrypted).unwrap();
        assert_eq!(opened.version, PROTOCOL_VERSION);
        assert!(opened.can_ack_pings);

        // Server -> client: build the exact ServerInfo wire body.
        let server_payload = ServerInfoPayload {
            version: PROTOCOL_VERSION,
            token_bucket_bytes_per_second: Some(1_000_000),
            token_bucket_bytes_burst: Some(250_000),
        };
        let (nonce, ciphertext) =
            make_server_info(&server_secret, &client_public, &server_payload).unwrap();
        let mut wire = ServerInfoBody { nonce }.encode_prefix().to_vec();
        wire.extend_from_slice(&ciphertext);
        let prefix = ServerInfoBody::decode_prefix(&wire).unwrap();
        let encrypted = &wire[ServerInfoBody::PREFIX_LEN..];
        let opened =
            open_server_info(&server_public, &client_secret, &prefix.nonce, encrypted).unwrap();
        assert_eq!(opened.version, PROTOCOL_VERSION);
        assert_eq!(opened.token_bucket_bytes_per_second, Some(1_000_000));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let server_secret = SecretKey::random();
        let server_public = server_secret.public();
        let client_secret = SecretKey::random();
        let (_, nonce, mut ciphertext) = make_client_info(
            &client_secret,
            &server_public,
            &ClientInfoPayload::default(),
        )
        .unwrap();
        ciphertext[0] ^= 0x01;
        assert!(matches!(
            open_client_info(&client_secret.public(), &server_secret, &nonce, &ciphertext),
            Err(HandshakeError::DecryptionFailed)
        ));
    }

    #[test]
    fn server_info_serializes_wire_field_names() {
        let payload = ServerInfoPayload {
            version: PROTOCOL_VERSION,
            token_bucket_bytes_per_second: Some(1_000_000),
            token_bucket_bytes_burst: Some(250_000),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"version\":2"), "got {json}");
        assert!(
            json.contains("\"TokenBucketBytesPerSecond\":1000000"),
            "got {json}"
        );
        assert!(
            json.contains("\"TokenBucketBytesBurst\":250000"),
            "got {json}"
        );

        // Decoding accepts the PascalCase form too.
        let parsed: ServerInfoPayload =
            serde_json::from_str(r#"{"Version":2,"TokenBucketBytesPerSecond":1000000}"#).unwrap();
        assert_eq!(parsed.version, PROTOCOL_VERSION);
        assert_eq!(parsed.token_bucket_bytes_per_second, Some(1_000_000));
    }

    #[test]
    fn client_info_accepts_reference_field_names() {
        // The reference client sends CanAckPings/meshKey (no snake_case).
        let parsed: ClientInfoPayload = serde_json::from_str(
            r#"{"CanAckPings":true,"IsProber":false,"meshKey":"","version":2}"#,
        )
        .unwrap();
        assert!(parsed.can_ack_pings);
        assert!(!parsed.is_prober);
        assert_eq!(parsed.mesh_key, "");

        let json = serde_json::to_string(&parsed).unwrap();
        assert!(json.contains("\"CanAckPings\":true"), "got {json}");
        assert!(json.contains("\"meshKey\":\"\""), "got {json}");
    }
}
