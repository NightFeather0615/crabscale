//! Noise IK handshake primitives and the TS2021 responder.
//!
//! This module implements the exact Noise pattern required by Spec-Transport:
//! `Noise_IK_25519_ChaChaPoly_BLAKE2s`. The implementation is intentionally
//! self-contained so the transport crate owns its wire behavior.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::SimpleHkdf;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::TransportError;
use crate::messages::{
    AEAD_TAG_LEN, InitMessage, MSG_TYPE_INIT, RESPONSE_MESSAGE_LEN, write_response_message,
};

/// The Noise protocol name used by TS2021.
pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// The role of a local endpoint in a Noise session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The endpoint that started the handshake.
    Initiator,
    /// The endpoint that answered the handshake.
    Responder,
}

/// Symmetric keys produced by a completed Noise handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Key used by the initiator to send and the responder to receive.
    pub initiator_to_responder: [u8; 32],
    /// Key used by the responder to send and the initiator to receive.
    pub responder_to_initiator: [u8; 32],
    /// Local role in the handshake.
    pub role: Role,
}

/// A completed responder handshake.
#[derive(Debug)]
pub struct ResponderOutput {
    /// The 51-byte response message to send to the client.
    pub response: [u8; RESPONSE_MESSAGE_LEN],
    /// The established Noise session.
    pub session: Session,
    /// The client's long-term machine public key, recovered from the handshake.
    pub peer_static_public: PublicKey,
}

/// Server-side Noise IK responder.
#[derive(Clone)]
pub struct NoiseResponder {
    static_private: StaticSecret,
    static_public: PublicKey,
}

impl NoiseResponder {
    /// Create a responder from a raw 32-byte static secret.
    pub fn from_bytes(secret: [u8; 32]) -> Self {
        let static_private = StaticSecret::from(secret);
        let static_public = PublicKey::from(&static_private);
        Self {
            static_private,
            static_public,
        }
    }

    /// Create a responder with a freshly generated static key.
    pub fn random() -> Self {
        let static_private = StaticSecret::random();
        let static_public = PublicKey::from(&static_private);
        Self {
            static_private,
            static_public,
        }
    }

    /// The responder's long-term public key.
    pub fn public_key(&self) -> PublicKey {
        self.static_public
    }

    /// Process a client init message and produce the response.
    ///
    /// The capability version is checked before any cryptographic work so an
    /// unsupported client is rejected before the handshake can succeed.
    pub fn respond(
        &self,
        init: &InitMessage,
        prologue: &[u8],
    ) -> Result<ResponderOutput, TransportError> {
        self.respond_with_ephemeral(init, prologue, StaticSecret::random())
    }

    /// Process a client init message with a caller-supplied server ephemeral.
    ///
    /// This is exposed for deterministic golden-vector tests; production code
    /// should use [`NoiseResponder::respond`].
    pub fn respond_with_ephemeral(
        &self,
        init: &InitMessage,
        prologue: &[u8],
        server_ephemeral: StaticSecret,
    ) -> Result<ResponderOutput, TransportError> {
        if init.version < crabscale_proto::MIN_SUPPORTED_CAPVER as u16 {
            return Err(TransportError::UnsupportedCapabilityVersion(init.version));
        }
        let client_ephemeral = PublicKey::from(init.client_ephemeral);

        let state = State::new(PROTOCOL_NAME)
            .mix_hash(prologue)
            .mix_hash(self.static_public.as_bytes())
            .mix_hash(&init.client_ephemeral)
            .mix_dh(&self.static_private, &client_ephemeral);

        let mut client_static = [0u8; 32];
        client_static.copy_from_slice(&init.client_static_ciphertext[..32]);
        let mut static_tag = [0u8; AEAD_TAG_LEN];
        static_tag.copy_from_slice(&init.client_static_ciphertext[32..48]);

        let state = state
            .open(&mut client_static, &static_tag)
            .ok_or(TransportError::HandshakeFailed)?;

        let client_static_public = PublicKey::from(client_static);

        let state = state
            .mix_dh(&self.static_private, &client_static_public)
            .open(&mut [], &init.payload_tag)
            .ok_or(TransportError::HandshakeFailed)?;

        let server_ephemeral_public = PublicKey::from(&server_ephemeral);

        let mut auth_tag = [0u8; AEAD_TAG_LEN];
        let state = state
            .mix_hash(server_ephemeral_public.as_bytes())
            .mix_dh(&server_ephemeral, &client_ephemeral)
            .mix_dh(&server_ephemeral, &client_static_public)
            .seal(&mut [], &mut auth_tag)
            .finish(Role::Responder);

        let response = write_response_message(&server_ephemeral_public.to_bytes(), &auth_tag);

        Ok(ResponderOutput {
            response,
            session: state,
            peer_static_public: client_static_public,
        })
    }
}

/// Client-side Noise IK initiator, used by loopback tests and tooling.
#[derive(Clone)]
pub struct NoiseInitiator {
    static_private: StaticSecret,
    state: State,
    ephemeral_private: StaticSecret,
}

impl NoiseInitiator {
    /// Build an init message and the handshake state needed to finish it.
    pub fn initialize(
        client_static: StaticSecret,
        server_public: PublicKey,
        prologue: &[u8],
        version: u16,
    ) -> (Self, [u8; crate::messages::INIT_MESSAGE_LEN]) {
        Self::initialize_with_ephemeral(
            client_static,
            StaticSecret::random(),
            server_public,
            prologue,
            version,
        )
    }

    /// Build an init message with a caller-supplied client ephemeral.
    ///
    /// This is exposed for deterministic golden-vector tests; production code
    /// should use [`NoiseInitiator::initialize`].
    pub fn initialize_with_ephemeral(
        client_static: StaticSecret,
        ephemeral: StaticSecret,
        server_public: PublicKey,
        prologue: &[u8],
        version: u16,
    ) -> (Self, [u8; crate::messages::INIT_MESSAGE_LEN]) {
        let ephemeral_public = PublicKey::from(&ephemeral);

        let mut client_static_ciphertext = [0u8; 48];
        client_static_ciphertext[..32].copy_from_slice(&client_static_public_bytes(&client_static));

        let mut static_tag = [0u8; AEAD_TAG_LEN];
        let state = State::new(PROTOCOL_NAME)
            .mix_hash(prologue)
            .mix_hash(server_public.as_bytes())
            .mix_hash(ephemeral_public.as_bytes())
            .mix_dh(&ephemeral, &server_public)
            .seal(&mut client_static_ciphertext[..32], &mut static_tag);

        client_static_ciphertext[32..48].copy_from_slice(&static_tag);

        let mut payload_tag = [0u8; AEAD_TAG_LEN];
        let state = state
            .mix_dh(&client_static, &server_public)
            .seal(&mut [], &mut payload_tag);

        let mut init = [0u8; crate::messages::INIT_MESSAGE_LEN];
        init[0..2].copy_from_slice(&version.to_be_bytes());
        init[2] = MSG_TYPE_INIT;
        init[3..5].copy_from_slice(&96u16.to_be_bytes());
        init[5..37].copy_from_slice(ephemeral_public.as_bytes());
        init[37..85].copy_from_slice(&client_static_ciphertext);
        init[85..101].copy_from_slice(&payload_tag);

        (
            Self {
                static_private: client_static,
                state,
                ephemeral_private: ephemeral,
            },
            init,
        )
    }

    /// Complete the handshake with the server's 51-byte response.
    pub fn finish(&self, response: &[u8; RESPONSE_MESSAGE_LEN]) -> Result<Session, TransportError> {
        let parsed = crate::messages::parse_response_message(response)?;
        let server_ephemeral = PublicKey::from(parsed.server_ephemeral);

        let state = self
            .state
            .clone()
            .mix_hash(server_ephemeral.as_bytes())
            .mix_dh(&self.ephemeral_private, &server_ephemeral)
            .mix_dh(&self.static_private, &server_ephemeral)
            .open(&mut [], &parsed.auth_tag)
            .ok_or(TransportError::HandshakeFailed)?;

        Ok(state.finish(Role::Initiator))
    }
}

fn client_static_public_bytes(secret: &StaticSecret) -> [u8; 32] {
    PublicKey::from(secret).to_bytes()
}

/// Base Noise handshake state.
#[derive(Debug, Clone)]
struct State {
    hash: [u8; 32],
    chaining_key: [u8; 32],
}

impl State {
    fn new(protocol_name: &[u8]) -> Self {
        let digest = Blake2s256::digest(protocol_name);
        Self {
            hash: digest.into(),
            chaining_key: digest.into(),
        }
    }

    fn mix_hash(mut self, data: &[u8]) -> Self {
        let mut hasher = Blake2s256::new_with_prefix(self.hash);
        hasher.update(data);
        self.hash = hasher.finalize().into();
        self
    }

    fn mix_hash_gather(mut self, data: &[&[u8]]) -> Self {
        let mut hasher = Blake2s256::new_with_prefix(self.hash);
        for piece in data {
            hasher.update(piece);
        }
        self.hash = hasher.finalize().into();
        self
    }

    fn mix_dh(self, private: &StaticSecret, public: &PublicKey) -> StateWithAead {
        let shared = private.diffie_hellman(public);
        let [ck, k] = hkdf_pair(&self.chaining_key, shared.as_bytes());
        StateWithAead {
            state: State {
                hash: self.hash,
                chaining_key: ck,
            },
            aead: ChaCha20Poly1305::new(&Key::from(k)),
        }
    }

    fn finish(self, role: Role) -> Session {
        let [initiator_to_responder, responder_to_initiator] = hkdf_pair(&self.chaining_key, &[]);
        Session {
            initiator_to_responder,
            responder_to_initiator,
            role,
        }
    }
}

/// Handshake state with an active AEAD cipher.
struct StateWithAead {
    state: State,
    aead: ChaCha20Poly1305,
}

impl StateWithAead {
    fn mix_dh(self, private: &StaticSecret, public: &PublicKey) -> Self {
        self.state.mix_dh(private, public)
    }

    fn seal(self, cleartext: &mut [u8], tag: &mut [u8; AEAD_TAG_LEN]) -> State {
        let nonce = Nonce::default();
        let result = self
            .aead
            .encrypt_in_place_detached(&nonce, &self.state.hash, cleartext)
            .expect("ChaCha20-Poly1305 encryption cannot fail");
        tag.copy_from_slice(result.as_ref());
        self.state.mix_hash_gather(&[cleartext, tag])
    }

    fn open(self, ciphertext: &mut [u8], tag: &[u8; AEAD_TAG_LEN]) -> Option<State> {
        let hash = self.state.hash;
        let state = self.state.mix_hash_gather(&[ciphertext, tag]);
        let nonce = Nonce::default();
        self.aead
            .decrypt_in_place_detached(&nonce, &hash, ciphertext, tag.into())
            .ok()?;
        Some(state)
    }
}

/// Derive one or two 32-byte keys from a Noise chaining key.
fn hkdf_pair(chaining_key: &[u8; 32], key: &[u8]) -> [[u8; 32]; 2] {
    let kdf = SimpleHkdf::<Blake2s256>::new(Some(chaining_key), key);
    let mut out = [[0u8; 32]; 2];
    kdf.expand(&[], out.as_flattened_mut())
        .expect("HKDF output length is valid");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::parse_init_message;

    #[test]
    fn responder_handshake_round_trip() {
        let client_static = StaticSecret::random();
        let server = NoiseResponder::random();
        let prologue = b"Tailscale Control Protocol v113";

        let (initiator, init_bytes) =
            NoiseInitiator::initialize(client_static, server.public_key(), prologue, 113);
        let init = parse_init_message(&init_bytes).unwrap();
        let output = server.respond(&init, prologue).unwrap();

        let session = initiator.finish(&output.response).unwrap();
        assert_eq!(session.role, Role::Initiator);
        assert_eq!(output.session.role, Role::Responder);
        assert_eq!(
            session.initiator_to_responder,
            output.session.initiator_to_responder
        );
        assert_eq!(
            session.responder_to_initiator,
            output.session.responder_to_initiator
        );
    }

    fn test_key(range: std::ops::Range<u8>) -> StaticSecret {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = range.start + i as u8;
        }
        StaticSecret::from(bytes)
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        let hex = hex.as_bytes();
        let mut out = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let hi = (hex[i] as char).to_digit(16).unwrap() as u8;
            let lo = (hex[i + 1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    #[test]
    fn golden_vector_matches_external_reference() {
        // Fixed keys and prologue from the Noise IK reference vector. The
        // expected packets are the 96-byte init payload and 48-byte response
        // payload (without the TS2021 framing headers).
        const EXPECTED_INIT: &str = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254ad5b8febedeb97415be53612205e6bfab385e34cb127dd8854c4f9afb10f9b0e49075a6f14f9d5bc61412f096ae4950589aef8286944be93ca02ab76a5483b51";
        const EXPECTED_RESP: &str = "675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f5ef5508032efff8066fc858410f411e8";

        let client_static = test_key(0..32);
        let client_ephemeral = test_key(32..64);
        let server = NoiseResponder::from_bytes(test_key(64..96).to_bytes());
        let server_ephemeral = test_key(96..128);
        let prologue = b"TEST HANDSHAKE";

        let (initiator, init_bytes) = NoiseInitiator::initialize_with_ephemeral(
            client_static,
            client_ephemeral,
            server.public_key(),
            prologue,
            113,
        );
        assert_eq!(&init_bytes[5..], hex_decode(EXPECTED_INIT).as_slice());

        let init = parse_init_message(&init_bytes).unwrap();
        let output = server
            .respond_with_ephemeral(&init, prologue, server_ephemeral)
            .unwrap();
        assert_eq!(&output.response[3..], hex_decode(EXPECTED_RESP).as_slice());

        let session = initiator.finish(&output.response).unwrap();
        assert_eq!(
            session.initiator_to_responder,
            output.session.initiator_to_responder
        );
        assert_eq!(
            session.responder_to_initiator,
            output.session.responder_to_initiator
        );
    }

    #[test]
    fn rejects_unsupported_version_in_responder() {
        let server = NoiseResponder::random();
        let prologue = b"Tailscale Control Protocol v112";
        let (_, init_bytes) =
            NoiseInitiator::initialize(StaticSecret::random(), server.public_key(), prologue, 112);
        let init = parse_init_message(&init_bytes).unwrap();
        assert!(matches!(
            server.respond(&init, prologue),
            Err(TransportError::UnsupportedCapabilityVersion(112))
        ));
    }

    #[test]
    fn rejects_tampered_init() {
        let server = NoiseResponder::random();
        let prologue = b"Tailscale Control Protocol v113";
        let (_, mut init_bytes) =
            NoiseInitiator::initialize(StaticSecret::random(), server.public_key(), prologue, 113);
        init_bytes[37] ^= 0x01;
        let init = parse_init_message(&init_bytes).unwrap();
        assert!(matches!(
            server.respond(&init, prologue),
            Err(TransportError::HandshakeFailed)
        ));
    }
}
