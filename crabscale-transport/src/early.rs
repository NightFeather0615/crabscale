//! Early payload sent after the Noise handshake and before HTTP/2.
//!
//! The wire format is `0xFF 0xFF 0xFF 'T' 'S' | u32 BE JSON length | JSON`.

use crabscale_proto::{ChallengeKey, EarlyNoise};

use crate::error::TransportError;
use crate::messages::MAX_EARLY_PAYLOAD_LEN;

/// Magic prefix that identifies an early payload.
pub const EARLY_PAYLOAD_MAGIC: [u8; 5] = [0xFF, 0xFF, 0xFF, b'T', b'S'];

/// Encode an early payload for a fresh per-connection challenge key.
pub fn encode_early_payload(challenge: ChallengeKey) -> Result<Vec<u8>, TransportError> {
    let body = EarlyNoise {
        node_key_challenge: challenge,
    };
    let json = serde_json::to_vec(&body).map_err(|_| TransportError::InvalidEarlyPayload)?;
    if json.len() > MAX_EARLY_PAYLOAD_LEN {
        return Err(TransportError::EarlyPayloadTooLarge);
    }
    let mut out = Vec::with_capacity(EARLY_PAYLOAD_MAGIC.len() + 4 + json.len());
    out.extend_from_slice(&EARLY_PAYLOAD_MAGIC);
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Decode an early payload, returning the challenge key.
pub fn decode_early_payload(buf: &[u8]) -> Result<ChallengeKey, TransportError> {
    if buf.len() < EARLY_PAYLOAD_MAGIC.len() + 4 {
        return Err(TransportError::Truncated);
    }
    if buf[..EARLY_PAYLOAD_MAGIC.len()] != EARLY_PAYLOAD_MAGIC {
        return Err(TransportError::InvalidEarlyPayload);
    }
    let len = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) as usize;
    if len > MAX_EARLY_PAYLOAD_LEN {
        return Err(TransportError::EarlyPayloadTooLarge);
    }
    let body = buf
        .get(EARLY_PAYLOAD_MAGIC.len() + 4..EARLY_PAYLOAD_MAGIC.len() + 4 + len)
        .ok_or(TransportError::Truncated)?;
    let parsed: EarlyNoise =
        serde_json::from_slice(body).map_err(|_| TransportError::InvalidEarlyPayload)?;
    Ok(parsed.node_key_challenge)
}

/// Build a fresh random challenge key for one connection.
pub fn random_challenge() -> ChallengeKey {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    ChallengeKey::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn early_payload_round_trip() {
        let challenge = random_challenge();
        let encoded = encode_early_payload(challenge).unwrap();
        assert_eq!(&encoded[..5], &EARLY_PAYLOAD_MAGIC);
        let decoded = decode_early_payload(&encoded).unwrap();
        assert_eq!(decoded, challenge);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = encode_early_payload(random_challenge()).unwrap();
        buf[0] ^= 0x01;
        assert_eq!(
            decode_early_payload(&buf),
            Err(TransportError::InvalidEarlyPayload)
        );
    }

    #[test]
    fn rejects_oversized_length() {
        let mut buf = EARLY_PAYLOAD_MAGIC.to_vec();
        buf.extend_from_slice(&(MAX_EARLY_PAYLOAD_LEN as u32 + 1).to_be_bytes());
        buf.extend_from_slice(b"{}");
        assert_eq!(
            decode_early_payload(&buf),
            Err(TransportError::EarlyPayloadTooLarge)
        );
    }

    #[test]
    fn json_shape_matches_spec() {
        let challenge = ChallengeKey::from_bytes([0x11; 32]);
        let encoded = encode_early_payload(challenge).unwrap();
        let body = &encoded[9..];
        let value: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(value["nodeKeyChallenge"], json!(challenge.to_string()));
    }
}
