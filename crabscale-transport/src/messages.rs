//! Fixed-layout TS2021 handshake messages and record framing constants.
//!
//! The byte layouts are normative in the project wiki (Spec-Transport).

use crate::error::TransportError;

/// Minimum capability version accepted by the control server.
pub const MIN_SUPPORTED_CAPVER: u16 = 113;

/// Length of the client-to-server init message.
pub const INIT_MESSAGE_LEN: usize = 101;

/// Length of the server-to-client response message.
pub const RESPONSE_MESSAGE_LEN: usize = 51;

/// Maximum total size of a Noise record frame, including the 3-byte header.
pub const MAX_RECORD_FRAME_SIZE: usize = 4096;

/// Number of bytes in a record frame header.
pub const RECORD_HEADER_LEN: usize = 3;

/// Authentication tag size for ChaCha20-Poly1305.
pub const AEAD_TAG_LEN: usize = 16;

/// Maximum plaintext bytes that fit in one record frame.
pub const MAX_RECORD_PLAINTEXT: usize = MAX_RECORD_FRAME_SIZE - RECORD_HEADER_LEN - AEAD_TAG_LEN;

/// Maximum accepted early payload JSON length.
pub const MAX_EARLY_PAYLOAD_LEN: usize = 1024 * 1024;

/// Message type for a client handshake initiation.
pub const MSG_TYPE_INIT: u8 = 0x01;

/// Message type for a server handshake response.
pub const MSG_TYPE_RESPONSE: u8 = 0x02;

/// Message type for an error body.
pub const MSG_TYPE_ERROR: u8 = 0x03;

/// Message type for an encrypted data record.
pub const MSG_TYPE_RECORD: u8 = 0x04;

/// A parsed TS2021 init message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitMessage {
    /// Client capability version, big-endian u16.
    pub version: u16,
    /// Client ephemeral X25519 public key (cleartext).
    pub client_ephemeral: [u8; 32],
    /// Encrypted client static X25519 public key (32 bytes ciphertext + 16-byte tag).
    pub client_static_ciphertext: [u8; 48],
    /// Authentication tag for the empty handshake payload.
    pub payload_tag: [u8; AEAD_TAG_LEN],
}

/// A parsed TS2021 response message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseMessage {
    /// Server ephemeral X25519 public key (cleartext).
    pub server_ephemeral: [u8; 32],
    /// Authentication tag for the empty handshake payload.
    pub auth_tag: [u8; AEAD_TAG_LEN],
}

/// Parse a 101-byte TS2021 init message.
///
/// The caller is responsible for checking the capability version before
/// proceeding with the Noise handshake; [`InitMessage::version`] is returned
/// so the server can reject unsupported versions early.
pub fn parse_init_message(buf: &[u8]) -> Result<InitMessage, TransportError> {
    if buf.len() != INIT_MESSAGE_LEN {
        return Err(TransportError::InvalidInitMessage);
    }
    if buf[2] != MSG_TYPE_INIT {
        return Err(TransportError::UnexpectedMessageType(buf[2]));
    }
    let payload_len = u16::from_be_bytes([buf[3], buf[4]]);
    if payload_len != 96 {
        return Err(TransportError::InvalidInitMessage);
    }

    let mut client_ephemeral = [0u8; 32];
    client_ephemeral.copy_from_slice(&buf[5..37]);

    let mut client_static_ciphertext = [0u8; 48];
    client_static_ciphertext.copy_from_slice(&buf[37..85]);

    let mut payload_tag = [0u8; AEAD_TAG_LEN];
    payload_tag.copy_from_slice(&buf[85..101]);

    Ok(InitMessage {
        version: u16::from_be_bytes([buf[0], buf[1]]),
        client_ephemeral,
        client_static_ciphertext,
        payload_tag,
    })
}

/// Write a 51-byte TS2021 response message.
pub fn write_response_message(
    server_ephemeral: &[u8; 32],
    auth_tag: &[u8; AEAD_TAG_LEN],
) -> [u8; RESPONSE_MESSAGE_LEN] {
    let mut out = [0u8; RESPONSE_MESSAGE_LEN];
    out[0] = MSG_TYPE_RESPONSE;
    out[1..3].copy_from_slice(&48u16.to_be_bytes());
    out[3..35].copy_from_slice(server_ephemeral);
    out[35..51].copy_from_slice(auth_tag);
    out
}

/// Parse a 51-byte TS2021 response message.
pub fn parse_response_message(buf: &[u8]) -> Result<ResponseMessage, TransportError> {
    if buf.len() != RESPONSE_MESSAGE_LEN {
        return Err(TransportError::InvalidResponseMessage);
    }
    if buf[0] != MSG_TYPE_RESPONSE {
        return Err(TransportError::UnexpectedMessageType(buf[0]));
    }
    let payload_len = u16::from_be_bytes([buf[1], buf[2]]);
    if payload_len != 48 {
        return Err(TransportError::InvalidResponseMessage);
    }

    let mut server_ephemeral = [0u8; 32];
    server_ephemeral.copy_from_slice(&buf[3..35]);

    let mut auth_tag = [0u8; AEAD_TAG_LEN];
    auth_tag.copy_from_slice(&buf[35..51]);

    Ok(ResponseMessage {
        server_ephemeral,
        auth_tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_init_message() {
        let mut buf = [0u8; INIT_MESSAGE_LEN];
        buf[0..2].copy_from_slice(&113u16.to_be_bytes());
        buf[2] = MSG_TYPE_INIT;
        buf[3..5].copy_from_slice(&96u16.to_be_bytes());
        for (i, byte) in buf[5..37].iter_mut().enumerate() {
            *byte = i as u8;
        }
        for (i, byte) in buf[37..85].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(0x80);
        }
        for (i, byte) in buf[85..101].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(0x40);
        }

        let msg = parse_init_message(&buf).unwrap();
        assert_eq!(msg.version, 113);
        assert_eq!(msg.client_ephemeral[0], 0);
        assert_eq!(msg.client_ephemeral[31], 31);
        assert_eq!(msg.client_static_ciphertext[0], 0x80);
        assert_eq!(msg.payload_tag[0], 0x40);
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            parse_init_message(&[0; 100]),
            Err(TransportError::InvalidInitMessage)
        );
    }

    #[test]
    fn rejects_wrong_type() {
        let mut buf = [0u8; INIT_MESSAGE_LEN];
        buf[2] = 0x02;
        assert_eq!(
            parse_init_message(&buf),
            Err(TransportError::UnexpectedMessageType(0x02))
        );
    }

    #[test]
    fn response_round_trip() {
        let ephemeral = [7u8; 32];
        let tag = [9u8; AEAD_TAG_LEN];
        let buf = write_response_message(&ephemeral, &tag);
        assert_eq!(buf.len(), RESPONSE_MESSAGE_LEN);
        let parsed = parse_response_message(&buf).unwrap();
        assert_eq!(parsed.server_ephemeral, ephemeral);
        assert_eq!(parsed.auth_tag, tag);
    }
}
