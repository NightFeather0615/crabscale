//! Errors returned by the TS2021 transport layer.

use std::fmt;

/// Errors produced while parsing, framing, or completing a TS2021 handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The init message did not have the required 101-byte layout.
    InvalidInitMessage,
    /// The response message did not have the required 51-byte layout.
    InvalidResponseMessage,
    /// A record frame had an invalid body length.
    InvalidRecord,
    /// The init message carried an unsupported capability version.
    UnsupportedCapabilityVersion(u16),
    /// A message had an unexpected type byte.
    UnexpectedMessageType(u8),
    /// A length field exceeded the protocol limit.
    Oversized,
    /// A buffer ended before the full message was available.
    Truncated,
    /// The Noise handshake failed to authenticate.
    HandshakeFailed,
    /// The early payload exceeded the protocol limit.
    EarlyPayloadTooLarge,
    /// The early payload was not valid JSON.
    InvalidEarlyPayload,
    /// An HTTP upgrade request was missing required headers.
    InvalidUpgradeRequest,
    /// The WebSocket subprotocol was not supported.
    UnsupportedSubprotocol,
    /// An HTTP/2 operation failed.
    Http2(String),
    /// An inner request body exceeded the protocol limit.
    BodyTooLarge,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInitMessage => write!(f, "invalid TS2021 init message"),
            Self::InvalidResponseMessage => write!(f, "invalid TS2021 response message"),
            Self::InvalidRecord => write!(f, "invalid Noise record frame"),
            Self::UnsupportedCapabilityVersion(v) => {
                write!(f, "unsupported capability version {v}")
            }
            Self::UnexpectedMessageType(t) => write!(f, "unexpected message type 0x{t:02x}"),
            Self::Oversized => write!(f, "message exceeds the protocol size limit"),
            Self::Truncated => write!(f, "message is truncated"),
            Self::HandshakeFailed => write!(f, "Noise handshake failed"),
            Self::EarlyPayloadTooLarge => write!(f, "early payload is too large"),
            Self::InvalidEarlyPayload => write!(f, "early payload is not valid JSON"),
            Self::InvalidUpgradeRequest => write!(f, "invalid TS2021 upgrade request"),
            Self::UnsupportedSubprotocol => write!(f, "unsupported WebSocket subprotocol"),
            Self::Http2(e) => write!(f, "HTTP/2 error: {e}"),
            Self::BodyTooLarge => write!(f, "request body exceeds the 1 MiB limit"),
        }
    }
}

impl std::error::Error for TransportError {}
