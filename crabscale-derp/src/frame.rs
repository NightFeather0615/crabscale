//! DERP frame header and body wire format (Spec-DERP-STUN §1, §2).
//!
//! Every DERP frame is `[1 byte frame type][4 byte big-endian payload
//! length][payload]`. This module owns the pure byte-level codec: frame
//! types, the connection magic, protocol constants, and encode/decode helpers
//! that enforce the size limits *before* any payload allocation.

use std::fmt;

/// Number of bytes in a DERP frame header (type + length).
pub const FRAME_HEADER_LEN: usize = 5;

/// Maximum packet payload carried in a `SendPacket`/`RecvPacket` (64 KiB).
///
/// This is the limit on the actual relayed packet bytes, independent of the
/// overall frame-body ceiling.
pub const MAX_PACKET_PAYLOAD_LEN: usize = 64 * 1024;

/// Maximum frame body accepted from a client (1 MiB).
///
/// The limit is enforced in the header decoder before any buffer is sized
/// from the length prefix, so a corrupt header cannot force an allocation.
pub const MAX_FRAME_BODY_LEN: usize = 1024 * 1024;

/// Connection magic carried in the first server frame: the 8 UTF-8 bytes of
/// the string `DERP🔑` (`44 45 52 50 F0 9F 94 91`).
pub const MAGIC: [u8; 8] = [0x44, 0x45, 0x52, 0x50, 0xF0, 0x9F, 0x94, 0x91];

/// DERP protocol version on the wire (Spec-DERP-STUN §1).
pub const PROTOCOL_VERSION: u32 = 2;

/// Errors returned while decoding or encoding a DERP frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The buffer ended before a complete header or body was available.
    Truncated,
    /// The declared body length exceeds [`MAX_FRAME_BODY_LEN`].
    ///
    /// This is returned before the payload is allocated.
    Oversized,
    /// The body length of a packet frame exceeds [`MAX_PACKET_PAYLOAD_LEN`].
    PacketTooLarge,
    /// The type byte is not a known DERP frame type.
    InvalidFrameType(u8),
    /// The body does not match the fixed length of its frame type.
    InvalidBodyLength {
        /// The expected fixed body length.
        expected: usize,
        /// The length actually present.
        actual: usize,
    },
    /// A fixed-length body does not carry the expected connection magic.
    InvalidMagic,
    /// A `PeerGone` body carries an unknown reason code.
    InvalidPeerGoneReason(u8),
    /// A NaCl `crypto_box` seal or open operation failed.
    CryptoFailed,
    /// A known UTF-8 body contained invalid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "DERP frame is truncated"),
            Self::Oversized => write!(f, "DERP frame body exceeds the 1 MiB limit"),
            Self::PacketTooLarge => write!(f, "DERP packet payload exceeds the 64 KiB limit"),
            Self::InvalidFrameType(t) => write!(f, "unknown DERP frame type 0x{t:02x}"),
            Self::InvalidBodyLength { expected, actual } => write!(
                f,
                "DERP frame body has length {actual}, expected {expected}"
            ),
            Self::InvalidMagic => write!(f, "DERP frame does not start with the connection magic"),
            Self::InvalidPeerGoneReason(r) => {
                write!(f, "unknown DERP PeerGone reason code {r}")
            }
            Self::CryptoFailed => write!(f, "DERP crypto_box operation failed"),
            Self::InvalidUtf8 => write!(f, "DERP frame body is not valid UTF-8"),
        }
    }
}

impl std::error::Error for FrameError {}

/// A DERP frame type (Spec-DERP-STUN §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// `ServerKey`, server -> client: connection magic + server public key.
    ServerKey = 0x01,
    /// `ClientInfo`, client -> server: client key + nonce + encrypted JSON.
    ClientInfo = 0x02,
    /// `ServerInfo`, server -> client: nonce + encrypted JSON.
    ServerInfo = 0x03,
    /// `SendPacket`, client -> server: destination key + packet bytes.
    SendPacket = 0x04,
    /// `RecvPacket`, server -> client: source key + packet bytes.
    RecvPacket = 0x05,
    /// `KeepAlive`, server -> client: no payload.
    KeepAlive = 0x06,
    /// `NotePreferred`, server -> client: one byte, 0 or 1.
    NotePreferred = 0x07,
    /// `PeerGone`, server -> client: peer key + reason byte.
    PeerGone = 0x08,
    /// `PeerPresent`, mesh/observer: peer key and optional ip/port/flags.
    PeerPresent = 0x09,
    /// `ForwardPacket`, mesh: source + destination + packet.
    ForwardPacket = 0x0A,
    /// `WatchConns`, mesh: no payload.
    WatchConns = 0x10,
    /// `Ping`, server -> client: 8 bytes echoed in `Pong`.
    Ping = 0x12,
    /// `Pong`, client -> server: 8 bytes.
    Pong = 0x13,
    /// `Health`, server -> client: UTF-8 message or empty.
    Health = 0x14,
    /// `Restarting`, server -> client: two u32 big-endian durations in ms.
    Restarting = 0x15,
}

impl FrameType {
    /// Report whether this frame type is only sent by the server.
    pub const fn is_server_to_client(self) -> bool {
        matches!(
            self,
            Self::ServerKey
                | Self::ServerInfo
                | Self::RecvPacket
                | Self::KeepAlive
                | Self::NotePreferred
                | Self::PeerGone
                | Self::PeerPresent
                | Self::Ping
                | Self::Health
                | Self::Restarting
        )
    }
}

impl TryFrom<u8> for FrameType {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::ServerKey),
            0x02 => Ok(Self::ClientInfo),
            0x03 => Ok(Self::ServerInfo),
            0x04 => Ok(Self::SendPacket),
            0x05 => Ok(Self::RecvPacket),
            0x06 => Ok(Self::KeepAlive),
            0x07 => Ok(Self::NotePreferred),
            0x08 => Ok(Self::PeerGone),
            0x09 => Ok(Self::PeerPresent),
            0x0A => Ok(Self::ForwardPacket),
            0x10 => Ok(Self::WatchConns),
            0x12 => Ok(Self::Ping),
            0x13 => Ok(Self::Pong),
            0x14 => Ok(Self::Health),
            0x15 => Ok(Self::Restarting),
            other => Err(FrameError::InvalidFrameType(other)),
        }
    }
}

impl From<FrameType> for u8 {
    fn from(value: FrameType) -> Self {
        value as u8
    }
}

/// A decoded DERP frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// The frame type.
    pub ty: FrameType,
    /// The body length in bytes.
    pub len: usize,
}

impl FrameHeader {
    /// Build a header that bounds `len` to [`MAX_FRAME_BODY_LEN`].
    pub fn new(ty: FrameType, len: usize) -> Result<Self, FrameError> {
        if len > MAX_FRAME_BODY_LEN {
            return Err(FrameError::Oversized);
        }
        Ok(Self { ty, len })
    }

    /// Encode this header into its 5 wire bytes.
    pub fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        out[0] = self.ty as u8;
        out[1..].copy_from_slice(&(self.len as u32).to_be_bytes());
        out
    }

    /// Decode one header from the front of `buf`.
    ///
    /// Returns the header and the number of bytes consumed. The length is
    /// validated against [`MAX_FRAME_BODY_LEN`] before it is used anywhere,
    /// so an oversized prefix never drives an allocation.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), FrameError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(FrameError::Truncated);
        }
        let ty = FrameType::try_from(buf[0])?;
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        let header = Self::new(ty, len)?;
        Ok((header, FRAME_HEADER_LEN))
    }
}

/// Encode a complete DERP frame into a freshly allocated buffer.
pub fn encode_frame(ty: FrameType, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let header = FrameHeader::new(ty, payload.len())?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Decode one DERP frame from the front of `buf`.
///
/// On success returns the frame type, a borrowed payload slice, and the total
/// number of bytes consumed so a stream of frames can be decoded in sequence.
/// The payload is a slice of the input, so no allocation is performed for the
/// payload bytes.
pub fn decode_frame(buf: &[u8]) -> Result<(FrameType, &[u8], usize), FrameError> {
    let (header, header_len) = FrameHeader::decode(buf)?;
    let end = header_len + header.len;
    if buf.len() < end {
        return Err(FrameError::Truncated);
    }
    Ok((header.ty, &buf[header_len..end], end))
}

/// A buffered stream decoder that yields complete DERP frames.
///
/// The decoder never allocates a payload based on an untrusted length prefix:
/// an oversized length is rejected the instant its header arrives.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    /// Create an empty decoder.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append incoming bytes and decode as many complete frames as possible.
    ///
    /// Returns the frames that became complete, leaving partial trailing data
    /// buffered for the next call.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<(FrameType, Vec<u8>)>, FrameError> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            match decode_frame(&self.buf) {
                Ok((ty, payload, consumed)) => {
                    out.push((ty, payload.to_vec()));
                    self.buf.drain(..consumed);
                }
                Err(FrameError::Truncated) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_uses_big_endian_length() {
        let header = FrameHeader::new(FrameType::Health, 0x1234).unwrap();
        assert_eq!(&header.encode()[1..], &[0x00, 0x00, 0x12, 0x34]);
        let (decoded, consumed) = FrameHeader::decode(&header.encode()).unwrap();
        assert_eq!(decoded.ty, FrameType::Health);
        assert_eq!(decoded.len, 0x1234);
        assert_eq!(consumed, FRAME_HEADER_LEN);
    }

    #[test]
    fn frame_round_trip() {
        let frame = encode_frame(FrameType::ServerKey, &MAGIC).unwrap();
        assert_eq!(frame.len(), FRAME_HEADER_LEN + MAGIC.len());
        assert_eq!(frame[0], FrameType::ServerKey as u8);
        let (ty, payload, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(ty, FrameType::ServerKey);
        assert_eq!(payload, MAGIC);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn decodes_first_of_many_frames() {
        let a = encode_frame(FrameType::KeepAlive, &[]).unwrap();
        let b = encode_frame(FrameType::Ping, &[0xaa; 8]).unwrap();
        let mut stream = a.clone();
        stream.extend_from_slice(&b);
        let (ty, payload, consumed) = decode_frame(&stream).unwrap();
        assert_eq!(ty, FrameType::KeepAlive);
        assert!(payload.is_empty());
        let (ty, payload, _) = decode_frame(&stream[consumed..]).unwrap();
        assert_eq!(ty, FrameType::Ping);
        assert_eq!(payload, &[0xaa; 8]);
    }

    #[test]
    fn rejects_truncated_header() {
        assert_eq!(decode_frame(&[1, 2, 3, 4]), Err(FrameError::Truncated));
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut frame = encode_frame(FrameType::Health, b"hello").unwrap();
        frame.pop();
        assert_eq!(decode_frame(&frame), Err(FrameError::Truncated));
    }

    #[test]
    fn rejects_oversized_payload_without_allocating() {
        // A header claiming one byte more than the 1 MiB limit must be
        // rejected by the header decoder before any payload buffer exists.
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = FrameType::Health as u8;
        header[1..].copy_from_slice(&((MAX_FRAME_BODY_LEN + 1) as u32).to_be_bytes());
        assert_eq!(decode_frame(&header), Err(FrameError::Oversized));
    }

    #[test]
    fn rejects_on_encode() {
        let payload = vec![0u8; MAX_FRAME_BODY_LEN + 1];
        assert_eq!(
            encode_frame(FrameType::Health, &payload),
            Err(FrameError::Oversized)
        );
    }

    #[test]
    fn rejects_unknown_frame_type() {
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = 0x11;
        assert_eq!(
            decode_frame(&header),
            Err(FrameError::InvalidFrameType(0x11))
        );
    }

    #[test]
    fn stream_decoder_buffers_partial_frames() {
        let mut decoder = FrameDecoder::new();
        let frame = encode_frame(FrameType::SendPacket, &[1, 2, 3]).unwrap();
        let first = decoder.feed(&frame[..6]).unwrap();
        assert!(first.is_empty());
        let rest = decoder.feed(&frame[6..]).unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].0, FrameType::SendPacket);
        assert_eq!(rest[0].1, [1, 2, 3]);
    }

    #[test]
    fn stream_decoder_rejects_oversized_prefix() {
        let mut decoder = FrameDecoder::new();
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = FrameType::Health as u8;
        header[1..].copy_from_slice(&((MAX_FRAME_BODY_LEN + 1) as u32).to_be_bytes());
        assert_eq!(decoder.feed(&header), Err(FrameError::Oversized));
    }
}
