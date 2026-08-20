//! Length-prefixed framing for MapResponse bodies.
//!
//! A frame is `[u32 little-endian payload length][payload]`. The payload is
//! JSON, or a single zstd frame containing JSON when the corresponding
//! MapRequest has `Compress: "zstd"`.

use std::fmt;

/// Number of bytes in a frame header.
pub const MAP_RESPONSE_FRAME_HEADER_LEN: usize = 4;

/// Maximum accepted MapResponse payload length.
///
/// The limit is enforced before any allocation or JSON parsing so a corrupt
/// length prefix cannot make the server allocate unbounded memory.
pub const MAX_MAP_RESPONSE_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// Errors returned when decoding a MapResponse frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The buffer ended before the full header or payload was available.
    Truncated,
    /// The declared payload length exceeds [`MAX_MAP_RESPONSE_PAYLOAD_LEN`].
    Oversized,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "MapResponse frame is truncated"),
            Self::Oversized => write!(f, "MapResponse frame payload is too large"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Encode `payload` as a single MapResponse frame.
///
/// Fails with [`FrameError::Oversized`] if the payload exceeds
/// [`MAX_MAP_RESPONSE_PAYLOAD_LEN`].
pub fn encode_map_response_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_MAP_RESPONSE_PAYLOAD_LEN {
        return Err(FrameError::Oversized);
    }
    let mut frame = Vec::with_capacity(MAP_RESPONSE_FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Decode one MapResponse frame from the front of `buf`.
///
/// On success returns the payload slice and the number of bytes consumed
/// (header plus payload). Trailing bytes after the frame are left untouched
/// so callers can decode a stream of frames.
pub fn decode_map_response_frame(buf: &[u8]) -> Result<(&[u8], usize), FrameError> {
    if buf.len() < MAP_RESPONSE_FRAME_HEADER_LEN {
        return Err(FrameError::Truncated);
    }
    let mut header = [0u8; MAP_RESPONSE_FRAME_HEADER_LEN];
    header.copy_from_slice(&buf[..MAP_RESPONSE_FRAME_HEADER_LEN]);
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_MAP_RESPONSE_PAYLOAD_LEN {
        return Err(FrameError::Oversized);
    }
    let end = MAP_RESPONSE_FRAME_HEADER_LEN + len;
    if buf.len() < end {
        return Err(FrameError::Truncated);
    }
    Ok((&buf[MAP_RESPONSE_FRAME_HEADER_LEN..end], end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_little_endian_length() {
        let frame = encode_map_response_frame(b"{}").unwrap();
        assert_eq!(&frame[..4], &2u32.to_le_bytes());
        assert_eq!(&frame[4..], b"{}");
    }

    #[test]
    fn decodes_single_frame() {
        let frame = encode_map_response_frame(b"{\"KeepAlive\":true}").unwrap();
        let (payload, consumed) = decode_map_response_frame(&frame).unwrap();
        assert_eq!(payload, b"{\"KeepAlive\":true}");
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn decodes_first_of_many_frames() {
        let mut stream = encode_map_response_frame(b"first").unwrap();
        stream.extend_from_slice(&encode_map_response_frame(b"second").unwrap());
        let (payload, consumed) = decode_map_response_frame(&stream).unwrap();
        assert_eq!(payload, b"first");
        let (payload, _) = decode_map_response_frame(&stream[consumed..]).unwrap();
        assert_eq!(payload, b"second");
    }

    #[test]
    fn rejects_truncated_header() {
        assert_eq!(
            decode_map_response_frame(&[1, 2]),
            Err(FrameError::Truncated)
        );
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut frame = encode_map_response_frame(b"hello").unwrap();
        frame.pop();
        assert_eq!(
            decode_map_response_frame(&frame),
            Err(FrameError::Truncated)
        );
    }

    #[test]
    fn rejects_oversized_payload() {
        let len = (MAX_MAP_RESPONSE_PAYLOAD_LEN + 1) as u32;
        let mut header = len.to_le_bytes().to_vec();
        header.extend_from_slice(&[0; 8]);
        assert_eq!(
            decode_map_response_frame(&header),
            Err(FrameError::Oversized)
        );
    }

    #[test]
    fn rejects_oversized_encode() {
        let payload = vec![0u8; MAX_MAP_RESPONSE_PAYLOAD_LEN + 1];
        assert_eq!(
            encode_map_response_frame(&payload),
            Err(FrameError::Oversized)
        );
    }
}
