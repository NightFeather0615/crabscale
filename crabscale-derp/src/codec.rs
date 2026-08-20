//! Tokio-util codec for raw DERP framing over a byte stream.
//!
//! DERP frames are `[1 byte type][4 byte big-endian length][payload]`. The
//! codec enforces [`MAX_FRAME_BODY_LEN`] before buffering a payload, so an
//! oversized length prefix is rejected without allocating.

use std::io;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::frame::{FRAME_HEADER_LEN, FrameError, FrameHeader, FrameType, MAX_FRAME_BODY_LEN};

/// A DERP frame ready for a transport sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The frame type.
    pub ty: FrameType,
    /// The frame body (may be empty).
    pub payload: Bytes,
}

impl Frame {
    /// Build a frame from an owned body.
    pub fn new(ty: FrameType, payload: Bytes) -> Self {
        Self { ty, payload }
    }
}

/// Errors surfaced by the raw DERP codec.
#[derive(Debug)]
pub struct CodecError {
    /// The underlying frame error.
    pub kind: FrameError,
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for CodecError {}

impl From<FrameError> for CodecError {
    fn from(kind: FrameError) -> Self {
        Self { kind }
    }
}

fn io_err(e: FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, CodecError { kind: e })
}

/// Read one complete DERP frame from an async reader.
///
/// Returns `Ok(None)` on a clean EOF at a frame boundary. The body length is
/// validated before any buffer is sized from the wire, so an oversized header
/// is rejected without allocating the payload.
pub async fn read_frame<R>(reader: &mut R) -> io::Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    let mut filled = 0;
    while filled < FRAME_HEADER_LEN {
        let n = reader.read(&mut header[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "DERP connection closed mid-header",
            ));
        }
        filled += n;
    }
    let (parsed, _) = FrameHeader::decode(&header).map_err(io_err)?;
    let mut payload = vec![0u8; parsed.len];
    reader.read_exact(&mut payload).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "DERP connection closed mid-frame",
        )
    })?;
    Ok(Some(Frame {
        ty: parsed.ty,
        payload: Bytes::from(payload),
    }))
}

/// Write one complete DERP frame to an async writer and flush it.
pub async fn write_frame<W>(writer: &mut W, frame: Frame) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let header = FrameHeader::new(frame.ty, frame.payload.len()).map_err(io_err)?;
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + frame.payload.len());
    buf.extend_from_slice(&header.encode());
    buf.extend_from_slice(&frame.payload);
    writer.write_all(&buf).await?;
    writer.flush().await
}

/// A [`Decoder`]/[`Encoder`] pair for the raw DERP wire format.
#[derive(Debug, Clone, Copy, Default)]
pub struct DerpCodec {
    /// Maximum accepted body length; defaults to [`MAX_FRAME_BODY_LEN`].
    max_body_len: usize,
}

impl DerpCodec {
    /// Create a codec with the spec default limits.
    pub fn new() -> Self {
        Self {
            max_body_len: MAX_FRAME_BODY_LEN,
        }
    }

    /// Create a codec with a custom body ceiling (used by tests).
    pub fn with_max_body_len(max_body_len: usize) -> Self {
        Self { max_body_len }
    }
}

impl Decoder for DerpCodec {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let (header, _) = FrameHeader::decode(src).map_err(io_err)?;
        if header.len > self.max_body_len {
            // Rejected before any payload buffer is sized from the prefix.
            return Err(io_err(FrameError::Oversized));
        }
        let total = FRAME_HEADER_LEN + header.len;
        if src.len() < total {
            // Gently grow the buffer to avoid repeated reallocations while a
            // frame streams in; the length was already validated above.
            src.reserve(total - src.len());
            return Ok(None);
        }
        let mut frame = src.split_to(total);
        let _ = frame.split_to(FRAME_HEADER_LEN);
        Ok(Some(Frame {
            ty: header.ty,
            payload: frame.freeze(),
        }))
    }
}

impl Encoder<Frame> for DerpCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.payload.len() > self.max_body_len {
            return Err(io_err(FrameError::Oversized));
        }
        let header = FrameHeader::new(item.ty, item.payload.len()).map_err(io_err)?;
        dst.reserve(FRAME_HEADER_LEN + item.payload.len());
        dst.put_slice(&header.encode());
        dst.put_slice(&item.payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn raw_codec_round_trip() {
        let frame = Frame::new(FrameType::Health, Bytes::from_static(b"ok"));
        let mut codec = DerpCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let mut decoder = DerpCodec::new();
        let decoded = decoder.decode(&mut buf).unwrap().expect("a full frame");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn raw_codec_buffers_partial_input() {
        let frame = Frame::new(FrameType::Ping, Bytes::from_static(&[1; 8]));
        let mut enc = DerpCodec::new();
        let mut whole = BytesMut::new();
        enc.encode(frame, &mut whole).unwrap();

        // Feed the codec a growing buffer so it can buffer partial frames.
        let mut dec = DerpCodec::new();
        let mut partial = whole.split_to(3);
        assert!(dec.decode(&mut partial).unwrap().is_none());
        partial.extend_from_slice(&whole.split_to(4));
        assert!(dec.decode(&mut partial).unwrap().is_none());
        partial.extend_from_slice(&whole);
        let decoded = dec.decode(&mut partial).unwrap().expect("complete frame");
        assert_eq!(decoded.ty, FrameType::Ping);
        assert_eq!(&decoded.payload[..], &[1; 8]);
    }

    #[test]
    fn raw_codec_rejects_oversized_without_allocation() {
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = FrameType::Health as u8;
        header[1..].copy_from_slice(&((MAX_FRAME_BODY_LEN + 1) as u32).to_be_bytes());
        let mut dec = DerpCodec::new();
        let err = dec
            .decode(&mut BytesMut::from(&header[..]))
            .expect_err("oversized must error");
        assert_eq!(err.to_string(), FrameError::Oversized.to_string());
    }

    #[test]
    fn raw_codec_rejects_oversized_encode() {
        let payload = vec![0u8; MAX_FRAME_BODY_LEN + 1];
        let mut enc = DerpCodec::new();
        let mut buf = BytesMut::new();
        assert!(
            enc.encode(
                Frame::new(FrameType::Health, Bytes::from(payload)),
                &mut buf
            )
            .is_err()
        );
    }
}
