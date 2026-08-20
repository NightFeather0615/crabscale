//! RFC 6455 WebSocket framing for the DERP transport (Spec-DERP-STUN §5).
//!
//! DERP runs inside binary WebSocket messages: the server writes unmasked
//! binary messages that carry a continuous stream of DERP frames, and the
//! client's masked binary messages are reassembled into the same stream. This
//! module provides a Tokio-util codec for the WebSocket framing and a
//! `WebSocketByteStream` adapter that presents a WebSocket connection as a
//! plain `AsyncRead + AsyncWrite` byte stream so the relay core can be reused
//! unchanged.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_core::Stream;
use futures_sink::Sink;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Decoder, Encoder, Framed};

use crate::frame::{FrameError, MAX_FRAME_BODY_LEN};

/// Maximum WebSocket message size accepted (mirrors the DERP frame ceiling).
const MAX_WEBSOCKET_MESSAGE_LEN: usize = MAX_FRAME_BODY_LEN;

/// WebSocket opcodes (RFC 6455 §5.2).
mod opcode {
    pub const CONTINUATION: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xA;
}

/// A decoded WebSocket frame as surfaced by [`WebSocketCodec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsFrame {
    /// A complete binary message (fragmented messages are reassembled).
    Binary(Bytes),
    /// A complete text message.
    Text(Bytes),
    /// A ping control frame.
    Ping(Bytes),
    /// A pong control frame.
    Pong(Bytes),
    /// A close control frame.
    Close,
}

/// The role of a WebSocket endpoint, which fixes the masking direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketRole {
    /// A server: incoming frames must be masked; outgoing frames are unmasked.
    Server,
    /// A client: incoming frames must be unmasked; outgoing frames are masked.
    Client,
}

/// Errors returned by the WebSocket codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsError {
    kind: WsErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WsErrorKind {
    /// A client frame was not masked (RFC 6455 requires masking).
    WrongMasking(&'static str),
    /// A continuation frame arrived without an open message.
    UnexpectedContinuation,
    /// A new data frame arrived while a fragmented message was open.
    MessageAlreadyOpen,
    /// Control frames longer than 125 bytes are invalid.
    ControlFrameTooLong,
    /// The declared length or accumulated message exceeds the limit.
    Oversized,
    /// The RSV bits were set without a negotiated extension.
    RsvNotZero,
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            WsErrorKind::WrongMasking(what) => write!(f, "{what}"),
            WsErrorKind::UnexpectedContinuation => {
                write!(f, "unexpected WebSocket continuation frame")
            }
            WsErrorKind::MessageAlreadyOpen => {
                write!(f, "new data frame while a fragmented message is open")
            }
            WsErrorKind::ControlFrameTooLong => {
                write!(f, "WebSocket control frame exceeds 125 bytes")
            }
            WsErrorKind::Oversized => write!(f, "WebSocket message exceeds the size limit"),
            WsErrorKind::RsvNotZero => {
                write!(f, "WebSocket RSV bits set without a negotiated extension")
            }
        }
    }
}

impl std::error::Error for WsError {}

impl From<FrameError> for WsError {
    fn from(_: FrameError) -> Self {
        Self {
            kind: WsErrorKind::Oversized,
        }
    }
}

fn ws_err(kind: WsErrorKind) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, WsError { kind })
}

/// A [`Decoder`]/[`Encoder`] pair for RFC 6455 WebSocket frames.
///
/// The codec is role-aware: a server endpoint requires masked client frames
/// and emits unmasked frames, while a client endpoint requires unmasked
/// server frames and emits masked frames. Fragmented data messages are
/// reassembled before being surfaced.
#[derive(Debug)]
pub struct WebSocketCodec {
    /// Which direction this endpoint sits on.
    role: WebSocketRole,
    /// Accumulated payload of the message currently being reassembled.
    open_message: Option<BytesMut>,
}

impl Default for WebSocketCodec {
    fn default() -> Self {
        Self::server()
    }
}

impl WebSocketCodec {
    /// A codec for the server side of a WebSocket connection.
    pub fn server() -> Self {
        Self {
            role: WebSocketRole::Server,
            open_message: None,
        }
    }

    /// A codec for the client side of a WebSocket connection.
    pub fn client() -> Self {
        Self {
            role: WebSocketRole::Client,
            open_message: None,
        }
    }
}

impl Decoder for WebSocketCodec {
    type Item = WsFrame;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            return Ok(None);
        }
        let first = src[0];
        let second = src[1];
        let fin = first & 0x80 != 0;
        let opcode = first & 0x0F;
        let masked = second & 0x80 != 0;
        let payload_len = (second & 0x7F) as usize;

        // RSV bits must be clear unless a per-message extension is negotiated.
        if first & 0x70 != 0 {
            return Err(ws_err(WsErrorKind::RsvNotZero));
        }

        // Enforce the RFC 6455 masking direction for this endpoint's role.
        match (self.role, masked) {
            (WebSocketRole::Server, false) => {
                return Err(ws_err(WsErrorKind::WrongMasking(
                    "client WebSocket frame was not masked",
                )));
            }
            (WebSocketRole::Client, true) => {
                return Err(ws_err(WsErrorKind::WrongMasking(
                    "server WebSocket frame was masked",
                )));
            }
            _ => {}
        }

        // Parse the extended length field. The length is bounded against the
        // message ceiling before any arithmetic or buffering, so a crafted
        // 64-bit length cannot overflow or drive a huge allocation.
        let (length, header_len) = match payload_len {
            0..=125 => (payload_len as u64, 2),
            126 => {
                if src.len() < 4 {
                    return Ok(None);
                }
                (u16::from_be_bytes([src[2], src[3]]) as u64, 4)
            }
            127 => {
                if src.len() < 10 {
                    return Ok(None);
                }
                (
                    u64::from_be_bytes([
                        src[2], src[3], src[4], src[5], src[6], src[7], src[8], src[9],
                    ]),
                    10,
                )
            }
            _ => unreachable!(),
        };
        if length > MAX_WEBSOCKET_MESSAGE_LEN as u64 {
            return Err(ws_err(WsErrorKind::Oversized));
        }
        let length = length as usize;
        let mask_offset = header_len;
        let total = header_len + if masked { 4 } else { 0 } + length;
        if src.len() < total {
            return Ok(None);
        }

        // Control frames cannot be fragmented and cap at 125 bytes.
        let is_control = opcode & 0x08 != 0;
        if is_control {
            if !fin {
                return Err(ws_err(WsErrorKind::MessageAlreadyOpen));
            }
            if length > 125 {
                return Err(ws_err(WsErrorKind::ControlFrameTooLong));
            }
        }

        let mut frame = src.split_to(total);
        let payload_offset = mask_offset + if masked { 4 } else { 0 };
        let mut payload = frame.split_off(payload_offset);
        if masked {
            let mask = [
                frame[mask_offset],
                frame[mask_offset + 1],
                frame[mask_offset + 2],
                frame[mask_offset + 3],
            ];
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i & 3];
            }
        }

        match opcode {
            opcode::PING => Ok(Some(WsFrame::Ping(payload.freeze()))),
            opcode::PONG => Ok(Some(WsFrame::Pong(payload.freeze()))),
            opcode::CLOSE => Ok(Some(WsFrame::Close)),
            opcode::CONTINUATION => {
                let Some(open) = self.open_message.as_mut() else {
                    return Err(ws_err(WsErrorKind::UnexpectedContinuation));
                };
                if open.len() + payload.len() > MAX_WEBSOCKET_MESSAGE_LEN {
                    return Err(ws_err(WsErrorKind::Oversized));
                }
                open.extend_from_slice(&payload);
                if fin {
                    let bytes = self
                        .open_message
                        .take()
                        .expect("open message exists")
                        .freeze();
                    Ok(Some(WsFrame::Binary(bytes)))
                } else {
                    Ok(None)
                }
            }
            opcode::TEXT => {
                if self.open_message.is_some() {
                    return Err(ws_err(WsErrorKind::MessageAlreadyOpen));
                }
                if fin {
                    Ok(Some(WsFrame::Text(payload.freeze())))
                } else {
                    self.open_message = Some(payload);
                    Ok(None)
                }
            }
            opcode::BINARY => {
                if self.open_message.is_some() {
                    return Err(ws_err(WsErrorKind::MessageAlreadyOpen));
                }
                if fin {
                    Ok(Some(WsFrame::Binary(payload.freeze())))
                } else {
                    self.open_message = Some(payload);
                    Ok(None)
                }
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown WebSocket opcode 0x{opcode:x}"),
            )),
        }
    }
}

impl Encoder<WsFrame> for WebSocketCodec {
    type Error = io::Error;

    fn encode(&mut self, item: WsFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let (opcode, payload): (u8, Bytes) = match item {
            WsFrame::Binary(b) => (opcode::BINARY, b),
            WsFrame::Text(t) => (opcode::TEXT, t),
            WsFrame::Ping(p) => (opcode::PING, p),
            WsFrame::Pong(p) => (opcode::PONG, p),
            WsFrame::Close => (opcode::CLOSE, Bytes::new()),
        };
        if payload.len() > MAX_WEBSOCKET_MESSAGE_LEN {
            return Err(ws_err(WsErrorKind::Oversized));
        }
        let mask = match self.role {
            WebSocketRole::Server => None,
            // Client frames must be masked; use an all-zero key so the byte
            // stream tests stay deterministic (RFC 6455 allows any key).
            WebSocketRole::Client => Some([0u8; 4]),
        };
        dst.put_u8(0x80 | opcode); // FIN + opcode.
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            0..=125 => dst.put_u8(mask_bit | payload.len() as u8),
            126..=0xFFFF => {
                dst.put_u8(mask_bit | 126);
                dst.put_u16(payload.len() as u16);
            }
            _ => {
                dst.put_u8(mask_bit | 127);
                dst.put_u64(payload.len() as u64);
            }
        }
        if let Some(key) = mask {
            dst.extend_from_slice(&key);
            let payload = payload.to_vec();
            for (i, byte) in payload.iter().enumerate() {
                dst.put_u8(byte ^ key[i & 3]);
            }
        } else {
            dst.extend_from_slice(&payload);
        }
        Ok(())
    }
}

/// Present a WebSocket connection as a byte stream.
///
/// Reads yield the payloads of incoming binary (or text) messages as
/// contiguous bytes, so DERP framing over WebSocket is byte-identical to the
/// raw transport from the relay's point of view. Client pings are answered
/// best-effort on the next write.
pub struct WebSocketByteStream<S> {
    inner: Framed<S, WebSocketCodec>,
    read_buf: BytesMut,
    pending_pongs: VecDeque<Vec<u8>>,
}

impl<S> WebSocketByteStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    /// Wrap a stream as the server endpoint after the WebSocket handshake.
    ///
    /// Incoming frames are expected to be masked (RFC 6455 client -> server);
    /// outgoing frames are written unmasked.
    pub fn new(stream: S) -> Self {
        Self::with_role(stream, WebSocketRole::Server)
    }

    /// Wrap a stream as a client endpoint.
    ///
    /// Incoming frames are expected to be unmasked (RFC 6455 server -> client);
    /// outgoing frames are written masked.
    pub fn new_client(stream: S) -> Self {
        Self::with_role(stream, WebSocketRole::Client)
    }

    /// Wrap a stream with an explicit role.
    pub fn with_role(stream: S, role: WebSocketRole) -> Self {
        Self {
            inner: Framed::new(
                stream,
                WebSocketCodec {
                    role,
                    open_message: None,
                },
            ),
            read_buf: BytesMut::new(),
            pending_pongs: VecDeque::new(),
        }
    }
}

impl<S> AsyncRead for WebSocketByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // Drain any buffered message bytes first. A zero-length message
            // must not be misread as EOF, so consume it and keep waiting when
            // the caller requested no bytes.
            if !self.read_buf.is_empty() {
                let n = std::cmp::min(self.read_buf.len(), buf.remaining());
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(WsFrame::Binary(data))))
                | Poll::Ready(Some(Ok(WsFrame::Text(data)))) => {
                    self.read_buf = BytesMut::from(data.as_ref());
                    // Loop back to hand the bytes out.
                }
                Poll::Ready(Some(Ok(WsFrame::Ping(payload)))) => {
                    self.pending_pongs.push_back(payload.to_vec());
                }
                Poll::Ready(Some(Ok(WsFrame::Pong(_)))) => {
                    // Acknowledgment only; never signal EOF for it.
                }
                Poll::Ready(Some(Ok(WsFrame::Close))) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WebSocketByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        while let Some(pong) = self.pending_pongs.pop_front() {
            ready!(Pin::new(&mut self.inner).poll_ready(cx))?;
            Pin::new(&mut self.inner).start_send(WsFrame::Pong(pong.into()))?;
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        }
        ready!(Pin::new(&mut self.inner).poll_ready(cx))?;
        Pin::new(&mut self.inner).start_send(WsFrame::Binary(buf.to_vec().into()))?;
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[test]
    fn decodes_masked_binary_message() {
        // A single binary frame, masked with key 0x01020304, containing "hi".
        let mut raw = [0u8; 8];
        raw[0] = 0x82; // FIN + binary
        raw[1] = 0x82; // masked + len 2
        raw[2..6].copy_from_slice(&[1, 2, 3, 4]);
        raw[6] = b'h' ^ 1;
        raw[7] = b'i' ^ 2;
        let mut codec = WebSocketCodec::default();
        let decoded = codec
            .decode(&mut BytesMut::from(&raw[..]))
            .unwrap()
            .expect("one frame");
        assert_eq!(decoded, WsFrame::Binary(Bytes::from_static(b"hi")));
    }

    #[test]
    fn reassembles_fragmented_binary_message() {
        let mut codec = WebSocketCodec::default();
        let mut chunk = BytesMut::new();
        // First fragment: FIN=0, binary, masked, length 2.
        chunk.extend_from_slice(&[0x02, 0x82, 0, 0, 0, 0, b'h', b'i']);
        assert!(codec.decode(&mut chunk).unwrap().is_none());
        // Continuation: FIN=1, continuation, masked, length 2.
        chunk.extend_from_slice(&[0x80, 0x82, 0, 0, 0, 0, b'!', b'?']);
        let frame = codec.decode(&mut chunk).unwrap().expect("complete message");
        assert_eq!(frame, WsFrame::Binary(Bytes::from_static(b"hi!?")));
    }

    #[test]
    fn rejects_rsv_bits() {
        let mut codec = WebSocketCodec::server();
        // FIN | RSV1 | binary, masked, length 0.
        let mut raw = BytesMut::from(&[0xC2u8, 0x80, 0, 0, 0, 0][..]);
        let err = codec.decode(&mut raw).unwrap_err();
        assert!(err.kind() == io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_oversized_127_length() {
        let mut codec = WebSocketCodec::server();
        let mut raw = vec![0x82u8, 0xFF]; // FIN | binary, masked, extended 64-bit length
        raw.extend_from_slice(&((MAX_WEBSOCKET_MESSAGE_LEN as u64) + 1).to_be_bytes());
        raw.extend_from_slice(&[0, 0, 0, 0]); // mask key
        let err = codec.decode(&mut BytesMut::from(&raw[..])).unwrap_err();
        assert!(err.kind() == io::ErrorKind::InvalidData);
    }

    #[test]
    fn server_rejects_unmasked_client_frame() {
        let mut codec = WebSocketCodec::server();
        let mut raw = BytesMut::from(&[0x82u8, 0x02, b'h', b'i'][..]);
        let err = codec.decode(&mut raw).unwrap_err();
        assert!(err.kind() == io::ErrorKind::InvalidData);
    }

    #[test]
    fn client_rejects_masked_server_frame() {
        let mut codec = WebSocketCodec::client();
        let mut raw = [0u8; 8];
        raw[0] = 0x82;
        raw[1] = 0x82; // masked
        raw[2..6].copy_from_slice(&[0, 0, 0, 0]);
        let err = codec.decode(&mut BytesMut::from(&raw[..])).unwrap_err();
        assert!(err.kind() == io::ErrorKind::InvalidData);
    }

    #[test]
    fn client_decodes_unmasked_server_frame() {
        let mut codec = WebSocketCodec::client();
        let mut raw = BytesMut::from(&[0x82u8, 0x02, b'h', b'i'][..]);
        let decoded = codec.decode(&mut raw).unwrap().expect("one frame");
        assert_eq!(decoded, WsFrame::Binary(Bytes::from_static(b"hi")));
    }

    #[test]
    fn encodes_unmasked_server_frame() {
        let mut codec = WebSocketCodec::default();
        let mut out = BytesMut::new();
        codec
            .encode(WsFrame::Binary(Bytes::from_static(b"hi")), &mut out)
            .unwrap();
        assert_eq!(&out[..], &[0x82, 0x02, b'h', b'i']);
    }

    #[test]
    fn encodes_masked_client_frame() {
        let mut codec = WebSocketCodec::client();
        let mut out = BytesMut::new();
        codec
            .encode(WsFrame::Binary(Bytes::from_static(b"hi")), &mut out)
            .unwrap();
        // Mask bit set, 4-byte zero mask, then unmasked content.
        assert_eq!(out.len(), 8);
        assert_eq!(out[0], 0x82);
        assert_eq!(out[1], 0x82);
        assert_eq!(&out[2..6], &[0, 0, 0, 0]);
        assert_eq!(&out[6..], b"hi");
    }

    #[tokio::test]
    async fn byte_stream_transfers_bytes() {
        let (client_side, server_side) = duplex(1024);
        let mut server_ws = WebSocketByteStream::new(server_side);
        let mut client_ws = WebSocketByteStream::new_client(client_side);

        let server_task = async move {
            server_ws.write_all(b"hello derp").await.unwrap();
            let mut buf = [0u8; 16];
            let n = server_ws.read(&mut buf).await.unwrap();
            buf[..n].to_vec()
        };
        let client_task = async move {
            let mut buf = [0u8; 16];
            let n = client_ws.read(&mut buf).await.unwrap();
            let got = buf[..n].to_vec();
            client_ws.write_all(b"pong").await.unwrap();
            got
        };
        let (server_got, client_got) = tokio::join!(server_task, client_task);
        assert_eq!(String::from_utf8(client_got).unwrap(), "hello derp");
        assert_eq!(String::from_utf8(server_got).unwrap(), "pong");
    }

    #[tokio::test]
    async fn empty_binary_message_does_not_signal_eof() {
        let (mut client_raw, server_side) = duplex(1024);
        let mut server_ws = WebSocketByteStream::new(server_side);

        let server_task = async move {
            let mut buf = [0u8; 4];
            let n = server_ws.read(&mut buf).await.unwrap();
            buf[..n].to_vec()
        };
        let client_task = async move {
            // A masked empty binary message followed by a masked "b" message.
            client_raw
                .write_all(&[0x82, 0x80, 0, 0, 0, 0])
                .await
                .unwrap();
            client_raw
                .write_all(&[0x82, 0x81, 0, 0, 0, 0, b'b'])
                .await
                .unwrap();
        };
        let (got, ()) = tokio::join!(server_task, client_task);
        assert_eq!(got, b"b");
    }
}
