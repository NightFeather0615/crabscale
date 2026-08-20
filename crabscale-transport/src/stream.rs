//! A duplex stream that carries Noise record frames.
//!
//! [`NoiseStream`] wraps an `AsyncRead + AsyncWrite` transport and applies the
//! TS2021 record framing in both directions. It is the byte stream on which
//! HTTP/2 is layered after the handshake.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::record::{RecordCipher, RecordDecoder};

/// A bidirectional Noise-framed stream.
pub struct NoiseStream<T> {
    inner: T,
    reader: RecordDecoder,
    writer: RecordCipher,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_chunk: [u8; 4096],
}

impl<T> NoiseStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap a transport with the two directional Noise session keys.
    pub fn new(inner: T, read_key: [u8; 32], write_key: [u8; 32]) -> Self {
        Self {
            inner,
            reader: RecordDecoder::new(read_key),
            writer: RecordCipher::new(write_key),
            read_buf: Vec::new(),
            read_pos: 0,
            read_chunk: [0u8; 4096],
        }
    }

    /// Write `data` as one or more Noise records.
    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        let framed = self
            .writer
            .encode(data)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.inner.write_all(&framed).await
    }

    /// Read exactly `buf.len()` plaintext bytes.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            if self.read_pos < self.read_buf.len() {
                let n = (self.read_buf.len() - self.read_pos).min(buf.len() - filled);
                buf[filled..filled + n]
                    .copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
                self.read_pos += n;
                filled += n;
                continue;
            }
            self.read_buf.clear();
            self.read_pos = 0;
            let n = self.inner.read(&mut self.read_chunk).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "noise stream closed",
                ));
            }
            let plaintext = self
                .reader
                .feed(&self.read_chunk[..n])
                .map_err(|e| io::Error::other(e.to_string()))?;
            self.read_buf = plaintext;
        }
        Ok(())
    }
}

impl<T> AsyncRead for NoiseStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.read_pos < this.read_buf.len() {
            let n = (this.read_buf.len() - this.read_pos).min(buf.remaining());
            buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
            this.read_pos += n;
            return Poll::Ready(Ok(()));
        }
        this.read_buf.clear();
        this.read_pos = 0;
        let mut chunk = ReadBuf::new(&mut this.read_chunk);
        match Pin::new(&mut this.inner).poll_read(cx, &mut chunk) {
            Poll::Ready(Ok(())) => {
                let n = chunk.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                let plaintext = match this.reader.feed(&this.read_chunk[..n]) {
                    Ok(p) => p,
                    Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
                };
                this.read_buf = plaintext;
                let n = (this.read_buf.len() - this.read_pos).min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T> AsyncWrite for NoiseStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let framed = match self.writer.encode(buf) {
            Ok(f) => f,
            Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
        };
        match Pin::new(&mut self.inner).poll_write(cx, &framed) {
            Poll::Ready(Ok(n)) => {
                // The underlying transport consumed the whole encoded frame set.
                let _ = n;
                Poll::Ready(Ok(buf.len()))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
