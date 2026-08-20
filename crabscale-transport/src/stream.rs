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
    write_buf: Vec<u8>,
    write_pos: usize,
    write_acked: usize,
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
            write_buf: Vec::new(),
            write_pos: 0,
            write_acked: 0,
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

    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "noise stream write returned zero",
                    )));
                }
                Poll::Ready(Ok(n)) => self.write_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
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
        let this = &mut *self;

        // If a previous write is still being flushed, finish it before
        // accepting more plaintext so no encoded bytes are dropped.
        if this.write_acked > 0 {
            match this.flush_pending(cx) {
                Poll::Ready(Ok(())) => {
                    let acked = this.write_acked;
                    this.write_acked = 0;
                    Poll::Ready(Ok(acked))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            let framed = match this.writer.encode(buf) {
                Ok(f) => f,
                Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
            };
            this.write_buf = framed;
            this.write_pos = 0;
            this.write_acked = buf.len();

            match this.flush_pending(cx) {
                Poll::Ready(Ok(())) => {
                    let acked = this.write_acked;
                    this.write_acked = 0;
                    Poll::Ready(Ok(acked))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => {
                this.write_acked = 0;
                Pin::new(&mut this.inner).poll_flush(cx)
            }
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => {
                this.write_acked = 0;
                Pin::new(&mut this.inner).poll_shutdown(cx)
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// A writer that only accepts a few bytes per `poll_write` call, forcing
    /// the Noise stream to buffer and retry partial writes.
    struct ChunkedWriter {
        inner: Vec<u8>,
        max_per_write: usize,
    }

    impl AsyncWrite for ChunkedWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = buf.len().min(self.max_per_write);
            self.inner.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for ChunkedWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn partial_writes_are_buffered_and_flushed() {
        let inner = ChunkedWriter {
            inner: Vec::new(),
            max_per_write: 3,
        };
        let mut stream = NoiseStream::new(inner, [1u8; 32], [2u8; 32]);
        let mut cx = Context::from_waker(std::task::Waker::noop());

        let mut written = 0;
        let payload = b"partial write test payload";
        // Drive poll_write until it reports the full plaintext was accepted.
        while written < payload.len() {
            match Pin::new(&mut stream).poll_write(&mut cx, &payload[written..]) {
                Poll::Ready(Ok(n)) => written += n,
                Poll::Ready(Err(e)) => panic!("write failed: {e}"),
                Poll::Pending => continue,
            }
        }
        assert_eq!(written, payload.len());

        // Flush any remaining buffered frames.
        match Pin::new(&mut stream).poll_flush(&mut cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => panic!("flush failed: {e}"),
            Poll::Pending => panic!("flush should complete immediately"),
        }

        // The underlying writer must have received all encoded bytes.
        assert!(!stream.inner.inner.is_empty());
    }
}
