//! A tokio async adapter over a blocking [`std::net::TcpStream`].
//!
//! Each read and write is offloaded to the tokio blocking thread pool with
//! [`tokio::task::spawn_blocking`], so the async runtime is never blocked. This
//! lets callers use the standard library's TCP types without enabling tokio's
//! `net` feature (and therefore without a `mio` dependency).

use std::future::Future;
use std::io;
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

/// Size of each blocking read chunk.
const READ_CHUNK: usize = 4096;

/// A tokio [`AsyncRead`] + [`AsyncWrite`] adapter over a blocking
/// [`std::net::TcpStream`].
pub struct BlockingTcpStream {
    stream: Arc<TcpStream>,
    read_buf: Vec<u8>,
    read_pos: usize,
    pending_read: Option<JoinHandle<io::Result<Vec<u8>>>>,
    pending_write: Option<JoinHandle<io::Result<usize>>>,
}

impl BlockingTcpStream {
    /// Wrap a blocking TCP stream.
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: Arc::new(stream),
            read_buf: Vec::new(),
            read_pos: 0,
            pending_read: None,
            pending_write: None,
        }
    }

    fn take_read_result(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut handle = self.pending_read.take().expect("pending read present");
        match Pin::new(&mut handle).poll(cx) {
            Poll::Ready(Ok(Ok(data))) => {
                self.read_buf = data;
                self.read_pos = 0;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => {
                self.pending_read = Some(handle);
                Poll::Pending
            }
        }
    }

    fn take_write_result(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut handle = self.pending_write.take().expect("pending write present");
        match Pin::new(&mut handle).poll(cx) {
            Poll::Ready(Ok(Ok(n))) => Poll::Ready(Ok(n)),
            Poll::Ready(Ok(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => {
                self.pending_write = Some(handle);
                Poll::Pending
            }
        }
    }
}

impl AsyncRead for BlockingTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Serve any buffered bytes first.
        if this.read_pos < this.read_buf.len() {
            let n = (this.read_buf.len() - this.read_pos).min(buf.remaining());
            buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
            this.read_pos += n;
            return Poll::Ready(Ok(()));
        }

        if this.pending_read.is_some() {
            match this.take_read_result(cx) {
                Poll::Ready(Ok(())) => {
                    let n = (this.read_buf.len() - this.read_pos).min(buf.remaining());
                    buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
                    this.read_pos += n;
                    Poll::Ready(Ok(()))
                }
                other => other,
            }
        } else {
            let stream = this.stream.clone();
            this.pending_read = Some(tokio::task::spawn_blocking(move || {
                use std::io::Read;
                let mut s = &*stream;
                let mut chunk = vec![0u8; READ_CHUNK];
                let n = s.read(&mut chunk)?;
                chunk.truncate(n);
                Ok(chunk)
            }));
            // Poll the handle immediately so its waker is registered; otherwise
            // the task would never be re-polled when the blocking read finishes.
            this.take_read_result(cx)
        }
    }
}

impl AsyncWrite for BlockingTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.pending_write.is_some() {
            return this.take_write_result(cx);
        }
        let data = buf.to_vec();
        let stream = this.stream.clone();
        this.pending_write = Some(tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let mut s = &*stream;
            s.write(&data)
        }));
        // Poll the handle immediately so its waker is registered.
        this.take_write_result(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pending_write.is_some() {
            match this.take_write_result(cx) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pending_write.is_some() {
            match this.take_write_result(cx) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
