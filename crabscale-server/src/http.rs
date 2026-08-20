//! Minimal HTTP/1.1 server for the outer control endpoints.
//!
//! This module serves the two outer endpoints required by Spec-Transport:
//!
//! - `GET /key?v=<capability_version>` returns the server machine key.
//! - `POST /ts2021` upgrades the connection to the TS2021 Noise transport and
//!   then hands the resulting stream to the inner HTTP/2 control router.
//!
//! The implementation is intentionally dependency-light: it parses just enough
//! HTTP/1.1 to support these two endpoints and does not require a full HTTP
//! server framework. TCP accept and per-connection I/O are bridged from the
//! blocking standard library into tokio with [`tokio::task::spawn_blocking`], so
//! the crate does not need tokio's `net` feature (and therefore no `mio`).

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};

use crabscale_transport::{
    BlockingTcpStream, HANDSHAKE_HEADER, NoiseStream, UPGRADE_HEADER_VALUE, parse_init_message,
    validate_native_upgrade,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::key::ServerKey;
use crate::router::{ControlRouter, serve_control};

/// Maximum size of an outer HTTP request head (request line + headers).
const MAX_REQUEST_HEAD: usize = 16 * 1024;

/// A handle to a running outer control server, used to request shutdown.
#[derive(Clone)]
pub struct ServerHandle {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl ServerHandle {
    /// Ask the accept loop to stop accepting new connections.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Bind `addr` and serve the outer control endpoints until shutdown is
/// requested. Returns the actual bound address (useful when `addr` uses port
/// 0) and a handle that can be used to stop the server.
pub async fn serve_on_addr(
    addr: SocketAddr,
    router: ControlRouter,
    server_key: ServerKey,
) -> io::Result<(SocketAddr, ServerHandle)> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = ServerHandle { shutdown_tx };
    tokio::spawn(async move {
        let _ = serve(listener, router, server_key, shutdown_rx).await;
    });
    Ok((local, handle))
}

/// Accept connections and serve the outer control endpoints until shutdown is
/// requested.
pub async fn serve(
    listener: TcpListener,
    router: ControlRouter,
    server_key: ServerKey,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    loop {
        let accept_listener = listener.try_clone()?;
        let accept = tokio::task::spawn_blocking(move || accept_listener.accept());
        tokio::select! {
            _ = shutdown.changed() => {
                return Ok(());
            }
            res = accept => {
                let (stream, _) = res
                    .map_err(|e| io::Error::other(e.to_string()))??;
                let router = router.clone();
                let server_key = server_key.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, router, server_key).await;
                });
            }
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    router: ControlRouter,
    server_key: ServerKey,
) -> io::Result<()> {
    let mut stream = BlockingTcpStream::new(stream);
    let head = read_request_head(&mut stream).await?;
    let Some((method, path, headers)) = parse_request_head(&head) else {
        write_simple_response(&mut stream, 400, "text/plain", b"bad request").await?;
        return Ok(());
    };

    if method == "GET" && path.starts_with("/key") {
        let capver = query_param(&path, "v");
        let response = router.handle_key(capver);
        let status = response.status().as_u16();
        let body = response.body();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json");
        write_simple_response(&mut stream, status, content_type, body).await?;
        return Ok(());
    }

    if method == "POST" && path == "/ts2021" {
        return handle_ts2021(stream, &headers, router, server_key).await;
    }

    write_simple_response(&mut stream, 404, "text/plain", b"not found").await?;
    Ok(())
}

async fn handle_ts2021(
    mut stream: BlockingTcpStream,
    headers: &[(String, String)],
    router: ControlRouter,
    server_key: ServerKey,
) -> io::Result<()> {
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == &name.to_ascii_lowercase())
            .map(|(_, v)| v.as_str())
    };

    let init = match validate_native_upgrade(
        "POST",
        get("upgrade"),
        get("connection"),
        get(&HANDSHAKE_HEADER.to_ascii_lowercase()),
    ) {
        Ok(init) => init,
        Err(_) => {
            write_simple_response(&mut stream, 400, "text/plain", b"invalid upgrade request")
                .await?;
            return Ok(());
        }
    };

    let init = match parse_init_message(&init) {
        Ok(init) => init,
        Err(_) => {
            write_simple_response(&mut stream, 400, "text/plain", b"invalid handshake").await?;
            return Ok(());
        }
    };

    let prologue = format!("Tailscale Control Protocol v{}", init.version);
    let output = match server_key.responder().respond(&init, prologue.as_bytes()) {
        Ok(output) => output,
        Err(_) => {
            write_simple_response(&mut stream, 400, "text/plain", b"handshake rejected").await?;
            return Ok(());
        }
    };

    // Send 101 Switching Protocols before any Noise bytes.
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: {UPGRADE_HEADER_VALUE}\r\n\
         Connection: upgrade\r\n\
         \r\n"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    // Write the Noise response and then hand the raw stream to the inner
    // HTTP/2-over-Noise router.
    stream.write_all(&output.response).await?;
    stream.flush().await?;

    let noise_stream = NoiseStream::new(
        stream,
        output.session.initiator_to_responder,
        output.session.responder_to_initiator,
    );
    let _ = serve_control(noise_stream, router).await;
    Ok(())
}

/// Read the HTTP request head (request line + headers) up to a size limit.
async fn read_request_head<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REQUEST_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
    }
}

/// A parsed outer HTTP request head: `(method, path, headers)`.
type RequestHead = (String, String, Vec<(String, String)>);

/// Parse a request head into `(method, path, headers)`.
fn parse_request_head(head: &[u8]) -> Option<RequestHead> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Some((method, path, headers))
}

/// Extract a query parameter from a path like `/key?v=130`.
fn query_param<'a>(path: &'a str, name: &str) -> Option<&'a str> {
    let query = path.split_once('?')?.1;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == name {
            return Some(v);
        }
    }
    None
}

/// Write a minimal HTTP/1.1 response with a Content-Length body.
async fn write_simple_response<S>(
    stream: &mut S,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_head() {
        let head = b"POST /ts2021 HTTP/1.1\r\nHost: localhost\r\nUpgrade: tailscale-control-protocol\r\n\r\n";
        let (method, path, headers) = parse_request_head(head).unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/ts2021");
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "upgrade" && v == "tailscale-control-protocol")
        );
    }

    #[test]
    fn extracts_query_param() {
        assert_eq!(query_param("/key?v=130", "v"), Some("130"));
        assert_eq!(query_param("/key", "v"), None);
    }
}
