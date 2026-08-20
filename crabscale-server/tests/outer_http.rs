//! Integration tests for the outer HTTP/1.1 control endpoints.

use std::time::Duration;

use crabscale_proto::MachineKey;
use crabscale_server::{ControlRouter, ServerKey, serve_on_addr};
use crabscale_transport::NoiseResponder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A client observes a clean FIN after the server closes a `/key` connection.
#[tokio::test]
async fn key_response_ends_with_clean_fin() {
    let responder = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(responder.public_key().to_bytes());
    let server_key = ServerKey::new(responder, machine_key);
    let router = ControlRouter::new(machine_key);
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr, handle) = serve_on_addr(bind, router, server_key).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /key?v=130 HTTP/1.1\r\n\
              Host: localhost\r\n\
              Connection: close\r\n\
              \r\n",
        )
        .await
        .unwrap();
    stream.flush().await.unwrap();

    let (head, body) = read_http_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "unexpected head: {head}");
    assert!(!body.is_empty());

    // The server advertises `Connection: close` and shuts down the write side,
    // so the next read must observe EOF promptly instead of hanging.
    let mut buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    assert!(eof.is_ok(), "expected a clean FIN after the response body");
    assert_eq!(eof.unwrap().unwrap(), 0);

    handle.shutdown();
}

/// Read an HTTP/1.1 response head and body using Content-Length.
async fn read_http_response<S>(stream: &mut S) -> (String, Vec<u8>)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let head = read_http_head(stream).await;
    let content_length = head
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body).await.unwrap();
    }
    (head, body)
}

/// Read an HTTP/1.1 response head up to the blank line, one byte at a time so
/// any body bytes that arrive in the same segment stay in the socket buffer.
async fn read_http_head<S>(stream: &mut S) -> String
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.unwrap();
        assert!(n > 0, "connection closed while reading head");
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return String::from_utf8_lossy(&buf).to_string();
        }
    }
}
