//! Integration tests for the `GET /register/{id}` approval page.

use crabscale_control::{ControlConfig, ControlPlane};
use crabscale_proto::{Hostinfo, MachineKey, NodeKey, RegisterAuth, RegisterRequest};
use crabscale_server::{ControlRouter, ServerKey, serve_on_addr};
use crabscale_transport::NoiseResponder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Start a pending interactive registration and return its auth id.
fn start_pending(plane: &ControlPlane, machine_key: MachineKey) -> String {
    let request = RegisterRequest {
        version: 130,
        node_key: NodeKey::from_bytes([0x22; 32]),
        auth: Some(RegisterAuth {
            auth_key: "wrong".to_string(),
        }),
        hostinfo: Some(Hostinfo {
            hostname: "node1".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let response = plane.register(machine_key, request);
    assert!(!response.machine_authorized);
    assert!(!response.auth_url.is_empty());
    crabscale_control::auth_id_from_followup(&response.auth_url).unwrap()
}

/// The known pending id returns the approval page with a 200 status.
#[tokio::test]
async fn register_page_returns_200_for_known_id() {
    let plane = ControlPlane::new(ControlConfig::default());
    let responder = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(responder.public_key().to_bytes());
    let server_key = ServerKey::new(responder, machine_key);
    let auth_id = start_pending(&plane, machine_key);
    let router = ControlRouter::with_control(machine_key, plane);

    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr, handle) = serve_on_addr(bind, router, server_key).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request =
        format!("GET /register/{auth_id} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let (head, body) = read_http_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "unexpected head: {head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: text/html"),
        "unexpected head: {head}"
    );
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains(&auth_id));
    assert!(body.contains("node1"));

    handle.shutdown();
}

/// An unknown or expired id returns 404.
#[tokio::test]
async fn register_page_returns_404_for_unknown_id() {
    let plane = ControlPlane::new(ControlConfig::default());
    let responder = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(responder.public_key().to_bytes());
    let server_key = ServerKey::new(responder, machine_key);
    let router = ControlRouter::with_control(machine_key, plane);

    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr, handle) = serve_on_addr(bind, router, server_key).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /register/does-not-exist HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    stream.flush().await.unwrap();

    let (head, _body) = read_http_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 404"), "unexpected head: {head}");

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
