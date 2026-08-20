//! Integration tests for the outer `/verify` and `/bootstrap-dns` endpoints.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use crabscale_control::{ControlConfig, ControlPlane};
use crabscale_proto::{Hostinfo, MachineKey, NodeKey, RegisterAuth, RegisterRequest};
use crabscale_server::{BootstrapDns, ControlRouter, ServerKey, serve_on_addr};
use crabscale_transport::NoiseResponder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_key() -> MachineKey {
    MachineKey::from_bytes([0x42; 32])
}

fn server_key() -> ServerKey {
    let responder = NoiseResponder::random();
    let public = MachineKey::from_bytes(responder.public_key().to_bytes());
    ServerKey::new(responder, public)
}

async fn send_raw(req: &str) -> (String, Vec<u8>) {
    let router = ControlRouter::new(test_key());
    let key = server_key();
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr, handle) = serve_on_addr(bind, router, key).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let (head, body) = read_http_response(&mut stream).await;
    handle.shutdown();
    (head, body)
}

#[tokio::test]
async fn verify_allows_known_and_denies_unknown_over_http() {
    let plane = ControlPlane::new(ControlConfig::default());
    let machine_key = test_key();
    let request = RegisterRequest {
        version: 130,
        node_key: NodeKey::from_bytes([0x22; 32]),
        auth: Some(RegisterAuth {
            auth_key: "hskey-auth-test-secret".to_string(),
        }),
        hostinfo: Some(Hostinfo {
            hostname: "node1".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(plane.register(machine_key, request).machine_authorized);

    let router = ControlRouter::with_control(machine_key, plane);
    let key = server_key();
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr, handle) = serve_on_addr(bind, router, key).await.unwrap();

    let known_body = format!("{{\"NodePublic\":\"{}\"}}", NodeKey::from_bytes([0x22; 32]));
    let unknown_body = format!("{{\"NodePublic\":\"{}\"}}", NodeKey::from_bytes([0x99; 32]));

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    write_post(&mut stream, "/verify", &known_body).await;
    let (head, body) = read_http_response(&mut stream).await;
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "known verify head: {head}"
    );
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["Allow"], serde_json::json!(true));

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    write_post(&mut stream, "/verify", &unknown_body).await;
    let (head, body) = read_http_response(&mut stream).await;
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "unknown verify head: {head}"
    );
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["Allow"], serde_json::json!(false));

    handle.shutdown();
}

#[tokio::test]
async fn verify_rejects_non_post_and_oversized_body() {
    let (head, _body) =
        send_raw("GET /verify HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 405"), "head: {head}");

    // A body over 4 KiB must be rejected with 413.
    let oversized = format!("{{\"NodePublic\":\"{}\"}}", "x".repeat(5000));
    let router = ControlRouter::new(test_key());
    let key = server_key();
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr, handle) = serve_on_addr(bind, router, key).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    write_post(&mut stream, "/verify", &oversized).await;
    let (head, _body) = read_http_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 413"), "oversized head: {head}");
    handle.shutdown();
}

#[tokio::test]
async fn bootstrap_dns_over_http_serves_configured_snapshot() {
    let dns = BootstrapDns::from_entries(BTreeMap::from([(
        "derp.example.com".to_string(),
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
    )]));
    let router = ControlRouter::new(test_key()).with_bootstrap_dns(dns);
    let key = server_key();
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr, handle) = serve_on_addr(bind, router, key).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /bootstrap-dns?q=derp.example.com HTTP/1.1\r\n\
              Host: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    stream.flush().await.unwrap();
    let (head, body) = read_http_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["derp.example.com"][0], serde_json::json!("192.0.2.1"));

    handle.shutdown();
}

#[tokio::test]
async fn bootstrap_dns_unconfigured_returns_404() {
    let (head, _body) =
        send_raw("GET /bootstrap-dns HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await;
    assert!(head.starts_with("HTTP/1.1 404"), "head: {head}");
}

async fn write_post(stream: &mut tokio::net::TcpStream, path: &str, body: &str) {
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
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

/// Read an HTTP/1.1 response head up to the blank line.
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
