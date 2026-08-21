//! Integration smoke for M4-03 (#26): the server behind a reverse proxy.
//!
//! Trusted proxy CIDRs make `/ts2021` rate limiting key on the real client IP
//! carried in `X-Forwarded-For` instead of on the proxy's IP. These tests
//! simulate the proxied requests directly (a proxy rewrites headers before
//! forwarding) and verify the rate limiter buckets by client IP.

use std::sync::Arc;

use crabscale_proto::MachineKey;
use crabscale_server::{
    ControlRouter, RateLimitConfig, ServerKey, ServerOptions, TrustedProxies,
    serve_on_addr_with_options,
};
use crabscale_transport::NoiseResponder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn machine_key() -> MachineKey {
    MachineKey::from_bytes([0x42; 32])
}

fn server_key() -> ServerKey {
    let responder = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(responder.public_key().to_bytes());
    ServerKey::new(responder, machine_key)
}

fn trusted_loopback_proxy() -> ServerOptions {
    let proxies = TrustedProxies::from_cidrs(&["127.0.0.1/32"]).expect("valid loopback CIDR");
    ServerOptions {
        trusted_proxies: Some(Arc::new(proxies)),
        ..Default::default()
    }
}

/// A server whose `/ts2021` limiter has a single token per client IP.
async fn start_single_token_server(
    options: ServerOptions,
) -> (std::net::SocketAddr, crabscale_server::ServerHandle) {
    let router = ControlRouter::new(machine_key()).with_rate_limits(RateLimitConfig {
        ts2021_per_min: 60,
        ts2021_burst: 1,
        ..Default::default()
    });
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    serve_on_addr_with_options(bind, router, server_key(), options)
        .await
        .unwrap()
}

async fn send_ts2021(addr: std::net::SocketAddr, forwarded_for: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST /ts2021 HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: {forwarded_for}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    read_http_head(&mut stream).await
}

/// A malformed `POST /ts2021` with one token per resolved client IP: the first
/// request from a client consumes the token (400), the second is limited (429).
#[tokio::test]
async fn ts2021_limiter_keys_on_forwarded_client_ip_behind_trusted_proxy() {
    let (addr, handle) = start_single_token_server(trusted_loopback_proxy()).await;

    let first = send_ts2021(addr, "198.51.100.7").await;
    assert!(first.starts_with("HTTP/1.1 400"), "first head: {first}");

    // Same forwarded client IP is now limited, even though the TCP peer (the
    // trusted proxy) never changed.
    let limited = send_ts2021(addr, "198.51.100.7").await;
    assert!(
        limited.starts_with("HTTP/1.1 429"),
        "limited head: {limited}"
    );
    assert!(
        limited.to_ascii_lowercase().contains("retry-after:"),
        "Retry-After must be present: {limited}"
    );

    // A different forwarded client IP has its own bucket.
    let other = send_ts2021(addr, "198.51.100.8").await;
    assert!(other.starts_with("HTTP/1.1 400"), "other head: {other}");

    handle.shutdown();
}

/// Without a trusted-proxy CIDR, `X-Forwarded-For` must be ignored: both
/// requests come from the same socket peer (127.0.0.1) and share its bucket.
#[tokio::test]
async fn ts2021_ignores_forwarded_header_without_trusted_proxy() {
    // Default options: nobody is trusted.
    let (addr, handle) = start_single_token_server(ServerOptions::default()).await;

    let first = send_ts2021(addr, "203.0.113.1").await;
    assert!(first.starts_with("HTTP/1.1 400"), "first head: {first}");

    // A different X-Forwarded-For value still hits the same peer bucket.
    let limited = send_ts2021(addr, "203.0.113.2").await;
    assert!(
        limited.starts_with("HTTP/1.1 429"),
        "limited head: {limited}"
    );

    handle.shutdown();
}

/// A trusted proxy may also pass `X-Real-IP` when no `X-Forwarded-For` chain is
/// present; the resolved client IP feeds the same limiter.
#[tokio::test]
async fn ts2021_uses_x_real_ip_from_trusted_proxy() {
    let (addr, handle) = start_single_token_server(trusted_loopback_proxy()).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"POST /ts2021 HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 198.51.100.9\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    stream.flush().await.unwrap();
    let first = read_http_head(&mut stream).await;
    assert!(first.starts_with("HTTP/1.1 400"), "first head: {first}");

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"POST /ts2021 HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 198.51.100.9\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    stream.flush().await.unwrap();
    let limited = read_http_head(&mut stream).await;
    assert!(
        limited.starts_with("HTTP/1.1 429"),
        "limited head: {limited}"
    );

    handle.shutdown();
}

/// The HTTP->HTTPS redirect listener answers 301 with a Location that preserves
/// the path and query, which keeps `/key` and web flows redirectable to TLS.
#[tokio::test]
async fn redirect_listener_points_at_https() {
    let (addr, handle) = crabscale_server::serve_redirect_on_addr(
        "127.0.0.1:0".parse().unwrap(),
        "control.example.com".to_string(),
    )
    .await
    .unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /key?v=130 HTTP/1.1\r\nHost: control.example.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    stream.flush().await.unwrap();

    let head = read_http_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 301"), "head: {head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("location: https://control.example.com/key?v=130"),
        "redirect must preserve path/query and upgrade to https: {head}"
    );

    handle.shutdown();
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
