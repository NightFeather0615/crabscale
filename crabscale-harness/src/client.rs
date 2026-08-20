//! Rust client test peer.
//!
//! This module implements a minimal Tailscale-compatible client that talks to
//! a crabscale control server over real TCP. It performs the full TS2021
//! upgrade, Noise IK handshake, HTTP/2-over-Noise session, registration, a
//! non-streaming map request, and logout. It is used both as a standalone
//! binary (`crabscale-peer`) and by the harness orchestrator.

use std::net::TcpStream;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use crabscale_proto::{
    DiscoKey, Hostinfo, LogoutRequest, MachineKey, MapRequest, NodeKey, RegisterAuth,
    RegisterRequest, RegisterResponse, decode_map_response_frame,
};
use crabscale_transport::{
    BlockingTcpStream, EARLY_PAYLOAD_MAGIC, NoiseInitiator, NoiseStream, RESPONSE_MESSAGE_LEN,
    decode_early_payload,
};
use h2::client;
use http::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::HarnessConfig;

/// The capability version this peer advertises.
pub const CAPABILITY_VERSION: u16 = 130;

/// Result of a Rust peer run.
#[derive(Clone, Debug, Default)]
pub struct PeerReport {
    /// Whether registration succeeded.
    pub registered: bool,
    /// The IP addresses assigned to the node.
    pub assigned_ips: Vec<String>,
    /// Whether the map response contained a peer list.
    pub saw_peers: bool,
    /// Whether logout returned the node to needs-login.
    pub logged_out: bool,
    /// Human-readable notes.
    pub notes: Vec<String>,
}

/// Run the Rust client peer against the configured control server.
pub async fn run_rust_peer(config: &HarnessConfig) -> Result<PeerReport, String> {
    let mut report = PeerReport::default();
    let addr = config.addr();

    // 1. Fetch the server machine key.
    let server_public = fetch_server_key(addr).await?;
    report
        .notes
        .push(format!("fetched server machine key {server_public}"));

    // 2. Open the TS2021 upgrade and complete the Noise handshake.
    let client_static = StaticSecret::random();
    let node_key = NodeKey::from_bytes(PublicKey::from(&client_static).to_bytes());
    let mut noise = open_ts2021(addr, &client_static, server_public).await?;
    report
        .notes
        .push("completed TS2021 Noise handshake".to_string());

    // 3. Read the early payload.
    let challenge = read_early_payload(&mut noise).await?;
    report
        .notes
        .push(format!("received early payload challenge {challenge}"));

    // 4. Start HTTP/2 over the Noise stream.
    let (mut h2, conn) = client::handshake(noise)
        .await
        .map_err(|e| format!("HTTP/2 handshake failed: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // 5. Register with the pre-auth key.
    let register = RegisterRequest {
        version: CAPABILITY_VERSION as u32,
        node_key,
        auth: Some(RegisterAuth {
            auth_key: config.auth_key.clone(),
        }),
        hostinfo: Some(Hostinfo {
            hostname: config.rust_peer_hostname.clone(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let reg_response: RegisterResponse = post_json(&mut h2, "/machine/register", &register).await?;
    if !reg_response.machine_authorized {
        return Err(format!(
            "registration not authorized: {}",
            reg_response.error
        ));
    }
    report.registered = true;
    report.notes.push("registration authorized".to_string());

    // 6. Request a non-streaming full map.
    let disco_key = DiscoKey::from_bytes([0x33; 32]);
    let map = MapRequest {
        version: CAPABILITY_VERSION as u32,
        node_key,
        disco_key,
        stream: false,
        ..Default::default()
    };
    let map_body = post_json_raw(&mut h2, "/machine/map", &map).await?;
    let (payload, consumed) = decode_map_response_frame(&map_body)
        .map_err(|e| format!("failed to decode map frame: {e}"))?;
    if consumed != map_body.len() {
        return Err("map frame had trailing bytes".to_string());
    }
    let map_json: serde_json::Value =
        serde_json::from_slice(payload).map_err(|e| format!("invalid map JSON: {e}"))?;
    if let Some(node) = map_json.get("Node") {
        if let Some(addrs) = node.get("Addresses").and_then(|a| a.as_array()) {
            for addr in addrs {
                if let Some(s) = addr.as_str() {
                    report.assigned_ips.push(s.to_string());
                }
            }
        }
    }
    report.saw_peers = map_json.get("Peers").is_some();
    report.notes.push(format!(
        "received map with {} assigned IPs",
        report.assigned_ips.len()
    ));

    // 7. Log out and verify the node returns to needs-login.
    let logout = LogoutRequest { node_key };
    let logout_response: RegisterResponse = post_json(&mut h2, "/machine/logout", &logout).await?;
    report.logged_out = !logout_response.machine_authorized;
    if report.logged_out {
        report
            .notes
            .push("logout returned node to needs-login".to_string());
    } else {
        report
            .notes
            .push("logout did not deauthorize node".to_string());
    }

    Ok(report)
}

/// Fetch the server machine key from `GET /key`.
async fn fetch_server_key(addr: std::net::SocketAddr) -> Result<MachineKey, String> {
    let tcp = TcpStream::connect(addr).map_err(|e| format!("connect failed: {e}"))?;
    let mut stream = BlockingTcpStream::new(tcp);
    let request = format!(
        "GET /key?v={CAPABILITY_VERSION} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write /key request failed: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("flush /key request failed: {e}"))?;

    let (head, body) = read_http_response(&mut stream).await?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err(format!("GET /key returned non-200: {head}"));
    }
    let json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("invalid /key JSON: {e}"))?;
    let key_str = json
        .get("publicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "GET /key response missing publicKey".to_string())?;
    key_str
        .parse::<MachineKey>()
        .map_err(|e| format!("invalid machine key: {e}"))
}

/// Open the TS2021 upgrade and complete the Noise handshake.
async fn open_ts2021(
    addr: std::net::SocketAddr,
    client_static: &StaticSecret,
    server_public: MachineKey,
) -> Result<NoiseStream<BlockingTcpStream>, String> {
    let tcp = TcpStream::connect(addr).map_err(|e| format!("connect failed: {e}"))?;
    let mut stream = BlockingTcpStream::new(tcp);

    let prologue = format!("Tailscale Control Protocol v{CAPABILITY_VERSION}");
    let (initiator, init_bytes) = NoiseInitiator::initialize(
        client_static.clone(),
        PublicKey::from(server_public.to_bytes()),
        prologue.as_bytes(),
        CAPABILITY_VERSION,
    );
    let init_b64 = BASE64.encode(init_bytes);
    let request = format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Upgrade: tailscale-control-protocol\r\n\
         Connection: upgrade\r\n\
         X-Tailscale-Handshake: {init_b64}\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write /ts2021 request failed: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("flush /ts2021 request failed: {e}"))?;
    let head = read_http_head(&mut stream).await?;
    if !head.starts_with("HTTP/1.1 101") {
        return Err(format!("/ts2021 upgrade rejected: {head}"));
    }

    let mut response = [0u8; RESPONSE_MESSAGE_LEN];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|e| format!("read Noise response failed: {e}"))?;
    let session = initiator
        .finish(&response)
        .map_err(|e| format!("Noise handshake failed: {e}"))?;

    let noise = NoiseStream::new(
        stream,
        session.responder_to_initiator,
        session.initiator_to_responder,
    );
    Ok(noise)
}

/// Read and decode the early payload the server writes before HTTP/2.
async fn read_early_payload<S>(stream: &mut S) -> Result<String, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut magic = [0u8; EARLY_PAYLOAD_MAGIC.len()];
    stream
        .read_exact(&mut magic)
        .await
        .map_err(|e| format!("read early payload magic failed: {e}"))?;
    if magic != EARLY_PAYLOAD_MAGIC {
        return Err("early payload magic mismatch".to_string());
    }
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("read early payload length failed: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| format!("read early payload body failed: {e}"))?;
    let mut buf = Vec::with_capacity(magic.len() + len_buf.len() + body.len());
    buf.extend_from_slice(&magic);
    buf.extend_from_slice(&len_buf);
    buf.extend_from_slice(&body);
    let challenge =
        decode_early_payload(&buf).map_err(|e| format!("decode early payload failed: {e}"))?;
    Ok(challenge.to_string())
}

/// POST a JSON body and deserialize the JSON response.
async fn post_json<T: serde::Serialize, R: serde::de::DeserializeOwned>(
    h2: &mut client::SendRequest<Bytes>,
    path: &str,
    body: &T,
) -> Result<R, String> {
    let raw = post_json_raw(h2, path, body).await?;
    serde_json::from_slice(&raw).map_err(|e| format!("invalid JSON response: {e}"))
}

/// POST a JSON body and return the raw response body.
async fn post_json_raw<T: serde::Serialize>(
    h2: &mut client::SendRequest<Bytes>,
    path: &str,
    body: &T,
) -> Result<Vec<u8>, String> {
    let body_bytes = serde_json::to_vec(body).map_err(|e| format!("serialize failed: {e}"))?;
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .body(())
        .map_err(|e| format!("build request failed: {e}"))?;
    let (response, mut send_stream) = h2
        .send_request(request, false)
        .map_err(|e| format!("send request failed: {e}"))?;
    send_stream
        .send_data(Bytes::from(body_bytes), true)
        .map_err(|e| format!("send body failed: {e}"))?;
    let response = response
        .await
        .map_err(|e| format!("await response failed: {e}"))?;
    if response.status() != http::StatusCode::OK {
        return Err(format!("{path} returned {}", response.status()));
    }
    let mut body = response.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| format!("read body failed: {e}"))?;
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Read an HTTP/1.1 response head (up to the blank line).
async fn read_http_head<S>(stream: &mut S) -> Result<String, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read head failed: {e}"))?;
        if n == 0 {
            return Err("connection closed while reading head".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&buf).to_string());
        }
    }
}

/// Read an HTTP/1.1 response head and body (using Content-Length).
async fn read_http_response<S>(stream: &mut S) -> Result<(String, Vec<u8>), String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let head = read_http_head(stream).await?;
    let content_length = head
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower.strip_prefix("content-length:").map(|v| {
                v.trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid content-length".to_string())
            })
        })
        .transpose()?
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| format!("read body failed: {e}"))?;
    }
    Ok((head, body))
}
