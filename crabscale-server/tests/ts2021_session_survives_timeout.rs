//! Regression test for the TS2021 handshake timeout (M4-02, #25).
//!
//! The 10-second `HANDSHAKE_TIMEOUT` must bound only the handshake portion
//! (the HTTP upgrade wait and the Noise response write), never the inner
//! HTTP/2 control session. This test opens a real TS2021 upgrade over TCP,
//! registers, holds a streaming map open well past the handshake timeout, and
//! proves the connection is still serving requests afterwards.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use crabscale_proto::{
    DiscoKey, Hostinfo, MachineKey, MapRequest, NodeKey, RegisterAuth, RegisterRequest,
};
use crabscale_server::{ControlRouter, ServerKey, serve_on_addr};
use crabscale_transport::{
    EARLY_PAYLOAD_MAGIC, HANDSHAKE_TIMEOUT, NoiseInitiator, NoiseResponder, NoiseStream,
    RESPONSE_MESSAGE_LEN, decode_early_payload,
};
use h2::client;
use http::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::test]
async fn streaming_control_session_survives_handshake_timeout() {
    let responder = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(responder.public_key().to_bytes());
    let server_key = ServerKey::new(responder, machine_key);
    let router = ControlRouter::new(machine_key);
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr, handle) = serve_on_addr(bind, router, server_key).await.unwrap();

    let client_static = StaticSecret::random();
    let version: u16 = 130;
    let node_key = NodeKey::from_bytes(PublicKey::from(&client_static).to_bytes());

    // 1. Full native TS2021 upgrade + Noise handshake over real TCP.
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let prologue = format!("Tailscale Control Protocol v{version}");
    let (initiator, init_bytes) = NoiseInitiator::initialize(
        client_static.clone(),
        PublicKey::from(machine_key.to_bytes()),
        prologue.as_bytes(),
        version,
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
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let head = read_http_head(&mut stream).await;
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected 101 Switching Protocols, got: {head}"
    );

    let mut response = [0u8; RESPONSE_MESSAGE_LEN];
    stream.read_exact(&mut response).await.unwrap();
    let session = initiator.finish(&response).unwrap();
    let mut noise = NoiseStream::new(
        stream,
        session.responder_to_initiator,
        session.initiator_to_responder,
    );

    // 2. Read the early payload.
    read_early_payload(&mut noise).await;

    // 3. HTTP/2 over Noise.
    let (mut h2, conn) = client::handshake(noise).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // 4. Register.
    let register = RegisterRequest {
        version: 130,
        node_key,
        auth: Some(RegisterAuth {
            auth_key: "hskey-auth-test-secret".to_string(),
        }),
        hostinfo: Some(Hostinfo {
            hostname: "node1".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let reg_raw = post_json_raw(
        &mut h2,
        "/machine/register",
        &serde_json::to_vec(&register).unwrap(),
    )
    .await;
    let reg_json: serde_json::Value = serde_json::from_slice(&reg_raw).unwrap();
    assert_eq!(reg_json["MachineAuthorized"], serde_json::json!(true));

    // 5. Open a streaming map and leave the response stream open.
    let map = MapRequest {
        version: 130,
        node_key,
        disco_key: DiscoKey::from_bytes([0x33; 32]),
        stream: true,
        ..Default::default()
    };
    let map_body = serde_json::to_vec(&map).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/machine/map")
        .body(())
        .unwrap();
    let (response, mut send_stream) = h2.send_request(request, false).unwrap();
    send_stream.send_data(map_body.into(), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);

    // 6. Hold well past the handshake timeout. If the timeout wrapped the
    // whole control session, the socket would be dropped here and the
    // subsequent request would fail.
    let hold = HANDSHAKE_TIMEOUT + Duration::from_secs(1);
    tokio::time::sleep(hold).await;

    // 7. The same connection must still serve requests.
    let whoami = Request::builder()
        .method("GET")
        .uri("/machine/whoami")
        .body(())
        .unwrap();
    let (resp, _) = h2.send_request(whoami, true).unwrap();
    let resp = resp
        .await
        .expect("session must stay alive past the handshake timeout");
    assert_eq!(resp.status(), 200);

    handle.shutdown();
}

async fn read_http_head<R>(stream: &mut R) -> String
where
    R: tokio::io::AsyncRead + Unpin,
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

async fn read_early_payload<S>(stream: &mut S) -> String
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut magic = [0u8; EARLY_PAYLOAD_MAGIC.len()];
    stream.read_exact(&mut magic).await.unwrap();
    assert_eq!(&magic, &EARLY_PAYLOAD_MAGIC);
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.unwrap();
    let mut buf = Vec::with_capacity(magic.len() + len_buf.len() + body.len());
    buf.extend_from_slice(&magic);
    buf.extend_from_slice(&len_buf);
    buf.extend_from_slice(&body);
    decode_early_payload(&buf).unwrap().to_string()
}

async fn post_json_raw(h2: &mut client::SendRequest<Bytes>, path: &str, body: &[u8]) -> Vec<u8> {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .body(())
        .unwrap();
    let (response, mut send_stream) = h2.send_request(request, false).unwrap();
    send_stream
        .send_data(Bytes::copy_from_slice(body), true)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut response = response.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = response.data().await {
        buf.extend_from_slice(&chunk.unwrap());
    }
    buf
}
