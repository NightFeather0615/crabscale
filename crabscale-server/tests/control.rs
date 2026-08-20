//! Integration tests for the control router over HTTP/2-over-Noise.

use crabscale_proto::MachineKey;
use crabscale_server::{ControlRouter, serve_control};
use crabscale_transport::{
    EARLY_PAYLOAD_MAGIC, NoiseResponder, NoiseStream, decode_early_payload, loopback_handshake,
};
use h2::client;
use tokio::io::DuplexStream;
use x25519_dalek::StaticSecret;

/// Read and discard the early payload the server writes before the HTTP/2
/// preface (Spec-Transport section 5).
async fn read_early_payload(stream: &mut NoiseStream<DuplexStream>) {
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
    let _ = decode_early_payload(&buf).unwrap();
}

#[tokio::test]
async fn whoami_over_noise_returns_machine_key() {
    let server = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(server.public_key().to_bytes());
    let router = ControlRouter::new(machine_key);
    let (mut client_stream, server_stream) =
        loopback_handshake(&server, StaticSecret::random(), 113)
            .await
            .unwrap();

    let server_task = tokio::spawn(async move {
        let _ = serve_control(server_stream, router).await;
    });

    read_early_payload(&mut client_stream).await;

    let (mut client, conn) = client::handshake(client_stream).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = http::Request::builder()
        .method("GET")
        .uri("/machine/whoami")
        .body(())
        .unwrap();
    let (response, _send_stream) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);

    let mut body = response.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        buf.extend_from_slice(&chunk.unwrap());
    }
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert_eq!(json["machineKey"], machine_key.to_string());
    assert_eq!(json["protocolVersion"], 130);

    drop(server_task);
}

#[tokio::test]
async fn stub_route_returns_501() {
    let server = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(server.public_key().to_bytes());
    let router = ControlRouter::new(machine_key);
    let (mut client_stream, server_stream) =
        loopback_handshake(&server, StaticSecret::random(), 113)
            .await
            .unwrap();

    let server_task = tokio::spawn(async move {
        let _ = serve_control(server_stream, router).await;
    });

    read_early_payload(&mut client_stream).await;

    let (mut client, conn) = client::handshake(client_stream).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = http::Request::builder()
        .method("POST")
        .uri("/machine/set-dns")
        .body(())
        .unwrap();
    let (response, _send_stream) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 501);

    drop(server_task);
}
