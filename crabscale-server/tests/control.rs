//! Integration tests for the control router over HTTP/2-over-Noise.

use crabscale_proto::MachineKey;
use crabscale_server::{ControlRouter, serve_control};
use crabscale_transport::{NoiseResponder, loopback_handshake};
use h2::client;
use x25519_dalek::StaticSecret;

#[tokio::test]
async fn whoami_over_noise_returns_machine_key() {
    let server = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(server.public_key().to_bytes());
    let router = ControlRouter::new(machine_key);
    let (client_stream, server_stream) = loopback_handshake(&server, StaticSecret::random(), 113)
        .await
        .unwrap();

    let server_task = tokio::spawn(async move {
        let _ = serve_control(server_stream, router).await;
    });

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
    let (client_stream, server_stream) = loopback_handshake(&server, StaticSecret::random(), 113)
        .await
        .unwrap();

    let server_task = tokio::spawn(async move {
        let _ = serve_control(server_stream, router).await;
    });

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
