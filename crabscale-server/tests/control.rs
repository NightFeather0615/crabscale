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

#[tokio::test]
async fn register_and_map_over_noise() {
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

    let node_key = crabscale_proto::NodeKey::from_bytes([0x22; 32]);
    let disco_key = crabscale_proto::DiscoKey::from_bytes([0x33; 32]);

    // Register with the default test auth key.
    let register = crabscale_proto::RegisterRequest {
        version: 130,
        node_key,
        auth: Some(crabscale_proto::RegisterAuth {
            auth_key: "hskey-auth-test-secret".to_string(),
        }),
        hostinfo: Some(crabscale_proto::Hostinfo {
            hostname: "node1".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let register_body = serde_json::to_vec(&register).unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("/machine/register")
        .body(())
        .unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();
    send_stream.send_data(register_body.into(), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        buf.extend_from_slice(&chunk.unwrap());
    }
    let reg_json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert_eq!(reg_json["MachineAuthorized"], true);

    // Request a non-streaming full map.
    let map = crabscale_proto::MapRequest {
        version: 130,
        node_key,
        disco_key,
        stream: false,
        ..Default::default()
    };
    let map_body = serde_json::to_vec(&map).unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("/machine/map")
        .body(())
        .unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();
    send_stream.send_data(map_body.into(), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        buf.extend_from_slice(&chunk.unwrap());
    }
    let (payload, consumed) = crabscale_proto::decode_map_response_frame(&buf).unwrap();
    assert_eq!(consumed, buf.len());
    let map_json: serde_json::Value = serde_json::from_slice(payload).unwrap();
    assert!(map_json.get("Node").is_some());
    assert!(map_json.get("DERPMap").is_some());
    assert!(map_json.get("Peers").is_some());
    assert_eq!(map_json["Peers"], serde_json::json!([]));
    assert_eq!(
        map_json["Node"]["DiscoKey"],
        serde_json::json!(
            "discokey:3333333333333333333333333333333333333333333333333333333333333333"
        )
    );

    drop(server_task);
}

#[tokio::test]
async fn interactive_register_approve_followup_authorizes() {
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

    let node_key = crabscale_proto::NodeKey::from_bytes([0x44; 32]);

    // 1. Register with an invalid auth key -> interactive AuthURL.
    let register = crabscale_proto::RegisterRequest {
        version: 130,
        node_key,
        auth: Some(crabscale_proto::RegisterAuth {
            auth_key: "wrong".to_string(),
        }),
        hostinfo: Some(crabscale_proto::Hostinfo {
            hostname: "node1".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let register_body = serde_json::to_vec(&register).unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("/machine/register")
        .body(())
        .unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();
    send_stream.send_data(register_body.into(), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        buf.extend_from_slice(&chunk.unwrap());
    }
    let reg_json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert!(reg_json.get("MachineAuthorized").is_none());
    let auth_url = reg_json["AuthURL"].as_str().unwrap().to_string();
    let auth_id = crabscale_control::auth_id_from_followup(&auth_url).unwrap();

    // 2. Approve the pending registration via the admin API.
    let approve = serde_json::json!({ "auth_id": auth_id, "user": "alice" });
    let approve_body = serde_json::to_vec(&approve).unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("/machine/register/approve")
        .body(())
        .unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();
    send_stream.send_data(approve_body.into(), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        buf.extend_from_slice(&chunk.unwrap());
    }
    let approve_json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert_eq!(approve_json["approved"], true);

    // 3. Followup with the same machine key -> authorized.
    let followup = crabscale_proto::RegisterRequest {
        version: 130,
        node_key,
        followup: auth_url,
        ..Default::default()
    };
    let followup_body = serde_json::to_vec(&followup).unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("/machine/register")
        .body(())
        .unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();
    send_stream.send_data(followup_body.into(), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        buf.extend_from_slice(&chunk.unwrap());
    }
    let followup_json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert_eq!(followup_json["MachineAuthorized"], true);

    drop(server_task);
}
