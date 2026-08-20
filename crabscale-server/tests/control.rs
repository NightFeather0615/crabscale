//! Integration tests for the control router over HTTP/2-over-Noise.

use bytes::Bytes;
use crabscale_control::{ControlConfig, ControlPlane};
use crabscale_proto::{DiscoKey, Hostinfo, MachineKey, NodeKey, RegisterAuth, RegisterRequest};
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
    // The control plane is shared with the router so the test can approve the
    // pending registration locally (the admin API is intentionally not exposed
    // over the Noise channel).
    let control = crabscale_control::ControlPlane::new(crabscale_control::ControlConfig::default());
    let router = ControlRouter::with_control(machine_key, control.clone());
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

    // 2. Approve the pending registration via the local control plane.
    control.approve_pending(&auth_id, "alice").unwrap();

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

/// Build an h2 client over a fresh Noise connection to `server` and return
/// it along with the spawned server task.
async fn connect_client(
    server: &NoiseResponder,
    router: ControlRouter,
) -> (client::SendRequest<Bytes>, tokio::task::JoinHandle<()>) {
    let (mut client_stream, server_stream) =
        loopback_handshake(server, StaticSecret::random(), 113)
            .await
            .unwrap();
    let server_task = tokio::spawn(async move {
        let _ = serve_control(server_stream, router).await;
    });

    read_early_payload(&mut client_stream).await;

    let (client, conn) = client::handshake(client_stream).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    (client, server_task)
}

/// POST `body` to the inner Noise-protected path and return the raw body.
async fn post_json_raw(
    client: &mut client::SendRequest<Bytes>,
    path: &str,
    body: &serde_json::Value,
) -> Vec<u8> {
    let body_bytes = serde_json::to_vec(body).unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri(path)
        .body(())
        .unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();
    send_stream.send_data(body_bytes.into(), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        buf.extend_from_slice(&chunk.unwrap());
    }
    buf
}

/// Decode a `MapResponse` frame returned by `/machine/map`.
fn decode_map(buf: &[u8]) -> serde_json::Value {
    let (payload, consumed) = crabscale_proto::decode_map_response_frame(buf).unwrap();
    assert_eq!(consumed, buf.len());
    serde_json::from_slice(payload).unwrap()
}

#[tokio::test]
async fn peer_ping_across_subnet_router() {
    let server = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(server.public_key().to_bytes());
    let policy = crabscale_policy::parse_policy(
        r#"{ "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*"] } ] }"#,
    )
    .unwrap();
    let control = crabscale_control::ControlPlane::new(crabscale_control::ControlConfig {
        policy,
        ..Default::default()
    });
    let router = ControlRouter::with_control(machine_key, control.clone());

    // Two clients: a subnet router and a regular host.
    let (mut router_client, router_task) = connect_client(&server, router.clone()).await;
    let (mut peer_client, peer_task) = connect_client(&server, router.clone()).await;

    let router_key = crabscale_proto::NodeKey::from_bytes([0x51; 32]);
    let router_disco = crabscale_proto::DiscoKey::from_bytes([0x61; 32]);

    // The router registers and advertises the LAN subnet it can route.
    let reg = serde_json::json!({
        "Version": 130,
        "NodeKey": router_key.to_string(),
        "Auth": { "AuthKey": "hskey-auth-test-secret" },
        "Hostinfo": {
            "Hostname": "router",
            "RoutableIPs": ["192.168.77.0/24"]
        }
    });
    let reg_raw = post_json_raw(&mut router_client, "/machine/register", &reg).await;
    let reg_json: serde_json::Value = serde_json::from_slice(&reg_raw).unwrap();
    assert_eq!(reg_json["MachineAuthorized"], true);

    // The administrator approves the advertised route.
    let router_node = control
        .node_by_key(&router_key)
        .unwrap()
        .expect("router node must exist");
    control
        .approve_route(&router_node.node_key, "192.168.77.0/24")
        .unwrap();

    // The regular host registers.
    let peer_key = crabscale_proto::NodeKey::from_bytes([0x52; 32]);
    let peer_disco = crabscale_proto::DiscoKey::from_bytes([0x62; 32]);
    let reg = serde_json::json!({
        "Version": 130,
        "NodeKey": peer_key.to_string(),
        "Auth": { "AuthKey": "hskey-auth-test-secret" },
        "Hostinfo": { "Hostname": "host" }
    });
    let reg_raw = post_json_raw(&mut peer_client, "/machine/register", &reg).await;
    let reg_json: serde_json::Value = serde_json::from_slice(&reg_raw).unwrap();
    assert_eq!(reg_json["MachineAuthorized"], true);

    // The host maps: the peer list routes the LAN subnet through the router,
    // so a ping to 192.168.77.7 would be forwarded via the router's
    // AllowedIPs.
    let map = serde_json::json!({
        "Version": 130,
        "NodeKey": peer_key.to_string(),
        "DiscoKey": peer_disco.to_string(),
        "Stream": false
    });
    let map_raw = post_json_raw(&mut peer_client, "/machine/map", &map).await;
    let host_map = decode_map(&map_raw);
    let peers = host_map["Peers"]
        .as_array()
        .expect("Peers must be an array");
    let router_peer = peers
        .iter()
        .find(|p| p["StableID"] == "n00000000000000000000001")
        .unwrap_or_else(|| panic!("router peer not advertised"));
    let allowed: Vec<String> = router_peer["AllowedIPs"]
        .as_array()
        .expect("AllowedIPs must be an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        allowed.contains(&"192.168.77.0/24".to_string()),
        "host must route the LAN subnet through the router: {allowed:?}"
    );
    assert_eq!(
        router_peer["PrimaryRoutes"][0],
        serde_json::json!("192.168.77.0/24")
    );

    // Keep the router's own map request exercised too: its PrimaryRoutes
    // advertise the subnet back to it.
    let map = serde_json::json!({
        "Version": 130,
        "NodeKey": router_key.to_string(),
        "DiscoKey": router_disco.to_string(),
        "Stream": false,
        "Hostinfo": { "Hostname": "router", "RoutableIPs": ["192.168.77.0/24"] }
    });
    let map_raw = post_json_raw(&mut router_client, "/machine/map", &map).await;
    let router_map = decode_map(&map_raw);
    let primary: Vec<String> = router_map["Node"]["PrimaryRoutes"]
        .as_array()
        .expect("PrimaryRoutes must be an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(primary.contains(&"192.168.77.0/24".to_string()));

    drop(router_task);
    drop(peer_task);
}

#[tokio::test]
async fn dns_reload_pushes_delta_to_live_map_session() {
    let dir = std::env::temp_dir().join(format!("crabscale-dns-push-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let records_path = dir.join("records.json");
    std::fs::write(
        &records_path,
        br#"[{ "name": "db.tailnet.example.", "type": "A", "value": "100.64.0.9" }]"#,
    )
    .unwrap();

    let mut config = ControlConfig::default();
    config.dns.extra_records_path = Some(records_path.clone());
    let plane = ControlPlane::new(config);

    let server = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(server.public_key().to_bytes());
    let router = ControlRouter::with_control(machine_key, plane.clone());
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

    let node_key = NodeKey::from_bytes([0x22; 32]);
    let disco_key = DiscoKey::from_bytes([0x33; 32]);

    // Register with the default test auth key.
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

    // Open a streaming map session (keepalive requested so the server enters
    // the select loop and can observe DNS changes).
    let map = crabscale_proto::MapRequest {
        version: 130,
        node_key,
        disco_key,
        stream: true,
        keep_alive: true,
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

    // First frame is the complete initial map.
    let chunk = body
        .data()
        .await
        .expect("initial map frame")
        .expect("data chunk");
    let (payload, consumed) = crabscale_proto::decode_map_response_frame(&chunk).unwrap();
    assert_eq!(consumed, chunk.len());
    let first: serde_json::Value = serde_json::from_slice(payload).unwrap();
    assert!(first.get("Node").is_some());
    assert!(first.get("DNS").is_some());

    // Hot-reload the extra records through the shared control plane clone.
    std::fs::write(
        &records_path,
        br#"[
            { "name": "db.tailnet.example.", "type": "A", "value": "100.64.0.9" },
            { "name": "wiki.tailnet.example.", "type": "AAAA", "value": "fd7a:115c:a1e0::9" }
        ]"#,
    )
    .unwrap();
    let count = plane.reload_dns_extra_records().unwrap();
    assert_eq!(count, 2);

    // The live session must receive a DNS delta frame.
    let chunk = body
        .data()
        .await
        .expect("dns delta frame")
        .expect("data chunk");
    let (payload, consumed) = crabscale_proto::decode_map_response_frame(&chunk).unwrap();
    assert_eq!(consumed, chunk.len());
    let delta: serde_json::Value = serde_json::from_slice(payload).unwrap();
    assert_eq!(
        delta["DNS"]["MagicDNSSuffix"],
        serde_json::json!("tailnet.example."),
        "the DNS delta must carry the MagicDNS suffix"
    );
    assert!(
        delta.get("Peers").is_none(),
        "a DNS delta must not repeat the peer list"
    );
    let names: Vec<&str> = delta["DNS"]["ExtraRecords"]
        .as_array()
        .expect("extra records")
        .iter()
        .map(|r| r["Name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"wiki.tailnet.example."),
        "reloaded records must be pushed to the live session: {names:?}"
    );

    drop(server_task);
    let _ = std::fs::remove_dir_all(&dir);
}
