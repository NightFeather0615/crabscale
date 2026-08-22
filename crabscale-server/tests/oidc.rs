//! Integration tests for OIDC registration approval.
//!
//! A mock OpenID Connect provider runs in-process on a loopback address and
//! serves discovery, authorization, and token endpoints. The authorization
//! code flow is driven end to end: the register page redirects to the mock
//! provider, the (simulated) browser follows back to `/oidc/callback`, and
//! the callback approves the pending registration through the same auth cache
//! the CLI uses.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::Mutex;

use bytes::Bytes;
use crabscale_control::{ControlConfig, ControlPlane, generate_secret};
use crabscale_proto::{Hostinfo, MachineKey, NodeKey, RegisterAuth, RegisterRequest};
use crabscale_server::{ControlRouter, OidcClient, OidcConfig, ServerKey, serve_on_addr};
use crabscale_transport::NoiseResponder;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CLIENT_ID: &str = "mock-client";
const CLIENT_SECRET: &str = "mock-secret";
/// A callback address that is never contacted: the test drives the callback
/// directly against the real server address instead of following the redirect.
const DUMMY_REDIRECT: &str = "http://127.0.0.1:9/oidc/callback";

/// A map of authorization codes to the `(nonce, state)` the provider bound
/// them to when the browser "logged in".
type CodeBindings = Arc<Mutex<HashMap<String, (String, String)>>>;

/// The in-process mock OpenID Connect provider.
struct MockProvider {
    issuer: String,
    code_bindings: CodeBindings,
}

impl MockProvider {
    fn new(addr: std::net::SocketAddr) -> Self {
        Self {
            issuer: format!("http://{addr}"),
            code_bindings: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn discovery(&self) -> serde_json::Value {
        serde_json::json!({
            "issuer": self.issuer,
            "authorization_endpoint": format!("{}/authorize", self.issuer),
            "token_endpoint": format!("{}/token", self.issuer),
            "jwks_uri": format!("{}/jwks", self.issuer),
            "id_token_signing_alg_values_supported": ["HS256"],
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
        })
    }

    /// Mint an HS256 ID token for the code's bound nonce.
    fn id_token_for(&self, code: &str) -> Option<String> {
        let (nonce, _state) = self.code_bindings.lock().unwrap().get(code)?.clone();
        let now = crabscale_server::oidc::now_unix();
        let claims = serde_json::json!({
            "iss": self.issuer,
            "sub": "user-1234",
            "aud": CLIENT_ID,
            "exp": now + 3600,
            "iat": now,
            "nonce": nonce,
            "email": "alice@example.com",
            "name": "Alice Example",
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(CLIENT_SECRET.as_bytes()),
        )
        .ok()
    }
}

/// Start the mock provider and return its bound address.
async fn start_mock_provider() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let provider = Arc::new(MockProvider::new(addr));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let provider = provider.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| handle_mock_request(req, provider.clone()));
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    addr
}

async fn handle_mock_request(
    req: Request<Incoming>,
    provider: Arc<MockProvider>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    if method == Method::GET && path == "/.well-known/openid-configuration" {
        return Ok(json_response(StatusCode::OK, provider.discovery()));
    }
    if method == Method::GET && path == "/authorize" {
        let pairs = query_pairs(req.uri().query().unwrap_or(""));
        let nonce = pairs.get("nonce").cloned().unwrap_or_default();
        let state = pairs.get("state").cloned().unwrap_or_default();
        let redirect_uri = pairs.get("redirect_uri").cloned().unwrap_or_default();
        let code = format!("code-{}", generate_secret());
        provider
            .code_bindings
            .lock()
            .unwrap()
            .insert(code.clone(), (nonce, state.clone()));
        let mut target = url::Url::parse(&redirect_uri).unwrap();
        target
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &state);
        return Ok(redirect_response(target.as_str()));
    }
    if method == Method::POST && path == "/token" {
        let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body_bytes).into_owned();
        let form = parse_form(&body);
        let code = form.get("code").map(String::as_str).unwrap_or("");
        return match provider.id_token_for(code) {
            Some(id_token) => Ok(json_response(
                StatusCode::OK,
                serde_json::json!({
                    "access_token": "access-1",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "id_token": id_token,
                }),
            )),
            None => Ok(json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "error": "invalid_grant" }),
            )),
        };
    }
    Ok(text_response(StatusCode::NOT_FOUND, "not found"))
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(value.to_string())))
        .unwrap()
}

fn redirect_response(location: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", location)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn text_response(status: StatusCode, text: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(text.to_string())))
        .unwrap()
}

fn parse_form(body: &str) -> HashMap<String, String> {
    query_pairs(body)
}

/// Parse a `k=v&k=v` query/form string into a decoded map.
fn query_pairs(query: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        };
        out.insert(k, v);
    }
    out
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Start a crabscale server wired to OIDC and return `(addr, handle)`.
async fn start_crabscale(
    plane: ControlPlane,
    oidc: OidcClient,
    flow_ttl: Option<i64>,
) -> (std::net::SocketAddr, crabscale_server::ServerHandle) {
    let responder = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(responder.public_key().to_bytes());
    let server_key = ServerKey::new(responder, machine_key);
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let router = build_router(plane, oidc, flow_ttl);
    let (addr, handle) = serve_on_addr(bind, router, server_key).await.unwrap();
    (addr, handle)
}

fn build_router(plane: ControlPlane, oidc: OidcClient, flow_ttl: Option<i64>) -> ControlRouter {
    let router =
        ControlRouter::with_control(MachineKey::from_bytes([0x42; 32]), plane).with_oidc(oidc);
    match flow_ttl {
        Some(ttl) => router.with_oidc_flow_ttl(ttl),
        None => router,
    }
}

/// Build an OIDC client for the mock provider issuing HS256 tokens.
///
/// Discovery performs a blocking HTTP call, so it runs on a blocking thread to
/// keep the mock provider's tokio task able to respond.
async fn mock_oidc_client(mock_addr: &std::net::SocketAddr) -> OidcClient {
    let issuer = format!("http://{mock_addr}");
    tokio::task::spawn_blocking(move || {
        OidcClient::discover(OidcConfig {
            issuer,
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
            redirect_uri: DUMMY_REDIRECT.to_string(),
            scope: "openid profile email".to_string(),
        })
        .unwrap()
    })
    .await
    .unwrap()
}

/// Start a pending interactive registration and return its auth id.
fn start_pending(plane: &ControlPlane) -> String {
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
    let response = plane.register(MachineKey::from_bytes([0x42; 32]), request);
    assert!(!response.machine_authorized);
    crabscale_control::auth_id_from_followup(&response.auth_url).unwrap()
}

/// Run a raw HTTP/1.1 GET and return `(start_line, head, body)`.
async fn http_get(addr: &std::net::SocketAddr, path: &str) -> (String, String, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let (head, body) = read_http_response(&mut stream).await;
    let start_line = head.lines().next().unwrap_or("").to_string();
    (start_line, head, body)
}

/// Read an HTTP/1.1 response head and body using Content-Length.
async fn read_http_response<S>(stream: &mut S) -> (String, String)
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
    (head, String::from_utf8(body).unwrap())
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

/// Extract a `Location` header value from a raw response head.
fn location_from(head: &str) -> String {
    head.lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("location:")
                .map(|v| v.trim().to_string())
        })
        .expect("Location header")
}

/// Follow the provider's authorize URL (browser half of the flow) and return
/// the `code` and `state` the provider redirects back with.
async fn follow_authorize(
    mock_addr: &std::net::SocketAddr,
    authorize_url: &str,
) -> (String, String) {
    let path = {
        let parsed = url::Url::parse(authorize_url).unwrap();
        match parsed.query() {
            Some(q) => format!("{}?{q}", parsed.path()),
            None => parsed.path().to_string(),
        }
    };
    let (_start, head, _body) = http_get(mock_addr, &path).await;
    let location = location_from(&head);
    let parsed = url::Url::parse(&location).unwrap();
    let params: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    (params["code"].clone(), params["state"].clone())
}

/// The full OIDC flow approves a pending registration and the node follows up.
#[tokio::test]
async fn oidc_flow_approves_pending_registration() {
    let mock_addr = start_mock_provider().await;
    let plane = ControlPlane::new(ControlConfig::default());
    let auth_id = start_pending(&plane);
    let oidc = mock_oidc_client(&mock_addr).await;
    let (addr, handle) = start_crabscale(plane.clone(), oidc, None).await;

    // 1. The register page redirects to the provider's authorization endpoint.
    let (start_line, head, _) = http_get(&addr, &format!("/register/{auth_id}")).await;
    assert!(
        start_line.contains("302"),
        "expected redirect: {start_line}"
    );
    let authorize_url = location_from(&head);
    let authorize = url::Url::parse(&authorize_url).unwrap();
    let params: HashMap<String, String> = authorize.query_pairs().into_owned().collect();
    let state = params["state"].clone();
    let nonce = params["nonce"].clone();
    assert_eq!(params["client_id"], CLIENT_ID);
    assert_eq!(params["response_type"], "code");

    // 2. The browser follows to the provider, which redirects back with a code
    //    bound to the authorize request's nonce.
    let (code, returned_state) = follow_authorize(&mock_addr, &authorize_url).await;
    assert_eq!(returned_state, state);

    // 3. The callback completes the code exchange and approves the pending
    //    registration.
    let (start_line_cb, _cb_head, cb_body) =
        http_get(&addr, &format!("/oidc/callback?code={code}&state={state}")).await;
    assert!(
        start_line_cb.contains("200"),
        "expected success: {start_line_cb}"
    );
    assert!(cb_body.contains("approved"));

    // 4. The client's followup poll now authorizes the node.
    let node_key = NodeKey::from_bytes([0x22; 32]);
    let followup = RegisterRequest {
        version: 130,
        node_key,
        followup: format!("https://tailnet.example/register/{auth_id}"),
        ..Default::default()
    };
    let response = plane.register(MachineKey::from_bytes([0x42; 32]), followup);
    assert!(response.machine_authorized);

    // Profile upsert details are covered by crabscale-control unit tests;
    // here the approved node proves the flow completed end to end.

    // 5. Replaying the same state is rejected: it was consumed on step 3.
    let (start_line_again, _, _) =
        http_get(&addr, &format!("/oidc/callback?code={code}&state={state}")).await;
    assert!(
        start_line_again.contains("400"),
        "reuse must be rejected: {start_line_again}"
    );

    let _ = nonce;
    handle.shutdown();
}

/// An expired CSRF state is rejected by the callback.
#[tokio::test]
async fn expired_oidc_state_is_rejected() {
    let mock_addr = start_mock_provider().await;
    let plane = ControlPlane::new(ControlConfig::default());
    let auth_id = start_pending(&plane);
    let oidc = mock_oidc_client(&mock_addr).await;
    // A negative TTL makes every flow already expired at issuance.
    let (addr, handle) = start_crabscale(plane.clone(), oidc, Some(-1)).await;

    let (start_line, head, _) = http_get(&addr, &format!("/register/{auth_id}")).await;
    assert!(
        start_line.contains("302"),
        "expected redirect: {start_line}"
    );
    let authorize_url = location_from(&head);
    let authorize = url::Url::parse(&authorize_url).unwrap();
    let params: HashMap<String, String> = authorize.query_pairs().into_owned().collect();
    let state = params["state"].clone();

    let (code, _returned_state) = follow_authorize(&mock_addr, &authorize_url).await;

    let (start_line_cb, _, cb_body) =
        http_get(&addr, &format!("/oidc/callback?code={code}&state={state}")).await;
    assert!(
        start_line_cb.contains("400"),
        "expired state must be rejected: {start_line_cb}"
    );
    assert!(cb_body.contains("invalid, expired, or reused"));

    handle.shutdown();
}

/// A callback without OIDC configured is a 404 and leaves no approval.
#[tokio::test]
async fn callback_without_oidc_is_not_found() {
    let plane = ControlPlane::new(ControlConfig::default());
    let responder = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(responder.public_key().to_bytes());
    let server_key = ServerKey::new(responder, machine_key);
    let router = ControlRouter::with_control(machine_key, plane.clone());
    let auth_id = start_pending(&plane);
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (addr, handle) = serve_on_addr(bind, router, server_key).await.unwrap();

    let (start_line, _, _) = http_get(&addr, "/oidc/callback?code=x&state=y").await;
    assert!(start_line.contains("404"), "unexpected: {start_line}");

    // Without OIDC the register page stays informational (200 HTML), not a
    // redirect to a provider.
    let (start_line_page, _, body) = http_get(&addr, &format!("/register/{auth_id}")).await;
    assert!(
        start_line_page.contains("200"),
        "unexpected: {start_line_page}"
    );
    assert!(body.contains("Pending registration"));

    handle.shutdown();
}
