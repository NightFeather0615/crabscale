//! Control router: outer `/key` and inner `/machine/*` endpoints.
//!
//! The outer `/key` endpoint is served over plain HTTP (or TLS in production)
//! and advertises the server's machine public key. The inner `/machine/*`
//! endpoints are served inside the HTTP/2-over-Noise connection and carry the
//! Noise machine key recovered from the handshake.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::bootstrap_dns::BootstrapDns;
use crate::oidc::{
    DEFAULT_OIDC_FLOW_LIMIT, DEFAULT_OIDC_FLOW_TTL_SECONDS, OidcClient, OidcFlowStore, now_unix,
};
use bytes::Bytes;
use crabscale_control::{ControlConfig, ControlError, ControlPlane, MapOutcome, SessionPeers};
use crabscale_proto::{
    LogoutRequest, MIN_SUPPORTED_CAPVER, MachineKey, MapRequest, RegisterRequest, VerifyRequest,
    VerifyResponse,
};
use crabscale_transport::{
    MAX_INNER_BODY_LEN, NoiseStream, TransportError, random_challenge, read_body_limited,
    serve_http2,
};
use h2::RecvStream;
use h2::server::SendResponse;
use http::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};

/// Maximum body accepted by `POST /verify` (Spec-Control-API `POST /verify`).
///
/// The limit is 4 KiB; the HTTP layer enforces it before the body reaches the
/// router, which re-checks it as defense in depth.
pub const VERIFY_MAX_BODY_LEN: usize = 4096;

/// A live streaming map session handed off from `handle_map` to the per-connection
/// writer task.
struct StreamSession {
    first_frame: Vec<u8>,
    keep_alive: bool,
    compress: bool,
    session_id: i64,
    node_id: i64,
    last_sent: SessionPeers,
}

/// Default keepalive interval for streaming map sessions.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(50);

/// How often the background session reaper advances lifecycle timers.
const REAP_INTERVAL: Duration = Duration::from_secs(1);

/// Router for the control API.
#[derive(Clone)]
pub struct ControlRouter {
    machine_key: MachineKey,
    control: Arc<ControlPlane>,
    /// Optional OIDC relying-party client; when present, `GET /register/{id}`
    /// redirects to the provider and `/oidc/callback` completes the flow.
    oidc: Option<Arc<OidcClient>>,
    /// Outstanding OIDC authorization flows keyed by CSRF state, shared across
    /// router clones so any connection can validate the callback.
    oidc_flows: Arc<Mutex<OidcFlowStore>>,
    /// Optional `/bootstrap-dns` snapshot served over the outer HTTP server.
    bootstrap_dns: Option<Arc<BootstrapDns>>,
}

impl ControlRouter {
    /// Create a router for the given server machine key with a default
    /// in-memory control plane (test auth key `hskey-auth-test-secret`).
    pub fn new(machine_key: MachineKey) -> Self {
        Self::with_control(machine_key, ControlPlane::new(ControlConfig::default()))
    }

    /// Create a router with an explicit control plane.
    pub fn with_control(machine_key: MachineKey, control: ControlPlane) -> Self {
        Self {
            machine_key,
            control: Arc::new(control),
            oidc: None,
            oidc_flows: Arc::new(Mutex::new(OidcFlowStore::new(
                DEFAULT_OIDC_FLOW_LIMIT,
                DEFAULT_OIDC_FLOW_TTL_SECONDS,
            ))),
            bootstrap_dns: None,
        }
    }

    /// Attach an OIDC relying-party client, enabling browser approval through
    /// the provider.
    pub fn with_oidc(mut self, oidc: OidcClient) -> Self {
        self.oidc = Some(Arc::new(oidc));
        self
    }

    /// Override the OIDC flow-store TTL (seconds).
    ///
    /// A negative value makes flows expire immediately, which the mock provider
    /// integration test uses to exercise expired-state rejection without
    /// waiting out the default ten minutes.
    pub fn with_oidc_flow_ttl(mut self, ttl_seconds: i64) -> Self {
        self.oidc_flows = Arc::new(Mutex::new(OidcFlowStore::new(
            DEFAULT_OIDC_FLOW_LIMIT,
            ttl_seconds,
        )));
        self
    }

    /// Attach a `/bootstrap-dns` snapshot served by the outer HTTP server.
    pub fn with_bootstrap_dns(mut self, bootstrap_dns: BootstrapDns) -> Self {
        self.bootstrap_dns = Some(Arc::new(bootstrap_dns));
        self
    }

    /// The machine key this router advertises and attaches to inner requests.
    pub fn machine_key(&self) -> MachineKey {
        self.machine_key
    }

    /// Spawn the single background session reaper for this control plane.
    ///
    /// The reaper periodically advances session lifecycle timers, emitting
    /// offline transitions and deleting expired ephemeral nodes. It is safe to
    /// call from every connection: only the first caller actually spawns the
    /// task, the rest are no-ops.
    pub fn spawn_reaper(&self) {
        if !self.control.claim_reaper() {
            return;
        }
        let control = self.control.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REAP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                control.reap_sessions();
            }
        });
        // One change-batcher sweeper per plane: it coalesces node/policy/DNS/
        // DERP changes into ordered delta batches for live map sessions.
        self.control.spawn_change_batcher();
    }

    /// Handle an outer `GET /key` request.
    ///
    /// Returns `200` with the machine key JSON when `v` is a supported
    /// capability version, or `400` with a plain-text body otherwise.
    pub fn handle_key(&self, capver: Option<&str>) -> Response<Bytes> {
        let supported = capver
            .and_then(|v| v.parse::<u32>().ok())
            .map(|v| v >= MIN_SUPPORTED_CAPVER)
            .unwrap_or(false);
        if !supported {
            return key_bad_request();
        }
        let body = serde_json::json!({
            "legacyPublicKey": "",
            "publicKey": self.machine_key.to_string(),
        });
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Bytes::from(body.to_string()))
            .expect("static response is valid")
    }

    /// Handle an outer `POST /verify` admission request.
    ///
    /// The body is limited to [`VERIFY_MAX_BODY_LEN`] bytes (enforced by the
    /// HTTP layer; re-checked here as defense in depth). An unknown or
    /// logged-out node key returns `{"Allow": false}` with `200`, never an
    /// error page (Spec-Control-API `POST /verify`).
    pub fn handle_verify(&self, body: &[u8]) -> Response<Bytes> {
        if body.len() > VERIFY_MAX_BODY_LEN {
            return plain_response(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
        }
        let request: VerifyRequest = match serde_json::from_slice(body) {
            Ok(request) => request,
            Err(_) => {
                return plain_response(StatusCode::BAD_REQUEST, "invalid verify request");
            }
        };
        let response = VerifyResponse {
            allow: self.control.node_is_authorized(&request.node_public),
        };
        let body = serde_json::to_vec(&response).unwrap_or_else(|_| b"{\"Allow\":false}".to_vec());
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Bytes::from(body))
            .expect("static response is valid")
    }

    /// Handle an outer `GET /bootstrap-dns` request.
    ///
    /// Serves the configured bootstrap DNS snapshot; when `q` names a known
    /// host only that entry is returned, otherwise the full map is returned
    /// so clients can discover names (Spec-Control-API, Bootstrap DNS).
    /// Returns `404` when no bootstrap DNS snapshot is configured.
    pub fn handle_bootstrap_dns(&self, q: Option<&str>) -> Response<Bytes> {
        let Some(dns) = &self.bootstrap_dns else {
            return plain_response(StatusCode::NOT_FOUND, "bootstrap DNS not configured");
        };
        let response = dns.handle(q);
        let (parts, body) = response.into_parts();
        Response::from_parts(parts, body.into_inner().unwrap_or_default())
    }

    /// Handle an outer `GET /register/{id}` approval page.
    ///
    /// When OIDC is configured, this endpoint begins the provider flow and
    /// redirects the browser to the provider's authorization endpoint
    /// (Spec-Registration §7). Otherwise it returns a minimal HTML page
    /// describing the pending registration. Unknown or expired ids return 404.
    pub fn handle_register_page(&self, auth_id: &str) -> Response<Bytes> {
        let pending = match self.control.pending_info(auth_id) {
            Ok(Some(pending)) => pending,
            Ok(None) => {
                return plain_response(StatusCode::NOT_FOUND, "pending registration not found");
            }
            Err(_) => {
                return plain_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
            }
        };
        if let Some(oidc) = &self.oidc {
            let (state, flow) = self.oidc_flows.lock().unwrap().begin(auth_id, now_unix());
            match oidc.authorization_url(&state, &flow.nonce) {
                Ok(location) => return redirect_response(&location),
                Err(e) => {
                    eprintln!("oidc: failed to build authorization URL for {auth_id}: {e}");
                    return plain_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to start OIDC authorization",
                    );
                }
            }
        }
        let hostname = pending
            .hostinfo
            .as_ref()
            .map(|h| h.hostname.as_str())
            .unwrap_or("unknown");
        // Host metadata is supplied by the (unauthenticated) client, so escape
        // every interpolated value before placing it in the HTML page.
        let auth_id_escaped = escape_html(auth_id);
        let hostname_escaped = escape_html(hostname);
        let expires_escaped = escape_html(&pending.expires_at);
        let html = format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Pending registration</title></head>             <body><h1>Pending registration</h1>             <p>Auth id: <code>{auth_id_escaped}</code></p>             <p>Hostname: <code>{hostname_escaped}</code></p>             <p>Expires: <code>{expires_escaped}</code></p>             <p>Approve or reject this registration with the <code>crabscale auth</code> CLI.</p>             </body></html>"
        );
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Bytes::from(html))
            .expect("static response is valid")
    }

    /// Handle an outer `GET /oidc/callback` completing the OIDC flow.
    ///
    /// Validates the CSRF state and nonce, exchanges the authorization code,
    /// verifies the ID token, upserts the user profile, and approves the
    /// pending registration through the same auth cache as CLI approval.
    /// Unknown, expired, or reused state is rejected with `400` so a stale or
    /// replayed callback can never authorize a registration.
    pub async fn handle_oidc_callback(&self, query: &str) -> Response<Bytes> {
        let Some(oidc) = &self.oidc else {
            return plain_response(StatusCode::NOT_FOUND, "oidc not configured");
        };
        let params = parse_query(query);
        if let Some(error) = params.get("error") {
            eprintln!("oidc: provider reported error: {error}");
            return plain_response(StatusCode::BAD_REQUEST, "oidc provider reported an error");
        }
        let (Some(state), Some(code)) = (params.get("state"), params.get("code")) else {
            return plain_response(StatusCode::BAD_REQUEST, "missing state or code");
        };
        let flow = match self.oidc_flows.lock().unwrap().take(state, now_unix()) {
            Some(flow) => flow,
            None => {
                return plain_response(
                    StatusCode::BAD_REQUEST,
                    "invalid, expired, or reused OIDC state",
                );
            }
        };
        let pending_still_valid = matches!(self.control.pending_info(&flow.auth_id), Ok(Some(_)));
        if !pending_still_valid {
            return plain_response(StatusCode::BAD_REQUEST, "registration is no longer pending");
        };
        let oidc_client = oidc.clone();
        let flow_clone = flow.clone();
        let code = code.to_string();
        let exchanged =
            tokio::task::spawn_blocking(move || oidc_client.complete(&flow_clone, &code)).await;
        let profile = match exchanged {
            Ok(Ok(profile)) => profile,
            Ok(Err(e)) => {
                eprintln!("oidc: callback validation failed for {}: {e}", flow.auth_id);
                return plain_response(StatusCode::BAD_REQUEST, "OIDC callback validation failed");
            }
            Err(_) => {
                return plain_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "OIDC exchange task failed",
                );
            }
        };
        match self.control.upsert_oidc_user(&profile) {
            Ok(_user_id) => match self.control.approve_pending(&flow.auth_id, &profile.email) {
                Ok(()) => {
                    let email_escaped = escape_html(&profile.email);
                    let html = format!(
                        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Registration approved</title></head><body><h1>Registration approved</h1><p>The node is now authorized to join the tailnet.</p><p>Login: <code>{email_escaped}</code></p></body></html>"
                    );
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/html; charset=utf-8")
                        .body(Bytes::from(html))
                        .expect("static response is valid")
                }
                Err(e) => {
                    eprintln!("oidc: approval failed for {}: {e}", flow.auth_id);
                    plain_response(StatusCode::BAD_REQUEST, "registration is no longer pending")
                }
            },
            Err(e) => {
                eprintln!("oidc: user upsert failed for {}: {e}", flow.auth_id);
                plain_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to record OIDC identity",
                )
            }
        }
    }

    /// Handle an inner `/machine/*` request.
    pub async fn handle_inner(
        &self,
        request: Request<RecvStream>,
        mut respond: SendResponse<Bytes>,
        machine_key: MachineKey,
    ) {
        let (parts, mut body) = request.into_parts();
        let method = parts.method.clone();
        let path = parts.uri.path().to_string();

        let body_bytes = match read_body_limited(&mut body, MAX_INNER_BODY_LEN).await {
            Ok(b) => b,
            Err(TransportError::BodyTooLarge) => {
                send_plain(
                    &mut respond,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    b"body too large",
                );
                return;
            }
            Err(_) => {
                send_plain(
                    &mut respond,
                    StatusCode::BAD_REQUEST,
                    b"invalid request body",
                );
                return;
            }
        };

        // Parse the SSH action path once; the guard and the dispatch arm use
        // the same computed value.
        let ssh_action_path = parse_ssh_action_path(&path);
        match (method.as_str(), path.as_str()) {
            ("GET", "/machine/whoami") => {
                let body = serde_json::json!({
                    "machineKey": machine_key.to_string(),
                    "protocolVersion": self.control.protocol_version(),
                });
                send_json(&mut respond, StatusCode::OK, body.to_string().into_bytes());
            }
            ("POST", "/machine/register") => {
                self.handle_register(&mut respond, machine_key, &body_bytes)
                    .await;
            }
            ("POST", "/machine/map") => {
                self.handle_map(&mut respond, machine_key, &body_bytes)
                    .await;
            }
            ("POST", "/machine/logout") => {
                self.handle_logout(&mut respond, machine_key, &body_bytes)
                    .await;
            }
            ("GET", _) if ssh_action_path.is_some() => {
                let (src, dst) = ssh_action_path.expect("guarded as some");
                self.handle_ssh_action(&mut respond, machine_key, &parts.uri, src, dst)
                    .await;
            }
            ("POST", "/machine/set-dns")
            | ("PATCH", "/machine/set-device-attr")
            | ("POST", "/machine/audit-log")
            | ("POST", "/machine/id-token")
            | ("POST", "/machine/feature/query")
            | ("POST", "/machine/update-health")
            | ("POST", "/machine/c2n") => {
                send_plain(
                    &mut respond,
                    StatusCode::NOT_IMPLEMENTED,
                    b"not implemented",
                );
            }
            _ => {
                send_plain(&mut respond, StatusCode::NOT_FOUND, b"not found");
            }
        }
    }

    async fn handle_ssh_action(
        &self,
        respond: &mut SendResponse<Bytes>,
        machine_key: MachineKey,
        uri: &http::Uri,
        src_node_id: u64,
        dst_node_id: u64,
    ) {
        let query = uri.query().unwrap_or("");
        let params = parse_query(query);
        let auth_id = params.get("auth_id").map(String::as_str);
        let ssh_user = params.get("ssh_user").cloned().unwrap_or_default();
        let local_user = params.get("local_user").cloned().unwrap_or_default();

        match self
            .control
            .handle_ssh_action(
                machine_key,
                src_node_id,
                dst_node_id,
                auth_id,
                &ssh_user,
                &local_user,
            )
            .await
        {
            Ok(action) => {
                let body = serde_json::to_vec(&action).unwrap_or_default();
                send_json(respond, StatusCode::OK, body);
            }
            Err(ControlError::NotFound) => {
                send_plain(respond, StatusCode::NOT_FOUND, b"node or auth not found");
            }
            Err(ControlError::Unauthorized) => {
                send_plain(respond, StatusCode::UNAUTHORIZED, b"unauthorized");
            }
            Err(ControlError::SshBinding(_)) => {
                send_plain(respond, StatusCode::BAD_REQUEST, b"ssh binding mismatch");
            }
            Err(ControlError::Timeout) => {
                send_plain(
                    respond,
                    StatusCode::REQUEST_TIMEOUT,
                    b"ssh approval timed out",
                );
            }
            Err(_) => {
                send_plain(
                    respond,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    b"internal error",
                );
            }
        }
    }

    async fn handle_register(
        &self,
        respond: &mut SendResponse<Bytes>,
        machine_key: MachineKey,
        body: &[u8],
    ) {
        let request: RegisterRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(_) => {
                send_plain(
                    respond,
                    StatusCode::BAD_REQUEST,
                    b"invalid register request",
                );
                return;
            }
        };
        let response = self.control.register(machine_key, request);
        let body = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
        send_json(respond, StatusCode::OK, body);
    }

    async fn handle_logout(
        &self,
        respond: &mut SendResponse<Bytes>,
        machine_key: MachineKey,
        body: &[u8],
    ) {
        let request: LogoutRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(_) => {
                send_plain(respond, StatusCode::BAD_REQUEST, b"invalid logout request");
                return;
            }
        };
        match self.control.logout(machine_key, &request.node_key) {
            Ok(response) => {
                let body = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
                send_json(respond, StatusCode::OK, body);
            }
            Err(ControlError::NotFound) => {
                send_plain(respond, StatusCode::NOT_FOUND, b"node not found");
            }
            Err(_) => {
                send_plain(
                    respond,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    b"internal error",
                );
            }
        }
    }

    async fn handle_map(
        &self,
        respond: &mut SendResponse<Bytes>,
        machine_key: MachineKey,
        body: &[u8],
    ) {
        let request: MapRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(_) => {
                send_plain(respond, StatusCode::BAD_REQUEST, b"invalid map request");
                return;
            }
        };
        match self.control.handle_map(machine_key, request) {
            Ok(MapOutcome::LiteUpdate) => {
                send_empty(respond, StatusCode::OK);
            }
            Ok(MapOutcome::FullFrame(frame)) => {
                send_bytes(respond, StatusCode::OK, frame);
            }
            Ok(MapOutcome::Stream {
                first_frame,
                keep_alive,
                compress,
                session_id,
                node_id,
                initial_peers,
            }) => {
                self.send_stream(
                    respond,
                    StreamSession {
                        first_frame,
                        keep_alive,
                        compress,
                        session_id,
                        node_id,
                        last_sent: initial_peers,
                    },
                )
                .await;
            }
            Err(ControlError::NotFound) => {
                send_plain(respond, StatusCode::NOT_FOUND, b"node not found");
            }
            Err(ControlError::UnsupportedVersion(_)) => {
                send_plain(
                    respond,
                    StatusCode::BAD_REQUEST,
                    b"unsupported capability version",
                );
            }
            Err(ControlError::InvalidEndpointTypes) => {
                send_plain(
                    respond,
                    StatusCode::BAD_REQUEST,
                    b"endpoint_types length does not match endpoints length",
                );
            }
            Err(_) => {
                send_plain(
                    respond,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    b"internal error",
                );
            }
        }
    }

    async fn send_stream(
        &self,
        respond: &mut SendResponse<Bytes>,
        session: StreamSession,
    ) {
        let StreamSession {
            first_frame,
            keep_alive,
            compress,
            session_id,
            node_id,
            mut last_sent,
        } = session;
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .body(())
            .expect("static response is valid");
        let mut send = match respond.send_response(response, false) {
            Ok(s) => s,
            Err(_) => {
                self.control.close_session(session_id);
                return;
            }
        };
        if send.send_data(Bytes::from(first_frame), false).is_err() {
            self.control.close_session(session_id);
            return;
        }
        if !keep_alive {
            let _ = send.send_data(Bytes::new(), true);
            self.control.close_session(session_id);
            return;
        }

        // Subscribe to the unified change bus. Node, policy, DNS, and DERP
        // changes are coalesced per node within a short batch window and
        // delivered to this session as one ordered ChangeBatch; the control
        // plane diff-s them against this session's last-sent peer set so an
        // endpoint change produces a patch rather than a full peer list.
        let mut changes = self.control.subscribe_changes();

        loop {
            // Spec-NetMap section 5: keepalive every 50s plus 0-9s random
            // jitter; a change batch interrupts the wait and pushes a delta.
            let jitter = Duration::from_secs(rand::random::<u64>() % 10);
            let sleep = std::pin::pin!(tokio::time::sleep(KEEPALIVE_INTERVAL + jitter));
            tokio::select! {
                _ = sleep => {
                    let frame = match self.control.keepalive_frame(compress) {
                        Ok(f) => f,
                        Err(_) => break,
                    };
                    if send.send_data(Bytes::from(frame), false).is_err() {
                        break;
                    }
                }
                batch = changes.recv() => {
                    match batch {
                        Ok(batch) => {
                            if batch.is_empty() {
                                continue;
                            }
                            let response = match self.control.build_delta(
                                node_id, &batch, &mut last_sent,
                            ) {
                                Ok(Some(response)) => response,
                                // Nothing for this session (e.g. an unrelated
                                // node changed, or DNS with nothing to push).
                                Ok(None) => continue,
                                Err(_) => continue,
                            };
                            let frame = match self.control.encode_frame(&response, compress) {
                                Ok(f) => f,
                                Err(_) => continue,
                            };
                            if send.send_data(Bytes::from(frame), false).is_err() {
                                break;
                            }
                        }
                        // Lagged: a batch was missed; the next one re-derives
                        // against the session's actual last-sent peer set, and
                        // a full-map fallback remains available to clients.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        // The control plane is gone; stop streaming.
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
        self.control.close_session(session_id);
    }
}

/// Serve the inner HTTP/2-over-Noise control router on a Noise stream.
pub async fn serve_control<T>(
    stream: NoiseStream<T>,
    router: ControlRouter,
) -> Result<(), TransportError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    router.spawn_reaper();
    let machine_key = router.machine_key();
    let challenge = random_challenge();
    serve_http2(
        stream,
        machine_key,
        challenge,
        move |request, respond, key| {
            let router = router.clone();
            async move {
                router.handle_inner(request, respond, key).await;
            }
        },
    )
    .await
}

/// Parse `/machine/ssh/action/{src}/to/{dst}` into `(src, dst)` node ids.
fn parse_ssh_action_path(path: &str) -> Option<(u64, u64)> {
    // Only the path component matters; a query string (if any) is stripped.
    let path = path.split('?').next().unwrap_or(path);
    let rest = path.strip_prefix("/machine/ssh/action/")?;
    let (src, to) = rest.split_once("/to/")?;
    let src = src.parse::<u64>().ok()?;
    let dst = to.parse::<u64>().ok()?;
    Some((src, dst))
}

/// Parse a URL query string into a decoded key/value map.
fn parse_query(query: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(percent_decode(key), percent_decode(value));
    }
    map
}

/// Percent-decode a URL query component (`%XX` and `+` for space).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
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

/// Decode a single hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn send_plain(respond: &mut SendResponse<Bytes>, status: StatusCode, text: &'static [u8]) {
    let response = Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(())
        .expect("static response is valid");
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    let _ = send.send_data(Bytes::from_static(text), true);
}

fn send_json(respond: &mut SendResponse<Bytes>, status: StatusCode, body: Vec<u8>) {
    let response = Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(())
        .expect("static response is valid");
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    let _ = send.send_data(Bytes::from(body), true);
}

fn send_bytes(respond: &mut SendResponse<Bytes>, status: StatusCode, body: Vec<u8>) {
    let response = Response::builder()
        .status(status)
        .header("Content-Type", "application/octet-stream")
        .body(())
        .expect("static response is valid");
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    let _ = send.send_data(Bytes::from(body), true);
}

fn send_empty(respond: &mut SendResponse<Bytes>, status: StatusCode) {
    let response = Response::builder()
        .status(status)
        .body(())
        .expect("static response is valid");
    let _ = respond.send_response(response, true);
}

fn key_bad_request() -> Response<Bytes> {
    plain_response(
        StatusCode::BAD_REQUEST,
        "missing or unsupported capability version",
    )
}

/// Escape text for safe inclusion in an HTML text node.
fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn plain_response(status: StatusCode, text: &'static str) -> Response<Bytes> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Bytes::from_static(text.as_bytes()))
        .expect("static response is valid")
}

/// A `302 Found` redirect response, used to start the OIDC provider flow.
fn redirect_response(location: &str) -> Response<Bytes> {
    let location = match http::HeaderValue::from_str(location) {
        Ok(value) => value,
        Err(_) => {
            return plain_response(StatusCode::INTERNAL_SERVER_ERROR, "invalid redirect target");
        }
    };
    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", location)
        .body(Bytes::new())
        .expect("static response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabscale_control::{ControlConfig, ControlPlane};
    use crabscale_proto::{Hostinfo, MachineKey, NodeKey, RegisterAuth, RegisterRequest};

    fn test_key() -> MachineKey {
        MachineKey::from_bytes([0x42; 32])
    }

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

    #[test]
    fn key_endpoint_returns_expected_json() {
        let router = ControlRouter::new(test_key());
        let response = router.handle_key(Some("130"));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/json");
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["legacyPublicKey"], "");
        assert_eq!(body["publicKey"], test_key().to_string());
    }

    #[test]
    fn key_endpoint_rejects_missing_version() {
        let router = ControlRouter::new(test_key());
        assert_eq!(router.handle_key(None).status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn key_endpoint_rejects_unsupported_version() {
        let router = ControlRouter::new(test_key());
        assert_eq!(
            router.handle_key(Some("112")).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            router.handle_key(Some("abc")).status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn verify_allows_registered_node_and_denies_unknown() {
        let plane = ControlPlane::new(ControlConfig::default());
        let router = ControlRouter::with_control(test_key(), plane.clone());
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
        assert!(plane.register(test_key(), request).machine_authorized);

        let allowed = router.handle_verify(
            &serde_json::to_vec(&VerifyRequest {
                node_public: NodeKey::from_bytes([0x22; 32]),
            })
            .unwrap(),
        );
        assert_eq!(allowed.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(allowed.body()).unwrap();
        assert_eq!(
            json["Allow"],
            serde_json::json!(true),
            "known node is allowed"
        );

        let denied = router.handle_verify(
            &serde_json::to_vec(&VerifyRequest {
                node_public: NodeKey::from_bytes([0x99; 32]),
            })
            .unwrap(),
        );
        assert_eq!(denied.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(denied.body()).unwrap();
        assert_eq!(
            json["Allow"],
            serde_json::json!(false),
            "unknown node key is denied, not an error"
        );
    }

    #[test]
    fn verify_rejects_malformed_and_oversized_body() {
        let router = ControlRouter::new(test_key());
        assert_eq!(
            router.handle_verify(b"not json").status(),
            StatusCode::BAD_REQUEST
        );
        let oversized = vec![b'x'; VERIFY_MAX_BODY_LEN + 1];
        assert_eq!(
            router.handle_verify(&oversized).status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn bootstrap_dns_serves_configured_snapshot() {
        use crate::bootstrap_dns::BootstrapDns;
        use std::collections::BTreeMap;
        use std::net::{IpAddr, Ipv4Addr};

        let router = ControlRouter::new(test_key()).with_bootstrap_dns(BootstrapDns::from_entries(
            BTreeMap::from([(
                "derp.example.com".to_string(),
                vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            )]),
        ));
        let response = router.handle_bootstrap_dns(Some("derp.example.com"));
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(json["derp.example.com"][0], serde_json::json!("192.0.2.1"));
    }

    #[test]
    fn bootstrap_dns_unconfigured_returns_404() {
        let router = ControlRouter::new(test_key());
        assert_eq!(
            router.handle_bootstrap_dns(None).status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn register_page_returns_html_for_known_id() {
        let plane = ControlPlane::new(ControlConfig::default());
        let router_machine_key = test_key();
        let router = ControlRouter::with_control(router_machine_key, plane.clone());
        let auth_id = start_pending(&plane, router_machine_key);

        let response = router.handle_register_page(&auth_id);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "text/html; charset=utf-8"
        );
        let body = String::from_utf8(response.body().to_vec()).unwrap();
        assert!(body.contains(&auth_id));
        assert!(body.contains("node1"));
        assert!(body.contains("<title>Pending registration</title>"));
    }

    #[test]
    fn register_page_returns_404_for_unknown_id() {
        let router = ControlRouter::new(test_key());
        let response = router.handle_register_page("does-not-exist");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["content-type"], "text/plain");
    }

    #[test]
    fn register_page_escapes_hostname() {
        let plane = ControlPlane::new(ControlConfig::default());
        let router_machine_key = test_key();
        let router = ControlRouter::with_control(router_machine_key, plane.clone());
        let request = RegisterRequest {
            version: 130,
            node_key: NodeKey::from_bytes([0x22; 32]),
            auth: Some(RegisterAuth {
                auth_key: "wrong".to_string(),
            }),
            hostinfo: Some(Hostinfo {
                hostname: "<script>alert(1)</script>".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let response = plane.register(router_machine_key, request);
        let auth_id = crabscale_control::auth_id_from_followup(&response.auth_url).unwrap();

        let page = router.handle_register_page(&auth_id);
        let body = String::from_utf8(page.body().to_vec()).unwrap();
        assert!(!body.contains("<script>"));
        assert!(body.contains("&lt;script&gt;"));
    }

    #[test]
    fn escape_html_escapes_special_characters() {
        assert_eq!(
            escape_html("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn parses_ssh_action_path() {
        assert_eq!(
            parse_ssh_action_path("/machine/ssh/action/3/to/9"),
            Some((3, 9))
        );
        assert_eq!(
            parse_ssh_action_path("/machine/ssh/action/12/to/34?auth_id=x"),
            Some((12, 34))
        );
        assert_eq!(parse_ssh_action_path("/machine/map"), None);
        assert_eq!(parse_ssh_action_path("/machine/ssh/action/a/to/9"), None);
    }

    #[test]
    fn parses_and_decodes_query() {
        let params = parse_query("auth_id=abc123&ssh_user=root&local_user=admin");
        assert_eq!(params["auth_id"], "abc123");
        assert_eq!(params["ssh_user"], "root");
        assert_eq!(params["local_user"], "admin");

        let encoded = parse_query("ssh_user=ro%20ot&local_user=a+b");
        assert_eq!(encoded["ssh_user"], "ro ot");
        assert_eq!(encoded["local_user"], "a b");
    }
}
