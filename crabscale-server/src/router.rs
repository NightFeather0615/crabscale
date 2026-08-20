//! Control router: outer `/key` and inner `/machine/*` endpoints.
//!
//! The outer `/key` endpoint is served over plain HTTP (or TLS in production)
//! and advertises the server's machine public key. The inner `/machine/*`
//! endpoints are served inside the HTTP/2-over-Noise connection and carry the
//! Noise machine key recovered from the handshake.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use crabscale_control::{ControlConfig, ControlError, ControlPlane, MapOutcome};
use crabscale_proto::{MachineKey, MapRequest, RegisterRequest};
use crabscale_transport::{
    MAX_INNER_BODY_LEN, NoiseStream, TransportError, random_challenge, read_body_limited,
    serve_http2,
};
use h2::RecvStream;
use h2::server::SendResponse;
use http::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};

/// The protocol version reported by `/machine/whoami`.
pub const PROTOCOL_VERSION: u16 = 130;

/// Default keepalive interval for streaming map sessions.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(50);

/// Router for the control API.
#[derive(Clone)]
pub struct ControlRouter {
    machine_key: MachineKey,
    control: Arc<ControlPlane>,
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
        }
    }

    /// The machine key this router advertises and attaches to inner requests.
    pub fn machine_key(&self) -> MachineKey {
        self.machine_key
    }

    /// Handle an outer `GET /key` request.
    ///
    /// Returns `200` with the machine key JSON when `v` is a supported
    /// capability version, or `400` with a plain-text body otherwise.
    pub fn handle_key(&self, capver: Option<&str>) -> Response<Bytes> {
        let supported = capver
            .and_then(|v| v.parse::<u16>().ok())
            .map(|v| v >= crabscale_transport::MIN_SUPPORTED_CAPVER)
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

        match (method.as_str(), path.as_str()) {
            ("GET", "/machine/whoami") => {
                let body = serde_json::json!({
                    "machineKey": machine_key.to_string(),
                    "protocolVersion": PROTOCOL_VERSION,
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
        match self.control.register(machine_key, request) {
            Ok(response) => {
                let body = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
                send_json(respond, StatusCode::OK, body);
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
            }) => {
                self.send_stream(respond, first_frame, keep_alive, compress)
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
        first_frame: Vec<u8>,
        keep_alive: bool,
        compress: bool,
    ) {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .body(())
            .expect("static response is valid");
        let mut send = match respond.send_response(response, false) {
            Ok(s) => s,
            Err(_) => return,
        };
        if send.send_data(Bytes::from(first_frame), false).is_err() {
            return;
        }
        if !keep_alive {
            let _ = send.send_data(Bytes::new(), true);
            return;
        }
        loop {
            tokio::time::sleep(KEEPALIVE_INTERVAL).await;
            let frame = match self.control.keepalive_frame(compress) {
                Ok(f) => f,
                Err(_) => break,
            };
            if send.send_data(Bytes::from(frame), false).is_err() {
                break;
            }
        }
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

fn send_plain(respond: &mut SendResponse<Bytes>, status: StatusCode, text: &'static [u8]) {
    let response = Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(())
        .expect("static response is valid");
    let mut send = respond.send_response(response, false).unwrap();
    let _ = send.send_data(Bytes::from_static(text), true);
}

fn send_json(respond: &mut SendResponse<Bytes>, status: StatusCode, body: Vec<u8>) {
    let response = Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(())
        .expect("static response is valid");
    let mut send = respond.send_response(response, false).unwrap();
    let _ = send.send_data(Bytes::from(body), true);
}

fn send_bytes(respond: &mut SendResponse<Bytes>, status: StatusCode, body: Vec<u8>) {
    let response = Response::builder()
        .status(status)
        .header("Content-Type", "application/octet-stream")
        .body(())
        .expect("static response is valid");
    let mut send = respond.send_response(response, false).unwrap();
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

fn plain_response(status: StatusCode, text: &'static str) -> Response<Bytes> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Bytes::from_static(text.as_bytes()))
        .expect("static response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabscale_proto::MachineKey;

    fn test_key() -> MachineKey {
        MachineKey::from_bytes([0x42; 32])
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
}
