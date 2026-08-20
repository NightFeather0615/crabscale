//! Control router: outer `/key` and inner `/machine/*` endpoints.
//!
//! The outer `/key` endpoint is served over plain HTTP (or TLS in production)
//! and advertises the server's machine public key. The inner `/machine/*`
//! endpoints are served inside the HTTP/2-over-Noise connection and carry the
//! Noise machine key recovered from the handshake.

use bytes::Bytes;
use crabscale_proto::MachineKey;
use crabscale_transport::{
    MAX_INNER_BODY_LEN, NoiseStream, TransportError, read_body_limited, serve_http2,
};
use h2::RecvStream;
use h2::server::SendResponse;
use http::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};

/// The protocol version reported by `/machine/whoami`.
pub const PROTOCOL_VERSION: u16 = 130;

/// Router for the control API.
#[derive(Clone)]
pub struct ControlRouter {
    machine_key: MachineKey,
}

impl ControlRouter {
    /// Create a router for the given server machine key.
    pub fn new(machine_key: MachineKey) -> Self {
        Self { machine_key }
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
            Err(_) => {
                let response = Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .header("Content-Type", "text/plain")
                    .body(())
                    .expect("static response is valid");
                let mut send = respond.send_response(response, false).unwrap();
                let _ = send.send_data(Bytes::from_static(b"body too large"), true);
                return;
            }
        };

        let (status, content_type, body) = route_inner(&method, &path, machine_key, &body_bytes);
        let response = Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .body(())
            .expect("static response is valid");
        let mut send = match respond.send_response(response, body.is_empty()) {
            Ok(s) => s,
            Err(_) => return,
        };
        if !body.is_empty() {
            let _ = send.send_data(body, true);
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
    serve_http2(stream, machine_key, move |request, respond, key| {
        let router = router.clone();
        async move {
            router.handle_inner(request, respond, key).await;
        }
    })
    .await
}

fn route_inner(
    method: &Method,
    path: &str,
    machine_key: MachineKey,
    _body: &[u8],
) -> (StatusCode, &'static str, Bytes) {
    match (method.as_str(), path) {
        ("GET", "/machine/whoami") => {
            let body = serde_json::json!({
                "machineKey": machine_key.to_string(),
                "protocolVersion": PROTOCOL_VERSION,
            });
            (
                StatusCode::OK,
                "application/json",
                Bytes::from(body.to_string()),
            )
        }
        ("POST", "/machine/set-dns")
        | ("PATCH", "/machine/set-device-attr")
        | ("POST", "/machine/audit-log")
        | ("POST", "/machine/id-token")
        | ("POST", "/machine/feature/query")
        | ("POST", "/machine/update-health")
        | ("POST", "/machine/c2n") => (
            StatusCode::NOT_IMPLEMENTED,
            "text/plain",
            Bytes::from_static(b"not implemented"),
        ),
        _ => (
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from_static(b"not found"),
        ),
    }
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
