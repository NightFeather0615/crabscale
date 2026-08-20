//! `/derp` HTTP upgrade negotiation (Spec-DERP-STUN §5).
//!
//! The relay endpoint accepts two transports on the same path:
//!
//! - `Upgrade: DERP` — raw DERP frames after a `101 Switching Protocols`.
//! - `Upgrade: websocket` — DERP frames inside binary WebSocket messages.
//!
//! A `Derp-Fast-Start: 1` request header for the raw transport permits the
//! server to skip the 101 response headers, letting the client start sending
//! DERP bytes immediately. The `Ideal-Node` header is advisory only.

use std::fmt;

use base64::Engine;
use http::{HeaderValue, Method, Request, Response, StatusCode, Version, header};
use sha1::{Digest, Sha1};

/// The WebSocket handshake GUID mandated by RFC 6455.
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The DERP transport negotiated for a `/derp` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// Native raw DERP after a `101` upgrade.
    Raw,
    /// DERP frames carried inside binary WebSocket messages.
    WebSocket,
}

/// A parsed `/derp` upgrade request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpRequest {
    /// The negotiated transport.
    pub kind: TransportKind,
    /// Whether the raw `Derp-Fast-Start` shortcut was requested.
    pub fast_start: bool,
    /// The advisory `Ideal-Node` header value, if any.
    pub ideal_node: Option<String>,
}

/// A negotiated request plus the response head to send (if any).
#[derive(Debug, Clone)]
pub struct UpgradedRequest {
    /// Negotiation result.
    pub request: DerpRequest,
    /// The `101` response to write before the DERP stream, or `None` when
    /// `Derp-Fast-Start` lets both sides skip the upgrade headers.
    pub response: Option<Response<()>>,
}

/// Errors returned while negotiating a `/derp` upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeError {
    /// The request did not carry a DERP `Upgrade` header.
    MissingUpgrade,
    /// A WebSocket upgrade is missing the `Sec-WebSocket-Key` header.
    MissingWebSocketKey,
    /// The request method is not allowed for a DERP upgrade.
    InvalidMethod,
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingUpgrade => write!(f, "missing DERP Upgrade header"),
            Self::MissingWebSocketKey => {
                write!(f, "WebSocket upgrade is missing Sec-WebSocket-Key")
            }
            Self::InvalidMethod => write!(f, "DERP upgrade requires an HTTP GET request"),
        }
    }
}

impl std::error::Error for UpgradeError {}

fn header_lower(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_lowercase)
}

fn header_bool(headers: &http::HeaderMap, name: &str) -> bool {
    header_lower(headers, name).as_deref() == Some("1")
}

/// Inspect an HTTP request and decide which DERP transport to speak.
pub fn negotiate(req: &Request<()>) -> Result<DerpRequest, UpgradeError> {
    let headers = req.headers();

    let fast_start = header_bool(headers, "derp-fast-start");
    let ideal_node = req
        .headers()
        .get("ideal-node")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    match header_lower(headers, header::UPGRADE.as_str()).as_deref() {
        Some("derp") => Ok(DerpRequest {
            kind: TransportKind::Raw,
            fast_start,
            ideal_node,
        }),
        Some("websocket") => {
            if !headers.contains_key("sec-websocket-key") {
                return Err(UpgradeError::MissingWebSocketKey);
            }
            Ok(DerpRequest {
                kind: TransportKind::WebSocket,
                fast_start: false,
                ideal_node,
            })
        }
        _ => Err(UpgradeError::MissingUpgrade),
    }
}

/// Compute the `Sec-WebSocket-Accept` value for a `Sec-WebSocket-Key`
/// (RFC 6455 §4.2.2): SHA-1 of `key + GUID`, base64-encoded.
pub fn compute_websocket_accept(sec_websocket_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(sec_websocket_key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// Build the full upgrade negotiation result for a `/derp` path.
///
/// Pass the client's `Sec-WebSocket-Key` header (if any) for WebSocket
/// upgrades. When the raw `Derp-Fast-Start` shortcut is active, the response
/// is `None` and both sides start the DERP stream immediately.
pub fn build_derp_response(
    req: &Request<()>,
    sec_websocket_key: Option<&str>,
) -> Result<UpgradedRequest, UpgradeError> {
    let request = negotiate(req)?;
    let response = match request.kind {
        TransportKind::Raw => {
            if request.fast_start {
                None
            } else {
                Some(switching_protocols(
                    HeaderValue::from_static("DERP"),
                    HeaderValue::from_static("Upgrade"),
                ))
            }
        }
        TransportKind::WebSocket => {
            let key = sec_websocket_key.ok_or(UpgradeError::MissingWebSocketKey)?;
            let accept = compute_websocket_accept(key);
            let mut response = switching_protocols(
                HeaderValue::from_static("websocket"),
                HeaderValue::from_static("Upgrade"),
            );
            response.headers_mut().insert(
                "Sec-WebSocket-Accept",
                HeaderValue::from_str(&accept)
                    .expect("base64 accept is a header-safe ASCII string"),
            );
            Some(response)
        }
    };
    Ok(UpgradedRequest { request, response })
}

fn switching_protocols(upgrade: HeaderValue, connection: HeaderValue) -> Response<()> {
    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .version(Version::HTTP_11)
        .body(())
        .expect("static 101 response builds");
    response.headers_mut().insert(header::UPGRADE, upgrade);
    response
        .headers_mut()
        .insert(header::CONNECTION, connection);
    response
}

/// Validate that this is an HTTP request targeted at the DERP endpoint.
///
/// Tailscale clients open DERP upgrades with `GET`; anything else is rejected
/// before negotiation.
pub fn validate_method(req: &Request<()>) -> Result<(), UpgradeError> {
    if req.method() != Method::GET {
        return Err(UpgradeError::InvalidMethod);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request<()> {
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost/derp")
            .body(())
            .unwrap()
    }

    #[test]
    fn negotiates_raw_derp_upgrade() {
        let mut req = request();
        req.headers_mut()
            .insert("upgrade", HeaderValue::from_static("DERP"));
        let req = negotiate(&req).unwrap();
        assert_eq!(req.kind, TransportKind::Raw);
        assert!(!req.fast_start);
    }

    #[test]
    fn negotiates_fast_start() {
        let mut req = request();
        req.headers_mut()
            .insert("Upgrade", HeaderValue::from_static("DERP"));
        req.headers_mut()
            .insert("Derp-Fast-Start", HeaderValue::from_static("1"));
        req.headers_mut()
            .insert("Ideal-Node", HeaderValue::from_static("crab-1"));
        let req = negotiate(&req).unwrap();
        assert!(req.fast_start);
        assert_eq!(req.ideal_node.as_deref(), Some("crab-1"));
    }

    #[test]
    fn negotiates_websocket_upgrade() {
        let mut req = request();
        req.headers_mut()
            .insert("Upgrade", HeaderValue::from_static("websocket"));
        req.headers_mut().insert(
            "Sec-WebSocket-Key",
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        let req = negotiate(&req).unwrap();
        assert_eq!(req.kind, TransportKind::WebSocket);
    }

    #[test]
    fn websocket_requires_key() {
        let mut req = request();
        req.headers_mut()
            .insert("Upgrade", HeaderValue::from_static("websocket"));
        assert_eq!(negotiate(&req), Err(UpgradeError::MissingWebSocketKey));
    }

    #[test]
    fn rejects_non_derp_upgrade() {
        let req = request();
        assert_eq!(negotiate(&req), Err(UpgradeError::MissingUpgrade));
    }

    #[test]
    fn websocket_accept_matches_rfc_6455_example() {
        // The canonical example from RFC 6455 §1.3.
        let accept = compute_websocket_accept("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn raw_response_is_101() {
        let mut req = request();
        req.headers_mut()
            .insert("Upgrade", HeaderValue::from_static("DERP"));
        let upgraded = build_derp_response(&req, None).unwrap();
        let response = upgraded.response.unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(response.headers().get(header::UPGRADE).unwrap(), "DERP");
    }

    #[test]
    fn fast_start_skips_response_headers() {
        let mut req = request();
        req.headers_mut()
            .insert("Upgrade", HeaderValue::from_static("DERP"));
        req.headers_mut()
            .insert("Derp-Fast-Start", HeaderValue::from_static("1"));
        let upgraded = build_derp_response(&req, None).unwrap();
        assert!(upgraded.response.is_none());
    }

    #[test]
    fn websocket_response_includes_accept() {
        let mut req = request();
        req.headers_mut()
            .insert("Upgrade", HeaderValue::from_static("websocket"));
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        req.headers_mut()
            .insert("Sec-WebSocket-Key", HeaderValue::from_str(key).unwrap());
        let upgraded = build_derp_response(&req, Some(key)).unwrap();
        let response = upgraded.response.unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            response.headers().get("Sec-WebSocket-Accept").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
