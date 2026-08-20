//! HTTP upgrade and WebSocket entry points for TS2021.
//!
//! Native clients use `POST /ts2021` with an `Upgrade` header; WebSocket
//! clients use `GET /ts2021` with the handshake bytes in a query/form
//! parameter. Both paths carry the same 101-byte init message.

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::error::TransportError;
use crate::messages::INIT_MESSAGE_LEN;

/// The subprotocol/upgrade token used by TS2021.
pub const UPGRADE_HEADER_VALUE: &str = "tailscale-control-protocol";

/// Header carrying the base64-encoded init message on native upgrades.
pub const HANDSHAKE_HEADER: &str = "X-Tailscale-Handshake";

/// Validate a native `POST /ts2021` upgrade request and return the decoded
/// 101-byte init message.
pub fn validate_native_upgrade(
    method: &str,
    upgrade: Option<&str>,
    connection: Option<&str>,
    handshake: Option<&str>,
) -> Result<Vec<u8>, TransportError> {
    if method != "POST" {
        return Err(TransportError::InvalidUpgradeRequest);
    }
    if upgrade.map(str::to_ascii_lowercase).as_deref() != Some(UPGRADE_HEADER_VALUE) {
        return Err(TransportError::InvalidUpgradeRequest);
    }
    let connection_ok = connection
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    if !connection_ok {
        return Err(TransportError::InvalidUpgradeRequest);
    }
    let handshake = handshake.ok_or(TransportError::InvalidUpgradeRequest)?;
    decode_handshake(handshake)
}

/// Validate a WebSocket `GET /ts2021` request and return the decoded init
/// message from the `X-Tailscale-Handshake` query/form parameter.
pub fn validate_websocket_upgrade(
    subprotocol: Option<&str>,
    handshake: Option<&str>,
) -> Result<Vec<u8>, TransportError> {
    if subprotocol != Some(UPGRADE_HEADER_VALUE) {
        return Err(TransportError::UnsupportedSubprotocol);
    }
    let handshake = handshake.ok_or(TransportError::InvalidUpgradeRequest)?;
    decode_handshake(handshake)
}

fn decode_handshake(encoded: &str) -> Result<Vec<u8>, TransportError> {
    let bytes = STANDARD
        .decode(encoded.trim())
        .map_err(|_| TransportError::InvalidUpgradeRequest)?;
    if bytes.len() != INIT_MESSAGE_LEN {
        return Err(TransportError::InvalidInitMessage);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_handshake() -> String {
        STANDARD.encode([0u8; INIT_MESSAGE_LEN])
    }

    #[test]
    fn accepts_native_upgrade() {
        let init = validate_native_upgrade(
            "POST",
            Some(UPGRADE_HEADER_VALUE),
            Some("keep-alive, Upgrade"),
            Some(&sample_handshake()),
        )
        .unwrap();
        assert_eq!(init.len(), INIT_MESSAGE_LEN);
    }

    #[test]
    fn rejects_missing_headers() {
        assert_eq!(
            validate_native_upgrade("POST", None, None, None),
            Err(TransportError::InvalidUpgradeRequest)
        );
    }

    #[test]
    fn accepts_websocket_subprotocol() {
        let init =
            validate_websocket_upgrade(Some(UPGRADE_HEADER_VALUE), Some(&sample_handshake()))
                .unwrap();
        assert_eq!(init.len(), INIT_MESSAGE_LEN);
    }

    #[test]
    fn rejects_wrong_subprotocol() {
        assert_eq!(
            validate_websocket_upgrade(Some("chat"), Some(&sample_handshake())),
            Err(TransportError::UnsupportedSubprotocol)
        );
    }
}
