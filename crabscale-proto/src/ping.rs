//! Control-to-node ping request wire type.

use serde::{Deserialize, Serialize};

/// A request from the control plane for the node to probe something.
///
/// A request with empty `types` and `ip` asks the node to make a `HEAD`
/// request to `url` to prove the long-polling connection is still alive.
/// A request with `types` populated asks the node to ping `ip` and `POST`
/// the result back to `url`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct PingRequest {
    /// URL the node must reply to.
    #[serde(rename = "URL", skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// Whether the node should reach `url` over the Noise transport.
    #[serde(
        rename = "URLIsNoise",
        skip_serializing_if = "crate::serde_util::is_false"
    )]
    pub url_is_noise: bool,
    /// Whether to log this ping on success.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub log: bool,
    /// Comma-separated ping types, e.g. `"disco,TSMP"`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub types: String,
    /// Ping target IP, when required by `types`.
    #[serde(rename = "IP", skip_serializing_if = "String::is_empty")]
    pub ip: String,
    /// Ping payload; only used for c2n requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_request_round_trips() {
        let request = PingRequest {
            url: "https://control.example/machine/ping-response?id=abc".to_string(),
            url_is_noise: true,
            log: false,
            types: "disco,TSMP".to_string(),
            ip: "100.64.0.1".to_string(),
            payload: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(serde_json::from_str::<PingRequest>(&json).unwrap(), request);
    }
}
