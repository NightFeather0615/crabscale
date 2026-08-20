//! Admission-control wire types for the embedded relay (`POST /verify`).
//!
//! An embedded DERP relay asks the control server whether a client node key
//! belongs to the tailnet before admitting it (Spec-Control-API `POST
//! /verify`). The request carries the node public key and the response is a
//! single `Allow` boolean.

use serde::{Deserialize, Serialize};

use crate::key::NodeKey;

/// The `POST /verify` admission request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct VerifyRequest {
    /// The node public key whose authorization is being questioned.
    pub node_public: NodeKey,
}

/// The `POST /verify` admission response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct VerifyResponse {
    /// Whether the node key is authorized for this tailnet.
    pub allow: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_request_uses_wire_field_names() {
        let request = VerifyRequest {
            node_public: NodeKey::from_bytes([0x55; 32]),
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json["NodePublic"],
            serde_json::json!(
                "nodekey:5555555555555555555555555555555555555555555555555555555555555555"
            )
        );
        let back: VerifyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, request);
    }

    #[test]
    fn verify_response_uses_wire_field_names() {
        let json = serde_json::to_value(VerifyResponse { allow: true }).unwrap();
        assert_eq!(json, serde_json::json!({ "Allow": true }));
    }
}
