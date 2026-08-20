//! Early Noise payload wire type.

use serde::{Deserialize, Serialize};

use crate::key::ChallengeKey;

/// The JSON payload the server sends right after the Noise handshake and
/// before the HTTP/2 preface.
///
/// The JSON field name is intentionally camelCase, matching the wire format
/// in Spec-Transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EarlyNoise {
    /// Fresh per-connection challenge public key.
    #[serde(rename = "nodeKeyChallenge")]
    pub node_key_challenge: ChallengeKey,
}
