//! Logout request wire type.

use serde::{Deserialize, Serialize};

use crate::key::NodeKey;

/// A request to log out a node.
///
/// Sent to `POST /machine/logout` inside the Noise-protected HTTP/2
/// connection. The server deauthorizes the node so it must re-authenticate
/// before it can join the tailnet again.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct LogoutRequest {
    /// The node key being logged out.
    pub node_key: NodeKey,
}
