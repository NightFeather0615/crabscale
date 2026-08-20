//! Registration request/response wire types.

use serde::{Deserialize, Serialize};

use crate::Hostinfo;
use crate::key::NodeKey;

/// Authentication information carried by a [`RegisterRequest`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RegisterAuth {
    /// Pre-auth key of the form `hskey-auth-<prefix>-<secret>`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub auth_key: String,
}

/// A request to register a node key with the control server.
///
/// Sent to `POST /machine/register` inside the Noise-protected HTTP/2
/// connection. See Spec-Registration for the wire object and semantics.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RegisterRequest {
    /// Client capability version.
    pub version: u32,
    /// The node key being registered.
    pub node_key: NodeKey,
    /// Previous node key during a key rotation; empty when absent.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub old_node_key: String,
    /// Network-lock public key; empty when absent.
    #[serde(rename = "NLKey", skip_serializing_if = "String::is_empty")]
    pub nl_key: String,
    /// Authentication information, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<RegisterAuth>,
    /// Requested key expiry as an RFC 3339 timestamp.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub expiry: String,
    /// Followup URL for an interactive registration poll.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub followup: String,
    /// Summary of the host the client runs on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostinfo: Option<Hostinfo>,
    /// Whether the client requests an ephemeral node.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub ephemeral: bool,
}

/// The server's response to a [`RegisterRequest`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct RegisterResponse {
    /// ID of the user that owns the node.
    pub user: u64,
    /// ID of the login used for this registration.
    pub login: u64,
    /// Whether the node key has expired and must be replaced.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub node_key_expired: bool,
    /// Whether the node is authorized to join the tailnet.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub machine_authorized: bool,
    /// When non-empty, registration is pending and the user must visit this URL.
    #[serde(rename = "AuthURL", skip_serializing_if = "String::is_empty")]
    pub auth_url: String,
    /// When non-empty, authorization failed; other fields must be ignored.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}
