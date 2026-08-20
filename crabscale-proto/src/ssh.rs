//! Tailscale SSH wire types.
//!
//! These types mirror the SSH check-mode protocol described by
//! [Spec-Control-API] and the `SSHPolicy` delivered inside a MapResponse.
//! Field names use the camelCase wire vocabulary the Tailscale clients
//! ship (see the `tailcfg.SSH*` types), so a compatible client can decode
//! them without case-insensitive matching.
//!
//! [Spec-Control-API]: https://github.com/NightFeather0615/crabscale/wiki/Spec-Control-API.md

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A Tailscale SSH policy delivered to a node in its MapResponse.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshPolicy {
    /// Ordered rules to evaluate for an incoming SSH connection. The first
    /// matching rule wins and processing stops.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SshRule>,
}

/// One rule of an [`SshPolicy`]: which principals may connect, as which
/// users, and what action the candidate connection receives.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshRule {
    /// Principals that match an incoming connection.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub principals: Vec<SshPrincipal>,
    /// Map of requested SSH user to local user. An empty value means the
    /// rule does not match that user; the value `"="` means the SSH user maps
    /// directly to the local user.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub ssh_users: BTreeMap<String, String>,
    /// The action to take when this rule matches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<SshAction>,
}

/// A principal that may match an incoming SSH connection.
///
/// Matching any one field yields a match. Selectors such as `tag:...`,
/// `group:...`, or `autogroup:...` are resolved by the control plane into
/// concrete [`SshPrincipal::node`]/[`SshPrincipal::user_login`] values;
/// `*` (or `autogroup:self`) becomes [`SshPrincipal::any`] = true.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshPrincipal {
    /// Stable node id (e.g. `n00000000000000000000001`) allowed to connect.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub node: String,
    /// A user login (`user@example.com`) allowed to connect from any of its
    /// nodes.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user_login: String,
    /// If true, this principal matches any connection.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub any: bool,
}

/// The outcome of evaluating an SSH rule for a connection.
///
/// `accept` admits the connection immediately, `reject` closes it, and
/// `holdAndDelegate`, when set, defers the verdict to the given URL (the
/// SSH check-mode endpoint), which the client polls until a terminal
/// action arrives.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshAction {
    /// A message shown to the user before the action happens.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    /// If true, terminate the connection.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub reject: bool,
    /// If true, accept the connection immediately.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub accept: bool,
    /// When set, a URL the connection blocks on for a followup verdict.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hold_and_delegate: String,
    /// Whether an accepted connection may forward the SSH agent.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub allow_agent_forwarding: bool,
    /// Whether an accepted connection may use local port forwarding.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub allow_local_port_forwarding: bool,
    /// Whether an accepted connection may use remote port forwarding.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub allow_remote_port_forwarding: bool,
}
