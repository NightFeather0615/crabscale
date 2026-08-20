//! Tailscale SSH wire types.
//!
//! These types mirror the SSH check-mode protocol described by
//! [Spec-Control-API] and the `SSHPolicy` delivered inside a MapResponse.
//! The control plane compiles the policy's `ssh` rules into a per-node
//! [`SshPolicy`] and serves `/machine/ssh/action/{src}/to/{dst}` verdicts as
//! [`SshAction`] JSON values.
//!
//! [Spec-Control-API]: https://github.com/NightFeather0615/crabscale/wiki/Spec-Control-API.md

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A Tailscale SSH policy delivered to a node in its MapResponse.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SshPolicy {
    /// Ordered rules to evaluate for an incoming SSH connection. The first
    /// matching rule wins and processing stops.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SshRule>,
}

/// One rule of an [`SshPolicy`]: which principals may connect, as which
/// users, and what action the candidate connection receives.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
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
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct SshPrincipal {
    /// A specific node id that is allowed to connect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<u64>,
    /// A user login (`user@example.com`) that is allowed to connect.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user_login: String,
    /// Opaque selectors (`tag:server`, `autogroup:member`, `*`) that match
    /// the connecting node's identity.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub any: Vec<String>,
}

/// The outcome of evaluating an SSH rule for a connection.
///
/// `Accept` admits the connection immediately, `Reject` closes it, and
/// `HoldAndDelegate`, when set, defers the verdict to the given URL (the
/// SSH check-mode endpoint), which the client polls until a terminal
/// action arrives.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
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
