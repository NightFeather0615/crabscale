//! The typed policy model.
//!
//! These types mirror the top-level keys described by [Spec-Policy]:
//! `groups`, `hosts`, `acls`, `grants`, `tagOwners`, `autoApprovers`, `ssh`,
//! `nodeAttrs`, `tests`, and `sshTests`. Fields are optional and default to
//! empty so that the minimal allow-all policy parses.
//!
//! Every struct opts into `deny_unknown_fields` so that a misspelled or
//! unsupported key is rejected rather than silently dropped.
//!
//! [Spec-Policy]: https://github.com/NightFeather0615/crabscale/wiki/Spec-Policy.md

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// A complete policy document parsed from a HUJSON policy file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Group name -> members (users, tags, or other principals).
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    /// Alias -> IP, CIDR, or subnet route owner.
    #[serde(default)]
    pub hosts: BTreeMap<String, String>,
    /// Ordered network ACL rules.
    #[serde(default)]
    pub acls: Vec<Acl>,
    /// Ordered capability grants.
    #[serde(default)]
    pub grants: Vec<Grant>,
    /// Tag -> list of users allowed to use the tag.
    #[serde(default, rename = "tagOwners")]
    pub tag_owners: BTreeMap<String, Vec<String>>,
    /// Routes and exit-node auto-approval rules.
    #[serde(default, rename = "autoApprovers")]
    pub auto_approvers: AutoApprovers,
    /// Tailscale SSH rules.
    #[serde(default)]
    pub ssh: Vec<SshRule>,
    /// Node attribute grants.
    #[serde(default, rename = "nodeAttrs")]
    pub node_attrs: Vec<NodeAttrGrant>,
    /// Declarative ACL tests.
    #[serde(default)]
    pub tests: Vec<PolicyTest>,
    /// Declarative SSH tests.
    #[serde(default, rename = "sshTests")]
    pub ssh_tests: Vec<SshTest>,
}

/// A network ACL rule.
///
/// Each rule grants traffic from every `src` principal to every `dst`
/// principal; the overall default is deny.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acl {
    /// Rule action; `"accept"` is the only supported value today.
    pub action: String,
    /// Source principals: users, tags, groups, autogroups, IPs, and CIDRs.
    pub src: Vec<String>,
    /// Destination principals: hosts, IPs/CIDRs with optional port lists.
    pub dst: Vec<String>,
    /// Optional layer-3/4 protocol constraint.
    #[serde(default)]
    pub proto: Option<String>,
}

/// An ordered capability grant.
///
/// Grants attach application-level capabilities (the `app` object) to pairs
/// of source and destination principals, and may also carry an IP protocol
/// constraint in `ip`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// Source principals.
    pub src: Vec<String>,
    /// Destination principals.
    pub dst: Vec<String>,
    /// Optional IP protocol constraints, e.g. `"tcp:80"`.
    #[serde(default)]
    pub ip: Vec<String>,
    /// Capability name -> arbitrary payload.
    #[serde(default)]
    pub app: BTreeMap<String, JsonValue>,
}

/// Route and exit-node auto-approval rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AutoApprovers {
    /// Subnet route CIDR -> list of approvers allowed to advertise it.
    #[serde(default)]
    pub routes: BTreeMap<String, Vec<String>>,
    /// Exit-node route -> list of approvers allowed to advertise it.
    #[serde(default, rename = "exitNode")]
    pub exit_node: BTreeMap<String, Vec<String>>,
}

/// A Tailscale SSH rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshRule {
    /// `"accept"` or `"check"`.
    pub action: String,
    /// Source principals.
    pub src: Vec<String>,
    /// Destination principals.
    pub dst: Vec<String>,
    /// Users allowed by the rule.
    #[serde(default)]
    pub users: Vec<String>,
    /// How long an SSH `check` approval is remembered for a src/dst pair.
    #[serde(default, rename = "checkPeriod")]
    pub check_period: Option<String>,
}

/// A node attribute grant assigning `attr` values to `target` nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAttrGrant {
    /// Nodes the attributes apply to (tags, users, groups, or `*`).
    pub target: Vec<String>,
    /// Attributes to set on the targets.
    pub attr: Vec<String>,
}

/// A declarative ACL test executed against the compiled policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTest {
    /// Source principal being tested.
    pub src: String,
    /// Legacy alias for `src`.
    #[serde(default)]
    pub user: Option<String>,
    /// Optional protocol under test.
    #[serde(default)]
    pub proto: Option<String>,
    /// Destinations that must be reachable.
    #[serde(default)]
    pub accept: Vec<String>,
    /// Destinations that must be unreachable.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Legacy alias for `accept`.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// A declarative Tailscale SSH test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshTest {
    /// `"accept"` or `"check"`.
    pub action: String,
    /// Source principal.
    pub src: String,
    /// Destination principal.
    pub dst: String,
    /// Users included in the test.
    #[serde(default)]
    pub users: Vec<String>,
}
