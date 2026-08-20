//! DERP map wire types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The set of DERP relay regions available to a node.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct DerpMap {
    /// Regions keyed by their region ID as a decimal string.
    pub regions: BTreeMap<String, DerpRegion>,
    /// Whether to ignore Tailscale's default DERP servers.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub omit_default_regions: bool,
}

/// A geographic region running one or more DERP relay nodes.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct DerpRegion {
    /// Unique region ID.
    #[serde(rename = "RegionID")]
    pub region_id: u64,
    /// Short region code, usually a city or airport code.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub region_code: String,
    /// Long English region name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub region_name: String,
    /// Deprecated: whether clients should avoid this region as home.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub avoid: bool,
    /// DERP nodes in this region, in priority order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<DerpNode>,
}

/// A single DERP relay node within a [`DerpRegion`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct DerpNode {
    /// Unique node name across all regions.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Region ID this node belongs to.
    #[serde(
        rename = "RegionID",
        skip_serializing_if = "crate::serde_util::is_zero_u64"
    )]
    pub region_id: u64,
    /// Hostname used to reach this node.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub host_name: String,
    /// Expected TLS certificate name; empty means use the hostname.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cert_name: String,
    /// Forced IPv4 address, or `"none"` to disable IPv4.
    #[serde(rename = "IPv4", skip_serializing_if = "String::is_empty")]
    pub ipv4: String,
    /// Forced IPv6 address, or `"none"` to disable IPv6.
    #[serde(rename = "IPv6", skip_serializing_if = "String::is_empty")]
    pub ipv6: String,
    /// STUN port; zero means 3478, `-1` disables STUN.
    #[serde(
        rename = "STUNPort",
        skip_serializing_if = "crate::serde_util::is_zero_i32"
    )]
    pub stun_port: i32,
    /// Whether this node only serves STUN, not DERP.
    #[serde(
        rename = "STUNOnly",
        skip_serializing_if = "crate::serde_util::is_false"
    )]
    pub stun_only: bool,
    /// Alternate TLS port for the DERP HTTPS server; zero means 443.
    #[serde(
        rename = "DERPPort",
        skip_serializing_if = "crate::serde_util::is_zero_i32"
    )]
    pub derp_port: i32,
    /// Test-only flag to disable TLS verification.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub insecure_for_tests: bool,
    /// Test-only STUN server IP override.
    #[serde(rename = "STUNTestIP", skip_serializing_if = "String::is_empty")]
    pub stun_test_ip: String,
    /// Whether this node is reachable over HTTP on port 80.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub can_port_80: bool,
}
