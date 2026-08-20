//! Host and network state reported by a client.

use serde::{Deserialize, Serialize};

/// A summary of the host a Tailscale-compatible client runs on.
///
/// Clients send far more fields than the M0 server consumes. Unknown fields
/// are ignored on deserialization, and only the fields modeled here are
/// emitted when the server serializes a [`Hostinfo`].
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Hostinfo {
    /// Version of the client code, in long format.
    #[serde(rename = "IPNVersion", skip_serializing_if = "String::is_empty")]
    pub ipn_version: String,
    /// Logtail ID of the frontend instance.
    #[serde(rename = "FrontendLogID", skip_serializing_if = "String::is_empty")]
    pub frontend_log_id: String,
    /// Logtail ID of the backend instance.
    #[serde(rename = "BackendLogID", skip_serializing_if = "String::is_empty")]
    pub backend_log_id: String,
    /// Operating system the client runs on.
    #[serde(rename = "OS", skip_serializing_if = "String::is_empty")]
    pub os: String,
    /// Operating system version, when available.
    #[serde(rename = "OSVersion", skip_serializing_if = "String::is_empty")]
    pub os_version: String,
    /// Best-effort whether the client runs inside a container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<bool>,
    /// Runtime environment type, in string form.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub env: String,
    /// Linux distribution name, when applicable.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub distro: String,
    /// Linux distribution version, when applicable.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub distro_version: String,
    /// Linux distribution code name, when applicable.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub distro_code_name: String,
    /// Application using the client library, when applicable.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub app: String,
    /// Whether a desktop environment was detected on Linux.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop: Option<bool>,
    /// Package or distribution channel of the client.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub package: String,
    /// Mobile device model, when applicable.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub device_model: String,
    /// Push notification device token, when applicable.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub push_device_token: String,
    /// Hostname of the host the client runs on.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    /// Whether the host blocks incoming connections.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub shields_up: bool,
    /// Whether this node exists because it is shared to another user.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub sharee_node: bool,
    /// Whether the user opted out of logs and support.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub no_logs_no_support: bool,
    /// Whether the node wants server-side wiring for Funnel.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub wire_ingress: bool,
    /// Whether the node has a Funnel endpoint enabled.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub ingress_enabled: bool,
    /// Whether the node opted in to remote updates.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub allows_update: bool,
    /// Machine architecture, equivalent to `uname -m`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub machine: String,
    /// `GOARCH` value of the client binary.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub go_arch: String,
    /// `GOARM`/`GOAMD64`/etc. value of the client binary.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub go_arch_var: String,
    /// Go version the client binary was built with.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub go_version: String,
    /// IP ranges this client can route.
    #[serde(rename = "RoutableIPs", skip_serializing_if = "Option::is_none")]
    pub routable_ips: Option<Vec<String>>,
    /// ACL tags this node wants to claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_tags: Option<Vec<String>>,
    /// MAC addresses for Wake-on-LAN, lowercase hex with colons.
    #[serde(rename = "WoLMACs", skip_serializing_if = "Option::is_none")]
    pub wol_macs: Option<Vec<String>>,
    /// Network state and connectivity information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_info: Option<NetInfo>,
    /// SSH host public keys, when advertised.
    #[serde(rename = "sshHostKeys", skip_serializing_if = "Option::is_none")]
    pub ssh_host_keys: Option<Vec<String>>,
    /// Cloud provider name, when the node runs in a cloud.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cloud: String,
    /// Whether the client runs in userspace (netstack) mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userspace: Option<bool>,
    /// Whether the subnet router runs in userspace mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userspace_router: Option<bool>,
    /// Whether the app-connector service is running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_connector: Option<bool>,
    /// Opaque hash of the most recent tailnet services list.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub services_hash: String,
    /// The client's selected exit node, empty when unselected.
    #[serde(rename = "ExitNodeID", skip_serializing_if = "String::is_empty")]
    pub exit_node_id: String,
    /// Whether node state is stored encrypted on disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_encrypted: Option<bool>,
}

/// Information about the host's network state.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct NetInfo {
    /// Whether NAT mappings vary by destination IP.
    #[serde(
        rename = "MappingVariesByDestIP",
        skip_serializing_if = "Option::is_none"
    )]
    pub mapping_varies_by_dest_ip: Option<bool>,
    /// Whether the host has IPv6 internet connectivity.
    #[serde(rename = "WorkingIPv6", skip_serializing_if = "Option::is_none")]
    pub working_ipv6: Option<bool>,
    /// Whether the OS supports IPv6 at all.
    #[serde(rename = "OSHasIPv6", skip_serializing_if = "Option::is_none")]
    pub os_has_ipv6: Option<bool>,
    /// Whether the host has UDP internet connectivity.
    #[serde(rename = "WorkingUDP", skip_serializing_if = "Option::is_none")]
    pub working_udp: Option<bool>,
    /// Whether ICMPv4 works; empty means not checked.
    #[serde(rename = "WorkingICMPv4", skip_serializing_if = "Option::is_none")]
    pub working_icmpv4: Option<bool>,
    /// Whether an existing port mapping is available.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub have_port_map: bool,
    /// Whether UPnP appears present on the LAN.
    #[serde(rename = "UPnP", skip_serializing_if = "Option::is_none")]
    pub upnp: Option<bool>,
    /// Whether NAT-PMP appears present on the LAN.
    #[serde(rename = "PMP", skip_serializing_if = "Option::is_none")]
    pub pmp: Option<bool>,
    /// Whether PCP appears present on the LAN.
    #[serde(rename = "PCP", skip_serializing_if = "Option::is_none")]
    pub pcp: Option<bool>,
    /// Preferred (home) DERP region ID; zero means unknown.
    #[serde(
        rename = "PreferredDERP",
        skip_serializing_if = "crate::serde_util::is_zero_u64"
    )]
    pub preferred_derp: u64,
    /// Current link type, when known.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub link_type: String,
}
