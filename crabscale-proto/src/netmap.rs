//! NetMap request/response wire types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::key::{DiscoKey, MachineKey, NodeKey};
use crate::{DerpMap, DnsConfig, Hostinfo, PingRequest};

/// A request to update node state or start a long-poll of network map updates.
///
/// Sent to `POST /machine/map` inside the Noise-protected HTTP/2 connection.
/// See Spec-NetMap for the wire object and semantics.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct MapRequest {
    /// Client capability version.
    pub version: u32,
    /// `"zstd"` to receive compressed responses, or `""` for plain JSON.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub compress: String,
    /// Whether the server should send keep-alive frames.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub keep_alive: bool,
    /// The node's WireGuard public key.
    pub node_key: NodeKey,
    /// The node's discovery public key.
    pub disco_key: DiscoKey,
    /// Whether the client wants a stream of MapResponses.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub stream: bool,
    /// Current host information; ignored for read-only streaming requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostinfo: Option<Hostinfo>,
    /// The client's magicsock UDP `ip:port` endpoints.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// Types of the corresponding entries in `endpoints`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoint_types: Vec<u8>,
    /// Whether the client accepts an omitted peer list.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub omit_peers: bool,
    /// Deprecated read-only fetch flag; always false for modern clients.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub read_only: bool,
    /// Hash of the latest tailnet-key-authority AUM, when operating.
    #[serde(rename = "TKAHead", skip_serializing_if = "String::is_empty")]
    pub tka_head: String,
    /// Opaque handle for reattaching to a previous map session.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub map_session_handle: String,
    /// Last processed sequence number when reattaching to a session.
    #[serde(skip_serializing_if = "crate::serde_util::is_zero_i64")]
    pub map_session_seq: i64,
}

/// The server's response to a [`MapRequest`].
///
/// The first frame of a stream is a complete map; later frames are deltas or
/// keep-alives. Omitted fields mean "unchanged", except for the slice fields
/// documented in Spec-NetMap section 6.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct MapResponse {
    /// Opaque handle for this map session, sent on the first frame.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub map_session_handle: String,
    /// Sequence number within the named map session.
    #[serde(skip_serializing_if = "crate::serde_util::is_zero_i64")]
    pub seq: i64,
    /// When true, this is an empty keep-alive frame.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub keep_alive: bool,
    /// Request for the client to prove the connection is still alive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ping_request: Option<PingRequest>,
    /// URL the client should open to complete an action.
    #[serde(rename = "PopBrowserURL", skip_serializing_if = "String::is_empty")]
    pub pop_browser_url: String,
    /// The node making the map request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<Node>,
    /// Available DERP relay regions.
    #[serde(rename = "DERPMap", skip_serializing_if = "Option::is_none")]
    pub derp_map: Option<DerpMap>,
    /// Tailnet domain string.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub domain: String,
    /// DNS configuration (MagicDNS, split DNS, search domains, records).
    /// Delivered under the conventional `DNS` field name. Absent means the
    /// client should keep its current DNS settings (Spec-NetMap section 7).
    #[serde(rename = "DNS", skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
    /// Complete peer list. `Some([])` is an authoritative empty peer list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<Node>>,
    /// Peers that changed or were added since the last frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers_changed: Option<Vec<Node>>,
    /// IDs of peers removed since the last frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers_removed: Option<Vec<u64>>,
    /// Lightweight peer patches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers_changed_patch: Option<Vec<PeerChange>>,
    /// Updates to peers' last-seen state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_seen_change: Option<BTreeMap<u64, bool>>,
    /// Updates to peers' online state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online_change: Option<BTreeMap<u64, bool>>,
    /// Whether the tailnet requests service info in Hostinfo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collect_services: Option<bool>,
    /// Firewall rules. `Some([])` means deny all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_filter: Option<Vec<FilterRule>>,
    /// Incremental named packet filter updates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_filters: Option<BTreeMap<String, Vec<FilterRule>>>,
    /// Profiles for the requesting user and peers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub user_profiles: Vec<UserProfile>,
    /// Current server timestamp as an RFC 3339 string.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub control_time: String,
}

/// A Tailscale-compatible device in a tailnet.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Node {
    /// Unique node ID.
    #[serde(rename = "ID")]
    pub id: u64,
    /// Stable string form of the node ID.
    #[serde(rename = "StableID", skip_serializing_if = "String::is_empty")]
    pub stable_id: String,
    /// Fully-qualified MagicDNS name, with a trailing dot.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// ID of the user that owns the node.
    #[serde(skip_serializing_if = "crate::serde_util::is_zero_u64")]
    pub user: u64,
    /// WireGuard public key.
    pub key: NodeKey,
    /// Long-term machine public key.
    pub machine: MachineKey,
    /// Discovery public key.
    pub disco_key: DiscoKey,
    /// IP addresses assigned to this node, as CIDR strings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    /// IP ranges routed to this node; `None` means "same as addresses".
    #[serde(rename = "AllowedIPs", skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<String>>,
    /// Direct `ip:port` endpoints for this node.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// Home DERP region ID; zero means unknown.
    #[serde(
        rename = "HomeDERP",
        skip_serializing_if = "crate::serde_util::is_zero_u64"
    )]
    pub home_derp: u64,
    /// Summary of the host this node runs on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostinfo: Option<Hostinfo>,
    /// Creation time as an RFC 3339 string.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created: String,
    /// Node capability version.
    #[serde(skip_serializing_if = "crate::serde_util::is_zero_u32")]
    pub cap: u32,
    /// ACL tags applied to this node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Capability map (node attributes) granted to this node.
    ///
    /// Keys are attribute names from the policy's `nodeAttrs` and values are
    /// the optional argument lists (empty for key-only capabilities). The
    /// control plane emits this for the self node from the compiled policy.
    #[serde(rename = "CapMap", skip_serializing_if = "BTreeMap::is_empty")]
    pub cap_map: BTreeMap<String, Vec<serde_json::Value>>,
    /// Subnet routes this node is the primary router for.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub primary_routes: Vec<String>,
    /// When the node was last online, as an RFC 3339 string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// Whether the node is currently online.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    /// Whether the node is authorized to join the tailnet.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub machine_authorized: bool,
    /// Deprecated free-form capability strings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

/// Display-friendly data for a user.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct UserProfile {
    /// Unique user ID.
    #[serde(rename = "ID")]
    pub id: u64,
    /// Login name, for display purposes only.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub login_name: String,
    /// Display name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    /// Profile picture URL.
    #[serde(rename = "ProfilePicURL", skip_serializing_if = "String::is_empty")]
    pub profile_pic_url: String,
    /// Group names reported to this node.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// One rule in a packet filter.
///
/// A rule grants either network access (via `dst_ports`/`ip_proto`) to
/// matching sources, or application-level capabilities (via `cap_grant`).
/// The two kinds are mutually exclusive: a rule carries at most one of them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct FilterRule {
    /// Source IPs, CIDRs, ranges, or `"*"`.
    #[serde(rename = "SrcIPs")]
    pub src_ips: Vec<String>,
    /// Destination port ranges allowed once a source matches.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dst_ports: Vec<NetPortRange>,
    /// Deprecated per-source CIDR bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_bits: Option<Vec<i32>>,
    /// IP protocol numbers to match; empty means TCP, UDP, and ICMP.
    #[serde(rename = "IPProto", skip_serializing_if = "Option::is_none")]
    pub ip_proto: Option<Vec<i32>>,
    /// Application capabilities granted to matching sources; empty means
    /// this is a network rule.
    #[serde(rename = "CapGrant", skip_serializing_if = "Vec::is_empty")]
    pub cap_grant: Vec<CapGrant>,
}

/// An inclusive port range on the receiving node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetPortRange {
    /// First port in the range.
    pub first: u16,
    /// Last port in the range.
    pub last: u16,
}

/// Application-level capabilities conditionally granted to the sources
/// matched by a [`FilterRule`] when they talk to one of `dsts`.
///
/// The destination prefixes are the receiver's own addresses; this object is
/// delivered inside the receiver's packet filter so the receiver can answer
/// capability lookups for its peers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct CapGrant {
    /// Destination IP ranges (CIDRs) this grant applies to.
    #[serde(rename = "Dsts")]
    pub dsts: Vec<String>,
    /// Capability name -> values to grant. Each value is emitted as a JSON
    /// array element on the wire.
    #[serde(rename = "CapMap")]
    pub cap_map: std::collections::BTreeMap<String, Vec<serde_json::Value>>,
}

/// A lightweight patch for a peer node.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct PeerChange {
    /// ID of the node being patched.
    #[serde(rename = "NodeID")]
    pub node_id: u64,
    /// New home DERP region ID.
    #[serde(rename = "DERPRegion", skip_serializing_if = "Option::is_none")]
    pub derp_region: Option<u64>,
    /// New direct endpoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<String>>,
    /// New WireGuard public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<NodeKey>,
    /// New discovery public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disco_key: Option<DiscoKey>,
    /// New online state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    /// New last-seen time as an RFC 3339 string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// New key expiry as an RFC 3339 string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_expiry: Option<String>,
    /// New capability version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_peers_serializes_as_empty_array() {
        let response = MapResponse {
            peers: Some(Vec::new()),
            ..MapResponse::default()
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["Peers"], serde_json::json!([]));
        assert!(json.get("Peers").is_some(), "Peers must not be omitted");
    }

    #[test]
    fn absent_peers_is_omitted() {
        let response = MapResponse::default();
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("Peers").is_none(), "absent Peers must be omitted");
    }

    #[test]
    fn empty_packet_filter_serializes_as_empty_array() {
        let response = MapResponse {
            packet_filter: Some(Vec::new()),
            ..MapResponse::default()
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["PacketFilter"], serde_json::json!([]));
        assert!(
            json.get("PacketFilter").is_some(),
            "PacketFilter must not be omitted"
        );
    }

    #[test]
    fn empty_packet_filters_serializes_as_empty_object() {
        let response = MapResponse {
            packet_filters: Some(BTreeMap::new()),
            ..MapResponse::default()
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["PacketFilters"], serde_json::json!({}));
    }

    #[test]
    fn cap_map_serializes_as_pascal_case_and_omits_when_empty() {
        let node = Node {
            cap_map: BTreeMap::from([(
                "randomize-client-port".to_string(),
                Vec::<serde_json::Value>::new(),
            )]),
            ..Node::default()
        };
        let json = serde_json::to_value(&node).unwrap();
        assert_eq!(
            json["CapMap"],
            serde_json::json!({ "randomize-client-port": [] })
        );

        let empty = Node::default();
        let empty_json = serde_json::to_value(&empty).unwrap();
        assert!(
            empty_json.get("CapMap").is_none(),
            "empty CapMap must be omitted"
        );
    }

    #[test]
    fn dns_config_serializes_under_dns_field() {
        let response = MapResponse {
            dns: Some(DnsConfig {
                proxied: true,
                magic_dns_suffix: "tailnet.example.".to_string(),
                search_domains: vec!["tailnet.example".to_string()],
                ..Default::default()
            }),
            ..MapResponse::default()
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(
            json["DNS"]["MagicDNSSuffix"],
            serde_json::json!("tailnet.example.")
        );
        assert_eq!(json["DNS"]["Proxied"], serde_json::json!(true));
        assert!(
            json.get("Dns").is_none(),
            "the field must be named DNS, not Dns"
        );
        assert!(json.get("DNS").is_some(), "DNS must be present");
    }

    #[test]
    fn absent_dns_is_omitted() {
        let response = MapResponse::default();
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("DNS").is_none(), "absent DNS must be omitted");
    }

    #[test]
    fn keepalive_frame_round_trips() {
        let response = MapResponse {
            keep_alive: true,
            ..MapResponse::default()
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"KeepAlive":true}"#);
        assert_eq!(
            serde_json::from_str::<MapResponse>(&json).unwrap(),
            response
        );
    }

    #[test]
    fn cap_grant_serializes_pascal_case() {
        let rule = FilterRule {
            src_ips: vec!["100.64.0.1/32".to_string()],
            cap_grant: vec![CapGrant {
                dsts: vec!["100.64.0.2/32".to_string()],
                cap_map: std::collections::BTreeMap::from([(
                    "tailscale.com/cap/foo".to_string(),
                    vec![serde_json::json!([{"a": 1}])],
                )]),
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["SrcIPs"], serde_json::json!(["100.64.0.1/32"]));
        assert_eq!(
            json["CapGrant"][0]["Dsts"],
            serde_json::json!(["100.64.0.2/32"])
        );
        assert!(json.get("CapGrant").is_some(), "CapGrant must be present");
        assert_eq!(
            json["CapGrant"][0]["CapMap"]["tailscale.com/cap/foo"],
            serde_json::json!([[{"a": 1}]])
        );
        assert!(json.get("DstPorts").is_none(), "no ports on app rule");
        assert!(json.get("IPProto").is_none(), "no ip proto on app rule");
    }

    #[test]
    fn network_rule_omits_cap_grant() {
        let rule = FilterRule {
            src_ips: vec!["*".to_string()],
            dst_ports: vec![NetPortRange {
                first: 0,
                last: 65535,
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(&rule).unwrap();
        assert!(json.get("CapGrant").is_none(), "CapGrant must be omitted");
        assert_eq!(
            json["DstPorts"],
            serde_json::json!([{ "First": 0, "Last": 65535 }])
        );
    }
}
