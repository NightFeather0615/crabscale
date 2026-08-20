//! DNS configuration: MagicDNS, split DNS, search domains, and extra records.
//!
//! This module owns the server-side DNS configuration model and builds the
//! wire [`crabscale_proto::DnsConfig`] delivered inside the MapResponse `DNS`
//! field. MagicDNS records for every node are derived from the node profile
//! (its MagicDNS name and tailnet addresses), which is what lets peers
//! resolve each other by name.
//!
//! The MagicDNS resolver addresses are derived from the configured IPv4 and
//! IPv6 tailnet prefixes so an administrator who changes those prefixes gets
//! a resolver address inside them automatically (Spec-NetMap section 7).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crabscale_proto::{DnsConfig, DnsRecord, DnsResolver, Node as ProtoNode};
use serde::{Deserialize, Serialize};

/// The well-known MagicDNS resolver IPv4 address in the default CGNAT range.
pub const DEFAULT_MAGIC_DNS_IPV4: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);
/// The well-known MagicDNS resolver IPv6 address in the default tailnet range.
pub const DEFAULT_MAGIC_DNS_IPV6: Ipv6Addr =
    Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x100);

/// Default TTL (seconds) for records injected into the MagicDNS zone.
pub const DEFAULT_EXTRA_RECORD_TTL: u32 = 300;

/// Server-side DNS configuration with defaults.
#[derive(Clone, Debug)]
pub struct DnsSettings {
    /// Whether MagicDNS is enabled. When disabled the client keeps its
    /// upstream resolvers and no tailnet suffix, node records, or MagicDNS
    /// route are sent; configured split DNS and search domains still are.
    pub magic_dns: bool,
    /// Override for the IPv4 MagicDNS resolver address. `None` derives it
    /// from the configured IPv4 tailnet prefix.
    pub magic_dns_ipv4: Option<Ipv4Addr>,
    /// Override for the IPv6 MagicDNS resolver address. `None` derives it
    /// from the configured IPv6 tailnet prefix.
    pub magic_dns_ipv6: Option<Ipv6Addr>,
    /// Additional search domains (without trailing dots) sent to clients.
    pub search_domains: Vec<String>,
    /// Split DNS: map of DNS suffix (with trailing dot) to resolver
    /// addresses that must answer names under that suffix.
    pub split_dns: BTreeMap<String, Vec<String>>,
    /// Path to a JSON file of extra records to inject into the MagicDNS
    /// zone. The file is re-read by `ControlPlane::reload_dns_extra_records`
    /// for hot reload.
    pub extra_records_path: Option<std::path::PathBuf>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            magic_dns: true,
            magic_dns_ipv4: None,
            magic_dns_ipv6: None,
            search_domains: Vec::new(),
            split_dns: BTreeMap::new(),
            extra_records_path: None,
        }
    }
}

/// Errors produced while loading or parsing DNS extra records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// The extra-records file could not be read.
    Io(String),
    /// The extra-records file is not valid JSON or contains a bad record.
    Parse(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "failed to read DNS extra records: {e}"),
            Self::Parse(e) => write!(f, "invalid DNS extra records: {e}"),
        }
    }
}

impl std::error::Error for DnsError {}

/// The on-disk shape of one extra record. The file is an array of these
/// objects; field names are case-insensitive (serde uses what is given).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ExtraRecordFile {
    name: String,
    /// Record type mnemonic (`"A"`, `"AAAA"`, `"CNAME"`). Empty lets the
    /// loader infer the family from `value` where possible.
    #[serde(rename = "type")]
    rec_type: String,
    class: u16,
    ttl: u32,
    value: String,
}

impl DnsSettings {
    /// Build the wire DNS config for the tailnet.
    ///
    /// `magic_dns_ipv4`/`magic_dns_ipv6` are the resolved MagicDNS resolver
    /// addresses (already derived from the configured prefixes or overridden
    /// by the operator). `nodes` are the wire nodes whose MagicDNS name the
    /// zone should answer; `extra_records` are the hot-reloadable static
    /// records.
    pub fn build(
        &self,
        tailnet_domain: &str,
        magic_dns_ipv4: Ipv4Addr,
        magic_dns_ipv6: Ipv6Addr,
        nodes: &[ProtoNode],
        extra_records: &[DnsRecord],
    ) -> DnsConfig {
        let suffix = format!("{tailnet_domain}.");

        let mut config = DnsConfig {
            routes: self
                .split_dns
                .iter()
                .map(|(suffix, addrs)| {
                    (
                        suffix.clone(),
                        addrs
                            .iter()
                            .map(|addr| DnsResolver {
                                addr: addr.clone(),
                                ..Default::default()
                            })
                            .collect(),
                    )
                })
                .collect(),
            ..Default::default()
        };

        // Search domains always include explicitly configured ones; the
        // tailnet domain is added when MagicDNS is on so short hostnames
        // resolve inside the tailnet.
        let mut search_domains: Vec<String> = Vec::new();
        if self.magic_dns {
            search_domains.push(tailnet_domain.to_string());
        }
        for domain in &self.search_domains {
            if !search_domains.iter().any(|d| d == domain) {
                search_domains.push(domain.clone());
            }
        }
        config.domains = search_domains.clone();
        // `SearchDomains` is populated as a crabscale compatibility
        // extension; clients read search domains from `Domains`.
        config.search_domains = search_domains;

        if self.magic_dns {
            let magic_resolvers = vec![
                DnsResolver {
                    addr: magic_dns_ipv4.to_string(),
                    ..Default::default()
                },
                DnsResolver {
                    addr: magic_dns_ipv6.to_string(),
                    ..Default::default()
                },
            ];
            config.resolvers = magic_resolvers.clone();
            config.proxied = true;
            config.magic_dns_suffix = suffix.clone();

            // The MagicDNS route: the tailnet suffix resolves through the
            // MagicDNS resolver derived from the prefixes.
            config
                .routes
                .entry(suffix.clone())
                .or_default()
                .extend(magic_resolvers);

            // One A/AAAA record per node so peers resolve each other by name.
            for node in nodes {
                for address in &node.addresses {
                    if let Some(record) = Self::node_record(node, address) {
                        config.extra_records.push(record);
                    }
                }
            }
            config.extra_records.extend(extra_records.iter().cloned());
        }

        config
    }

    /// Build the record mapping a node's MagicDNS name to one of its tailnet
    /// addresses.
    fn node_record(node: &ProtoNode, address: &str) -> Option<DnsRecord> {
        let (ip_str, family) = Self::split_address(address)?;
        Some(DnsRecord {
            name: node_name(node),
            rec_type: family,
            class: 1,
            ttl: DEFAULT_EXTRA_RECORD_TTL,
            value: ip_str,
        })
    }

    /// Split a CIDR address into its IP literal and DNS record type mnemonic
    /// (`"A"` for IPv4, `"AAAA"` for IPv6). Returns `None` for unparseable
    /// addresses.
    fn split_address(address: &str) -> Option<(String, String)> {
        let ip_literal = address.split('/').next()?;
        let ip: IpAddr = ip_literal.parse().ok()?;
        let rec_type = if ip.is_ipv4() { "A" } else { "AAAA" };
        Some((ip_literal.to_string(), rec_type.to_string()))
    }
}

/// The MagicDNS name for a wire node, normalized to have a trailing dot.
pub fn node_name(node: &ProtoNode) -> String {
    if node.name.is_empty() {
        return node.name.clone();
    }
    if node.name.ends_with('.') {
        node.name.clone()
    } else {
        format!("{}.", node.name)
    }
}

/// Derive the IPv4 MagicDNS resolver address from a configured IPv4 prefix.
///
/// The well-known `100.100.100.100` is used when the configured prefix covers
/// it (the default CGNAT range). For any other prefix a deterministic
/// highest-host address inside the prefix is chosen to avoid depending on a
/// fixed address that may lie outside the operator's network.
pub fn derive_magic_dns_ipv4(prefix: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    if ipv4_contains(prefix, prefix_len, DEFAULT_MAGIC_DNS_IPV4) {
        return DEFAULT_MAGIC_DNS_IPV4;
    }
    ipv4_last_host(prefix, prefix_len)
}

/// Derive the IPv6 MagicDNS resolver address from a configured IPv6 prefix.
pub fn derive_magic_dns_ipv6(prefix: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    if ipv6_contains(prefix, prefix_len, DEFAULT_MAGIC_DNS_IPV6) {
        return DEFAULT_MAGIC_DNS_IPV6;
    }
    ipv6_last_host(prefix, prefix_len)
}

fn ipv4_contains(prefix: Ipv4Addr, prefix_len: u8, ip: Ipv4Addr) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }
    let mask = if prefix_len == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };
    (u32::from(prefix) & mask) == (u32::from(ip) & mask)
}

fn ipv6_contains(prefix: Ipv6Addr, prefix_len: u8, ip: Ipv6Addr) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 128 {
        return false;
    }
    let mask = if prefix_len == 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix_len)
    };
    (u128::from(prefix) & mask) == (u128::from(ip) & mask)
}

/// The highest usable host in an IPv4 prefix (the broadcast address is
/// skipped). Falls back to the prefix address for degenerate lengths.
fn ipv4_last_host(prefix: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 || prefix_len >= 31 {
        return prefix;
    }
    let mask = u32::MAX << (32 - prefix_len);
    let network = u32::from(prefix) & mask;
    let host_bits = 32 - prefix_len;
    let host_count = 1u32 << host_bits;
    Ipv4Addr::from(network + host_count - 2)
}

/// The highest usable host in an IPv6 prefix (the subnet-router anycast
/// address is skipped). Falls back to the prefix for degenerate lengths.
fn ipv6_last_host(prefix: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    if prefix_len == 0 || prefix_len >= 128 {
        return prefix;
    }
    let mask = u128::MAX << (128 - prefix_len);
    let network = u128::from(prefix) & mask;
    let host_bits = 128 - prefix_len;
    let host_count = 1u128 << host_bits;
    Ipv6Addr::from(network + host_count - 1)
}

/// Resolve a record's type mnemonic. An explicitly provided type is kept;
/// an empty type is inferred from the value (`"A"` for an IPv4 literal,
/// `"AAAA"` for an IPv6 literal) and stays empty otherwise so the client can
/// infer it.
fn infer_record_type(explicit: &str, value: &str) -> String {
    if !explicit.is_empty() {
        return explicit.to_string();
    }
    if value.parse::<Ipv4Addr>().is_ok() {
        return "A".to_string();
    }
    if value.parse::<Ipv6Addr>().is_ok() {
        return "AAAA".to_string();
    }
    String::new()
}

/// Parse an extra-records JSON file body into wire records.
pub fn parse_extra_records(body: &[u8]) -> Result<Vec<DnsRecord>, DnsError> {
    let records: Vec<ExtraRecordFile> =
        serde_json::from_slice(body).map_err(|e| DnsError::Parse(e.to_string()))?;
    records
        .into_iter()
        .map(|r| {
            if r.name.is_empty() {
                return Err(DnsError::Parse(
                    "an extra record must have a non-empty name".to_string(),
                ));
            }
            if r.value.is_empty() {
                return Err(DnsError::Parse(
                    "an extra record must have a non-empty value".to_string(),
                ));
            }
            let rec_type = infer_record_type(&r.rec_type, &r.value);
            Ok(DnsRecord {
                name: r.name,
                rec_type,
                class: if r.class == 0 { 1 } else { r.class },
                ttl: r.ttl,
                value: r.value,
            })
        })
        .collect()
}

/// Read and parse an extra-records JSON file.
pub fn load_extra_records(path: &Path) -> Result<Vec<DnsRecord>, DnsError> {
    let body = std::fs::read(path).map_err(|e| DnsError::Io(e.to_string()))?;
    parse_extra_records(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_nodes() -> Vec<ProtoNode> {
        vec![
            ProtoNode {
                id: 1,
                name: "node1.tailnet.example.".to_string(),
                addresses: vec![
                    "100.64.0.1/32".to_string(),
                    "fd7a:115c:a1e0::1/128".to_string(),
                ],
                ..Default::default()
            },
            ProtoNode {
                id: 2,
                name: "node2.tailnet.example.".to_string(),
                addresses: vec!["100.64.0.2/32".to_string()],
                ..Default::default()
            },
        ]
    }

    #[test]
    fn magic_dns_config_includes_suffix_resolvers_and_node_records() {
        let settings = DnsSettings::default();
        let config = settings.build(
            "tailnet.example",
            DEFAULT_MAGIC_DNS_IPV4,
            DEFAULT_MAGIC_DNS_IPV6,
            &sample_nodes(),
            &[],
        );
        assert_eq!(config.magic_dns_suffix, "tailnet.example.");
        assert!(config.proxied);
        assert_eq!(config.search_domains, vec!["tailnet.example".to_string()]);
        assert_eq!(
            config.domains,
            vec!["tailnet.example".to_string()],
            "search domains must be delivered in Domains"
        );
        assert!(config.resolvers.iter().any(|r| r.addr == "100.100.100.100"));
        let route = config
            .routes
            .get("tailnet.example.")
            .expect("magic DNS route must exist");
        assert!(route.iter().any(|r| r.addr == "100.100.100.100"));
        let names: Vec<&str> = config
            .extra_records
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert!(names.contains(&"node1.tailnet.example."));
        assert!(names.contains(&"node2.tailnet.example."));
        let a = config
            .extra_records
            .iter()
            .find(|r| r.value == "100.64.0.2")
            .expect("node2 A record");
        assert_eq!(a.rec_type, "A");
        assert_eq!(a.class, 1);
        let aaaa = config
            .extra_records
            .iter()
            .find(|r| r.value == "fd7a:115c:a1e0::1")
            .expect("node1 AAAA record");
        assert_eq!(aaaa.rec_type, "AAAA");
    }

    #[test]
    fn disabling_magic_dns_drops_magic_fields_but_keeps_split_dns() {
        let settings = DnsSettings {
            magic_dns: false,
            search_domains: vec!["corp.example".to_string()],
            split_dns: BTreeMap::from([(
                "corp.example.".to_string(),
                vec!["10.0.0.53".to_string()],
            )]),
            ..Default::default()
        };
        let config = settings.build(
            "tailnet.example",
            DEFAULT_MAGIC_DNS_IPV4,
            DEFAULT_MAGIC_DNS_IPV6,
            &sample_nodes(),
            &[],
        );
        assert!(!config.proxied);
        assert!(config.magic_dns_suffix.is_empty());
        assert!(config.resolvers.is_empty());
        assert!(config.extra_records.is_empty());
        assert_eq!(
            config.routes.get("corp.example.").unwrap()[0].addr,
            "10.0.0.53"
        );
        assert_eq!(config.search_domains, vec!["corp.example".to_string()]);
        assert_eq!(config.domains, vec!["corp.example".to_string()]);
    }

    #[test]
    fn custom_prefix_derives_in_prefix_magic_dns_address() {
        let addr = derive_magic_dns_ipv4(Ipv4Addr::new(10, 100, 0, 0), 16);
        assert_eq!(addr, Ipv4Addr::new(10, 100, 255, 254));
        let v6 = derive_magic_dns_ipv6(Ipv6Addr::new(0xfd00, 0x10, 0, 0, 0, 0, 0, 0), 32);
        assert_eq!(
            v6,
            Ipv6Addr::new(0xfd00, 0x10, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)
        );
    }

    #[test]
    fn default_prefixes_use_well_known_magic_dns_addresses() {
        assert_eq!(
            derive_magic_dns_ipv4(Ipv4Addr::new(100, 64, 0, 0), 10),
            DEFAULT_MAGIC_DNS_IPV4
        );
        assert_eq!(
            derive_magic_dns_ipv6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0), 48),
            DEFAULT_MAGIC_DNS_IPV6
        );
    }

    #[test]
    fn prefix_matching_handles_degenerate_lengths() {
        // /0 contains everything and must not overflow the shift.
        assert!(ipv4_contains(
            Ipv4Addr::new(10, 0, 0, 0),
            0,
            Ipv4Addr::new(192, 168, 1, 1)
        ));
        assert!(ipv6_contains(Ipv6Addr::LOCALHOST, 0, Ipv6Addr::LOCALHOST));
        // /32 and /128 masks are the full width.
        assert!(ipv4_contains(
            Ipv4Addr::new(10, 0, 0, 0),
            32,
            Ipv4Addr::new(10, 0, 0, 0)
        ));
        assert!(ipv6_contains(Ipv6Addr::LOCALHOST, 128, Ipv6Addr::LOCALHOST));
        // Last-host helpers fall back instead of overflowing on /0.
        assert_eq!(
            ipv4_last_host(Ipv4Addr::new(10, 0, 0, 0), 0),
            Ipv4Addr::new(10, 0, 0, 0)
        );
        assert_eq!(ipv6_last_host(Ipv6Addr::LOCALHOST, 0), Ipv6Addr::LOCALHOST);
    }

    #[test]
    fn parses_extra_records_file() {
        let body = br#"[
            { "name": "db.tailnet.example.", "type": "A", "ttl": 60, "value": "100.64.0.9" },
            { "name": "ns.tailnet.example.", "value": "fd7a:115c:a1e0::9" }
        ]"#;
        let records = parse_extra_records(body).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].name, "db.tailnet.example.");
        assert_eq!(records[0].rec_type, "A");
        assert_eq!(records[0].ttl, 60);
        assert_eq!(records[0].class, 1, "missing class defaults to IN");
        // Empty type with an IPv6 value infers AAAA.
        assert_eq!(records[1].rec_type, "AAAA");
    }

    #[test]
    fn record_type_is_inferred_from_value_when_empty() {
        assert_eq!(infer_record_type("", "100.64.0.9"), "A");
        assert_eq!(infer_record_type("", "fd7a:115c:a1e0::9"), "AAAA");
        assert_eq!(infer_record_type("CNAME", "alias.example."), "CNAME");
        assert_eq!(infer_record_type("", "not-an-ip"), "");
    }

    #[test]
    fn rejects_invalid_extra_records_file() {
        assert!(parse_extra_records(b"not json").is_err());
        assert!(parse_extra_records(br#"[{ "name": "", "value": "x" }]"#).is_err());
        assert!(parse_extra_records(br#"[{ "name": "x", "value": "" }]"#).is_err());
    }

    #[test]
    fn node_name_is_normalized_with_trailing_dot() {
        let node = ProtoNode {
            name: "host.tailnet.example".to_string(),
            ..Default::default()
        };
        assert_eq!(node_name(&node), "host.tailnet.example.");
        let node = ProtoNode {
            name: "host.tailnet.example.".to_string(),
            ..Default::default()
        };
        assert_eq!(node_name(&node), "host.tailnet.example.");
    }
}

/// Shared, clone-safe DNS state owned by the control plane.
///
/// The extra-records snapshot lives here so a hot reload can swap it without
/// rebuilding the control plane, and the revision broadcast lets every live
/// map session learn about a DNS change and push a delta frame.
#[derive(Debug)]
pub(crate) struct DnsState {
    extra_records: std::sync::Mutex<Vec<DnsRecord>>,
    revision: std::sync::atomic::AtomicU64,
    changed: tokio::sync::broadcast::Sender<u64>,
}

impl DnsState {
    /// Create a state seeded with `extra_records` at revision 0.
    pub(crate) fn new(extra_records: Vec<DnsRecord>) -> Self {
        let (changed, _) = tokio::sync::broadcast::channel(16);
        Self {
            extra_records: std::sync::Mutex::new(extra_records),
            revision: std::sync::atomic::AtomicU64::new(0),
            changed,
        }
    }

    /// Atomically replace the extra-records snapshot and broadcast a new
    /// revision to subscribers. Returns the new revision.
    pub(crate) fn set_extra_records(&self, records: Vec<DnsRecord>) -> u64 {
        *self.extra_records.lock().expect("dns state mutex poisoned") = records;
        let revision = self
            .revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let _ = self.changed.send(revision);
        revision
    }

    /// Snapshot of the current extra records.
    pub(crate) fn extra_records(&self) -> Vec<DnsRecord> {
        self.extra_records
            .lock()
            .expect("dns state mutex poisoned")
            .clone()
    }

    /// Current DNS revision (1 = as configured at startup).
    pub(crate) fn revision(&self) -> u64 {
        self.revision.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Subscribe to DNS revisions. The receiver yields a new revision for
    /// every successful hot reload.
    pub(crate) fn subscribe(&self) -> tokio::sync::broadcast::Receiver<u64> {
        self.changed.subscribe()
    }
}
