//! DNS configuration wire types.
//!
//! A `DnsConfig` is delivered to a client inside the MapResponse `DNS`
//! field. It describes which resolvers to use, how to split names across
//! resolvers, which suffixes are searchable, and which static records the
//! client's MagicDNS resolver should serve.
//!
//! Wire rules for these objects are documented in Spec-NetMap.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A DNS server a client should use for some set of names.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct DnsResolver {
    /// The resolver address as an IP literal, optionally with a `:port`.
    pub addr: String,
    /// Bootstrap IP literals to use when the resolver address itself is only
    /// reachable once the tailnet interface is up.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bootstrap_resolution: Vec<String>,
}

/// A single static record injected into the MagicDNS zone.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct DnsRecord {
    /// Fully-qualified record name with a trailing dot, e.g.
    /// `db.tailnet.example.`.
    pub name: String,
    /// DNS record type as a mnemonic string: `"A"`, `"AAAA"`, `"CNAME"`,
    /// or empty to let the client infer the type from `value`.
    #[serde(rename = "Type", skip_serializing_if = "String::is_empty")]
    pub rec_type: String,
    /// DNS class; 1 is the standard IN class used for the records we emit.
    #[serde(skip_serializing_if = "crate::serde_util::is_zero_u16")]
    pub class: u16,
    /// Time-to-live in seconds.
    #[serde(rename = "TTL", skip_serializing_if = "crate::serde_util::is_zero_u32")]
    pub ttl: u32,
    /// Record payload, e.g. `100.64.0.2` for an A record.
    pub value: String,
}

/// DNS configuration sent to clients in the MapResponse `DNS` field.
///
/// The field uses the conventional name `DNS` (not `Dns`) on the wire.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct DnsConfig {
    /// Ordered list of resolvers to consult for names not covered by a
    /// specific split-DNS route.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<DnsResolver>,
    /// Split DNS: map of DNS suffix (with trailing dot) to the resolvers
    /// that must answer names under that suffix.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub routes: BTreeMap<String, Vec<DnsResolver>>,
    /// Search domains (without trailing dots) appended when resolving a
    /// short hostname. This mirrors `domains` and is emitted as a crabscale
    /// compatibility extension; clients read search domains from `domains`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub search_domains: Vec<String>,
    /// Search / candidate domains (without trailing dots). This is the field
    /// compatible clients read for search/name resolution.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// True when the resolver is the client's local MagicDNS proxy, which
    /// serves the `magic_dns_suffix` zone and any `extra_records`.
    #[serde(skip_serializing_if = "crate::serde_util::is_false")]
    pub proxied: bool,
    /// The suffix (with trailing dot) served by the MagicDNS proxy. Clients
    /// derive the MagicDNS suffix from the self node's name; this field is a
    /// crabscale extension that mirrors the same value.
    #[serde(rename = "MagicDNSSuffix", skip_serializing_if = "String::is_empty")]
    pub magic_dns_suffix: String,
    /// Static records the MagicDNS resolver serves for the tailnet zone.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_records: Vec<DnsRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serde_util;

    #[test]
    fn dns_config_serializes_the_conventional_field_names() {
        let config = DnsConfig {
            resolvers: vec![DnsResolver {
                addr: "100.100.100.100".to_string(),
                ..Default::default()
            }],
            routes: BTreeMap::from([(
                "split.example.".to_string(),
                vec![DnsResolver {
                    addr: "10.0.0.53".to_string(),
                    ..Default::default()
                }],
            )]),
            search_domains: vec!["example.com".to_string()],
            domains: vec!["example.com".to_string()],
            proxied: true,
            magic_dns_suffix: "tailnet.example.".to_string(),
            extra_records: vec![DnsRecord {
                name: "db.tailnet.example.".to_string(),
                rec_type: "A".to_string(),
                class: 1,
                ttl: 300,
                value: "100.64.0.2".to_string(),
            }],
        };
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(
            json["Resolvers"][0]["Addr"],
            serde_json::json!("100.100.100.100")
        );
        assert_eq!(
            json["Routes"]["split.example."][0]["Addr"],
            serde_json::json!("10.0.0.53")
        );
        assert_eq!(json["SearchDomains"], serde_json::json!(["example.com"]));
        assert_eq!(json["Domains"], serde_json::json!(["example.com"]));
        assert_eq!(json["Proxied"], serde_json::json!(true));
        assert_eq!(
            json["MagicDNSSuffix"],
            serde_json::json!("tailnet.example.")
        );
        assert_eq!(
            json["ExtraRecords"][0],
            serde_json::json!({
                "Name": "db.tailnet.example.",
                "Type": "A",
                "Class": 1,
                "TTL": 300,
                "Value": "100.64.0.2"
            })
        );
    }

    #[test]
    fn empty_dns_config_omits_optional_fields() {
        let json = serde_json::to_value(DnsConfig::default()).unwrap();
        assert!(json.get("Resolvers").is_none());
        assert!(json.get("Routes").is_none());
        assert!(json.get("SearchDomains").is_none());
        assert!(json.get("Proxied").is_none());
        assert!(json.get("MagicDNSSuffix").is_none());
        assert!(json.get("ExtraRecords").is_none());
    }

    #[test]
    fn dns_config_round_trips() {
        let config = DnsConfig {
            resolvers: vec![DnsResolver {
                addr: "100.100.100.100".to_string(),
                bootstrap_resolution: vec!["1.1.1.1".to_string()],
            }],
            magic_dns_suffix: "tailnet.example.".to_string(),
            ..Default::default()
        };
        let wire = serde_json::to_string(&config).unwrap();
        let back: DnsConfig = serde_json::from_str(&wire).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn serde_util_helpers_are_stable() {
        assert!(serde_util::is_zero_u32(&0));
        assert!(!serde_util::is_zero_u32(&1));
    }
}
