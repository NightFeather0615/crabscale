//! ACL and grants compiler: turn a parsed [`Policy`] into per-node packet
//! filters, peer visibility, and capability grants.
//!
//! Compilation follows [Spec-Policy]:
//!
//! - ACL rules are allow rules; the default is deny. Each `accept` rule is
//!   compiled into one or more [`FilterRule`]s whose `SrcIPs` are the
//!   resolved source addresses and whose `DstPorts` are the allowed ports.
//! - A global base filter (the union of all compiled network rules) is
//!   derived first, then reduced per node: a node's filter only contains the
//!   rules whose destination matches one of the node's addresses.
//! - A peer `P` is visible to node `N` iff traffic `N -> P` or `P -> N` is
//!   allowed by some ACL rule.
//! - `grants` compile into application-level filter rules (carrying
//!   `CapGrant`) delivered to the destination node, mirroring how the wire
//!   format encodes peer capabilities.
//! - Tags match nodes carrying the same `tag:` value.
//! - Supported autogroups resolve as follows: `autogroup:self` matches every
//!   node (each node is, from its own point of view, "self"),
//!   `autogroup:member` matches untagged (user-owned) nodes, and
//!   `autogroup:tagged` matches tagged nodes.
//!
//! [`node_attributes`] resolves the policy's `nodeAttrs` into the per-node
//! `CapMap` the control plane emits on the self node.
//!
//! [Spec-Policy]: https://github.com/NightFeather0615/crabscale/wiki/Spec-Policy.md

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};

use crabscale_proto::{CapGrant, FilterRule, NetPortRange};
use serde_json::Value as JsonValue;

use crate::model::Policy;

/// A node as seen by the ACL compiler.
///
/// The control plane builds one of these per registered node; only the
/// fields required for policy matching are exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileNode {
    /// Unique node id.
    pub id: u64,
    /// Stable node id string (e.g. `n00000000000000000000001`), used to emit
    /// concrete `Node` SSH principals on the wire. May be empty for
    /// synthetic/test nodes.
    pub stable_id: String,
    /// Owning user's login name (e.g. `alice@example.com`), when known.
    pub user_login: Option<String>,
    /// The node's tailnet addresses as CIDR strings.
    pub addresses: Vec<String>,
    /// Tags applied to this node.
    pub tags: Vec<String>,
}

impl CompileNode {
    /// Build a node with no identity or tags; useful for address-only tests.
    pub fn with_addresses(id: u64, addresses: Vec<String>) -> Self {
        CompileNode {
            id,
            stable_id: String::new(),
            user_login: None,
            addresses,
            tags: Vec::new(),
        }
    }
}

/// The result of compiling a [`Policy`] against a set of nodes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompiledPolicy {
    /// The global base filter: every compiled network rule, deduplicated.
    pub global_filter: Vec<FilterRule>,
    /// Per-node reduced filters: network and capability rules relevant to
    /// each node. Every node has an entry (possibly empty).
    pub node_filters: BTreeMap<u64, Vec<FilterRule>>,
    /// Per-node capability grants (subset of `node_filters` carrying
    /// `CapGrant`), kept separately for inspection and tests.
    pub grants: BTreeMap<u64, Vec<FilterRule>>,
    /// Peer visibility: for each node, the ids of peers that must appear in
    /// its map (reachable in at least one direction).
    pub peer_visibility: BTreeMap<u64, BTreeSet<u64>>,
}

/// Compile a policy against the current node set.
pub fn compile_policy(policy: &Policy, nodes: &[CompileNode]) -> CompiledPolicy {
    let mut ctx = Ctx {
        policy,
        resolving_groups: BTreeSet::new(),
    };

    let mut compiled = CompiledPolicy::default();
    let mut can_reach: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();

    // Network rules from ACLs.
    for rule in &policy.acls {
        let resolved_src = ctx.resolve(rule.src.iter().map(String::as_str));
        let src_ips = resolved_src.to_src_ips(nodes);

        // A rule whose source resolves to nothing cannot allow any traffic.
        if src_ips.is_empty() {
            continue;
        }

        // The nodes the source matches, used for peer visibility.
        let src_nodes: Vec<&CompileNode> = nodes
            .iter()
            .filter(|n| resolved_src.matches_node(n))
            .collect();

        let ip_proto = parse_ip_proto(rule.proto.as_deref());
        for dst in &rule.dst {
            let Some(dst_target) = ctx.parse_dst(dst) else {
                continue;
            };
            let ports = dst_target.ports();
            let filter = FilterRule {
                src_ips: src_ips.clone(),
                dst_ports: ports.clone(),
                ip_proto: ip_proto.clone(),
                ..Default::default()
            };
            // The global base filter holds every compiled rule regardless of
            // which nodes happen to exist.
            push_dedup(&mut compiled.global_filter, &filter);

            // Per-node reduction: only nodes matching the destination carry
            // the rule in their own filter.
            let mut dst_nodes = Vec::new();
            for node in nodes {
                if !dst_target.matches(cctx_snapshot(&ctx, node)) {
                    continue;
                }
                dst_nodes.push(node);
                compiled
                    .node_filters
                    .entry(node.id)
                    .or_default()
                    .push(filter.clone());
            }

            // Peer visibility: every node matching the source may reach every
            // node matching the destination.
            for s in &src_nodes {
                let reach = can_reach.entry(s.id).or_default();
                for d in &dst_nodes {
                    reach.insert(d.id);
                }
            }
        }
    }

    // Application capability grants.
    for grant in &policy.grants {
        let resolved_src = ctx.resolve(grant.src.iter().map(String::as_str));
        let src_ips = resolved_src.to_src_ips(nodes);
        if src_ips.is_empty() {
            continue;
        }
        let dst_targets: Vec<DstTarget> =
            grant.dst.iter().filter_map(|d| ctx.parse_dst(d)).collect();
        for node in nodes {
            let visible_dst = dst_targets
                .iter()
                .any(|t| t.matches(cctx_snapshot(&ctx, node)));
            if !visible_dst {
                continue;
            }
            let cap_grant = CapGrant {
                dsts: node.addresses.clone(),
                cap_map: grant
                    .app
                    .iter()
                    .map(|(name, value)| (name.clone(), values_of(value)))
                    .collect(),
            };
            let filter = FilterRule {
                src_ips: src_ips.clone(),
                cap_grant: vec![cap_grant],
                ..Default::default()
            };
            compiled
                .node_filters
                .entry(node.id)
                .or_default()
                .push(filter.clone());
            compiled.grants.entry(node.id).or_default().push(filter);
        }
    }

    // Every node gets an entry (possibly empty) so deny-all serializes `[]`
    // rather than an omitted filter.
    for node in nodes {
        compiled.node_filters.entry(node.id).or_default();
        compiled.peer_visibility.insert(node.id, BTreeSet::new());
    }

    // Peer visibility is symmetric in the sense that N sees P if N->P or
    // P->N is allowed.
    let reach = &can_reach;
    for (node, visible) in &mut compiled.peer_visibility {
        let out = reach.get(node).cloned().unwrap_or_default();
        visible.extend(out.iter().copied());
        for (from, tos) in reach {
            if tos.contains(node) && from != node {
                visible.insert(*from);
            }
        }
    }
    // A node never sees itself.
    for (node, visible) in &mut compiled.peer_visibility {
        visible.remove(node);
    }

    compiled
}

/// Resolve the policy's `nodeAttrs` into the node's `CapMap`.
///
/// Each `nodeAttrs` grant whose target matches `node` contributes its `attr`
/// names as capability keys whose value is an empty JSON array (the
/// wire shape for a key-only capability). Matching grants are merged, so a
/// node targeted by several grants accumulates every attribute. Unsupported
/// or undefined targets simply match nothing.
///
/// The returned map is what the control plane puts in the self node's
/// [`crabscale_proto::Node::cap_map`] (Spec-Policy §6).
pub fn node_attributes(
    policy: &Policy,
    node: &CompileNode,
    nodes: &[CompileNode],
) -> BTreeMap<String, Vec<JsonValue>> {
    let mut attrs = BTreeSet::new();
    for grant in &policy.node_attrs {
        if grant
            .target
            .iter()
            .any(|t| node_attr_target_matches(policy, t, node, nodes))
        {
            attrs.extend(grant.attr.iter().cloned());
        }
    }
    attrs.into_iter().map(|attr| (attr, Vec::new())).collect()
}

/// Whether a `nodeAttrs` target principal matches `node`.
///
/// Supported targets are `*`, user logins, `tag:` values, `group:` members,
/// `autogroup:self` (the node itself), `autogroup:member` (untagged nodes),
/// and `autogroup:tagged` (tagged nodes).
fn node_attr_target_matches(
    policy: &Policy,
    target: &str,
    node: &CompileNode,
    _nodes: &[CompileNode],
) -> bool {
    if target == "*" {
        return true;
    }
    if let Some(rest) = target.strip_prefix("autogroup:") {
        return match rest {
            "self" => true,
            "member" => node.tags.is_empty(),
            "tagged" => !node.tags.is_empty(),
            _ => false,
        };
    }
    if let Some(tag) = target.strip_prefix("tag:") {
        if tag.is_empty() {
            return false;
        }
        return node.tags.iter().any(|t| t == target);
    }
    if target.starts_with("group:") {
        // Groups are resolved transitively (group members may themselves be
        // users or nested groups), matching `tags::principal_matches_user`.
        return node
            .user_login
            .as_deref()
            .is_some_and(|login| crate::tags::principal_matches_user(policy, target, login));
    }
    if let Some(login) = &node.user_login {
        if login == target {
            return true;
        }
    }
    false
}

/// A snapshot of the compile context sufficient for destination matching.
pub(crate) struct Ctx<'a> {
    policy: &'a Policy,
    resolving_groups: BTreeSet<String>,
}

fn cctx_snapshot<'a>(_ctx: &'a Ctx<'_>, node: &'a CompileNode) -> NodeMatchCtx<'a> {
    NodeMatchCtx { node }
}

/// Borrowed context used to test whether a node matches a resolved target.
struct NodeMatchCtx<'a> {
    node: &'a CompileNode,
}

/// A fully or partially resolved address/identity target.
///
/// In addition to static networks and identities, a target may carry
/// autogroup markers. The supported autogroups (Spec-Policy §5) expand to:
///
/// - `autogroup:self` ([`ResolvedTarget::self_match`]): every node. Each
///   node is, from its own point of view, "self", so the rule applies to
///   every node in both source and destination position.
/// - `autogroup:member` ([`ResolvedTarget::member_match`]): untagged
///   (user-owned) nodes.
/// - `autogroup:tagged` ([`ResolvedTarget::tagged_match`]): tagged nodes.
#[derive(Debug, Clone, Default)]
pub(crate) struct ResolvedTarget {
    /// `true` when the target is `*` and matches every node.
    pub(crate) wildcard: bool,
    /// `true` when the target contains `autogroup:self`; matches every node.
    pub(crate) self_match: bool,
    /// `true` when the target contains `autogroup:member`; matches untagged nodes.
    pub(crate) member_match: bool,
    /// `true` when the target contains `autogroup:tagged`; matches tagged nodes.
    pub(crate) tagged_match: bool,
    /// IP networks (CIDR or bare IP, kept as input strings).
    nets: Vec<String>,
    /// Identities (user logins or tags) matched against node credentials.
    identities: BTreeSet<String>,
}

impl ResolvedTarget {
    /// Whether this target matches the given node.
    pub(crate) fn matches_node(&self, node: &CompileNode) -> bool {
        if self.wildcard || self.self_match {
            return true;
        }
        if node
            .user_login
            .as_deref()
            .is_some_and(|login| self.identities.contains(login))
        {
            return true;
        }
        if node.tags.iter().any(|tag| self.identities.contains(tag)) {
            return true;
        }
        if self.member_match && node.tags.is_empty() {
            return true;
        }
        if self.tagged_match && !node.tags.is_empty() {
            return true;
        }
        self.nets
            .iter()
            .any(|net| node.addresses.iter().any(|addr| addr_in_cidr(addr, net)))
    }

    /// Collect the addresses of every node matched by an autogroup marker.
    fn autogroup_ips(&self, nodes: &[CompileNode]) -> Vec<String> {
        let mut ips = Vec::new();
        for node in nodes {
            if self.self_match
                || (self.member_match && node.tags.is_empty())
                || (self.tagged_match && !node.tags.is_empty())
            {
                ips.extend(node.addresses.iter().cloned());
            }
        }
        ips
    }

    /// The `SrcIPs` list to emit for this target, expanding identities and
    /// autogroups to the addresses of the matching nodes. Empty means the
    /// target matched no node, so no rule should be produced.
    fn to_src_ips(&self, nodes: &[CompileNode]) -> Vec<String> {
        if self.wildcard {
            return vec!["*".to_string()];
        }
        let mut ips = self.nets.clone();
        ips.extend(self.autogroup_ips(nodes));
        for node in nodes {
            if node
                .user_login
                .as_deref()
                .is_some_and(|l| self.identities.contains(l))
                || node.tags.iter().any(|t| self.identities.contains(t))
            {
                ips.extend(node.addresses.iter().cloned());
            }
        }
        ips.sort();
        ips.dedup();
        ips
    }
}

/// A parsed destination target: address/identity matcher plus port ranges.
#[derive(Debug, Clone)]
struct DstTarget {
    target: ResolvedTarget,
    ports: Vec<NetPortRange>,
    /// `true` when the destination is a wildcard (`*`).
    wildcard: bool,
}

impl DstTarget {
    fn matches(&self, ctx: NodeMatchCtx<'_>) -> bool {
        self.wildcard || self.target.matches_node(ctx.node)
    }

    fn ports(&self) -> Vec<NetPortRange> {
        self.ports.clone()
    }
}

impl<'a> Ctx<'a> {
    /// Create a resolution context over a parsed policy.
    pub(crate) fn new(policy: &'a Policy) -> Self {
        Ctx {
            policy,
            resolving_groups: BTreeSet::new(),
        }
    }

    /// Resolve a source/destination target (without the port suffix).
    pub(crate) fn resolve<'s, I>(&mut self, targets: I) -> ResolvedTarget
    where
        I: IntoIterator<Item = &'s str>,
    {
        let mut resolved = ResolvedTarget::default();
        for target in targets {
            let single = self.resolve_single(target);
            resolved.wildcard |= single.wildcard;
            resolved.self_match |= single.self_match;
            resolved.member_match |= single.member_match;
            resolved.tagged_match |= single.tagged_match;
            resolved.nets.extend(single.nets);
            resolved.identities.extend(single.identities);
        }
        resolved.nets.sort();
        resolved.nets.dedup();
        resolved
    }

    fn resolve_single(&mut self, target: &str) -> ResolvedTarget {
        let mut resolved = ResolvedTarget::default();
        if target == "*" {
            resolved.wildcard = true;
            return resolved;
        }
        if let Some(rest) = target.strip_prefix("autogroup:") {
            match rest {
                "self" => resolved.self_match = true,
                "member" => resolved.member_match = true,
                "tagged" => resolved.tagged_match = true,
                // Unsupported autogroups (admin, owner, internet) match nothing.
                _ => {}
            }
            return resolved;
        }
        if let Some(group) = target.strip_prefix("group:") {
            let group = group.to_string();
            if self.resolving_groups.insert(group.clone()) {
                if let Some(members) = self.policy.groups.get(&group) {
                    for member in members {
                        let member_resolved = self.resolve_single(member);
                        resolved.wildcard |= member_resolved.wildcard;
                        resolved.nets.extend(member_resolved.nets);
                        resolved.identities.extend(member_resolved.identities);
                    }
                }
                self.resolving_groups.remove(&group);
            }
            return resolved;
        }
        if target.starts_with("tag:") {
            resolved.identities.insert(target.to_string());
            return resolved;
        }
        if is_user_ident(target) {
            resolved.identities.insert(target.to_string());
            return resolved;
        }
        if is_ip_or_cidr_str(target) {
            resolved.nets.push(normalize_cidr(target));
            return resolved;
        }
        // Host alias from the `hosts` map.
        if let Some(value) = self.policy.hosts.get(target) {
            if is_ip_or_cidr_str(value) {
                resolved.nets.push(normalize_cidr(value));
            }
        }
        resolved
    }

    /// Parse a destination target (host identity + optional `:ports`).
    fn parse_dst(&mut self, target: &str) -> Option<DstTarget> {
        if target == "*" {
            return Some(DstTarget {
                target: ResolvedTarget::default(),
                ports: all_ports(),
                wildcard: true,
            });
        }
        // Bracketed IPv6 with ports: `[addr]:ports`.
        if let Some((host, ports)) = split_bracketed_ports(target) {
            return Some(DstTarget {
                target: self.resolve_bare(&host),
                ports: parse_ports(&ports),
                wildcard: false,
            });
        }
        // Split off a trailing `:portlist` when the prefix is non-IPv6.
        if let Some((host, ports)) = split_ports_literal(target) {
            return Some(DstTarget {
                target: self.resolve_bare(&host),
                ports: parse_ports(&ports),
                wildcard: false,
            });
        }
        Some(DstTarget {
            target: self.resolve_bare(target),
            ports: all_ports(),
            wildcard: false,
        })
    }

    /// Resolve a bare (port-free) destination host/identity.
    fn resolve_bare(&mut self, host: &str) -> ResolvedTarget {
        let mut resolved = ResolvedTarget::default();
        if host == "*" {
            resolved.wildcard = true;
        } else if let Some(rest) = host.strip_prefix("autogroup:") {
            match rest {
                "self" => resolved.self_match = true,
                "member" => resolved.member_match = true,
                "tagged" => resolved.tagged_match = true,
                // Unsupported autogroups (admin, owner, internet) match nothing.
                _ => {}
            }
        } else if host.starts_with("tag:") {
            resolved.identities.insert(host.to_string());
        } else if host.starts_with("group:") {
            let group = host.trim_start_matches("group:");
            if let Some(members) = self.policy.groups.get(group) {
                for member in members {
                    let mut single = self.resolve_single(member);
                    resolved.wildcard |= single.wildcard;
                    resolved.nets.append(&mut single.nets);
                    resolved.identities.extend(single.identities);
                }
            }
        } else if is_user_ident(host) {
            resolved.identities.insert(host.to_string());
        } else if is_ip_or_cidr_str(host) {
            resolved.nets.push(normalize_cidr(host));
        } else if let Some(value) = self.policy.hosts.get(host) {
            if is_ip_or_cidr_str(value) {
                resolved.nets.push(normalize_cidr(value));
            }
        }
        resolved
    }
}

/// Convert a `grant.app` value into the wire's capability value array.
fn values_of(value: &JsonValue) -> Vec<JsonValue> {
    match value {
        JsonValue::Array(items) => items.clone(),
        other => vec![other.clone()],
    }
}

fn all_ports() -> Vec<NetPortRange> {
    vec![NetPortRange {
        first: 0,
        last: 65535,
    }]
}

/// Parse a port list (`"*"`, `"22,443"`, `"8000-9000"`) into ranges.
fn parse_ports(ports: &str) -> Vec<NetPortRange> {
    if ports == "*" {
        return all_ports();
    }
    let mut ranges = Vec::new();
    for item in ports.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = item.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (lo.parse::<u16>(), hi.parse::<u16>()) {
                if lo <= hi {
                    ranges.push(NetPortRange {
                        first: lo,
                        last: hi,
                    });
                }
            }
        } else if let Ok(port) = item.parse::<u16>() {
            ranges.push(NetPortRange {
                first: port,
                last: port,
            });
        }
    }
    ranges
}

/// Split `[addr]:ports` into `(addr, ports)`.
fn split_bracketed_ports(target: &str) -> Option<(String, String)> {
    let (rest, ports) = target.split_once("]:")?;
    let host = rest.strip_prefix('[')?;
    if host.is_empty() || ports.is_empty() {
        return None;
    }
    Some((host.to_string(), ports.to_string()))
}

/// Split a trailing `:portlist` when the prefix is clearly not a bare IPv6
/// address (IPv4/CIDR, `*`, hostname, or alias).
fn split_ports_literal(target: &str) -> Option<(String, String)> {
    let (host, ports) = target.rsplit_once(':')?;
    if host.is_empty() || ports.is_empty() {
        return None;
    }
    // A bare IPv6 address has no usable port split.
    if is_bare_ipv6(host) {
        return None;
    }
    if host == "*"
        || is_ip_or_cidr_str(host)
        || is_host_ident(host)
        || host.starts_with("tag:")
        || host.starts_with("group:")
        || host.starts_with("autogroup:")
        || is_user_ident(host)
    {
        return Some((host.to_string(), ports.to_string()));
    }
    None
}

fn is_bare_ipv6(s: &str) -> bool {
    s.contains(':') && !s.starts_with('[') && s.parse::<Ipv6Addr>().is_ok()
}

fn is_host_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

fn is_user_ident(s: &str) -> bool {
    let Some((user, host)) = s.split_once('@') else {
        return false;
    };
    !user.is_empty() && !host.is_empty() && user.chars().all(|c| !c.is_whitespace())
}

fn is_ip_or_cidr_str(s: &str) -> bool {
    if s.parse::<IpAddr>().is_ok() {
        return true;
    }
    let Some((addr, bits)) = s.split_once('/') else {
        return false;
    };
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    let Ok(bits) = bits.parse::<u8>() else {
        return false;
    };
    let max = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    bits <= max
}

/// Normalize an IP or CIDR string to CIDR form (`addr/prefix`).
fn normalize_cidr(s: &str) -> String {
    if let Ok(ip) = s.parse::<IpAddr>() {
        let bits = if ip.is_ipv4() { 32 } else { 128 };
        return format!("{ip}/{bits}");
    }
    s.to_string()
}

/// Whether `addr` (an IP or CIDR string) falls inside network `net` (a CIDR).
fn addr_in_cidr(addr: &str, net: &str) -> bool {
    let Some((addr_ip, _)) = parse_cidr(addr) else {
        return false;
    };
    let Some((net_ip, bits)) = parse_cidr(net) else {
        return false;
    };
    match (addr_ip, net_ip) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = mask_u32(bits.min(32) as u32);
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = mask_u128(bits.min(128) as u32);
            (u128::from(a) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        let bits = if ip.is_ipv4() { 32 } else { 128 };
        return Some((ip, bits));
    }
    let (addr, bits) = s.split_once('/')?;
    let ip = addr.parse::<IpAddr>().ok()?;
    let bits = bits.parse::<u8>().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if bits > max {
        return None;
    }
    Some((ip, bits))
}

fn mask_u32(bits: u32) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    }
}

fn mask_u128(bits: u32) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    }
}

/// Map an ACL `proto` value to an `IPProto` list.
fn parse_ip_proto(proto: Option<&str>) -> Option<Vec<i32>> {
    let proto = proto?;
    if proto.is_empty() {
        return None;
    }
    // `tcp:80` style constraints: use the protocol name before the colon.
    let name = proto.split(':').next().unwrap_or(proto);
    if let Ok(num) = name.parse::<i32>() {
        return Some(vec![num]);
    }
    let num = match name.to_ascii_lowercase().as_str() {
        "icmp" | "icmpv4" => 1,
        "tcp" => 6,
        "udp" => 17,
        "gre" => 47,
        "icmpv6" | "icmp6" => 58,
        _ => return None,
    };
    Some(vec![num])
}

/// Push a rule into a list unless an equal rule is already present.
fn push_dedup(rules: &mut Vec<FilterRule>, rule: &FilterRule) {
    if !rules.contains(rule) {
        rules.push(rule.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u64, login: Option<&str>, addresses: &[&str]) -> CompileNode {
        CompileNode {
            id,
            stable_id: format!("n{id:023}"),
            user_login: login.map(|s| s.to_string()),
            addresses: addresses.iter().map(|s| s.to_string()).collect(),
            tags: Vec::new(),
        }
    }

    fn filter_rule(src: &[&str], ports: &[(u16, u16)]) -> FilterRule {
        FilterRule {
            src_ips: src.iter().map(|s| s.to_string()).collect(),
            dst_ports: ports
                .iter()
                .map(|(f, l)| NetPortRange {
                    first: *f,
                    last: *l,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn deny_all_policy_compiles_to_empty_filters() {
        let policy = Policy::default();
        let nodes = vec![node(1, None, &["100.64.0.1/32"])];
        let compiled = compile_policy(&policy, &nodes);
        assert!(compiled.global_filter.is_empty());
        assert_eq!(compiled.node_filters.get(&1).unwrap(), &Vec::new());
        assert!(compiled.peer_visibility.get(&1).unwrap().is_empty());
    }

    #[test]
    fn allow_all_matches_wiki_example() {
        let policy: Policy = crate::parse_policy(
            r#"{ "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*"] } ] }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, None, &["100.64.0.1/32"]),
            node(2, None, &["100.64.0.2/32"]),
        ];
        let compiled = compile_policy(&policy, &nodes);
        let expected = filter_rule(&["*"], &[(0, 65535)]);
        assert_eq!(compiled.global_filter, vec![expected.clone()]);
        assert_eq!(
            compiled.node_filters.get(&1).unwrap(),
            &vec![expected.clone()]
        );
        assert_eq!(compiled.node_filters.get(&2).unwrap(), &vec![expected]);
        assert_eq!(compiled.peer_visibility[&1], BTreeSet::from([2]));
        assert_eq!(compiled.peer_visibility[&2], BTreeSet::from([1]));
    }

    #[test]
    fn specific_dst_reduces_filters_per_node() {
        let policy: Policy = crate::parse_policy(
            r#"{ "acls": [ { "action": "accept", "src": ["100.64.0.0/10"], "dst": ["100.64.0.3/32:22,443"] } ] }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, None, &["100.64.0.1/32"]),
            node(3, None, &["100.64.0.3/32"]),
        ];
        let compiled = compile_policy(&policy, &nodes);
        let expected = filter_rule(&["100.64.0.0/10"], &[(22, 22), (443, 443)]);
        assert_eq!(compiled.global_filter, vec![expected.clone()]);
        // Node 3 is the destination; node 1's filter stays empty.
        assert_eq!(compiled.node_filters.get(&3).unwrap(), &vec![expected]);
        assert_eq!(compiled.node_filters.get(&1).unwrap(), &Vec::new());
        // Node 1 can reach node 3, so node 1 sees 3 and (by the reverse
        // direction rule) node 3 sees node 1.
        assert_eq!(compiled.peer_visibility[&1], BTreeSet::from([3]));
        assert_eq!(compiled.peer_visibility[&3], BTreeSet::from([1]));
    }

    #[test]
    fn host_alias_in_dst_resolves_to_cidr() {
        // The destination uses the `hosts` alias; the source is a CIDR. The
        // validator treats bare aliases as valid destinations only.
        let policy: Policy = crate::parse_policy(
            r#"{ "hosts": { "db": "10.0.0.5" }, "acls": [ { "action": "accept", "src": ["100.64.0.0/10"], "dst": ["db:5432"] } ] }"#,
        )
        .unwrap();
        let nodes = vec![node(1, None, &["100.64.0.1/32"])];
        let compiled = compile_policy(&policy, &nodes);
        let expected = filter_rule(&["100.64.0.0/10"], &[(5432, 5432)]);
        assert_eq!(compiled.global_filter, vec![expected]);
        // The alias resolves to 10.0.0.5/32, which matches no tailnet node,
        // so no per-node filter is produced.
        assert_eq!(compiled.node_filters.get(&1).unwrap(), &Vec::new());
    }

    #[test]
    fn identity_sources_expand_to_node_addresses() {
        let policy: Policy = crate::parse_policy(
            r#"{ "acls": [ { "action": "accept", "src": ["alice@example.com"], "dst": ["*:*"] } ] }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, Some("alice@example.com"), &["100.64.0.1/32"]),
            node(2, Some("bob@example.com"), &["100.64.0.2/32"]),
        ];
        let compiled = compile_policy(&policy, &nodes);
        let expected = filter_rule(&["100.64.0.1/32"], &[(0, 65535)]);
        assert_eq!(compiled.global_filter, vec![expected.clone()]);
        // The `*` destination matches every node, so both nodes receive the
        // rule; alice can reach everyone.
        assert_eq!(
            compiled.node_filters.get(&2).unwrap(),
            &vec![expected.clone()]
        );
        assert_eq!(
            compiled.node_filters.get(&1).unwrap(),
            &vec![expected.clone()]
        );
        assert_eq!(compiled.peer_visibility[&1], BTreeSet::from([2]));
        assert_eq!(compiled.peer_visibility[&2], BTreeSet::from([1]));
    }

    #[test]
    fn grant_compiles_into_destination_application_rule() {
        let policy: Policy = crate::parse_policy(
            r#"{ "grants": [ { "src": ["alice@example.com"], "dst": ["bob@example.com"], "app": { "tailscale.com/cap/kubernetes": [ { "impersonate": { "groups": ["ts:ops"] } } ] } } ] }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, Some("alice@example.com"), &["100.64.0.1/32"]),
            node(2, Some("bob@example.com"), &["100.64.0.2/32"]),
        ];
        let compiled = compile_policy(&policy, &nodes);
        let grantees = compiled.grants.get(&2).expect("bob should have grants");
        assert_eq!(grantees.len(), 1);
        let rule = &grantees[0];
        assert_eq!(rule.src_ips, vec!["100.64.0.1/32".to_string()]);
        assert!(rule.dst_ports.is_empty());
        assert_eq!(rule.cap_grant.len(), 1);
        assert_eq!(rule.cap_grant[0].dsts, vec!["100.64.0.2/32".to_string()]);
        assert_eq!(
            rule.cap_grant[0].cap_map["tailscale.com/cap/kubernetes"],
            vec![serde_json::json!({ "impersonate": { "groups": ["ts:ops"] } })]
        );
        // Capability grants alone do not create peer visibility.
        assert!(compiled.peer_visibility[&1].is_empty());
        assert!(compiled.peer_visibility[&2].is_empty());
    }

    #[test]
    fn ip_proto_named_protocol_maps_to_number() {
        assert_eq!(parse_ip_proto(Some("tcp")), Some(vec![6]));
        assert_eq!(parse_ip_proto(Some("17")), Some(vec![17]));
        assert_eq!(parse_ip_proto(Some("udp:53")), Some(vec![17]));
        assert_eq!(parse_ip_proto(None), None);
    }

    #[test]
    fn wildcard_and_group_sources_resolve() {
        let policy: Policy = crate::parse_policy(
            r#"{
              "groups": { "eng": ["alice@example.com", "100.64.0.9/32"] },
              "acls": [
                { "action": "accept", "src": ["group:eng"], "dst": ["*:443"] }
              ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, Some("alice@example.com"), &["100.64.0.1/32"]),
            node(2, Some("bob@example.com"), &["100.64.0.2/32"]),
        ];
        let compiled = compile_policy(&policy, &nodes);
        // alice's node and the literal 100.64.0.9/32 both become sources.
        let expected = filter_rule(&["100.64.0.1/32", "100.64.0.9/32"], &[(443, 443)]);
        assert_eq!(compiled.global_filter, vec![expected.clone()]);
        assert_eq!(
            compiled.node_filters.get(&2).unwrap(),
            &vec![expected.clone()]
        );
        assert_eq!(compiled.node_filters.get(&1).unwrap(), &vec![expected]);
        // Both source nodes may reach bob's node.
        assert_eq!(compiled.peer_visibility[&1], BTreeSet::from([2]));
    }

    /// Build a node with tags; used by tag and autogroup tests.
    fn tagged_node(id: u64, addresses: &[&str], tags: &[&str]) -> CompileNode {
        CompileNode {
            id,
            stable_id: format!("n{id:023}"),
            user_login: None,
            addresses: addresses.iter().map(|s| s.to_string()).collect(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn autogroup_tagged_matches_only_tagged_nodes() {
        let policy: Policy = crate::parse_policy(
            r#"{
              "acls": [
                { "action": "accept", "src": ["autogroup:tagged"], "dst": ["autogroup:tagged:*"] }
              ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, Some("alice@example.com"), &["100.64.0.1/32"]),
            tagged_node(2, &["100.64.0.2/32"], &["tag:server"]),
            tagged_node(3, &["100.64.0.3/32"], &["tag:server"]),
        ];
        let compiled = compile_policy(&policy, &nodes);
        let expected = filter_rule(&["100.64.0.2/32", "100.64.0.3/32"], &[(0, 65535)]);
        assert_eq!(compiled.global_filter, vec![expected.clone()]);
        // Only tagged nodes are destinations, so they alone carry the rule.
        assert_eq!(compiled.node_filters.get(&1).unwrap(), &Vec::new());
        assert_eq!(
            compiled.node_filters.get(&2).unwrap(),
            &vec![expected.clone()]
        );
        assert_eq!(compiled.node_filters.get(&3).unwrap(), &vec![expected]);
        // Tagged nodes see each other; the untagged node is invisible.
        assert_eq!(compiled.peer_visibility[&2], BTreeSet::from([3]));
        assert_eq!(compiled.peer_visibility[&3], BTreeSet::from([2]));
        assert!(compiled.peer_visibility[&1].is_empty());
    }

    #[test]
    fn autogroup_member_matches_only_untagged_nodes() {
        let policy: Policy = crate::parse_policy(
            r#"{
              "acls": [
                { "action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"] }
              ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, Some("alice@example.com"), &["100.64.0.1/32"]),
            node(2, Some("bob@example.com"), &["100.64.0.2/32"]),
            tagged_node(3, &["100.64.0.3/32"], &["tag:server"]),
        ];
        let compiled = compile_policy(&policy, &nodes);
        let expected = filter_rule(&["100.64.0.1/32", "100.64.0.2/32"], &[(0, 65535)]);
        assert_eq!(compiled.global_filter, vec![expected.clone()]);
        assert_eq!(compiled.node_filters.get(&3).unwrap(), &Vec::new());
        assert_eq!(
            compiled.node_filters.get(&1).unwrap(),
            &vec![expected.clone()]
        );
        assert_eq!(compiled.node_filters.get(&2).unwrap(), &vec![expected]);
        assert_eq!(compiled.peer_visibility[&1], BTreeSet::from([2]));
        assert_eq!(compiled.peer_visibility[&2], BTreeSet::from([1]));
    }

    #[test]
    fn autogroup_self_matches_every_node_as_source_and_destination() {
        // Each node is its own "self", so autogroup:self in both positions
        // expands to all nodes.
        let policy: Policy = crate::parse_policy(
            r#"{
              "acls": [
                { "action": "accept", "src": ["autogroup:self"], "dst": ["autogroup:self:443"] }
              ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, Some("alice@example.com"), &["100.64.0.1/32"]),
            tagged_node(2, &["100.64.0.2/32"], &["tag:server"]),
        ];
        let compiled = compile_policy(&policy, &nodes);
        let expected = filter_rule(&["100.64.0.1/32", "100.64.0.2/32"], &[(443, 443)]);
        assert_eq!(compiled.global_filter, vec![expected.clone()]);
        assert_eq!(
            compiled.node_filters.get(&1).unwrap(),
            &vec![expected.clone()]
        );
        assert_eq!(compiled.node_filters.get(&2).unwrap(), &vec![expected]);
        assert_eq!(compiled.peer_visibility[&1], BTreeSet::from([2]));
        assert_eq!(compiled.peer_visibility[&2], BTreeSet::from([1]));
    }

    #[test]
    fn tag_sources_expand_to_tagged_node_addresses() {
        let policy: Policy = crate::parse_policy(
            r#"{
              "acls": [
                { "action": "accept", "src": ["tag:web"], "dst": ["tag:web:443"] }
              ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, Some("alice@example.com"), &["100.64.0.1/32"]),
            tagged_node(2, &["100.64.0.2/32"], &["tag:web"]),
            tagged_node(3, &["100.64.0.3/32"], &["tag:db"]),
        ];
        let compiled = compile_policy(&policy, &nodes);
        let expected = filter_rule(&["100.64.0.2/32"], &[(443, 443)]);
        assert_eq!(compiled.global_filter, vec![expected.clone()]);
        // Only the tag:web node is a destination, so only it carries the rule.
        assert_eq!(compiled.node_filters.get(&3).unwrap(), &Vec::new());
        assert_eq!(compiled.node_filters.get(&2).unwrap(), &vec![expected]);
        // tag:db (node 3) is neither source nor destination, so it is absent.
        assert!(compiled.peer_visibility[&3].is_empty());
        // tag:web node 2 is not visible to the untagged node 1.
        assert!(compiled.peer_visibility[&1].is_empty());
    }

    #[test]
    fn node_attrs_resolve_into_cap_map() {
        let policy: Policy = crate::parse_policy(
            r#"{
              "tagOwners": { "tag:server": ["alice@example.com"] },
              "nodeAttrs": [
                { "target": ["tag:server"], "attr": ["randomize-client-port"] },
                { "target": ["alice@example.com"], "attr": ["drive:share"] }
              ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, Some("alice@example.com"), &["100.64.0.1/32"]),
            tagged_node(2, &["100.64.0.2/32"], &["tag:server"]),
        ];
        let alice_attrs = node_attributes(&policy, &nodes[0], &nodes);
        assert_eq!(
            alice_attrs,
            BTreeMap::from([("drive:share".to_string(), Vec::<serde_json::Value>::new())])
        );
        let server_attrs = node_attributes(&policy, &nodes[1], &nodes);
        assert_eq!(
            server_attrs,
            BTreeMap::from([(
                "randomize-client-port".to_string(),
                Vec::<serde_json::Value>::new()
            )])
        );
    }

    #[test]
    fn node_attrs_support_autogroup_targets() {
        let policy: Policy = crate::parse_policy(
            r#"{
              "tagOwners": { "tag:server": ["alice@example.com"] },
              "nodeAttrs": [
                { "target": ["autogroup:tagged"], "attr": ["disable-captive-portal-detection"] }
              ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, Some("alice@example.com"), &["100.64.0.1/32"]),
            tagged_node(2, &["100.64.0.2/32"], &["tag:server"]),
        ];
        assert!(
            node_attributes(&policy, &nodes[0], &nodes).is_empty(),
            "untagged node is not in autogroup:tagged"
        );
        assert_eq!(
            node_attributes(&policy, &nodes[1], &nodes)
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["disable-captive-portal-detection".to_string()]
        );
    }

    #[test]
    fn node_attrs_group_target_resolves_transitively() {
        let policy: Policy = crate::parse_policy(
            r#"{
                "groups": {
                    "all": ["group:eng", "bob@example.com"],
                    "eng": ["alice@example.com"]
                },
                "nodeAttrs": [
                    { "target": ["group:all"], "attr": ["drive:share"] }
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, Some("alice@example.com"), &["100.64.0.1/32"]),
            node(2, Some("bob@example.com"), &["100.64.0.2/32"]),
            node(3, Some("carol@example.com"), &["100.64.0.3/32"]),
        ];
        // alice is a member of group:all via nested group:eng; bob directly.
        assert_eq!(
            node_attributes(&policy, &nodes[0], &nodes)
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["drive:share".to_string()]
        );
        assert_eq!(
            node_attributes(&policy, &nodes[1], &nodes)
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["drive:share".to_string()]
        );
        assert!(
            node_attributes(&policy, &nodes[2], &nodes).is_empty(),
            "carol is not a member of group:all"
        );
    }
}
