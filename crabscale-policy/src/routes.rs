//! Subnet-route and exit-node helpers: canonicalization and auto-approval.
//!
//! The two concepts here are part of the route slice of the M2 control
//! plane:
//!
//! - Clients advertise routes they can route on their behalf through
//!   `Hostinfo.RoutableIPs`. A route is an IP or CIDR; it is canonicalized to
//!   CIDR form (`addr/prefix`) before it is stored or compared.
//! - The policy's `autoApprovers` object decides which advertised routes are
//!   approved without an explicit admin action: `routes` covers subnet
//!   routes and `exitNode` covers exit-node (default) routes, each mapping a
//!   route prefix to the principals whose nodes may advertise it.
//!
//! [Spec-Policy](https://github.com/NightFeather0615/crabscale/wiki/Spec-Policy.md)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::CompileNode;
use crate::model::Policy;

/// Canonical CIDR form of an IP or CIDR route, with host bits zeroed.
///
/// A bare IP becomes `addr/32` (IPv4) or `addr/128` (IPv6); a CIDR keeps
/// its prefix and masks the address to the network (so `10.0.0.5/24`
/// canonicalizes to `10.0.0.0/24`). Zeroing the host bits is what makes
/// approvals and advertisements of the same network compare equal regardless
/// of which host address the client happened to write. Returns `None` when
/// `s` is not a valid IP or CIDR.
pub fn canonical_route(s: &str) -> Option<String> {
    let (ip, bits) = parse_cidr(s)?;
    Some(format!("{}/{bits}", mask_addr(ip, bits)))
}

/// Whether network `addr` (an IP or CIDR string) falls inside `net` (a CIDR).
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

/// Mask `ip` to the network determined by `bits`, zeroing the host bits.
fn mask_addr(ip: IpAddr, bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask_u32(bits as u32))),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask_u128(bits as u32))),
    }
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

/// Whether `principal`, one entry of an `autoApprovers` value, designates
/// `node`.
///
/// Supported principals mirror the tag-owner matching used elsewhere in the
/// policy layer:
///
/// - `*` matches every node;
/// - `autogroup:self` matches every node, `autogroup:member` matches
///   untagged (user-owned) nodes, and `autogroup:tagged` matches tagged
///   nodes;
/// - `group:` matches a node whose owner is a member of the group;
/// - `tag:` matches a node carrying that tag;
/// - a user login matches a user-owned node;
/// - an IP/CIDR matches a node whose address falls inside it.
fn approver_matches_node(policy: &Policy, principal: &str, node: &CompileNode) -> bool {
    if principal == "*" {
        return true;
    }
    if let Some(rest) = principal.strip_prefix("autogroup:") {
        return match rest {
            "self" => true,
            "member" => node.tags.is_empty(),
            "tagged" => !node.tags.is_empty(),
            _ => false,
        };
    }
    if principal.starts_with("group:") {
        return node
            .user_login
            .as_deref()
            .is_some_and(|login| crate::tags::principal_matches_user(policy, principal, login));
    }
    if principal.starts_with("tag:") {
        return node.tags.iter().any(|t| t == principal);
    }
    if let Some(login) = &node.user_login {
        if login == principal {
            return true;
        }
    }
    // A CIDR approver matches nodes whose own address falls inside it.
    canonical_route(principal)
        .is_some_and(|net| node.addresses.iter().any(|addr| addr_in_cidr(addr, &net)))
}

/// The subset of `advertised` routes that the policy auto-approves for
/// `node`, in canonical CIDR form, sorted and deduplicated.
///
/// An advertised route is auto-approved when it falls inside an
/// `autoApprovers.routes` or `autoApprovers.exitNode` prefix and the node
/// matches one of that entry's approvers. Malformed advertised routes are
/// ignored.
pub fn auto_approved_routes(
    policy: &Policy,
    node: &CompileNode,
    advertised: &[String],
) -> Vec<String> {
    let mut approved = Vec::new();
    let mut consider = |prefix: &str, approvers: &[String]| {
        let Some(canon_prefix) = canonical_route(prefix) else {
            return;
        };
        for route in advertised {
            let Some(canon_route) = canonical_route(route) else {
                continue;
            };
            if addr_in_cidr(&canon_route, &canon_prefix)
                && approvers
                    .iter()
                    .any(|approver| approver_matches_node(policy, approver, node))
            {
                approved.push(canon_route);
            }
        }
    };
    for (prefix, approvers) in &policy.auto_approvers.routes {
        consider(prefix, approvers);
    }
    for (prefix, approvers) in &policy.auto_approvers.exit_node {
        consider(prefix, approvers);
    }
    approved.sort();
    approved.dedup();
    approved
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_policy;

    fn node(id: u64, login: Option<&str>, tags: &[&str]) -> CompileNode {
        CompileNode {
            id,
            stable_id: format!("n{id:023}"),
            user_login: login.map(|s| s.to_string()),
            addresses: vec![
                "100.64.0.1/32".to_string(),
                "fd7a:115c:a1e0::1/128".to_string(),
            ],
            tags: tags.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn canonicalizes_ips_and_cidrs() {
        assert_eq!(
            canonical_route("192.168.1.5").as_deref(),
            Some("192.168.1.5/32")
        );
        assert_eq!(
            canonical_route("10.0.0.0/24").as_deref(),
            Some("10.0.0.0/24")
        );
        assert_eq!(canonical_route("::1").as_deref(), Some("::1/128"));
        assert_eq!(
            canonical_route("2001:db8::/32").as_deref(),
            Some("2001:db8::/32")
        );
        assert!(canonical_route("not-a-route").is_none());
        assert!(canonical_route("10.0.0.0/33").is_none());
    }

    #[test]
    fn canonical_route_zeros_host_bits() {
        assert_eq!(
            canonical_route("10.0.0.5/24").as_deref(),
            Some("10.0.0.0/24")
        );
        assert_eq!(
            canonical_route("192.168.1.7/16").as_deref(),
            Some("192.168.0.0/16")
        );
        assert_eq!(
            canonical_route("2001:db8:0:1::5/64").as_deref(),
            Some("2001:db8:0:1::/64")
        );
    }

    #[test]
    fn auto_approves_user_route_within_prefix() {
        let policy = parse_policy(
            r#"{
                "autoApprovers": {
                    "routes": { "10.0.0.0/8": ["alice@example.com"] }
                }
            }"#,
        )
        .unwrap();
        let alice = node(1, Some("alice@example.com"), &[]);
        assert_eq!(
            auto_approved_routes(&policy, &alice, &["10.1.2.0/24".to_string()]),
            vec!["10.1.2.0/24".to_string()]
        );
        let bob = node(2, Some("bob@example.com"), &[]);
        assert!(auto_approved_routes(&policy, &bob, &["10.1.2.0/24".to_string()]).is_empty());
    }

    #[test]
    fn auto_approves_exit_node_for_listed_user() {
        let policy = parse_policy(
            r#"{
                "autoApprovers": {
                    "exitNode": { "0.0.0.0/0": ["alice@example.com"] }
                }
            }"#,
        )
        .unwrap();
        let alice = node(1, Some("alice@example.com"), &[]);
        assert_eq!(
            auto_approved_routes(&policy, &alice, &["0.0.0.0/0".to_string()]),
            vec!["0.0.0.0/0".to_string()]
        );
        // A tagged node that is not listed is not auto-approved.
        let tagged = node(3, None, &["tag:server"]);
        assert!(auto_approved_routes(&policy, &tagged, &["0.0.0.0/0".to_string()]).is_empty());
    }

    #[test]
    fn auto_approves_tag_owned_node_via_tag_approver() {
        let policy = parse_policy(
            r#"{
                "autoApprovers": {
                    "routes": { "192.168.0.0/16": ["tag:router"] }
                }
            }"#,
        )
        .unwrap();
        let router = node(1, None, &["tag:router"]);
        assert_eq!(
            auto_approved_routes(&policy, &router, &["192.168.5.0/24".to_string()]),
            vec!["192.168.5.0/24".to_string()]
        );
        let server = node(2, None, &["tag:server"]);
        assert!(auto_approved_routes(&policy, &server, &["192.168.5.0/24".to_string()]).is_empty());
    }

    #[test]
    fn auto_approves_group_owner() {
        let policy = parse_policy(
            r#"{
                "groups": { "ops": ["bob@example.com"] },
                "autoApprovers": {
                    "routes": { "10.0.0.0/8": ["group:ops"] }
                }
            }"#,
        )
        .unwrap();
        let bob = node(1, Some("bob@example.com"), &[]);
        assert_eq!(
            auto_approved_routes(&policy, &bob, &["10.0.0.0/8".to_string()]),
            vec!["10.0.0.0/8".to_string()]
        );
    }

    #[test]
    fn invalid_advertised_routes_are_ignored() {
        let policy = parse_policy(
            r#"{
                "autoApprovers": {
                    "routes": { "10.0.0.0/8": ["alice@example.com"] }
                }
            }"#,
        )
        .unwrap();
        let alice = node(1, Some("alice@example.com"), &[]);
        let routes = auto_approved_routes(
            &policy,
            &alice,
            &["10.1.0.0/24".to_string(), "garbage".to_string()],
        );
        assert_eq!(routes, vec!["10.1.0.0/24".to_string()]);
    }
}
