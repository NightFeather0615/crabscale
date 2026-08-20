//! Semantic validation of a parsed [`Policy`].
//!
//! Syntax errors (comments, trailing commas, malformed JSON) are caught by
//! [`crate::hujson`]; this module validates the *meaning* of the document:
//!
//! - `acls`/`grants`/`ssh` source and destination targets are well formed;
//! - `hosts` values are IPs or CIDRs;
//! - `tagOwners` keys are tags and its values are principals;
//! - `autoApprovers` route keys are IPs/CIDRs and values are principals;
//! - actions (`accept`, `check`) are recognized.
//!
//! Unknown keys are rejected by [`validate_unknown_keys`] (with line
//! numbers) and reinforced by the `deny_unknown_fields` serde attribute on
//! [`Policy`]; duplicate keys are rejected by [`crate::hujson`].

use std::net::IpAddr;

use serde_json::{Map, Value as JsonValue};

use crate::HujsonError;
use crate::model::Policy;

const POLICY_KEYS: &[&str] = &[
    "groups",
    "hosts",
    "acls",
    "grants",
    "tagOwners",
    "autoApprovers",
    "ssh",
    "nodeAttrs",
    "tests",
    "sshTests",
];
const ACL_KEYS: &[&str] = &["action", "src", "dst", "proto"];
const GRANT_KEYS: &[&str] = &["src", "dst", "ip", "app"];
const AUTO_APPROVERS_KEYS: &[&str] = &["routes", "exitNode"];
const SSH_KEYS: &[&str] = &["action", "src", "dst", "users", "checkPeriod"];
const NODE_ATTR_KEYS: &[&str] = &["target", "attr"];
const TEST_KEYS: &[&str] = &["src", "user", "proto", "accept", "deny", "allow"];
const SSH_TEST_KEYS: &[&str] = &["action", "src", "dst", "users"];

/// Reject unknown object keys, attaching the line where each key appears.
///
/// `value` is the freshly parsed HUJSON document. Capability payloads inside
/// `grants[].app` are intentionally not traversed: their contents are opaque.
pub fn validate_unknown_keys(source: &str, value: &JsonValue) -> Result<(), HujsonError> {
    let ctx = Ctx { source };
    let root = value.as_object().ok_or_else(|| {
        HujsonError::at_line(
            locate_line(source, "{"),
            "policy must be a top-level JSON object",
        )
    })?;
    check_keys(&ctx, POLICY_KEYS, root, "policy")?;
    if let Some(v) = root.get("acls") {
        walk_array(&ctx, v, "acls", walk_acl)?;
    }
    if let Some(v) = root.get("grants") {
        walk_array(&ctx, v, "grants", walk_grant)?;
    }
    if let Some(v) = root.get("autoApprovers") {
        walk_auto_approvers(&ctx, v)?;
    }
    if let Some(v) = root.get("ssh") {
        walk_array(&ctx, v, "ssh", walk_ssh)?;
    }
    if let Some(v) = root.get("nodeAttrs") {
        walk_array(&ctx, v, "nodeAttrs", walk_node_attr)?;
    }
    if let Some(v) = root.get("tests") {
        walk_array(&ctx, v, "tests", walk_test)?;
    }
    if let Some(v) = root.get("sshTests") {
        walk_array(&ctx, v, "sshTests", walk_ssh_test)?;
    }
    Ok(())
}

fn check_keys(
    ctx: &Ctx<'_>,
    allowed: &[&str],
    obj: &Map<String, JsonValue>,
    what: &str,
) -> Result<(), HujsonError> {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(ctx.error_here(key, format!("unknown key `{key}` in {what}")));
        }
    }
    Ok(())
}

fn as_object<'a>(
    ctx: &Ctx<'_>,
    value: &'a JsonValue,
    what: &str,
) -> Result<&'a Map<String, JsonValue>, HujsonError> {
    value
        .as_object()
        .ok_or_else(|| ctx.error_here("", format!("{what} must be a JSON object")))
}

fn walk_array(
    ctx: &Ctx<'_>,
    value: &JsonValue,
    what: &str,
    item: fn(&Ctx<'_>, &JsonValue) -> Result<(), HujsonError>,
) -> Result<(), HujsonError> {
    let Some(items) = value.as_array() else {
        return Err(ctx.error_here("", format!("{what} must be a JSON array")));
    };
    for element in items {
        item(ctx, element)?;
    }
    Ok(())
}

fn walk_acl(ctx: &Ctx<'_>, value: &JsonValue) -> Result<(), HujsonError> {
    let obj = as_object(ctx, value, "ACL rule")?;
    check_keys(ctx, ACL_KEYS, obj, "ACL rule")
}

fn walk_grant(ctx: &Ctx<'_>, value: &JsonValue) -> Result<(), HujsonError> {
    let obj = as_object(ctx, value, "grant")?;
    check_keys(ctx, GRANT_KEYS, obj, "grant")
}

fn walk_auto_approvers(ctx: &Ctx<'_>, value: &JsonValue) -> Result<(), HujsonError> {
    let obj = as_object(ctx, value, "autoApprovers")?;
    check_keys(ctx, AUTO_APPROVERS_KEYS, obj, "autoApprovers")
}

fn walk_ssh(ctx: &Ctx<'_>, value: &JsonValue) -> Result<(), HujsonError> {
    let obj = as_object(ctx, value, "SSH rule")?;
    check_keys(ctx, SSH_KEYS, obj, "SSH rule")
}

fn walk_node_attr(ctx: &Ctx<'_>, value: &JsonValue) -> Result<(), HujsonError> {
    let obj = as_object(ctx, value, "nodeAttrs grant")?;
    check_keys(ctx, NODE_ATTR_KEYS, obj, "nodeAttrs grant")
}

fn walk_test(ctx: &Ctx<'_>, value: &JsonValue) -> Result<(), HujsonError> {
    let obj = as_object(ctx, value, "test")?;
    check_keys(ctx, TEST_KEYS, obj, "test")
}

fn walk_ssh_test(ctx: &Ctx<'_>, value: &JsonValue) -> Result<(), HujsonError> {
    let obj = as_object(ctx, value, "sshTest")?;
    check_keys(ctx, SSH_TEST_KEYS, obj, "sshTest")
}

/// Validate a parsed policy and return the first problem found.
///
/// `source` is the raw policy text; it is used only to attach a 1-based line
/// number to semantic errors so that they match the on-disk file.
pub fn validate_policy(source: &str, policy: &Policy) -> Result<(), HujsonError> {
    let ctx = Ctx { source };

    for (name, members) in &policy.groups {
        if name.trim().is_empty() {
            return Err(ctx.error_here(name, "group name must not be empty"));
        }
        for member in members {
            if !is_principal(member) {
                return Err(ctx.error_here(
                    member,
                    format!("invalid member `{member}` in group `{name}`"),
                ));
            }
        }
    }

    for (alias, value) in &policy.hosts {
        if alias.trim().is_empty() {
            return Err(ctx.error_here(alias, "host alias must not be empty"));
        }
        if !is_ip_or_cidr(value) {
            return Err(ctx.error_here(
                value,
                format!("host `{alias}` maps to invalid target `{value}`"),
            ));
        }
    }

    for (i, rule) in policy.acls.iter().enumerate() {
        if rule.action != "accept" {
            return Err(ctx.error_here(
                &rule.action,
                format!("unsupported ACL action `{}` (rule {i})", rule.action),
            ));
        }
        if rule.src.is_empty() || rule.dst.is_empty() {
            return Err(ctx.error_here(
                "",
                format!("ACL rule {i} must have at least one src and one dst"),
            ));
        }
        for target in &rule.src {
            if !is_principal(target) {
                return Err(ctx.error_here(
                    target,
                    format!("invalid ACL source target `{target}` (rule {i})"),
                ));
            }
        }
        for target in &rule.dst {
            if !is_dst(target) {
                return Err(ctx.error_here(
                    target,
                    format!("invalid ACL destination target `{target}` (rule {i})"),
                ));
            }
        }
    }

    for (i, grant) in policy.grants.iter().enumerate() {
        if grant.src.is_empty() || grant.dst.is_empty() {
            return Err(ctx.error_here(
                "",
                format!("grant {i} must have at least one src and one dst"),
            ));
        }
        for target in &grant.src {
            if !is_principal(target) {
                return Err(ctx.error_here(
                    target,
                    format!("invalid grant source target `{target}` (grant {i})"),
                ));
            }
        }
        for target in &grant.dst {
            if !is_dst(target) {
                return Err(ctx.error_here(
                    target,
                    format!("invalid grant destination target `{target}` (grant {i})"),
                ));
            }
        }
    }

    for (tag, owners) in &policy.tag_owners {
        if !tag.starts_with("tag:") || tag.len() == "tag:".len() {
            return Err(ctx.error_here(
                tag,
                format!("tagOwner key `{tag}` must start with `tag:` and be non-empty"),
            ));
        }
        for owner in owners {
            if !is_principal(owner) {
                return Err(
                    ctx.error_here(owner, format!("invalid tag owner `{owner}` for `{tag}`"))
                );
            }
        }
    }

    for (route, approvers) in &policy.auto_approvers.routes {
        if !is_ip_or_cidr(route) {
            return Err(ctx.error_here(
                route,
                format!("autoApprovers route `{route}` must be an IP or CIDR"),
            ));
        }
        for approver in approvers {
            if !is_principal(approver) {
                return Err(ctx.error_here(
                    approver,
                    format!("invalid autoApprovers route approver `{approver}`"),
                ));
            }
        }
    }

    for (route, approvers) in &policy.auto_approvers.exit_node {
        if !is_ip_or_cidr(route) {
            return Err(ctx.error_here(
                route,
                format!("autoApprovers exitNode `{route}` must be an IP or CIDR"),
            ));
        }
        for approver in approvers {
            if !is_principal(approver) {
                return Err(ctx.error_here(
                    approver,
                    format!("invalid autoApprovers exitNode approver `{approver}`"),
                ));
            }
        }
    }

    for (i, rule) in policy.ssh.iter().enumerate() {
        if rule.action != "accept" && rule.action != "check" {
            return Err(ctx.error_here(
                &rule.action,
                format!("unsupported SSH action `{}` (rule {i})", rule.action),
            ));
        }
        if rule.src.is_empty() || rule.dst.is_empty() {
            return Err(ctx.error_here(
                "",
                format!("SSH rule {i} must have at least one src and one dst"),
            ));
        }
        for target in &rule.src {
            if !is_principal(target) {
                return Err(ctx.error_here(
                    target,
                    format!("invalid SSH source target `{target}` (rule {i})"),
                ));
            }
        }
        for target in &rule.dst {
            if !is_dst(target) {
                return Err(ctx.error_here(
                    target,
                    format!("invalid SSH destination target `{target}` (rule {i})"),
                ));
            }
        }
        for user in &rule.users {
            if user.trim().is_empty() {
                return Err(ctx.error_here(user, format!("SSH rule {i} has an empty user")));
            }
        }
    }

    for (i, grant) in policy.node_attrs.iter().enumerate() {
        if grant.target.is_empty() || grant.attr.is_empty() {
            return Err(ctx.error_here(
                "",
                format!("nodeAttrs grant {i} must have at least one target and one attr"),
            ));
        }
        for target in &grant.target {
            if !is_principal(target) {
                return Err(ctx.error_here(
                    target,
                    format!("invalid nodeAttrs target `{target}` (grant {i})"),
                ));
            }
        }
    }

    for (i, test) in policy.tests.iter().enumerate() {
        if !is_principal(&test.src) {
            return Err(ctx.error_here(
                &test.src,
                format!("invalid test source `{}` (test {i})", test.src),
            ));
        }
    }

    for (i, test) in policy.ssh_tests.iter().enumerate() {
        if test.action != "accept" && test.action != "check" {
            return Err(ctx.error_here(
                &test.action,
                format!("unsupported SSH test action `{}` (test {i})", test.action),
            ));
        }
        if !is_principal(&test.src) || !is_dst(&test.dst) {
            return Err(ctx.error_here(
                &test.src,
                format!(
                    "invalid SSH test target `{} -> {}` (test {i})",
                    test.src, test.dst
                ),
            ));
        }
    }

    Ok(())
}

struct Ctx<'a> {
    source: &'a str,
}

impl<'a> Ctx<'a> {
    /// Build an error located at the first line of `source` that contains
    /// `needle`, falling back to line 1.
    fn error_here(&self, needle: &str, message: impl Into<String>) -> HujsonError {
        let line = locate_line(self.source, needle);
        HujsonError::at_line(line, message)
    }
}

/// Return the 1-based line number of the first line containing `needle`.
fn locate_line(source: &str, needle: &str) -> usize {
    for (index, line) in source.lines().enumerate() {
        if line.contains(needle) {
            return index + 1;
        }
    }
    1
}

/// A source target: `*`, `autogroup:x`, `group:x`, `tag:x`, `user@host`,
/// or an IP/CIDR.
fn is_principal(target: &str) -> bool {
    if target == "*" {
        return true;
    }
    if let Some(rest) = target.strip_prefix("autogroup:") {
        return !rest.is_empty();
    }
    if let Some(rest) = target.strip_prefix("group:") {
        return !rest.is_empty();
    }
    if let Some(rest) = target.strip_prefix("tag:") {
        return !rest.is_empty();
    }
    if let Some((user, host)) = target.split_once('@') {
        return !user.is_empty() && !host.is_empty() && user.chars().all(|c| !c.is_whitespace());
    }
    is_ip_or_cidr(target)
}

/// A destination target: everything `is_principal` accepts plus an optional
/// `:portlist` suffix (and bracketed IPv6 addresses).
fn is_dst(target: &str) -> bool {
    if target == "*" {
        return true;
    }
    if let Some(rest) = target.strip_prefix("autogroup:") {
        return !rest.is_empty();
    }
    if let Some(rest) = target.strip_prefix("group:") {
        return !rest.is_empty();
    }
    if let Some(rest) = target.strip_prefix("tag:") {
        return !rest.is_empty();
    }
    if let Some((user, host)) = target.split_once('@') {
        return !user.is_empty() && !host.is_empty();
    }
    if let Some((host, ports)) = split_ports(target) {
        let host = strip_brackets(host);
        let host_ok = host == "*" || is_ip_or_cidr(host) || valid_host_ident(host);
        return host_ok && valid_portlist(ports);
    }
    if target.starts_with('[') && target.ends_with(']') {
        return is_ip_or_cidr(&target[1..target.len() - 1]);
    }
    is_ip_or_cidr(target) || valid_host_ident(target)
}

/// Split `host:ports` on the last colon.
fn split_ports(target: &str) -> Option<(&str, &str)> {
    let idx = target.rfind(':')?;
    if idx == 0 || idx + 1 == target.len() {
        return None;
    }
    let host = &target[..idx];
    // A bare IPv6 address contains colons and must not be treated as a
    // host:ports split unless it is bracketed.
    if host.starts_with('[') || is_plain_ipv4_or_cidr(host) || host == "*" || valid_host_ident(host)
    {
        Some((host, &target[idx + 1..]))
    } else {
        None
    }
}

fn strip_brackets(host: &str) -> &str {
    if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

fn is_plain_ipv4_or_cidr(s: &str) -> bool {
    // IPv4 (and its CIDR form) contains dots and no colons, so a trailing
    // `:ports` split is unambiguous.
    !s.contains(':') && s.contains('.') && is_ip_or_cidr(s)
}

/// A bare hostname/alias identifier: letters, digits, `-`, `.`, `_`.
fn valid_host_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

/// A port list: `*`, or comma-separated ports and inclusive ranges.
fn valid_portlist(ports: &str) -> bool {
    if ports == "*" {
        return true;
    }
    if ports.is_empty() {
        return false;
    }
    ports.split(',').all(|item| {
        let item = item.trim();
        if item.is_empty() {
            return false;
        }
        match item.split_once('-') {
            Some((lo, hi)) => matches!(
                (lo.parse::<u16>(), hi.parse::<u16>()),
                (Ok(a), Ok(b)) if a > 0 && b > 0 && a <= b
            ),
            None => item.parse::<u16>().map(|port| port > 0).unwrap_or(false),
        }
    })
}

/// `true` if `s` is a plain IP address or an IP/CIDR range.
fn is_ip_or_cidr(s: &str) -> bool {
    if s.parse::<IpAddr>().is_ok() {
        return true;
    }
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    let Ok(bits) = prefix.parse::<u8>() else {
        return false;
    };
    let max_bits = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    bits <= max_bits && !prefix.is_empty()
}
