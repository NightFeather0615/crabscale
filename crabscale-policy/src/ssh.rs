//! Tailscale SSH rule compiler.
//!
//! [Spec-Policy section 7](https://github.com/NightFeather0615/crabscale/wiki/Spec-Policy.md)
//! defines `ssh` rules with `action: accept` (permit immediately) or
//! `action: check` (use the SSH check-mode endpoint). This module compiles
//! those rules into a per-node [`CompiledSshPolicy`]: for every destination
//! node, the ordered list of rules whose destination matches it, each with
//! the set of source nodes it applies to.
//!
//! The compiled policy is what the control plane consults to answer
//! `/machine/ssh/action/{src}/to/{dst}`: the first rule matching the
//! (source, destination, ssh-user) tuple decides whether the connection is
//! accepted, rejected, or delegated to the check-mode endpoint (with
//! auto-approval within `checkPeriod`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crabscale_proto::SshAction as WireSshAction;
use crabscale_proto::SshPolicy as WireSshPolicy;
use crabscale_proto::SshPrincipal as WireSshPrincipal;
use crabscale_proto::SshRule as WireSshRule;

use crate::model::Policy;
use crate::compile::{CompileNode, Ctx};

/// Default `checkPeriod` (12h) applied when an SSH `check` rule omits it.
///
/// This mirrors the wiki example rule and gives a sensible auto-approval
/// window. An operator can override it per rule with `checkPeriod`.
pub const DEFAULT_SSH_CHECK_PERIOD: Duration = Duration::from_secs(12 * 60 * 60);

/// The action a compiled SSH rule produces for a matching connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshRuleAction {
    /// Admit the connection immediately.
    Accept,
    /// Route the connection through the SSH check-mode endpoint; a previous
    /// approval within `check_period` auto-approves the new connection.
    Check {
        /// How long one approval is remembered for the same src/dst pair.
        check_period: Duration,
    },
}

/// A compiled SSH rule for one destination node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSshRule {
    /// The rule's original source principals (`user@host`, `tag:...`,
    /// `autogroup:...`, `group:...`, `*`, IP/CIDR), kept for the wire
    /// [`WireSshPolicy`] delivered to clients.
    pub src: Vec<String>,
    /// Node ids matching this rule's source principals.
    pub src_nodes: BTreeSet<u64>,
    /// `true` when the source matched every node (`*` or `autogroup:self`),
    /// including nodes that may join later.
    pub src_all: bool,
    /// SSH users the rule allows. Empty means the rule matches any user.
    pub users: Vec<String>,
    /// The action a matching connection receives.
    pub action: SshRuleAction,
}

/// A per-node compiled SSH policy.
///
/// Every node has an entry (possibly empty). The rules in `node_rules[node]`
/// are ordered and are exactly those whose destination matches `node`, so a
/// destination node only ever evaluates rules that concern it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledSshPolicy {
    /// Destination node id -> ordered applicable SSH rules.
    pub node_rules: BTreeMap<u64, Vec<CompiledSshRule>>,
}

/// Compile the policy's `ssh` rules into a per-node
/// [`CompiledSshPolicy`]. Ordered rules are preserved per destination.
pub fn compile_ssh_policy(policy: &Policy, nodes: &[CompileNode]) -> CompiledSshPolicy {
    let mut compiled = CompiledSshPolicy::default();
    let mut ctx = Ctx::new(policy);

    // Every node gets an entry (possibly empty) so the map always carries a
    // per-node SSHPolicy even when it has no rules.
    for node in nodes {
        compiled.node_rules.entry(node.id).or_default();
    }

    for rule in &policy.ssh {
        let src = ctx.resolve(rule.src.iter().map(String::as_str));
        let dst = ctx.resolve(rule.dst.iter().map(String::as_str));

        let mut src_nodes = BTreeSet::new();
        for node in nodes {
            if src.matches_node(node) {
                src_nodes.insert(node.id);
            }
        }

        let action = match rule.action.as_str() {
            "accept" => SshRuleAction::Accept,
            _ => SshRuleAction::Check {
                check_period: rule
                    .check_period
                    .as_deref()
                    .and_then(parse_ssh_duration)
                    .unwrap_or(DEFAULT_SSH_CHECK_PERIOD),
            },
        };

        let compiled_rule = CompiledSshRule {
            src: rule.src.clone(),
            src_nodes,
            src_all: src.wildcard || src.self_match,
            users: rule.users.clone(),
            action,
        };

        for node in nodes {
            if dst.matches_node(node) {
                compiled
                    .node_rules
                    .entry(node.id)
                    .or_default()
                    .push(compiled_rule.clone());
            }
        }
    }

    compiled
}

/// Return the first rule in `policy` applying to `src -> dst` for the given
/// SSH user. Rules are evaluated in order for the destination node's list
/// and the first match wins (the policy default is deny).
pub fn first_matching_ssh_rule<'a>(
    policy: &'a CompiledSshPolicy,
    src_id: u64,
    dst_id: u64,
    ssh_user: &str,
) -> Option<&'a CompiledSshRule> {
    for rule in policy.node_rules.get(&dst_id)? {
        let src_ok = rule.src_all || rule.src_nodes.contains(&src_id);
        let user_ok = rule.users.is_empty()
            || rule.users.iter().any(|u| u == ssh_user || u == "*");
        if src_ok && user_ok {
            return Some(rule);
        }
    }
    None
}

/// Build the wire [`WireSshPolicy`] for destination node `dst_id`, using
/// `server_url` as the base for check-mode `holdAndDelegate` URLs.
///
/// Returns `None` when the node has no applicable SSH rules. The check-mode
/// URL keeps the `$SRC_NODE_ID`/`$DST_NODE_ID`/`$SSH_USER`/`$LOCAL_USER`
/// placeholders that a compatible client expands before fetching the
/// endpoint (the endpoint itself fills them in concrete responses).
pub fn build_wire_ssh_policy(
    compiled: &CompiledSshPolicy,
    dst_id: u64,
    server_url: &str,
) -> Option<WireSshPolicy> {
    let rules = compiled.node_rules.get(&dst_id)?;
    if rules.is_empty() {
        return None;
    }
    let mut wire_rules = Vec::with_capacity(rules.len());
    for rule in rules {
        let principals: Vec<WireSshPrincipal> = rule
            .src
            .iter()
            .map(|principal| {
                if principal.contains('@') {
                    WireSshPrincipal {
                        user_login: principal.clone(),
                        ..Default::default()
                    }
                } else {
                    WireSshPrincipal {
                        any: vec![principal.clone()],
                        ..Default::default()
                    }
                }
            })
            .collect();
        let mut ssh_users = BTreeMap::new();
        for user in &rule.users {
            // `=` means the requested SSH user maps directly to the local
            // user; crabscale rules do not remap users.
            ssh_users.insert(user.clone(), "=".to_string());
        }
        let action = match rule.action {
            SshRuleAction::Accept => WireSshAction {
                message: "SSH connection accepted".to_string(),
                accept: true,
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                ..Default::default()
            },
            SshRuleAction::Check { .. } => WireSshAction {
                message: "approval required".to_string(),
                hold_and_delegate: format!(
                    "{server_url}/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?ssh_user=$SSH_USER&local_user=$LOCAL_USER"
                ),
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                ..Default::default()
            },
        };
        wire_rules.push(WireSshRule {
            principals,
            ssh_users,
            action: Some(action),
        });
    }
    Some(WireSshPolicy { rules: wire_rules })
}

/// Parse a `checkPeriod` string (`"30m"`, `"12h"`, `"1h30m"`, `"2d"`) into a
/// [`Duration`]. Returns `None` for empty or malformed values.
pub fn parse_ssh_duration(input: &str) -> Option<Duration> {
    if input.is_empty() {
        return None;
    }
    let mut total: u64 = 0;
    let mut number = String::new();
    for c in input.chars() {
        if c.is_ascii_digit() {
            number.push(c);
            continue;
        }
        let amount: u64 = number.parse().ok()?;
        let seconds = match c.to_ascii_lowercase() {
            's' => amount,
            'm' => amount.checked_mul(60)?,
            'h' => amount.checked_mul(3600)?,
            'd' => amount.checked_mul(86400)?,
            _ => return None,
        };
        total = total.checked_add(seconds)?;
        number.clear();
    }
    if !number.is_empty() {
        // A trailing number with no unit is malformed.
        return None;
    }
    Some(Duration::from_secs(total))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompileNode;

    fn node(id: u64, login: Option<&str>, tags: &[&str]) -> CompileNode {
        CompileNode {
            id,
            user_login: login.map(|s| s.to_string()),
            addresses: vec![format!("100.64.0.{id}/32")],
            tags: tags.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn parse(text: &str) -> Policy {
        crate::parse_policy(text).expect("policy must parse")
    }

    #[test]
    fn parses_check_periods() {
        assert_eq!(parse_ssh_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(
            parse_ssh_duration("30m"),
            Some(Duration::from_secs(30 * 60))
        );
        assert_eq!(
            parse_ssh_duration("12h"),
            Some(Duration::from_secs(12 * 3600))
        );
        assert_eq!(
            parse_ssh_duration("1h30m"),
            Some(Duration::from_secs(90 * 60))
        );
        assert_eq!(parse_ssh_duration("2d"), Some(Duration::from_secs(2 * 86400)));
        assert_eq!(parse_ssh_duration(""), None);
        assert_eq!(parse_ssh_duration("12"), None);
        assert_eq!(parse_ssh_duration("1x"), None);
    }

    #[test]
    fn check_rule_compiles_per_destination_node() {
        let policy = parse(
            r#"{ "ssh": [ { "action": "check", "src": ["autogroup:member"],
                "dst": ["tag:web"], "users": ["root"], "checkPeriod": "12h" } ] }"#,
        );
        let nodes = vec![
            node(1, Some("alice@example.com"), &[]),
            node(2, None, &["tag:web"]),
            node(3, None, &["tag:db"]),
        ];
        let compiled = compile_ssh_policy(&policy, &nodes);
        // Only the tag:web node carries the rule.
        assert_eq!(compiled.node_rules.get(&2).unwrap().len(), 1);
        assert!(compiled.node_rules.get(&3).unwrap().is_empty());
        assert!(compiled.node_rules.get(&1).unwrap().is_empty());
        // The rule applies to untagged source nodes.
        let rule = first_matching_ssh_rule(&compiled, 1, 2, "root")
            .expect("alice matches");
        assert_eq!(
            rule.action,
            SshRuleAction::Check {
                check_period: Duration::from_secs(12 * 3600)
            }
        );
        // A tagged source and a wrong user do not match.
        assert!(first_matching_ssh_rule(&compiled, 2, 2, "root").is_none());
        assert!(first_matching_ssh_rule(&compiled, 1, 2, "ubuntu").is_none());
    }

    #[test]
    fn accept_rule_matches_first_and_wins() {
        let policy = parse(
            r#"{ "ssh": [
                { "action": "accept", "src": ["alice@example.com"], "dst": ["tag:web"], "users": ["root"] },
                { "action": "check", "src": ["*"], "dst": ["tag:web"], "users": ["*"], "checkPeriod": "1h" }
            ] }"#,
        );
        let nodes = vec![
            node(1, Some("alice@example.com"), &[]),
            node(2, Some("bob@example.com"), &[]),
            node(10, None, &["tag:web"]),
        ];
        let compiled = compile_ssh_policy(&policy, &nodes);
        // alice hits the accept rule first.
        let alice = first_matching_ssh_rule(&compiled, 1, 10, "root").expect("alice rule");
        assert_eq!(alice.action, SshRuleAction::Accept);
        // bob falls through to the wildcard check rule.
        let bob = first_matching_ssh_rule(&compiled, 2, 10, "ubuntu").unwrap();
        assert!(matches!(bob.action, SshRuleAction::Check { .. }));
    }

    #[test]
    fn empty_user_list_matches_any_user() {
        let policy = parse(
            r#"{ "ssh": [ { "action": "check", "src": ["autogroup:tagged"],
                "dst": ["tag:web"], "checkPeriod": "1h" } ] }"#,
        );
        let nodes = vec![
            node(1, None, &["tag:client"]),
            node(10, None, &["tag:web"]),
        ];
        let compiled = compile_ssh_policy(&policy, &nodes);
        let rule = first_matching_ssh_rule(&compiled, 1, 10, "anything").expect("any user");
        assert!(matches!(rule.action, SshRuleAction::Check { .. }));
    }

    #[test]
    fn wire_policy_uses_check_period_and_placeholder_url() {
        let policy = parse(
            r#"{ "ssh": [ { "action": "check", "src": ["autogroup:member"],
                "dst": ["tag:web"], "users": ["root"], "checkPeriod": "12h" } ] }"#,
        );
        let nodes = vec![
            node(1, Some("alice@example.com"), &[]),
            node(10, None, &["tag:web"]),
        ];
        let compiled = compile_ssh_policy(&policy, &nodes);
        let wire = build_wire_ssh_policy(&compiled, 10, "https://control.example.com")
            .expect("web node has a policy");
        let rule = &wire.rules[0];
        assert!(rule.principals[0].any.contains(&"autogroup:member".to_string()));
        assert_eq!(rule.ssh_users["root"], "=");
        let action = rule.action.as_ref().unwrap();
        assert!(action
            .hold_and_delegate
            .contains("/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID"));
        assert!(action.hold_and_delegate.contains("ssh_user=$SSH_USER"));
        assert!(action.hold_and_delegate.contains("local_user=$LOCAL_USER"));
        // A node with no rules gets no wire policy.
        assert!(build_wire_ssh_policy(&compiled, 1, "https://control.example.com").is_none());
    }
}

