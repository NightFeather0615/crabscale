//! SSH check-mode endpoint and approval cache.
//!
//! This module implements the `GET /machine/ssh/action/{src}/to/{dst}`
//! decision logic from [Spec-Control-API]: it evaluates the compiled
//! per-node [`crabscale_policy::CompiledSshPolicy`], auto-approves repeat
//! connections within `checkPeriod`, creates a pending approval with an
//! unguessable auth id when an admin verdict is required, and long-polls
//! followup requests until an approve/reject resolves them.
//!
//! Auth records are persisted through the [`crate::Store`] so a separate
//! process (the CLI) can approve or reject a pending SSH check against the
//! same database. An in-process broadcast channel wakes waiting followups
//! immediately; a short store poll covers approvals made out-of-process.
//!
//! [Spec-Control-API]: https://github.com/NightFeather0615/crabscale/wiki/Spec-Control-API.md

use std::time::Duration;

use crabscale_proto::{MachineKey, SshAction};

use crate::{ControlError, ControlPlane, time};

/// Default time-to-live for a pending SSH approval before it expires.
pub const DEFAULT_SSH_AUTH_TTL_SECONDS: i64 = 15 * 60;

/// Default maximum number of pending SSH auth records kept before the
/// oldest are pruned (M4-02: bound the SSH cache with TTL and a cap).
pub const DEFAULT_SSH_AUTH_LIMIT: usize = 1024;

/// Default maximum time a followup request holds while waiting for a verdict
/// before the client is told to re-fetch.
pub const DEFAULT_SSH_WAIT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// How often a followup re-checks the durable store when no in-process
/// broadcast woke it (for example an approval from a separate CLI process).
const SSH_WAIT_POLL: Duration = Duration::from_millis(250);

/// An SSH check-mode auth record awaiting (or carrying) an admin verdict.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshAuth {
    /// Unguessable identifier embedded in the followup URL.
    pub auth_id: String,
    /// The node id that initiated the SSH connection.
    pub src_node_id: u64,
    /// The node id targeted by the SSH connection.
    pub dst_node_id: u64,
    /// The SSH user requested on the connection.
    pub ssh_user: String,
    /// The local user the rule maps the connection to.
    pub local_user: String,
    /// The Noise machine key that made the request (the destination node's).
    pub machine_key: MachineKey,
    /// When the record was created.
    pub created_at: String,
    /// When the record expires.
    pub expires_at: String,
    /// The current admin verdict.
    pub verdict: SshVerdict,
}

/// The admin verdict for an SSH check-mode auth record.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SshVerdict {
    /// No decision has been made yet; followup requests block.
    Pending,
    /// The (src,dst) pair was accepted at `last_auth_at`, which is how long
    /// the auto-approval window (`checkPeriod`) is measured from.
    Accepted {
        /// RFC 3339 timestamp of the last approval for this binding.
        last_auth_at: String,
    },
    /// The auth record was rejected.
    Rejected,
}

impl SshVerdict {
    /// Whether the verdict is still awaiting an admin decision.
    pub fn is_pending(&self) -> bool {
        matches!(self, SshVerdict::Pending)
    }

    /// Whether the verdict admits the connection.
    pub fn is_accepted(&self) -> bool {
        matches!(self, SshVerdict::Accepted { .. })
    }
}

impl ControlPlane {
    /// Decide the SSH action for an initial or followup check-mode request.
    ///
    /// `machine_key` must equal the destination node's machine key (the SSH
    /// server side asks on behalf of the destination). Initial requests
    /// evaluate the compiled SSH policy; followup requests (carrying
    /// `auth_id`) verify the binding and block until the verdict resolves.
    pub async fn handle_ssh_action(
        &self,
        machine_key: MachineKey,
        src_node_id: u64,
        dst_node_id: u64,
        auth_id: Option<&str>,
        ssh_user: &str,
        local_user: &str,
    ) -> Result<SshAction, ControlError> {
        let dst = self
            .store
            .get_node_by_id(dst_node_id as i64)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .ok_or(ControlError::NotFound)?;
        if dst.machine_key != machine_key {
            return Err(ControlError::Unauthorized);
        }
        self.store
            .get_node_by_id(src_node_id as i64)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .ok_or(ControlError::NotFound)?;

        if let Some(auth_id) = auth_id {
            return self
                .respond_ssh_followup(
                    machine_key,
                    src_node_id,
                    dst_node_id,
                    auth_id,
                    ssh_user,
                    local_user,
                )
                .await;
        }

        self.respond_ssh_initial(machine_key, src_node_id, dst_node_id, ssh_user, local_user)
    }

    /// Approve a pending SSH check-mode auth record, recording the approval
    /// time so repeat connections within `checkPeriod` auto-approve.
    pub fn approve_ssh(&self, auth_id: &str) -> Result<(), ControlError> {
        let now = time::now_rfc3339();
        let Some(mut entry) = self.get_ssh_auth(auth_id)? else {
            return Err(ControlError::NotFound);
        };
        if time::is_past(&entry.expires_at, &now) {
            self.store
                .delete_ssh_auth(&entry.auth_id)
                .map_err(|e| ControlError::Store(e.to_string()))?;
            return Err(ControlError::NotFound);
        }
        entry.verdict = SshVerdict::Accepted { last_auth_at: now };
        self.store
            .save_ssh_auth(&entry)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        let _ = self.ssh_waiters.send(entry.auth_id);
        Ok(())
    }

    /// Reject a pending SSH check-mode auth record.
    pub fn reject_ssh(&self, auth_id: &str) -> Result<(), ControlError> {
        let now = time::now_rfc3339();
        let Some(mut entry) = self.get_ssh_auth(auth_id)? else {
            return Err(ControlError::NotFound);
        };
        if time::is_past(&entry.expires_at, &now) {
            self.store
                .delete_ssh_auth(&entry.auth_id)
                .map_err(|e| ControlError::Store(e.to_string()))?;
            return Err(ControlError::NotFound);
        }
        entry.verdict = SshVerdict::Rejected;
        self.store
            .save_ssh_auth(&entry)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        let _ = self.ssh_waiters.send(entry.auth_id);
        Ok(())
    }

    /// List the known, non-expired SSH auth records.
    pub fn list_ssh_auths(&self) -> Result<Vec<SshAuth>, ControlError> {
        let now = time::now_rfc3339();
        let entries = self
            .store
            .list_ssh_auths()
            .map_err(|e| ControlError::Store(e.to_string()))?;
        Ok(entries
            .into_iter()
            .filter(|entry| !time::is_past(&entry.expires_at, &now))
            .collect())
    }

    /// Return a copy of a pending SSH auth record, if known and not expired.
    pub fn ssh_auth_info(&self, auth_id: &str) -> Result<Option<SshAuth>, ControlError> {
        let now = time::now_rfc3339();
        let Some(entry) = self.get_ssh_auth(auth_id)? else {
            return Ok(None);
        };
        if time::is_past(&entry.expires_at, &now) {
            self.store
                .delete_ssh_auth(&entry.auth_id)
                .map_err(|e| ControlError::Store(e.to_string()))?;
            return Ok(None);
        }
        Ok(Some(entry))
    }

    /// Evaluate the initial (auth id absent) request against the compiled
    /// SSH policy.
    fn respond_ssh_initial(
        &self,
        machine_key: MachineKey,
        src_node_id: u64,
        dst_node_id: u64,
        ssh_user: &str,
        local_user: &str,
    ) -> Result<SshAction, ControlError> {
        let compile_nodes = self.compile_nodes()?;
        crabscale_metrics::registry().policy_compiles_total.inc();
        let ssh_policy = crabscale_policy::compile_ssh_policy(&self.config.policy, &compile_nodes);
        let rule = crabscale_policy::first_matching_ssh_rule(
            &ssh_policy,
            src_node_id,
            dst_node_id,
            ssh_user,
        );
        let Some(rule) = rule else {
            return Ok(reject_action("no SSH rule permits this connection"));
        };
        match rule.action {
            crabscale_policy::SshRuleAction::Accept => Ok(accept_action()),
            crabscale_policy::SshRuleAction::Check { check_period } => {
                if self.recent_ssh_acceptance(
                    src_node_id,
                    dst_node_id,
                    ssh_user,
                    local_user,
                    check_period,
                )? {
                    return Ok(accept_action());
                }
                // Keep the durable SSH auth cache bounded (M4-02).
                self.prune_ssh_auths(DEFAULT_SSH_AUTH_LIMIT)?;
                let auth_id = crate::generate_secret();
                let entry = SshAuth {
                    auth_id: auth_id.clone(),
                    src_node_id,
                    dst_node_id,
                    ssh_user: ssh_user.to_string(),
                    local_user: local_user.to_string(),
                    machine_key,
                    created_at: time::now_rfc3339(),
                    expires_at: time::now_plus_seconds(DEFAULT_SSH_AUTH_TTL_SECONDS),
                    verdict: SshVerdict::Pending,
                };
                self.store
                    .save_ssh_auth(&entry)
                    .map_err(|e| ControlError::Store(e.to_string()))?;
                let url = self.build_ssh_action_url(
                    src_node_id,
                    dst_node_id,
                    &auth_id,
                    ssh_user,
                    local_user,
                );
                Ok(SshAction {
                    message: "approval required".to_string(),
                    hold_and_delegate: url,
                    allow_agent_forwarding: true,
                    allow_local_port_forwarding: true,
                    allow_remote_port_forwarding: true,
                    ..Default::default()
                })
            }
        }
    }
}

impl ControlPlane {
    /// Resolve a followup request (auth id present): verify the stored binding
    /// and block until an admin verdict resolves the auth id.
    async fn respond_ssh_followup(
        &self,
        machine_key: MachineKey,
        src_node_id: u64,
        dst_node_id: u64,
        auth_id: &str,
        ssh_user: &str,
        local_user: &str,
    ) -> Result<SshAction, ControlError> {
        let now = time::now_rfc3339();
        let Some(entry) = self.get_ssh_auth(auth_id)? else {
            return Err(ControlError::NotFound);
        };
        if time::is_past(&entry.expires_at, &now) {
            self.store
                .delete_ssh_auth(auth_id)
                .map_err(|e| ControlError::Store(e.to_string()))?;
            return Err(ControlError::NotFound);
        }
        // Binding verification: a followup must present the exact same
        // src/dst binding (and machine key) the initial request created.
        if entry.src_node_id != src_node_id
            || entry.dst_node_id != dst_node_id
            || entry.ssh_user != ssh_user
            || entry.local_user != local_user
            || entry.machine_key != machine_key
        {
            return Err(ControlError::SshBinding(auth_id.to_string()));
        }
        match entry.verdict {
            SshVerdict::Accepted { .. } => Ok(accept_action()),
            SshVerdict::Rejected => Ok(reject_action("SSH request rejected")),
            SshVerdict::Pending => {
                let verdict = self.wait_ssh_verdict(auth_id).await?;
                match verdict {
                    SshVerdict::Accepted { .. } => Ok(accept_action()),
                    SshVerdict::Rejected => Ok(reject_action("SSH request rejected")),
                    SshVerdict::Pending => Err(ControlError::Timeout),
                }
            }
        }
    }

    /// Block until `auth_id` resolves, waking on an in-process broadcast or,
    /// failing that, re-checking the durable store until the overall timeout.
    async fn wait_ssh_verdict(&self, auth_id: &str) -> Result<SshVerdict, ControlError> {
        let mut rx = self.ssh_waiters.subscribe();
        let deadline = tokio::time::Instant::now() + DEFAULT_SSH_WAIT_TIMEOUT;
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(ControlError::Timeout);
            }
            match self.get_ssh_auth(auth_id)? {
                None => return Err(ControlError::NotFound),
                Some(entry) => {
                    if time::is_past(&entry.expires_at, &time::now_rfc3339()) {
                        self.store
                            .delete_ssh_auth(auth_id)
                            .map_err(|e| ControlError::Store(e.to_string()))?;
                        return Err(ControlError::NotFound);
                    }
                    if !entry.verdict.is_pending() {
                        return Ok(entry.verdict);
                    }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(SSH_WAIT_POLL) => continue,
                changed = rx.recv() => match changed {
                    // Re-check immediately on any broadcast; the loop filters
                    // for our own auth id by reading the store again.
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(ControlError::Store(
                            "ssh waiter channel closed".to_string(),
                        ));
                    }
                },
            }
        }
    }

    /// Whether an accepted SSH auth exists for the given binding whose
    /// `last_auth_at` is within `check_period`. The record's approval time is
    /// refreshed so a steady stream of sessions keeps the window sliding.
    fn recent_ssh_acceptance(
        &self,
        src_node_id: u64,
        dst_node_id: u64,
        ssh_user: &str,
        local_user: &str,
        check_period: Duration,
    ) -> Result<bool, ControlError> {
        let now = time::now_unix();
        let entries = self
            .store
            .list_ssh_auths()
            .map_err(|e| ControlError::Store(e.to_string()))?;
        // Track the most recent accepted approval for this exact binding.
        let mut best: Option<SshAuth> = None;
        let mut best_last: i64 = 0;
        for entry in entries {
            if entry.src_node_id != src_node_id
                || entry.dst_node_id != dst_node_id
                || entry.ssh_user != ssh_user
                || entry.local_user != local_user
            {
                continue;
            }
            if let SshVerdict::Accepted { last_auth_at } = &entry.verdict {
                if let Some(last) = time::parse_rfc3339(last_auth_at) {
                    if best.is_none() || last > best_last {
                        best_last = last;
                        best = Some(entry);
                    }
                }
            }
        }
        let Some(mut entry) = best else {
            return Ok(false);
        };
        let window = check_period.as_secs() as i64;
        if best_last < now - window {
            return Ok(false);
        }
        // Slide the approval window forward so a steady stream of sessions
        // keeps the binding authorized.
        entry.verdict = SshVerdict::Accepted {
            last_auth_at: time::now_rfc3339(),
        };
        self.store
            .save_ssh_auth(&entry)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        Ok(true)
    }

    /// Bound the SSH auth cache: delete expired records, then delete the
    /// oldest pending records until at most `limit` remain (M4-02).
    fn prune_ssh_auths(&self, limit: usize) -> Result<(), ControlError> {
        let now = time::now_rfc3339();
        let entries = self
            .store
            .list_ssh_auths()
            .map_err(|e| ControlError::Store(e.to_string()))?;
        let mut remaining = Vec::new();
        for entry in entries {
            if time::is_past(&entry.expires_at, &now) {
                self.store
                    .delete_ssh_auth(&entry.auth_id)
                    .map_err(|e| ControlError::Store(e.to_string()))?;
            } else {
                remaining.push(entry);
            }
        }
        if remaining.len() > limit {
            // RFC 3339 timestamps sort chronologically, so the oldest
            // records are at the front after sorting.
            remaining.sort_by_key(|e| e.created_at.clone());
            let overflow = remaining.len() - limit;
            for entry in remaining.into_iter().take(overflow) {
                self.store
                    .delete_ssh_auth(&entry.auth_id)
                    .map_err(|e| ControlError::Store(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Fetch an SSH auth record from the durable store (the source of truth).
    fn get_ssh_auth(&self, auth_id: &str) -> Result<Option<SshAuth>, ControlError> {
        self.store
            .get_ssh_auth(auth_id)
            .map_err(|e| ControlError::Store(e.to_string()))
    }

    /// Build the concrete `/machine/ssh/action` followup URL for an initial
    /// check-mode response, carrying the generated auth id and binding.
    fn build_ssh_action_url(
        &self,
        src_node_id: u64,
        dst_node_id: u64,
        auth_id: &str,
        ssh_user: &str,
        local_user: &str,
    ) -> String {
        format!(
            "{}/machine/ssh/action/{}/to/{}?auth_id={}&ssh_user={}&local_user={}",
            self.config.server_url.trim_end_matches('/'),
            src_node_id,
            dst_node_id,
            auth_id,
            url_query_escape(ssh_user),
            url_query_escape(local_user),
        )
    }
}

/// An [`SshAction`] that admits the connection, with forwarding enabled.
fn accept_action() -> SshAction {
    SshAction {
        message: "SSH connection accepted".to_string(),
        accept: true,
        allow_agent_forwarding: true,
        allow_local_port_forwarding: true,
        allow_remote_port_forwarding: true,
        ..Default::default()
    }
}

/// An [`SshAction`] that closes the connection with `message`.
fn reject_action(message: &str) -> SshAction {
    SshAction {
        message: message.to_string(),
        reject: true,
        ..Default::default()
    }
}

/// Percent-encode a string for use in a URL query component (form style:
/// space becomes `+`, other non-unreserved bytes become `%XX`). This is the
/// inverse of the router's `percent_decode`, so values round-trip cleanly.
fn url_query_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte == b' ' {
            out.push('+');
        } else if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ControlConfig, ControlPlane};
    use crabscale_proto::{Hostinfo, MachineKey, NodeKey, RegisterAuth, RegisterRequest};

    fn test_policy() -> crabscale_policy::Policy {
        crabscale_policy::parse_policy(
            r#"{
                "tagOwners": { "tag:web": ["owner@example.com"] },
                "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*"] } ],
                "ssh": [
                    { "action": "check", "src": ["autogroup:member"], "dst": ["tag:web"],
                      "users": ["root"], "checkPeriod": "12h" }
                ]
            }"#,
        )
        .expect("test policy must parse")
    }

    fn test_plane() -> ControlPlane {
        ControlPlane::new(ControlConfig {
            policy: test_policy(),
            ..ControlConfig::default()
        })
    }

    fn register_user_node(plane: &ControlPlane, machine: [u8; 32], node: [u8; 32]) {
        let request = RegisterRequest {
            version: 130,
            node_key: NodeKey::from_bytes(node),
            auth: Some(RegisterAuth {
                auth_key: "hskey-auth-test-secret".to_string(),
            }),
            hostinfo: Some(Hostinfo {
                hostname: "user-node".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            plane
                .register(MachineKey::from_bytes(machine), request)
                .machine_authorized
        );
    }

    fn register_tagged_node(plane: &ControlPlane, machine: [u8; 32], node: [u8; 32]) {
        let key = plane
            .create_pre_auth_key(
                "m2ssh",
                true,
                false,
                None,
                Some(vec!["tag:web".to_string()]),
            )
            .expect("tagged key");
        let request = RegisterRequest {
            version: 130,
            node_key: NodeKey::from_bytes(node),
            auth: Some(RegisterAuth { auth_key: key }),
            hostinfo: Some(Hostinfo {
                hostname: "web-node".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            plane
                .register(MachineKey::from_bytes(machine), request)
                .machine_authorized
        );
    }

    /// Register a user-owned source node and a tagged destination node,
    /// returning `(src_id, dst_id, dst_machine)`.
    fn place(plane: &ControlPlane) -> (u64, u64, MachineKey) {
        register_user_node(plane, [0x11; 32], [0x21; 32]);
        register_tagged_node(plane, [0x99; 32], [0x29; 32]);
        let nodes = plane.store.list_nodes().unwrap();
        let src = nodes
            .iter()
            .find(|n| n.machine_key == MachineKey::from_bytes([0x11; 32]))
            .unwrap();
        let dst = nodes
            .iter()
            .find(|n| n.machine_key == MachineKey::from_bytes([0x99; 32]))
            .unwrap();
        (src.id as u64, dst.id as u64, dst.machine_key)
    }

    fn extract_auth_id(url: &str) -> String {
        url.split("auth_id=")
            .nth(1)
            .expect("auth_id in url")
            .split('&')
            .next()
            .unwrap()
            .to_string()
    }

    fn stored(plane: &ControlPlane, auth_id: &str) -> SshAuth {
        plane.ssh_auth_info(auth_id).unwrap().expect("auth record")
    }

    #[tokio::test]
    async fn check_mode_approval_allows_ssh_session() {
        let plane = test_plane();
        let (src, dst, machine) = place(&plane);

        // Initial request: no recent approval, so it delegates.
        let action = plane
            .handle_ssh_action(machine, src, dst, None, "root", "root")
            .await
            .unwrap();
        assert!(!action.accept);
        assert!(!action.reject);
        assert!(!action.hold_and_delegate.is_empty());
        let auth_id = extract_auth_id(&action.hold_and_delegate);

        // Approval through the control plane, then the followup admits.
        plane.approve_ssh(&auth_id).unwrap();
        let verdict = plane
            .handle_ssh_action(machine, src, dst, Some(&auth_id), "root", "root")
            .await
            .unwrap();
        assert!(verdict.accept);
        assert!(!verdict.reject);
        assert!(stored(&plane, &auth_id).verdict.is_accepted());
    }

    #[tokio::test]
    async fn check_mode_rejection_closes_ssh_session() {
        let plane = test_plane();
        let (src, dst, machine) = place(&plane);

        let action = plane
            .handle_ssh_action(machine, src, dst, None, "root", "root")
            .await
            .unwrap();
        let auth_id = extract_auth_id(&action.hold_and_delegate);

        // Rejection causes the followup to return Reject.
        plane.reject_ssh(&auth_id).unwrap();
        let verdict = plane
            .handle_ssh_action(machine, src, dst, Some(&auth_id), "root", "root")
            .await
            .unwrap();
        assert!(verdict.reject);
        assert!(!verdict.accept);
    }

    #[tokio::test]
    async fn repeat_request_auto_approves_within_check_period() {
        let plane = test_plane();
        let (src, dst, machine) = place(&plane);

        // First approval.
        let action = plane
            .handle_ssh_action(machine, src, dst, None, "root", "root")
            .await
            .unwrap();
        let auth_id = extract_auth_id(&action.hold_and_delegate);
        plane.approve_ssh(&auth_id).unwrap();

        // A new request for the same binding within checkPeriod auto-approves
        // without creating another hold.
        let again = plane
            .handle_ssh_action(machine, src, dst, None, "root", "root")
            .await
            .unwrap();
        assert!(again.accept);
        assert!(again.hold_and_delegate.is_empty());
    }

    #[tokio::test]
    async fn followup_with_wrong_binding_is_rejected() {
        let plane = test_plane();
        let (src, dst, machine) = place(&plane);

        let action = plane
            .handle_ssh_action(machine, src, dst, None, "root", "root")
            .await
            .unwrap();
        let auth_id = extract_auth_id(&action.hold_and_delegate);

        // A followup that presents a different local user is a binding
        // mismatch and must be rejected.
        let err = plane
            .handle_ssh_action(machine, src, dst, Some(&auth_id), "root", "nobody")
            .await
            .unwrap_err();
        assert!(matches!(err, ControlError::SshBinding(_)));
    }

    #[tokio::test]
    async fn wrong_machine_key_is_unauthorized() {
        let plane = test_plane();
        let (src, dst, _machine) = place(&plane);
        let wrong = MachineKey::from_bytes([0x77; 32]);
        let err = plane
            .handle_ssh_action(wrong, src, dst, None, "root", "root")
            .await
            .unwrap_err();
        assert!(matches!(err, ControlError::Unauthorized));
    }

    #[tokio::test]
    async fn unknown_nodes_return_not_found() {
        let plane = test_plane();
        let (_, dst, machine) = place(&plane);
        // Unknown source node.
        let err = plane
            .handle_ssh_action(machine, 999, dst, None, "root", "root")
            .await
            .unwrap_err();
        assert!(matches!(err, ControlError::NotFound));
        // Unknown destination node.
        let err = plane
            .handle_ssh_action(machine, 1, 999, None, "root", "root")
            .await
            .unwrap_err();
        assert!(matches!(err, ControlError::NotFound));
    }

    #[tokio::test]
    async fn accept_rule_returns_accept_without_hold() {
        let config = ControlConfig {
            policy: crabscale_policy::parse_policy(
                r#"{
                    "tagOwners": { "tag:web": ["owner@example.com"] },
                    "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*"] } ],
                    "ssh": [ { "action": "accept", "src": ["autogroup:member"],
                               "dst": ["tag:web"], "users": ["root"] } ]
                }"#,
            )
            .expect("policy must parse"),
            ..ControlConfig::default()
        };
        let plane = ControlPlane::new(config);
        register_user_node(&plane, [0x11; 32], [0x21; 32]);
        register_tagged_node(&plane, [0x99; 32], [0x29; 32]);
        let nodes = plane.store.list_nodes().unwrap();
        let src = nodes
            .iter()
            .find(|n| n.machine_key == MachineKey::from_bytes([0x11; 32]))
            .unwrap();
        let dst = nodes
            .iter()
            .find(|n| n.machine_key == MachineKey::from_bytes([0x99; 32]))
            .unwrap();
        let action = plane
            .handle_ssh_action(
                dst.machine_key,
                src.id as u64,
                dst.id as u64,
                None,
                "root",
                "root",
            )
            .await
            .unwrap();
        assert!(action.accept);
        assert!(action.hold_and_delegate.is_empty());
    }

    #[test]
    fn ssh_auth_cache_is_bounded_by_prune() {
        let plane = test_plane();
        // Insert 20 pending auth records directly into the durable store.
        for i in 0..20u32 {
            let entry = SshAuth {
                auth_id: format!("auth-{i}"),
                src_node_id: 1,
                dst_node_id: 2,
                ssh_user: "root".to_string(),
                local_user: "root".to_string(),
                machine_key: MachineKey::from_bytes([0x11; 32]),
                created_at: format!("2026-08-20T00:{:02}:00Z", i % 60),
                expires_at: "2926-01-01T00:00:00Z".to_string(),
                verdict: SshVerdict::Pending,
            };
            plane.store.save_ssh_auth(&entry).unwrap();
        }

        plane.prune_ssh_auths(5).unwrap();
        let remaining = plane.list_ssh_auths().unwrap();
        assert_eq!(
            remaining.len(),
            5,
            "prune must cap the SSH auth cache to the configured limit"
        );
        // The five oldest (created first) are deleted.
        for kept in remaining {
            assert!(
                kept.auth_id.starts_with("auth-1"),
                "only the newest records survive: {} vs {}",
                kept.auth_id,
                "first records are pruned",
            );
        }
    }

    #[test]
    fn prune_removes_expired_ssh_auths() {
        let plane = test_plane();
        let expired = SshAuth {
            auth_id: "expired-1".to_string(),
            src_node_id: 1,
            dst_node_id: 2,
            ssh_user: "root".to_string(),
            local_user: "root".to_string(),
            machine_key: MachineKey::from_bytes([0x11; 32]),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2000-01-01T00:00:00Z".to_string(),
            verdict: SshVerdict::Pending,
        };
        plane.store.save_ssh_auth(&expired).unwrap();
        plane.prune_ssh_auths(5).unwrap();
        assert_eq!(
            plane.list_ssh_auths().unwrap().len(),
            0,
            "expired auth records are deleted by the prune"
        );
    }
}
