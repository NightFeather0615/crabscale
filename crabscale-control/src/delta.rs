//! Incremental MapResponse delta building.
//!
//! Each streaming map session tracks the peers it last sent
//! ([`SessionPeers`]). When a change batch arrives,
//! [`ControlPlane::build_delta`] diffs the current peer set against the
//! session's last-sent set and emits the smallest spec-compliant delta
//! (Spec-NetMap section 4):
//!
//! - a full [`PeersChanged`] entry when structural fields changed
//!   (addresses, routes, name, machine key, host description, ...),
//! - a lightweight [`PeersChangedPatch`] when only patchable fields changed
//!   (endpoints, home DERP region, node/disco keys, online state, last-seen,
//!   key expiry, capability version), and
//! - a [`PeersRemoved`] entry for peers that disappeared.
//!
//! Online-state changes are also carried on the dedicated `OnlineChange` map
//! and peer-seen signals on `PeerSeenChange`. Deltas are only ever produced
//! after the initial complete frame has been sent, and a batch that affects
//! nothing for a particular session produces no frame at all.

use std::collections::{BTreeMap, BTreeSet};

use crabscale_proto::{FilterRule, MapResponse, Node as WireNode, PeerChange};

use crate::{ChangeBatch, ControlError, ControlPlane, DomainNode};

/// Per-session tracking of the peer set last sent to the client.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionPeers {
    peers: BTreeMap<u64, WireNode>,
    key_expiry: BTreeMap<u64, Option<String>>,
}

impl SessionPeers {
    /// An empty tracking set for a session that has not sent a frame yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate tracking from the peers of a just-built initial map, so the
    /// first delta only carries changes since the complete frame.
    pub fn from_peers<'a>(nodes: impl IntoIterator<Item = &'a WireNode>) -> Self {
        let mut peers = BTreeMap::new();
        for node in nodes {
            peers.insert(node.id, node.clone());
        }
        Self {
            peers,
            key_expiry: BTreeMap::new(),
        }
    }

    /// Number of peers currently tracked as sent.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether no peers are tracked yet.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// The result of diffing the current peer set against a session's last-sent
/// set.
#[derive(Debug, Default)]
struct PeerDeltas {
    /// Peer ids the session should drop.
    removed: Vec<u64>,
    /// Full peer objects to (re)send.
    changed: Vec<WireNode>,
    /// Lightweight patches to apply.
    patches: Vec<PeerChange>,
    /// The current, authoritative, sorted peer objects.
    current: Vec<WireNode>,
    /// Node ids visible to the session under the current policy.
    visible: BTreeSet<u64>,
}

/// How two snapshots of the same peer relate.
#[derive(Debug, Clone, PartialEq)]
enum PeerDiff {
    /// No change: nothing to send.
    Unchanged,
    /// Only lightweight fields differ; a patch is sufficient.
    Patch(PeerChange),
    /// Structural fields differ; the full node object must be re-sent.
    Full,
}

impl ControlPlane {
    /// Build the delta MapResponse for a live streaming session after a
    /// change batch, updating `last_sent` in place.
    ///
    /// Returns `None` when the batch has nothing to send to this session.
    /// This is only invoked after the initial complete frame, so deltas are
    /// never sent before the first frame.
    pub fn build_delta(
        &self,
        session_node_id: i64,
        batch: &ChangeBatch,
        last_sent: &mut SessionPeers,
        client_version: u32,
    ) -> Result<Option<MapResponse>, ControlError> {
        let mut response = MapResponse::default();

        // DNS and DERP changes are self-contained delta frames (Spec-NetMap
        // section 7.4 / 7.5).
        if batch.has_dns() {
            if let Some(dns) = self.build_dns_config()? {
                response.dns = Some(dns);
            }
        }
        if batch.has_derp() {
            response.derp_map = Some(self.derp_state.map());
        }

        if !batch.needs_peer_rescan() {
            return if response == MapResponse::default() {
                Ok(None)
            } else {
                Ok(Some(response))
            };
        }

        let self_node = self
            .store
            .get_node_by_id(session_node_id)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .ok_or(ControlError::NotFound)?;

        let deltas = self.compute_peer_delta(&self_node, last_sent, client_version)?;

        if batch.has_policy() {
            // A policy change can rewrite peer visibility, routed
            // `AllowedIPs`, the self node's capability map, the base packet
            // filter, and the per-node SSH policy. Spec-NetMap section 4
            // allows a delta frame to carry a full `Peers` replacement, which
            // is the authoritative way to express a topology rewrite.
            response.peers = Some(deltas.current);
            response.packet_filters = Some(self.base_packet_filters(&self_node)?);
            response.ssh_policy = self.ssh_policy_for(&self_node)?;
            response.node = self.self_node_proto(&self_node, client_version)?;
            return Ok(Some(response));
        }

        if !deltas.removed.is_empty() {
            response.peers_removed = Some(deltas.removed);
        }
        if !deltas.changed.is_empty() {
            response.peers_changed = Some(deltas.changed);
        }
        if !deltas.patches.is_empty() {
            response.peers_changed_patch = Some(deltas.patches);
        }

        // Online/seen signals only go to sessions that actually see the node.
        let online: BTreeMap<u64, bool> = batch
            .online_changes()
            .filter(|(id, _)| deltas.visible.contains(&(*id as u64)))
            .map(|(id, online)| (id as u64, online))
            .collect();
        if !online.is_empty() {
            response.online_change = Some(online);
        }
        let seen: BTreeMap<u64, bool> = batch
            .seen_nodes()
            .filter(|id| deltas.visible.contains(&(*id as u64)))
            .map(|id| (id as u64, true))
            .collect();
        if !seen.is_empty() {
            response.peer_seen_change = Some(seen);
        }

        if response == MapResponse::default() {
            return Ok(None);
        }
        Ok(Some(response))
    }

    /// Build the wire representation of a peer node for this session,
    /// including its live online/last-seen state and its effective routed
    /// `AllowedIPs`/`PrimaryRoutes` (which the raw stored node does not
    /// carry).
    pub(crate) fn peer_node(
        &self,
        stored: &DomainNode,
        client_version: u32,
    ) -> Result<WireNode, ControlError> {
        let mut node = stored.to_proto();
        node.online = Some(self.is_node_online(stored.id));
        let routes = self.effective_approved_routes(stored)?;
        if !routes.is_empty() {
            let mut allowed = stored.addresses.clone();
            allowed.extend(routes.iter().cloned());
            allowed.sort();
            allowed.dedup();
            node.allowed_ips = Some(allowed);
            node.primary_routes = Self::non_address_routes(&routes, &stored.addresses);
        }
        // Apply the AllowedIPs wire gate so the delta's peer snapshot agrees
        // with the initial map for the same client version (capver >= 112
        // omits `AllowedIPs` when it equals `Addresses`).
        node.allowed_ips = Self::allowed_ips_for(
            client_version,
            &stored.addresses,
            node.allowed_ips.as_deref(),
        );
        Ok(node)
    }

    /// Diff the current visible peer set against `last_sent`, updating the
    /// tracking and returning the ordered deltas.
    fn compute_peer_delta(
        &self,
        self_node: &DomainNode,
        last_sent: &mut SessionPeers,
        client_version: u32,
    ) -> Result<PeerDeltas, ControlError> {
        let compile_nodes = self.compile_nodes()?;
        crabscale_metrics::registry().policy_compiles_total.inc();
        let compiled = crabscale_policy::compile_policy(&self.config.policy, &compile_nodes);
        let visible = compiled
            .peer_visibility
            .get(&(self_node.id as u64))
            .cloned()
            .unwrap_or_default();

        // Current visible peer set: authorized, visible, not self, sorted by
        // id. Keep the domain node alongside so key-expiry can feed patches.
        let mut next: BTreeMap<u64, (WireNode, Option<String>)> = BTreeMap::new();
        for stored in self
            .store
            .list_nodes()
            .map_err(|e| ControlError::Store(e.to_string()))?
        {
            if stored.node_key == self_node.node_key {
                continue;
            }
            if !stored.machine_authorized {
                continue;
            }
            if !visible.contains(&(stored.id as u64)) {
                continue;
            }
            next.insert(
                stored.id as u64,
                (
                    self.peer_node(&stored, client_version)?,
                    stored.key_expiry.clone(),
                ),
            );
        }

        let mut deltas = PeerDeltas {
            visible,
            ..PeerDeltas::default()
        };

        // Peers that left the visible set.
        let removed: Vec<u64> = last_sent
            .peers
            .keys()
            .filter(|id| !next.contains_key(id))
            .copied()
            .collect();
        for id in &removed {
            last_sent.peers.remove(id);
            last_sent.key_expiry.remove(id);
        }
        deltas.removed = removed;

        for (id, (next_node, next_expiry)) in &next {
            let current = next_node.clone();
            match last_sent.peers.get(id) {
                None => {
                    deltas.changed.push(current.clone());
                }
                Some(prev) => {
                    let prev_expiry = last_sent.key_expiry.get(id).cloned().flatten();
                    match diff_peers(
                        prev,
                        &current,
                        prev_expiry.as_deref(),
                        next_expiry.as_deref(),
                    ) {
                        PeerDiff::Unchanged => {}
                        PeerDiff::Patch(patch) => deltas.patches.push(patch),
                        PeerDiff::Full => deltas.changed.push(current.clone()),
                    }
                }
            }
            last_sent.peers.insert(*id, current);
            last_sent.key_expiry.insert(*id, next_expiry.clone());
        }

        deltas.current = next.into_values().map(|(node, _)| node).collect();
        Ok(deltas)
    }

    fn base_packet_filters(
        &self,
        self_node: &DomainNode,
    ) -> Result<BTreeMap<String, Vec<FilterRule>>, ControlError> {
        let compile_nodes = self.compile_nodes()?;
        crabscale_metrics::registry().policy_compiles_total.inc();
        let compiled = crabscale_policy::compile_policy(&self.config.policy, &compile_nodes);
        let base = compiled
            .node_filters
            .get(&(self_node.id as u64))
            .cloned()
            .unwrap_or_default();
        Ok(BTreeMap::from([("base".to_string(), base)]))
    }

    fn ssh_policy_for(
        &self,
        self_node: &DomainNode,
    ) -> Result<Option<crabscale_proto::SshPolicy>, ControlError> {
        let compile_nodes = self.compile_nodes()?;
        crabscale_metrics::registry().policy_compiles_total.inc();
        let ssh_compiled =
            crabscale_policy::compile_ssh_policy(&self.config.policy, &compile_nodes);
        Ok(crabscale_policy::build_wire_ssh_policy(
            &ssh_compiled,
            self_node.id as u64,
            &self.config.server_url,
            &compile_nodes,
        ))
    }

    /// The self node's wire representation including the policy-derived
    /// `CapMap` and `PrimaryRoutes`, used when a policy change alters them.
    fn self_node_proto(
        &self,
        self_node: &DomainNode,
        client_version: u32,
    ) -> Result<Option<WireNode>, ControlError> {
        let mut proto_node = self_node.to_proto();
        proto_node.primary_routes = Self::non_address_routes(
            &self.effective_approved_routes(self_node)?,
            &self_node.addresses,
        );
        proto_node.allowed_ips = Self::allowed_ips_for(
            client_version,
            &self_node.addresses,
            proto_node.allowed_ips.as_deref(),
        );
        if !self.config.policy.node_attrs.is_empty() {
            let compile_nodes = self.compile_nodes()?;
            if let Some(self_compile) = compile_nodes.iter().find(|n| n.id == self_node.id as u64) {
                proto_node.cap_map = crabscale_policy::node_attributes(
                    &self.config.policy,
                    self_compile,
                    &compile_nodes,
                );
            }
        }
        Ok(Some(proto_node))
    }
}

/// Compare two snapshots of the same peer and decide what to send.
///
/// Structural fields (addresses, allowed IPs, name, machine key, hostinfo,
/// tags, capability map, primary routes, authorization) require a full
/// [`PeersChanged`] entry. When only the lightweight patched fields differ,
/// a [`PeersChangedPatch`] is sufficient and no full node is re-sent.
fn diff_peers(
    prev: &WireNode,
    next: &WireNode,
    prev_expiry: Option<&str>,
    next_expiry: Option<&str>,
) -> PeerDiff {
    let structural_equal = prev.stable_id == next.stable_id
        && prev.name == next.name
        && prev.user == next.user
        && prev.machine == next.machine
        && prev.addresses == next.addresses
        && prev.allowed_ips == next.allowed_ips
        && prev.hostinfo == next.hostinfo
        && prev.created == next.created
        && prev.tags == next.tags
        && prev.cap_map == next.cap_map
        && prev.primary_routes == next.primary_routes
        && prev.machine_authorized == next.machine_authorized
        && prev.capabilities == next.capabilities;

    if !structural_equal {
        return PeerDiff::Full;
    }

    let mut patch = PeerChange {
        node_id: next.id,
        ..Default::default()
    };
    let mut has_patch = false;

    if prev.endpoints != next.endpoints {
        patch.endpoints = Some(next.endpoints.clone());
        has_patch = true;
    }
    if prev.home_derp != next.home_derp {
        patch.derp_region = Some(next.home_derp);
        has_patch = true;
    }
    if prev.key != next.key {
        patch.key = Some(next.key);
        has_patch = true;
    }
    if prev.disco_key != next.disco_key {
        patch.disco_key = Some(next.disco_key);
        has_patch = true;
    }
    if prev.online != next.online {
        patch.online = next.online;
        has_patch = true;
    }
    if prev.last_seen != next.last_seen {
        patch.last_seen = next.last_seen.clone();
        has_patch = true;
    }
    if prev.cap != next.cap {
        patch.cap = Some(next.cap);
        has_patch = true;
    }
    if prev_expiry != next_expiry {
        patch.key_expiry = next_expiry.map(str::to_string);
        has_patch = true;
    }

    if has_patch {
        PeerDiff::Patch(patch)
    } else {
        PeerDiff::Unchanged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u64) -> WireNode {
        WireNode {
            id,
            stable_id: format!("n{id:023}"),
            name: format!("node{id}.tailnet.example."),
            endpoints: vec![format!("1.1.{id}.1:41641")],
            home_derp: 1,
            ..Default::default()
        }
    }

    #[test]
    fn endpoint_change_yields_a_patch_not_a_full_peer() {
        let prev = node(5);
        let mut next = prev.clone();
        next.endpoints = vec!["203.0.113.10:41641".to_string()];

        match diff_peers(&prev, &next, None, None) {
            PeerDiff::Patch(patch) => {
                assert_eq!(
                    patch.endpoints,
                    Some(vec!["203.0.113.10:41641".to_string()])
                );
                assert_eq!(patch.key, None, "an endpoint change must not re-send keys");
                assert_eq!(patch.derp_region, None);
            }
            other => panic!("expected a patch, got {other:?}"),
        }
    }

    #[test]
    fn key_rotation_yields_a_patch() {
        let prev = node(5);
        let mut next = prev.clone();
        next.key = crabscale_proto::NodeKey::from_bytes([0xAB; 32]);

        match diff_peers(&prev, &next, None, None) {
            PeerDiff::Patch(patch) => {
                assert_eq!(
                    patch.key,
                    Some(crabscale_proto::NodeKey::from_bytes([0xAB; 32]))
                )
            }
            other => panic!("a node key change must be a patch, got {other:?}"),
        }
    }

    #[test]
    fn machine_key_rotation_forces_a_full_peer_resend() {
        let prev = node(5);
        let mut next = prev.clone();
        next.machine = crabscale_proto::MachineKey::from_bytes([0xCD; 32]);

        assert_eq!(
            diff_peers(&prev, &next, None, None),
            PeerDiff::Full,
            "a machine key change is structural and must resend the peer"
        );
    }

    #[test]
    fn unchanged_peer_yields_no_delta() {
        let prev = node(5);
        let next = prev.clone();
        assert_eq!(diff_peers(&prev, &next, None, None), PeerDiff::Unchanged);
    }

    #[test]
    fn derp_region_change_yields_a_patch() {
        let prev = node(5);
        let mut next = prev.clone();
        next.home_derp = 9;
        match diff_peers(&prev, &next, None, None) {
            PeerDiff::Patch(patch) => assert_eq!(patch.derp_region, Some(9)),
            other => panic!("expected a patch, got {other:?}"),
        }
    }

    #[test]
    fn key_expiry_change_yields_a_patch() {
        let prev = node(5);
        let next = prev.clone();
        match diff_peers(&prev, &next, None, Some("2027-01-01T00:00:00Z")) {
            PeerDiff::Patch(patch) => {
                assert_eq!(patch.key_expiry, Some("2027-01-01T00:00:00Z".to_string()));
            }
            other => panic!("expected a patch, got {other:?}"),
        }
    }

    #[test]
    fn session_peers_tracks_sent_peers() {
        let peers = vec![node(1), node(2)];
        let mut session = SessionPeers::from_peers(&peers);
        assert_eq!(session.len(), 2);
        session.peers.remove(&1);
        assert_eq!(session.len(), 1);
    }
}
