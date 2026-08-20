//! Change event bus and batching for incremental MapResponse deltas.
//!
//! The control plane publishes [`ChangeEvent`]s whenever node, policy, DNS,
//! or DERP state changes. A [`ChangeBus`] coalesces events per node within a
//! short batch window and broadcasts a single [`ChangeBatch`] to every live
//! map session, so rapid changes are delivered in order without duplicates
//! causing client resets (Spec-NetMap section 4, Architecture "Concurrency
//! model": the event bus fans out one event per change, not one per session).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long node/policy/DNS/DERP changes are coalesced before a delta batch
/// is broadcast to live map sessions.
pub const DEFAULT_CHANGE_BATCH_WINDOW: Duration = Duration::from_millis(100);

/// Maximum number of coalesced events in a single batch before the bus flushes
/// early instead of waiting for the window to elapse.
pub const DEFAULT_CHANGE_BATCH_MAX: usize = 64;

/// A single control-plane change that may affect streaming map sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeEvent {
    /// A node's peer-visible state changed (endpoints, DERP region, keys,
    /// routes, authorization, ...). Sessions re-derive the delta against
    /// their last-sent peer set.
    NodeChanged(i64),
    /// A node was removed from the tailnet (deleted or deauthorized). Sessions
    /// drop it from their last-sent peer set.
    NodeRemoved(i64),
    /// The access-control policy changed; sessions re-derive peer visibility,
    /// packet filters, and SSH policy.
    PolicyChanged,
    /// DNS configuration changed; sessions push a DNS delta.
    DnsChanged,
    /// The DERP map changed; sessions push a DERP map delta.
    DerpMapChanged,
    /// A node's online state changed.
    OnlineChanged {
        node_id: i64,
        online: bool,
    },
    /// A peer was seen by the control plane (it sent a map request).
    PeerSeen(i64),
}

/// A coalesced batch of changes published at the end of a batch window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeBatch {
    /// The coalesced, deduplicated events in deterministic order.
    pub events: Vec<ChangeEvent>,
}

impl ChangeBatch {
    /// Whether the batch carries no changes.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Whether any event in the batch is a DNS change.
    pub(crate) fn has_dns(&self) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e, ChangeEvent::DnsChanged))
    }

    /// Whether any event in the batch is a DERP map change.
    pub(crate) fn has_derp(&self) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e, ChangeEvent::DerpMapChanged))
    }

    /// Whether any event in the batch is a policy change.
    pub(crate) fn has_policy(&self) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e, ChangeEvent::PolicyChanged))
    }

    /// Whether the batch requires re-deriving the peer set from the store.
    pub(crate) fn needs_peer_rescan(&self) -> bool {
        self.events.iter().any(|e| match e {
            ChangeEvent::NodeChanged(_)
            | ChangeEvent::NodeRemoved(_)
            | ChangeEvent::PolicyChanged
            | ChangeEvent::OnlineChanged { .. }
            | ChangeEvent::PeerSeen(_) => true,
            ChangeEvent::DnsChanged | ChangeEvent::DerpMapChanged => false,
        })
    }

    /// The online-state changes carried by the batch, in node-id order.
    pub(crate) fn online_changes(&self) -> impl Iterator<Item = (i64, bool)> + '_ {
        self.events.iter().filter_map(|e| match e {
            ChangeEvent::OnlineChanged { node_id, online } => Some((*node_id, *online)),
            _ => None,
        })
    }

    /// The peer-seen node ids carried by the batch, in node-id order.
    pub(crate) fn seen_nodes(&self) -> impl Iterator<Item = i64> + '_ {
        self.events.iter().filter_map(|e| match e {
            ChangeEvent::PeerSeen(id) => Some(*id),
            _ => None,
        })
    }
}

/// Per-node coalescing state within the current batch window.
#[derive(Debug, Clone, Default)]
struct NodeAccumulator {
    changed: bool,
    removed: bool,
    seen: bool,
    online: Option<bool>,
}

/// The mutable accumulator behind the change bus.
#[derive(Debug, Clone, Default)]
struct Accumulator {
    nodes: BTreeMap<i64, NodeAccumulator>,
    policy: bool,
    dns: bool,
    derp: bool,
}

impl Accumulator {
    fn apply(&mut self, event: ChangeEvent) {
        match event {
            ChangeEvent::NodeChanged(id) => {
                let acc = self.nodes.entry(id).or_default();
                // A removal dominates a change for the same node in a window.
                if !acc.removed {
                    acc.changed = true;
                }
            }
            ChangeEvent::NodeRemoved(id) => {
                let acc = self.nodes.entry(id).or_default();
                acc.removed = true;
                acc.changed = false;
                acc.seen = false;
                acc.online = None;
            }
            ChangeEvent::PolicyChanged => self.policy = true,
            ChangeEvent::DnsChanged => self.dns = true,
            ChangeEvent::DerpMapChanged => self.derp = true,
            ChangeEvent::OnlineChanged { node_id, online } => {
                let acc = self.nodes.entry(node_id).or_default();
                if !acc.removed {
                    acc.online = Some(online);
                }
            }
            ChangeEvent::PeerSeen(id) => {
                let acc = self.nodes.entry(id).or_default();
                if !acc.removed {
                    acc.seen = true;
                }
            }
        }
    }

    /// Number of distinct events the current accumulator would emit.
    fn count(&self) -> usize {
        let node_events: usize = self
            .nodes
            .values()
            .map(|n| {
                usize::from(n.removed || n.changed)
                    + usize::from(n.online.is_some())
                    + usize::from(n.seen)
            })
            .sum();
        node_events + usize::from(self.policy) + usize::from(self.dns) + usize::from(self.derp)
    }

    /// Take the accumulated state as an ordered, deduplicated batch.
    fn drain_batch(&mut self) -> ChangeBatch {
        let mut events = Vec::new();
        if self.policy {
            events.push(ChangeEvent::PolicyChanged);
            self.policy = false;
        }
        if self.dns {
            events.push(ChangeEvent::DnsChanged);
            self.dns = false;
        }
        if self.derp {
            events.push(ChangeEvent::DerpMapChanged);
            self.derp = false;
        }
        // BTreeMap iteration is by node id, so per-node events are delivered
        // in a stable, ascending id order.
        let nodes = std::mem::take(&mut self.nodes);
        for (node_id, acc) in nodes {
            if acc.removed {
                events.push(ChangeEvent::NodeRemoved(node_id));
                continue;
            }
            if acc.changed {
                events.push(ChangeEvent::NodeChanged(node_id));
            }
            if let Some(online) = acc.online {
                events.push(ChangeEvent::OnlineChanged { node_id, online });
            }
            if acc.seen {
                events.push(ChangeEvent::PeerSeen(node_id));
            }
        }
        ChangeBatch { events }
    }
}

/// The single owner of change coalescing for one control plane.
///
/// Publishers call [`ChangeBus::publish`]; a background sweeper (spawned by
/// [`ControlPlane::spawn_change_batcher`]) flushes the accumulated state every
/// batch window, and every live map session subscribes via
/// [`ChangeBus::subscribe`].
pub struct ChangeBus {
    pending: Mutex<Accumulator>,
    tx: tokio::sync::broadcast::Sender<ChangeBatch>,
    window: Duration,
    max_events: usize,
    sweeper_started: AtomicBool,
}

impl ChangeBus {
    /// Create an empty bus that coalesces for `window` and flushes early once
    /// `max_events` distinct events have accumulated.
    pub fn new(window: Duration, max_events: usize) -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(256);
        Self {
            pending: Mutex::new(Accumulator::default()),
            tx,
            window,
            max_events,
            sweeper_started: AtomicBool::new(false),
        }
    }

    /// The batch window this bus was configured with.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// The early-flush event count this bus was configured with.
    pub fn max_events(&self) -> usize {
        self.max_events
    }

    /// Publish a single change. If the accumulated count reaches the batch
    /// maximum, the bus flushes immediately.
    pub fn publish(&self, event: ChangeEvent) {
        let mut pending = self.pending.lock().unwrap();
        pending.apply(event);
        if pending.count() >= self.max_events {
            let batch = pending.drain_batch();
            drop(pending);
            self.broadcast(batch);
        }
    }

    /// Flush the accumulated changes now, broadcasting a batch if any events
    /// are pending.
    pub fn flush(&self) {
        let mut pending = self.pending.lock().unwrap();
        let batch = pending.drain_batch();
        drop(pending);
        self.broadcast(batch);
    }

    /// Number of distinct events currently accumulated (not yet flushed).
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().count()
    }

    fn broadcast(&self, batch: ChangeBatch) {
        if batch.is_empty() {
            return;
        }
        let _ = self.tx.send(batch);
    }

    /// Subscribe to coalesced change batches. Each batch is delivered to every
    /// subscriber; a lagging subscriber may observe a `Lagged` error and should
    /// fall back to a full refresh.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ChangeBatch> {
        self.tx.subscribe()
    }

    /// Spawn the background sweeper that flushes every `window`.
    ///
    /// At most one sweeper runs per bus; subsequent calls return `None`. The
    /// caller must be inside a Tokio runtime (the server spawns this from its
    /// housekeeping task).
    pub fn spawn_sweeper(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        if self.sweeper_started.swap(true, Ordering::SeqCst) {
            return None;
        }
        let this = self.clone();
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(this.window);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                this.flush();
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_duplicate_node_events_within_a_window() {
        let bus = ChangeBus::new(Duration::from_secs(10), 1024);
        let mut rx = bus.subscribe();

        bus.publish(ChangeEvent::NodeChanged(1));
        bus.publish(ChangeEvent::NodeChanged(1));
        bus.publish(ChangeEvent::PeerSeen(2));
        bus.publish(ChangeEvent::NodeChanged(1));
        bus.flush();

        let batch = rx.try_recv().unwrap();
        assert_eq!(
            batch.events,
            vec![ChangeEvent::NodeChanged(1), ChangeEvent::PeerSeen(2)],
            "duplicate node events must coalesce to a single event"
        );
        assert!(rx.try_recv().is_err(), "one batch per window");
    }

    #[test]
    fn removal_dominates_other_events_for_the_same_node() {
        let bus = ChangeBus::new(Duration::from_secs(10), 1024);
        let mut rx = bus.subscribe();

        bus.publish(ChangeEvent::OnlineChanged { node_id: 7, online: true });
        bus.publish(ChangeEvent::PeerSeen(7));
        bus.publish(ChangeEvent::NodeChanged(7));
        bus.publish(ChangeEvent::NodeRemoved(7));
        bus.flush();

        let batch = rx.try_recv().unwrap();
        assert_eq!(batch.events, vec![ChangeEvent::NodeRemoved(7)]);
    }

    #[test]
    fn global_events_precede_per_node_events_in_order() {
        let bus = ChangeBus::new(Duration::from_secs(10), 1024);
        let mut rx = bus.subscribe();

        bus.publish(ChangeEvent::NodeChanged(2));
        bus.publish(ChangeEvent::DerpMapChanged);
        bus.publish(ChangeEvent::DnsChanged);
        bus.publish(ChangeEvent::NodeChanged(1));
        bus.flush();

        let batch = rx.try_recv().unwrap();
        assert_eq!(
            batch.events,
            vec![
                ChangeEvent::DnsChanged,
                ChangeEvent::DerpMapChanged,
                ChangeEvent::NodeChanged(1),
                ChangeEvent::NodeChanged(2),
            ],
            "global events then per-node events ascending by id"
        );
    }

    #[test]
    fn empty_flush_produces_no_batch() {
        let bus = ChangeBus::new(Duration::from_secs(10), 1024);
        let mut rx = bus.subscribe();
        bus.flush();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn concurrent_changes_coalesce_without_duplicates_and_in_order() {
        let bus = Arc::new(ChangeBus::new(Duration::from_millis(10), 4096));
        let mut rx = bus.subscribe();

        // Eight threads hammer the same node ids: per-node coalescing must
        // collapse the burst into one NodeChanged and one PeerSeen per node,
        // delivered in ascending id order with no duplicates.
        let mut handles = Vec::new();
        for _ in 0..8 {
            let bus = bus.clone();
            handles.push(std::thread::spawn(move || {
                for i in 1..=200i64 {
                    bus.publish(ChangeEvent::NodeChanged(i));
                    bus.publish(ChangeEvent::PeerSeen(i));
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        bus.flush();

        let batch = rx.try_recv().expect("one coalesced batch");
        let changed: Vec<i64> = batch
            .events
            .iter()
            .filter_map(|e| match e {
                ChangeEvent::NodeChanged(id) => Some(*id),
                _ => None,
            })
            .collect();
        assert_eq!(changed.len(), 200, "one NodeChanged per node, no duplicates");
        assert!(
            changed.windows(2).all(|w| w[0] < w[1]),
            "NodeChanged ids must be delivered in ascending order"
        );

        let seen: Vec<i64> = batch
            .events
            .iter()
            .filter_map(|e| match e {
                ChangeEvent::PeerSeen(id) => Some(*id),
                _ => None,
            })
            .collect();
        assert_eq!(seen.len(), 200, "one PeerSeen per node, no duplicates");
        assert!(seen.windows(2).all(|w| w[0] < w[1]));
    }

    #[tokio::test]
    async fn sweeper_auto_flushes_deltas_after_batch_window() {
        let bus = Arc::new(ChangeBus::new(Duration::from_millis(20), 1024));
        let mut rx = bus.subscribe();
        let _handle = bus.spawn_sweeper().expect("sweeper starts");

        bus.publish(ChangeEvent::NodeChanged(1));
        let batch = tokio::time::timeout(Duration::from_millis(1000), rx.recv())
            .await
            .unwrap()
            .expect("batch broadcast within the window");
        assert_eq!(batch.events, vec![ChangeEvent::NodeChanged(1)]);

        // Nothing else pending means no further frames.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn max_events_triggers_early_flush() {
        let bus = ChangeBus::new(Duration::from_secs(10), 3);
        let mut rx = bus.subscribe();

        bus.publish(ChangeEvent::NodeChanged(1));
        bus.publish(ChangeEvent::NodeChanged(2));
        assert_eq!(bus.pending_count(), 2);

        // The third distinct event hits the maximum and flushes immediately.
        bus.publish(ChangeEvent::NodeChanged(3));
        assert_eq!(bus.pending_count(), 0);
        let batch = rx.try_recv().unwrap();
        assert_eq!(
            batch.events,
            vec![
                ChangeEvent::NodeChanged(1),
                ChangeEvent::NodeChanged(2),
                ChangeEvent::NodeChanged(3)
            ]
        );
    }
}
