//! Session lifecycle for the control plane.
//!
//! A node is considered online while it has at least one live map session.
//! Session counts are owned by a single [`SessionRegistry`] so that
//! connect/disconnect races are resolved in one place. When the last session
//! for a node closes, the offline transition is delayed by a reconnect grace
//! period; a session that reconnects inside that window cancels the pending
//! offline transition without emitting an offline/online flap. Ephemeral
//! nodes are only garbage-collected after their last session ends and the
//! same grace period has elapsed.

use std::collections::HashMap;

/// Default reconnect grace in seconds before a node is marked offline.
pub const DEFAULT_RECONNECT_GRACE_SECONDS: i64 = 10;

/// An event produced by the session registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// A node transitioned to online.
    Online(i64),
    /// A node transitioned to offline after the reconnect grace elapsed.
    Offline(i64),
    /// An ephemeral node's grace period elapsed and it should be deleted.
    EphemeralExpired(i64),
}

/// Per-node session bookkeeping.
#[derive(Debug)]
struct NodeSessions {
    live: usize,
    online: bool,
    offline_at: Option<i64>,
    ephemeral: bool,
}

/// The single owner of live map session counts.
#[derive(Debug)]
pub struct SessionRegistry {
    grace_seconds: i64,
    next_session_id: i64,
    nodes: HashMap<i64, NodeSessions>,
    session_to_node: HashMap<i64, i64>,
}

impl SessionRegistry {
    /// Create an empty registry with the given reconnect grace in seconds.
    pub fn new(grace_seconds: i64) -> Self {
        Self {
            grace_seconds,
            next_session_id: 1,
            nodes: HashMap::new(),
            session_to_node: HashMap::new(),
        }
    }

    /// Open a new live map session for `node_id`.
    ///
    /// Returns the new session id and any online/offline transitions that
    /// result. Reconnecting inside the grace window cancels a pending offline
    /// transition without emitting an offline/online flap.
    pub fn open(&mut self, node_id: i64, ephemeral: bool, now: i64) -> (i64, Vec<SessionEvent>) {
        let session_id = self.next_session_id;
        self.next_session_id += 1;

        let mut events = Vec::new();
        let entry = self.nodes.entry(node_id).or_insert(NodeSessions {
            live: 0,
            online: false,
            offline_at: None,
            ephemeral,
        });
        // `ephemeral` is refreshed on every open; today it always matches the
        // stored node's flag, but keeping it in sync here means a node whose
        // ephemeral status changes is handled correctly on the next session.
        entry.ephemeral = ephemeral;

        if entry.live == 0 {
            if let Some(at) = entry.offline_at.take() {
                if now >= at {
                    // The grace period already elapsed; the node was offline.
                    if entry.online {
                        entry.online = false;
                        events.push(SessionEvent::Offline(node_id));
                    }
                }
                // If now < at, the reconnect landed inside the grace window and
                // the pending offline transition is simply cancelled.
            }
            if !entry.online {
                entry.online = true;
                events.push(SessionEvent::Online(node_id));
            }
        }

        entry.live += 1;
        self.session_to_node.insert(session_id, node_id);
        (session_id, events)
    }

    /// Close a live map session by id.
    ///
    /// Closing the last session schedules an offline transition after the
    /// reconnect grace period; no offline event is emitted yet.
    pub fn close(&mut self, session_id: i64, now: i64) -> Vec<SessionEvent> {
        let Some(node_id) = self.session_to_node.remove(&session_id) else {
            return Vec::new();
        };
        let events = Vec::new();
        if let Some(entry) = self.nodes.get_mut(&node_id) {
            entry.live = entry.live.saturating_sub(1);
            if entry.live == 0 {
                entry.offline_at = Some(now + self.grace_seconds);
            }
        }
        events
    }

    /// Advance the registry to `now`, emitting offline transitions and
    /// ephemeral expiry events whose grace period has elapsed.
    pub fn tick(&mut self, now: i64) -> Vec<SessionEvent> {
        let mut events = Vec::new();
        let mut expired = Vec::new();

        for (&node_id, entry) in self.nodes.iter_mut() {
            if entry.live != 0 {
                continue;
            }
            let Some(at) = entry.offline_at else {
                continue;
            };
            if now < at {
                continue;
            }
            if entry.online {
                entry.online = false;
                events.push(SessionEvent::Offline(node_id));
            }
            entry.offline_at = None;
            if entry.ephemeral {
                events.push(SessionEvent::EphemeralExpired(node_id));
                expired.push(node_id);
            }
        }

        for node_id in expired {
            self.nodes.remove(&node_id);
        }
        events
    }

    /// Whether the node currently has a live session or is inside its
    /// reconnect grace window.
    pub fn is_online(&self, node_id: i64) -> bool {
        self.nodes.get(&node_id).map(|e| e.online).unwrap_or(false)
    }

    /// Number of live sessions currently open for a node.
    pub fn live_sessions(&self, node_id: i64) -> usize {
        self.nodes.get(&node_id).map(|e| e.live).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn losing_one_of_two_sessions_keeps_node_online() {
        let mut registry = SessionRegistry::new(10);
        let (s1, events) = registry.open(1, false, 100);
        assert!(events.contains(&SessionEvent::Online(1)));
        let (_s2, events) = registry.open(1, false, 101);
        assert!(events.is_empty());

        assert!(registry.is_online(1));
        assert_eq!(registry.live_sessions(1), 2);

        let events = registry.close(s1, 102);
        assert!(events.is_empty());
        assert!(registry.is_online(1));
        assert_eq!(registry.live_sessions(1), 1);

        // The node stays online even after the grace period would have elapsed
        // for the first session, because a second session is still live.
        let events = registry.tick(200);
        assert!(events.is_empty());
        assert!(registry.is_online(1));
    }

    #[test]
    fn rapid_reconnect_does_not_emit_offline_online_flap() {
        let mut registry = SessionRegistry::new(10);
        let (s1, _) = registry.open(1, false, 100);
        let (s2, _) = registry.open(1, false, 101);

        // Close both sessions; offline is scheduled 10s after the last close.
        registry.close(s1, 102);
        registry.close(s2, 103);
        assert!(registry.is_online(1));

        // Reconnect inside the grace window: no offline/online flap.
        let (s3, events) = registry.open(1, false, 105);
        assert!(events.is_empty());
        assert!(registry.is_online(1));

        // Even after the original grace deadline passes, the node is still
        // online because the reconnect cancelled the pending offline.
        let events = registry.tick(200);
        assert!(events.is_empty());
        assert!(registry.is_online(1));

        // Closing the new session eventually schedules offline again.
        registry.close(s3, 201);
        assert!(registry.tick(210).is_empty());
        assert_eq!(registry.tick(211), vec![SessionEvent::Offline(1)]);
        assert!(!registry.is_online(1));
    }

    #[test]
    fn offline_is_delayed_until_grace_elapses() {
        let mut registry = SessionRegistry::new(10);
        let (s1, _) = registry.open(1, false, 100);
        registry.close(s1, 101);

        // Before the grace elapses the node is still online.
        assert!(registry.is_online(1));
        assert!(registry.tick(110).is_empty());
        assert!(registry.is_online(1));

        // At the grace deadline the offline transition is emitted.
        assert_eq!(registry.tick(111), vec![SessionEvent::Offline(1)]);
        assert!(!registry.is_online(1));
    }

    #[test]
    fn ephemeral_node_is_deleted_after_last_session_and_grace() {
        let mut registry = SessionRegistry::new(10);
        let (s1, _) = registry.open(1, true, 100);
        let (s2, _) = registry.open(1, true, 101);

        // A live session cancels ephemeral GC.
        registry.close(s1, 102);
        assert!(registry.tick(200).is_empty());
        assert!(registry.is_online(1));

        // After the last session closes and the grace elapses, the ephemeral
        // node expires.
        registry.close(s2, 201);
        assert!(registry.tick(210).is_empty());
        assert_eq!(
            registry.tick(211),
            vec![SessionEvent::Offline(1), SessionEvent::EphemeralExpired(1)]
        );
        assert!(!registry.is_online(1));
        assert_eq!(registry.live_sessions(1), 0);
    }
}
