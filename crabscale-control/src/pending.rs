//! Interactive registration pending cache.
//!
//! When a client registers without a valid pre-auth key, the control plane
//! creates an unguessable auth id and stores the registration request in a
//! bounded, TTL'd cache. An administrator approves or rejects the pending
//! entry through the CLI or the control API; the client long-polls the
//! followup URL until a verdict is available.

use std::collections::{HashMap, VecDeque};

use crabscale_proto::{Hostinfo, MachineKey, NodeKey};

/// Default time-to-live for a pending interactive registration.
pub const DEFAULT_PENDING_TTL_SECONDS: i64 = 15 * 60;

/// Default maximum number of pending registrations kept in memory.
pub const DEFAULT_PENDING_CACHE_LIMIT: usize = 1024;

/// A pending interactive registration awaiting an admin verdict.
#[derive(Clone, Debug)]
pub struct PendingRegistration {
    /// Unguessable identifier embedded in the AuthURL.
    pub auth_id: String,
    /// The Noise machine key that started the registration.
    pub machine_key: MachineKey,
    /// The node key being registered.
    pub node_key: NodeKey,
    /// Host metadata supplied by the client.
    pub hostinfo: Option<Hostinfo>,
    /// Client-requested expiry, if any.
    pub expiry: String,
    /// Client capability version.
    pub version: u32,
    /// Whether the client requested an ephemeral node.
    pub ephemeral: bool,
    /// When the pending entry was created.
    pub created_at: String,
    /// When the pending entry expires.
    pub expires_at: String,
    /// Current admin verdict.
    pub verdict: PendingVerdict,
}

/// The admin verdict for a pending registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingVerdict {
    /// No decision has been made yet.
    Pending,
    /// The registration was approved for the given user.
    Approved {
        /// User id that owns the resulting node.
        user_id: i64,
        /// Optional tags applied to the node.
        tags: Option<Vec<String>>,
    },
    /// The registration was rejected.
    Rejected,
}

/// A bounded LRU cache of pending registrations keyed by auth id.
pub struct PendingCache {
    entries: HashMap<String, PendingRegistration>,
    order: VecDeque<String>,
    limit: usize,
}

impl PendingCache {
    /// Create an empty cache with the given maximum number of entries.
    pub fn new(limit: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            limit,
        }
    }

    /// Insert a pending registration, evicting the least-recently-used entry
    /// when the cache exceeds its bound.
    pub fn insert(&mut self, entry: PendingRegistration) {
        let auth_id = entry.auth_id.clone();
        if let Some(old) = self.entries.get_mut(&auth_id) {
            *old = entry;
            self.touch(&auth_id);
            return;
        }
        if self.entries.len() >= self.limit {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(auth_id.clone());
        self.entries.insert(auth_id, entry);
    }

    /// Look up a pending registration, marking it most-recently-used.
    pub fn get(&mut self, auth_id: &str) -> Option<&PendingRegistration> {
        if self.entries.contains_key(auth_id) {
            self.touch(auth_id);
        }
        self.entries.get(auth_id)
    }

    /// Look up a pending registration mutably, marking it most-recently-used.
    pub fn get_mut(&mut self, auth_id: &str) -> Option<&mut PendingRegistration> {
        if self.entries.contains_key(auth_id) {
            self.touch(auth_id);
        }
        self.entries.get_mut(auth_id)
    }

    /// Remove and return a pending registration, if present.
    pub fn remove(&mut self, auth_id: &str) -> Option<PendingRegistration> {
        let entry = self.entries.remove(auth_id)?;
        self.order.retain(|id| id != auth_id);
        Some(entry)
    }

    /// Number of entries currently cached.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn touch(&mut self, auth_id: &str) {
        if let Some(pos) = self.order.iter().position(|id| id == auth_id) {
            let id = self.order.remove(pos).unwrap();
            self.order.push_back(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str) -> PendingRegistration {
        PendingRegistration {
            auth_id: id.to_string(),
            machine_key: MachineKey::from_bytes([0x11; 32]),
            node_key: NodeKey::from_bytes([0x22; 32]),
            hostinfo: None,
            expiry: String::new(),
            version: 130,
            ephemeral: false,
            created_at: "2026-08-20T00:00:00Z".to_string(),
            expires_at: "2026-08-20T00:15:00Z".to_string(),
            verdict: PendingVerdict::Pending,
        }
    }

    #[test]
    fn cache_evicts_least_recently_used() {
        let mut cache = PendingCache::new(2);
        cache.insert(entry("a"));
        cache.insert(entry("b"));
        cache.insert(entry("c"));
        assert_eq!(cache.len(), 2);
        assert!(cache.get("a").is_none());
        assert!(cache.get("b").is_some());
        assert!(cache.get("c").is_some());
    }

    #[test]
    fn get_touches_lru_order() {
        let mut cache = PendingCache::new(2);
        cache.insert(entry("a"));
        cache.insert(entry("b"));
        // Touching "a" makes "b" the least-recently-used.
        assert!(cache.get("a").is_some());
        cache.insert(entry("c"));
        assert!(cache.get("a").is_some());
        assert!(cache.get("b").is_none());
        assert!(cache.get("c").is_some());
    }

    #[test]
    fn remove_drops_entry() {
        let mut cache = PendingCache::new(2);
        cache.insert(entry("a"));
        assert!(cache.remove("a").is_some());
        assert!(cache.is_empty());
    }
}
