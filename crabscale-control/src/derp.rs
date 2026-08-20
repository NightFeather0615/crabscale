//! DERP map state: the configured relay regions and change notifications.
//!
//! The DERP map is part of the control-plane configuration, but the map can
//! be replaced at runtime (for example to add an embedded region after the
//! relay's public address is known). This module owns the clone-safe
//! snapshot plus a revision broadcast so every live map session can learn
//! about a DERP map change and push a `DERPMap` delta frame
//! (Spec-NetMap §3/§4, Spec-DERP-STUN §7).

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crabscale_proto::DerpMap;

/// Shared, clone-safe DERP map state owned by the control plane.
///
/// The map snapshot lives here so a runtime replacement swaps it without
/// rebuilding the control plane, and the revision broadcast lets every live
/// map session push a delta frame to its client.
#[derive(Debug)]
pub(crate) struct DerpMapState {
    map: Mutex<DerpMap>,
    revision: AtomicU64,
    changed: tokio::sync::broadcast::Sender<u64>,
}

impl DerpMapState {
    /// Create state seeded with `map` at revision 0.
    pub(crate) fn new(map: DerpMap) -> Self {
        let (changed, _) = tokio::sync::broadcast::channel(16);
        Self {
            map: Mutex::new(map),
            revision: AtomicU64::new(0),
            changed,
        }
    }

    /// Atomically replace the map snapshot and broadcast a new revision.
    /// Returns the new revision number.
    pub(crate) fn set_map(&self, map: DerpMap) -> u64 {
        *self.map.lock().expect("derp map state mutex poisoned") = map;
        let revision = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.changed.send(revision);
        revision
    }

    /// Snapshot of the current DERP map.
    pub(crate) fn map(&self) -> DerpMap {
        self.map
            .lock()
            .expect("derp map state mutex poisoned")
            .clone()
    }

    /// Current DERP map revision (0 = the startup configuration, before any
    /// runtime replacement).
    pub(crate) fn revision(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    /// Subscribe to DERP map revisions. The receiver yields a new revision
    /// for every successful runtime replacement.
    pub(crate) fn subscribe(&self) -> tokio::sync::broadcast::Receiver<u64> {
        self.changed.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_bumps_and_broadcasts() {
        let state = DerpMapState::new(DerpMap::default());
        let mut rx = state.subscribe();
        assert_eq!(state.revision(), 0);

        let mut map = DerpMap::default();
        map.regions.insert(
            "900".to_string(),
            crabscale_proto::DerpRegion {
                region_id: 900,
                region_code: "crab".to_string(),
                region_name: "Crabscale".to_string(),
                ..Default::default()
            },
        );
        let revision = state.set_map(map.clone());
        assert_eq!(revision, 1);
        assert_eq!(state.revision(), 1);
        assert_eq!(rx.try_recv().unwrap(), 1);
        assert_eq!(state.map(), map);
    }
}
