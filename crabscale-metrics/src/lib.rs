//! Process-wide Prometheus metrics for Crabscale.
//!
//! This crate is the single seam through which the control plane and the DERP
//! relay record operational counters and gauges, and through which the server
//! renders them at `GET /metrics` in the Prometheus text exposition format.
//!
//! The registry is intentionally a process-global singleton:
//!
//! - Counters are recorded deep inside crate boundaries (`crabscale-control`
//!   session/registration/policy paths and `crabscale-derp` packet routing),
//!   so a global handle avoids threading a registry through every call site.
//! - All families are registered up front, so `GET /metrics` always renders
//!   them (including `0` values) even on paths that have not fired yet.
//!
//! Counters and gauges use lock-free atomics, so protocol paths never block
//! on observability. The Prometheus label set is deliberately empty: v0.1 has
//! a single tailnet and a single embedded relay, and each metric's name
//! already encodes the component.

use std::fmt::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// A monotonic, never-decreasing integer counter.
///
/// Rendered with Prometheus type `counter`.
pub struct Counter {
    name: &'static str,
    help: &'static str,
    value: AtomicU64,
}

impl Counter {
    const fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            value: AtomicU64::new(0),
        }
    }

    /// Increment the counter by one.
    pub fn inc(&self) {
        self.inc_by(1);
    }

    /// Increment the counter by `n`.
    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Read the current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    fn render(&self, out: &mut String) {
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} counter", self.name);
        let _ = writeln!(out, "{} {}", self.name, self.get());
    }
}

/// A value that can go up and down.
///
/// Rendered with Prometheus type `gauge`.
pub struct Gauge {
    name: &'static str,
    help: &'static str,
    value: AtomicU64,
}

impl Gauge {
    const fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            value: AtomicU64::new(0),
        }
    }

    /// Set the gauge to an absolute value.
    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    /// Add a delta to the gauge.
    pub fn add(&self, delta: i64) {
        let mut current = self.value.load(Ordering::Relaxed);
        loop {
            let next = (current as i128 + delta as i128).max(0) as u64;
            match self.value.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    /// Read the current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    fn render(&self, out: &mut String) {
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} gauge", self.name);
        let _ = writeln!(out, "{} {}", self.name, self.get());
    }
}

/// The set of operational metrics Crabscale exposes.
pub struct Metrics {
    /// Number of live control-plane map sessions (gauge).
    pub sessions_active: Gauge,
    /// Total control-plane map sessions opened (counter).
    pub sessions_opened_total: Counter,
    /// Total control-plane map sessions closed (counter).
    pub sessions_closed_total: Counter,
    /// Total registration requests processed by the control plane (counter).
    pub registrations_total: Counter,
    /// Total policy compilations performed by the control plane (counter).
    pub policy_compiles_total: Counter,
    /// Total DERP packets relayed between clients (counter).
    pub derp_packets_total: Counter,
    /// Total DERP packets dropped (e.g. oversize payload) (counter).
    pub derp_packets_dropped_total: Counter,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Access the process-wide metrics registry.
pub fn registry() -> &'static Metrics {
    METRICS.get_or_init(|| Metrics {
        sessions_active: Gauge::new(
            "crabscale_sessions_active",
            "Number of live control-plane map sessions.",
        ),
        sessions_opened_total: Counter::new(
            "crabscale_sessions_opened_total",
            "Total control-plane map sessions opened.",
        ),
        sessions_closed_total: Counter::new(
            "crabscale_sessions_closed_total",
            "Total control-plane map sessions closed.",
        ),
        registrations_total: Counter::new(
            "crabscale_registrations_total",
            "Total registration requests processed by the control plane.",
        ),
        policy_compiles_total: Counter::new(
            "crabscale_policy_compiles_total",
            "Total policy compilations performed by the control plane.",
        ),
        derp_packets_total: Counter::new(
            "crabscale_derp_packets_total",
            "Total DERP packets relayed between clients.",
        ),
        derp_packets_dropped_total: Counter::new(
            "crabscale_derp_packets_dropped_total",
            "Total DERP packets dropped by the relay (e.g. oversize payload).",
        ),
    })
}

/// Render every registered metric in the Prometheus text exposition format.
///
/// The output contains a trailing newline so a plain-text handler can return it
/// as-is with `content-type: text/plain; version=0.0.4; charset=utf-8`.
pub fn render_prometheus() -> String {
    let metrics = registry();
    let mut out = String::new();
    metrics.sessions_opened_total.render(&mut out);
    metrics.sessions_closed_total.render(&mut out);
    metrics.sessions_active.render(&mut out);
    metrics.registrations_total.render(&mut out);
    metrics.policy_compiles_total.render(&mut out);
    metrics.derp_packets_total.render(&mut out);
    metrics.derp_packets_dropped_total.render(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment_atomically() {
        let counter = Counter::new("test_counter_total", "test counter");
        assert_eq!(counter.get(), 0);
        counter.inc();
        counter.inc_by(4);
        assert_eq!(counter.get(), 5);
    }

    #[test]
    fn gauge_sets_and_never_goes_negative() {
        let gauge = Gauge::new("test_gauge", "test gauge");
        gauge.set(3);
        assert_eq!(gauge.get(), 3);
        gauge.add(-10);
        assert_eq!(gauge.get(), 0, "gauge clamps at zero");
        gauge.add(2);
        assert_eq!(gauge.get(), 2);
    }

    #[test]
    fn render_emits_all_families_in_text_format() {
        let text = render_prometheus();
        for family in [
            "crabscale_sessions_opened_total",
            "crabscale_sessions_closed_total",
            "crabscale_sessions_active",
            "crabscale_registrations_total",
            "crabscale_policy_compiles_total",
            "crabscale_derp_packets_total",
            "crabscale_derp_packets_dropped_total",
        ] {
            assert!(
                text.contains(&format!("# TYPE {family} counter"))
                    || text.contains(&format!("# TYPE {family} gauge")),
                "missing type for {family}"
            );
            assert!(
                text.contains(&format!("\n{family} ")),
                "missing sample {family}"
            );
        }
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn families_are_shared_and_mutable_through_registry() {
        let metrics = registry();
        let before = metrics.registrations_total.get();
        metrics.registrations_total.inc();
        assert_eq!(metrics.registrations_total.get(), before + 1);
    }
}
