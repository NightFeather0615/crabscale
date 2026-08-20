//! End-to-end client compatibility harness.
//!
//! This crate starts a crabscale control server on localhost, runs a Rust
//! client test peer (and optionally a stable Tailscale client binary), and
//! emits a Markdown report of the results. It is the M1-07 integration
//! harness described in the project wiki.

pub mod client;
pub mod config;
pub mod report;
pub mod server;

pub use client::{PeerReport, run_rust_peer};
pub use config::{DEFAULT_TAILNET, HarnessConfig};
pub use report::{HarnessReport, TailscaleReport, emit_report};
pub use server::start_server;
