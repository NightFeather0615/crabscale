//! Configuration for the end-to-end client compatibility harness.

use std::net::SocketAddr;

/// Default tailnet domain advertised by the control plane.
pub const DEFAULT_TAILNET: &str = "tailnet.example";

/// Configuration for a harness run.
#[derive(Clone, Debug)]
pub struct HarnessConfig {
    /// The control URL the server listens on, e.g. `http://127.0.0.1:8080`.
    pub control_url: String,
    /// The pre-auth key clients use to register.
    pub auth_key: String,
    /// The tailnet domain advertised to clients.
    pub tailnet: String,
    /// Hostname used by the Rust test peer.
    pub rust_peer_hostname: String,
    /// Capability version the Rust peer advertises (Spec-Compatibility §3).
    /// Defaults to the latest stable serialized by the peer.
    pub capability_version: u16,
    /// Optional path to the Tailscale client binary.
    pub tailscale_binary: Option<String>,
    /// Optional path to write the Markdown report.
    pub report_path: Option<String>,
}

impl HarnessConfig {
    /// Build a config that binds the server to an ephemeral localhost port.
    pub fn ephemeral() -> Self {
        Self {
            control_url: "http://127.0.0.1:0".to_string(),
            auth_key: crabscale_control::ControlConfig::default().auth_key,
            tailnet: DEFAULT_TAILNET.to_string(),
            rust_peer_hostname: "rust-peer".to_string(),
            capability_version: crate::client::DEFAULT_CAPABILITY_VERSION,
            tailscale_binary: None,
            report_path: None,
        }
    }

    /// The host and port of the control URL.
    pub fn addr(&self) -> SocketAddr {
        let rest = self
            .control_url
            .strip_prefix("http://")
            .expect("control URL must be http://");
        let (host, port) = rest
            .rsplit_once(':')
            .expect("control URL must include a port");
        let port: u16 = port.parse().expect("control URL port must be numeric");
        let host = if host.is_empty() { "127.0.0.1" } else { host };
        format!("{host}:{port}")
            .parse()
            .expect("control URL must be a valid socket address")
    }
}
