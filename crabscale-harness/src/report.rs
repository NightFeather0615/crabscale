//! Markdown report generation for the harness.

use std::fmt::Write as _;

use crate::client::PeerReport;

/// A complete harness report.
#[derive(Clone, Debug, Default)]
pub struct HarnessReport {
    /// The control URL the server listened on.
    pub control_url: String,
    /// The tailnet domain used.
    pub tailnet: String,
    /// The pre-auth key used.
    pub auth_key: String,
    /// Capability version the Rust peer advertised (Spec-Compatibility §3).
    pub capability_version: u16,
    /// Results from the Rust client peer.
    pub rust_peer: Option<PeerReport>,
    /// Results from the Tailscale client, when run.
    pub tailscale: Option<TailscaleReport>,
}

/// Results from a Tailscale client run.
#[derive(Clone, Debug, Default)]
pub struct TailscaleReport {
    /// Whether the client registered successfully.
    pub registered: bool,
    /// Whether `tailscale status` showed the node online.
    pub status_ok: bool,
    /// Whether a peer ping succeeded.
    pub ping_ok: bool,
    /// Whether logout returned the node to needs-login.
    pub logged_out: bool,
    /// Raw output captured from the client.
    pub output: String,
}

/// Render the report as Markdown.
pub fn render_report(report: &HarnessReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# crabscale end-to-end client compatibility report");
    let _ = writeln!(out);
    let _ = writeln!(out, "## Environment");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Control URL: `{}`", report.control_url);
    let _ = writeln!(out, "- Tailnet: `{}`", report.tailnet);
    let _ = writeln!(out, "- Pre-auth key: `{}`", report.auth_key);
    let _ = writeln!(out, "- Capability version: `{}`", report.capability_version);
    let _ = writeln!(out);

    let _ = writeln!(out, "## Rust client test peer");
    let _ = writeln!(out);
    match &report.rust_peer {
        Some(peer) => {
            let _ = writeln!(out, "- Registered: {}", yes_no(peer.registered));
            let _ = writeln!(out, "- Assigned IPs: {}", peer.assigned_ips.join(", "));
            let _ = writeln!(out, "- Saw peer list: {}", yes_no(peer.saw_peers));
            let _ = writeln!(
                out,
                "- MagicDNS suffix: {}",
                empty_dash(&peer.magic_dns_suffix)
            );
            let _ = writeln!(out, "- MagicDNS proxied: {}", yes_no(peer.dns_proxied));
            let _ = writeln!(
                out,
                "- Split-DNS suffixes: {}",
                if peer.split_dns_suffixes.is_empty() {
                    "-".to_string()
                } else {
                    peer.split_dns_suffixes.join(", ")
                }
            );
            let _ = writeln!(
                out,
                "- Search domains: {}",
                if peer.search_domains.is_empty() {
                    "-".to_string()
                } else {
                    peer.search_domains.join(", ")
                }
            );
            let _ = writeln!(out, "- Logged out: {}", yes_no(peer.logged_out));
            if !peer.notes.is_empty() {
                let _ = writeln!(out);
                let _ = writeln!(out, "### Notes");
                for note in &peer.notes {
                    let _ = writeln!(out, "- {note}");
                }
            }
        }
        None => {
            let _ = writeln!(out, "- Not run.");
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Tailscale client");
    let _ = writeln!(out);
    match &report.tailscale {
        Some(ts) => {
            let _ = writeln!(out, "- Registered: {}", yes_no(ts.registered));
            let _ = writeln!(out, "- Status OK: {}", yes_no(ts.status_ok));
            let _ = writeln!(out, "- Peer ping OK: {}", yes_no(ts.ping_ok));
            let _ = writeln!(out, "- Logged out: {}", yes_no(ts.logged_out));
            if !ts.output.is_empty() {
                let _ = writeln!(out);
                let _ = writeln!(out, "### Captured output");
                let _ = writeln!(out, "```text");
                let _ = writeln!(out, "{}", ts.output);
                let _ = writeln!(out, "```");
            }
        }
        None => {
            let _ = writeln!(out, "- Not run (no Tailscale binary configured).");
        }
    }
    let _ = writeln!(out);

    out
}

/// Write the report to a file, or print to stdout when `path` is `None`.
pub fn emit_report(report: &HarnessReport, path: Option<&str>) -> Result<(), String> {
    let rendered = render_report(report);
    match path {
        Some(path) => {
            std::fs::write(path, rendered).map_err(|e| format!("write report failed: {e}"))
        }
        None => {
            println!("{rendered}");
            Ok(())
        }
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn empty_dash(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}
