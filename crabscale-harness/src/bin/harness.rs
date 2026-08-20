//! End-to-end client compatibility harness orchestrator.
//!
//! Starts a crabscale control server on localhost, runs the Rust client test
//! peer, optionally runs a stable Tailscale client binary, and emits a
//! Markdown report.

use std::process::ExitCode;

use clap::Parser;
use crabscale_harness::{
    HarnessConfig, HarnessReport, TailscaleReport, emit_report, run_rust_peer, start_server,
};

/// End-to-end client compatibility harness.
#[derive(Parser)]
#[command(
    name = "crabscale-harness",
    about = "crabscale client compatibility harness"
)]
struct Args {
    /// Path to a Tailscale client binary to exercise (optional).
    #[arg(long)]
    tailscale_binary: Option<String>,
    /// Path to write the Markdown report (defaults to stdout).
    #[arg(long)]
    report: Option<String>,
    /// Pre-auth key used by clients.
    #[arg(long, default_value = "hskey-auth-test-secret")]
    auth_key: String,
    /// Tailnet domain advertised by the server.
    #[arg(long, default_value = "tailnet.example")]
    tailnet: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let mut config = HarnessConfig::ephemeral();
    config.auth_key = args.auth_key;
    config.tailnet = args.tailnet;
    config.tailscale_binary = args.tailscale_binary.clone();
    config.report_path = args.report.clone();

    let server = match start_server(&config).await {
        Ok(server) => server,
        Err(e) => {
            eprintln!("failed to start server: {e}");
            return ExitCode::FAILURE;
        }
    };
    config.control_url = format!("http://{}", server.addr);

    let mut report = HarnessReport {
        control_url: config.control_url.clone(),
        tailnet: config.tailnet.clone(),
        auth_key: config.auth_key.clone(),
        ..Default::default()
    };

    // Run the Rust client test peer.
    match run_rust_peer(&config).await {
        Ok(peer) => {
            report.rust_peer = Some(peer);
        }
        Err(e) => {
            eprintln!("rust peer failed: {e}");
            report.rust_peer = Some(crabscale_harness::PeerReport {
                registered: false,
                logged_out: false,
                notes: vec![format!("rust peer failed: {e}")],
                ..Default::default()
            });
        }
    }

    // Optionally run the Tailscale client binary.
    if let Some(binary) = &config.tailscale_binary {
        match run_tailscale(binary, &config) {
            Ok(ts) => report.tailscale = Some(ts),
            Err(e) => {
                eprintln!("tailscale client failed: {e}");
                report.tailscale = Some(TailscaleReport {
                    output: format!("failed: {e}"),
                    ..Default::default()
                });
            }
        }
    }

    // Stop accepting new connections; the report is complete.
    server.shutdown();

    if let Err(e) = emit_report(&report, config.report_path.as_deref()) {
        eprintln!("failed to emit report: {e}");
        return ExitCode::FAILURE;
    }

    let ok = report
        .rust_peer
        .as_ref()
        .map(|p| p.registered && p.logged_out)
        .unwrap_or(false);
    // The background reaper and any lingering connection tasks keep the tokio
    // runtime alive, so exit explicitly once the report has been emitted.
    std::process::exit(if ok { 0 } else { 1 });
}

/// Run a Tailscale client binary against the harness server.
fn run_tailscale(binary: &str, config: &HarnessConfig) -> Result<TailscaleReport, String> {
    use std::process::Command;

    let mut report = TailscaleReport::default();
    let control = config.control_url.trim_start_matches("http://");

    // 1. Login with the pre-auth key.
    let login = Command::new(binary)
        .args([
            "--login-server",
            control,
            "up",
            "--authkey",
            &config.auth_key,
        ])
        .output()
        .map_err(|e| format!("failed to run tailscale up: {e}"))?;
    report.registered = login.status.success();
    report
        .output
        .push_str(&String::from_utf8_lossy(&login.stdout));
    report
        .output
        .push_str(&String::from_utf8_lossy(&login.stderr));

    // 2. Status.
    let status = Command::new(binary)
        .args(["status"])
        .output()
        .map_err(|e| format!("failed to run tailscale status: {e}"))?;
    report.status_ok = status.status.success();
    report
        .output
        .push_str(&String::from_utf8_lossy(&status.stdout));

    // 3. Logout.
    let logout = Command::new(binary)
        .args(["logout"])
        .output()
        .map_err(|e| format!("failed to run tailscale logout: {e}"))?;
    report.logged_out = logout.status.success();
    report
        .output
        .push_str(&String::from_utf8_lossy(&logout.stdout));

    Ok(report)
}
