//! Standalone Rust client test peer.
//!
//! Connects to a crabscale control server, registers with a pre-auth key,
//! requests a map, and logs out. Prints a short summary and exits non-zero on
//! any assertion failure.

use std::process::ExitCode;

use clap::Parser;
use crabscale_harness::{HarnessConfig, run_rust_peer};

/// Rust client test peer for the crabscale harness.
#[derive(Parser)]
#[command(name = "crabscale-peer", about = "Rust client test peer")]
struct Args {
    /// Control URL, e.g. http://127.0.0.1:8080.
    #[arg(long)]
    control_url: String,
    /// Pre-auth key used to register.
    #[arg(long, default_value = "hskey-auth-test-secret")]
    auth_key: String,
    /// Hostname reported to the server.
    #[arg(long, default_value = "rust-peer")]
    hostname: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let config = HarnessConfig {
        control_url: args.control_url,
        auth_key: args.auth_key,
        tailnet: "tailnet.example".to_string(),
        rust_peer_hostname: args.hostname,
        tailscale_binary: None,
        report_path: None,
    };
    match run_rust_peer(&config).await {
        Ok(report) => {
            println!(
                "registered={} ips={} peers={} logged_out={}",
                report.registered,
                report.assigned_ips.join(","),
                report.saw_peers,
                report.logged_out,
            );
            if report.registered && report.logged_out {
                ExitCode::SUCCESS
            } else {
                eprintln!("rust peer assertions failed");
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("rust peer failed: {e}");
            ExitCode::FAILURE
        }
    }
}
