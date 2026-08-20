//! Server binary: wiring, config, HTTP serving, and shutdown.
//!
//! This milestone starts the outer HTTP control server (`/key`, `/ts2021`,
//! and the `/register/{id}` approval page) with a parsed CLI config and runs
//! it until shutdown (Ctrl-C).

use std::process::ExitCode;

use clap::Parser;
use crabscale_control::{ControlConfig, ControlPlane, DnsSettings};
use crabscale_server::{
    ControlRouter, DEFAULT_KEY_FILE, load_or_create_machine_key, serve_on_addr,
};

/// Default address the outer HTTP server listens on.
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";

/// crabscale control server.
#[derive(Parser)]
#[command(name = "crabscale-server", about = "crabscale control server")]
struct Args {
    /// Address the outer HTTP server listens on.
    #[arg(long, default_value = DEFAULT_LISTEN_ADDR)]
    listen: std::net::SocketAddr,

    /// Path to the server machine key file.
    #[arg(long, default_value = DEFAULT_KEY_FILE)]
    key_file: std::path::PathBuf,

    /// Path to the SQLite database file; an in-memory store is used when omitted.
    #[arg(long)]
    store: Option<std::path::PathBuf>,

    /// Pre-auth key accepted for bootstrap registration.
    #[arg(long)]
    auth_key: Option<String>,

    /// Tailnet domain advertised to clients.
    #[arg(long)]
    tailnet_domain: Option<String>,

    /// Base URL used to build interactive registration AuthURLs.
    #[arg(long)]
    server_url: Option<String>,

    /// Disable MagicDNS. Split DNS and search domains are still delivered.
    #[arg(long)]
    no_magic_dns: bool,

    /// Additional DNS search domain (no trailing dot). Repeatable.
    #[arg(long)]
    dns_search_domain: Vec<String>,

    /// Split-DNS rule as `suffix=resolver-address` (suffix includes the
    /// trailing dot). Repeatable.
    #[arg(long)]
    dns_split: Vec<String>,

    /// JSON file of extra DNS records to inject into the MagicDNS zone;
    /// re-read at runtime for hot reload.
    #[arg(long)]
    dns_extra_records: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Build the control plane configuration from CLI arguments.
fn control_config(args: &Args) -> ControlConfig {
    let defaults = ControlConfig::default();
    let mut split_dns = std::collections::BTreeMap::new();
    for rule in &args.dns_split {
        let Some((suffix, addr)) = rule.split_once('=') else {
            continue;
        };
        split_dns
            .entry(suffix.to_string())
            .or_insert_with(Vec::new)
            .push(addr.to_string());
    }
    let dns = DnsSettings {
        magic_dns: !args.no_magic_dns,
        search_domains: args.dns_search_domain.clone(),
        split_dns,
        extra_records_path: args.dns_extra_records.clone(),
        ..Default::default()
    };
    ControlConfig {
        auth_key: args
            .auth_key
            .clone()
            .unwrap_or_else(|| defaults.auth_key.clone()),
        tailnet_domain: args
            .tailnet_domain
            .clone()
            .unwrap_or_else(|| defaults.tailnet_domain.clone()),
        server_url: args
            .server_url
            .clone()
            .unwrap_or_else(|| defaults.server_url.clone()),
        dns,
        ..defaults
    }
}

/// Load the machine key, build the control plane and router, and serve the
/// outer HTTP endpoints until a shutdown signal arrives.
async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let server_key = load_or_create_machine_key(&args.key_file)?;

    let config = control_config(&args);
    let control = match &args.store {
        Some(path) => ControlPlane::open_sqlite(config, path)?,
        None => ControlPlane::try_new(config)?,
    };
    let router = ControlRouter::with_control(server_key.public_key(), control);
    router.spawn_reaper();

    let (addr, handle) = serve_on_addr(args.listen, router, server_key.clone()).await?;

    println!("server machine key: {}", server_key.public_key());
    println!("key file: {}", args.key_file.display());
    println!("control server listening on http://{addr}");

    tokio::signal::ctrl_c().await?;
    handle.shutdown();
    println!("shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_default_key_file_and_listen_addr() {
        let args = Args::try_parse_from(["crabscale-server"]).unwrap();
        assert_eq!(args.key_file, std::path::PathBuf::from(DEFAULT_KEY_FILE));
        assert_eq!(args.listen.to_string(), DEFAULT_LISTEN_ADDR);
        assert!(args.store.is_none());
    }

    #[test]
    fn parses_configured_options() {
        let args = Args::try_parse_from([
            "crabscale-server",
            "--listen",
            "127.0.0.1:9000",
            "--key-file",
            "custom.key",
            "--store",
            "data/crabscale.db",
            "--auth-key",
            "hskey-auth-test-other",
            "--tailnet-domain",
            "example.com",
            "--server-url",
            "https://control.example.com",
        ])
        .unwrap();
        assert_eq!(args.listen.to_string(), "127.0.0.1:9000");
        assert_eq!(args.key_file, std::path::PathBuf::from("custom.key"));
        assert_eq!(
            args.store,
            Some(std::path::PathBuf::from("data/crabscale.db"))
        );
        assert_eq!(args.auth_key.as_deref(), Some("hskey-auth-test-other"));
        assert_eq!(args.tailnet_domain.as_deref(), Some("example.com"));
        assert_eq!(
            args.server_url.as_deref(),
            Some("https://control.example.com")
        );
    }

    #[test]
    fn parses_dns_options() {
        let args = Args::try_parse_from([
            "crabscale-server",
            "--no-magic-dns",
            "--dns-search-domain",
            "corp.example",
            "--dns-split",
            "corp.example.=10.0.0.53",
            "--dns-extra-records",
            "records.json",
        ])
        .unwrap();
        assert!(args.no_magic_dns);
        assert_eq!(args.dns_search_domain, vec!["corp.example".to_string()]);
        assert_eq!(args.dns_split, vec!["corp.example.=10.0.0.53".to_string()]);
        assert_eq!(
            args.dns_extra_records,
            Some(std::path::PathBuf::from("records.json"))
        );
        let config = control_config(&args);
        assert!(!config.dns.magic_dns);
        assert_eq!(config.dns.search_domains, vec!["corp.example".to_string()]);
        assert_eq!(
            config.dns.split_dns.get("corp.example.").unwrap(),
            &vec!["10.0.0.53".to_string()]
        );
        assert_eq!(
            config.dns.extra_records_path,
            Some(std::path::PathBuf::from("records.json"))
        );
    }

    #[test]
    fn config_respects_overrides() {
        let args = Args::try_parse_from([
            "crabscale-server",
            "--auth-key",
            "hskey-auth-custom-secret",
            "--server-url",
            "https://control.example.com",
        ])
        .unwrap();
        let config = control_config(&args);
        assert_eq!(config.auth_key, "hskey-auth-custom-secret");
        assert_eq!(config.server_url, "https://control.example.com");
        assert_eq!(config.tailnet_domain, "tailnet.example");
    }
}
