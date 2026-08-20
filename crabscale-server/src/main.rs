//! Server binary: wiring, config, HTTP serving, and shutdown.
//!
//! This milestone starts the outer HTTP control server (`/key`, `/ts2021`,
//! and the `/register/{id}` approval page) with a parsed CLI config and runs
//! it until shutdown (Ctrl-C).

use std::process::ExitCode;

use clap::Parser;
use crabscale_control::{ControlConfig, ControlPlane, DnsSettings};
use crabscale_proto::{DerpMap, DerpNode, DerpRegion};
use crabscale_server::{
    BootstrapDns, ControlRouter, DEFAULT_KEY_FILE, OidcClient, OidcConfig,
    load_or_create_machine_key, serve_on_addr, serve_stun,
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

    /// OpenID Connect issuer URL; enables OIDC browser registration approval.
    #[arg(long)]
    oidc_issuer: Option<String>,

    /// OIDC client id registered with the provider.
    #[arg(long)]
    oidc_client_id: Option<String>,

    /// OIDC client secret registered with the provider.
    #[arg(long)]
    oidc_client_secret: Option<String>,

    /// OIDC callback URL; defaults to `<server-url>/oidc/callback`.
    #[arg(long)]
    oidc_redirect_uri: Option<String>,

    /// OIDC scopes to request, space-separated.
    #[arg(long, default_value = "openid profile email")]
    oidc_scope: String,

    /// DERP region ID for the embedded relay (stable across restarts).
    #[arg(long, default_value = "1")]
    derp_region_id: u64,

    /// Short DERP region code advertised to clients.
    #[arg(long, default_value = "crab")]
    derp_region_code: String,

    /// Long DERP region name advertised to clients.
    #[arg(long, default_value = "Crabscale")]
    derp_region_name: String,

    /// Node name of the embedded relay inside the advertised region.
    #[arg(long, default_value = "crab-1")]
    derp_node_name: String,

    /// Public hostname of the embedded relay.
    #[arg(long, default_value = "derp.example.com")]
    derp_hostname: String,

    /// DERP HTTPS port of the embedded relay.
    #[arg(long, default_value = "443")]
    derp_port: i32,

    /// STUN UDP port of the embedded relay; 0 disables the STUN listener and
    /// advertises `-1` in the DERP map so clients skip STUN.
    #[arg(long, default_value = "3478")]
    stun_port: i32,

    /// Address the STUN UDP listener binds to (combined with `--stun-port`).
    #[arg(long, default_value = "0.0.0.0")]
    stun_bind: std::net::IpAddr,

    /// Comma-separated hostnames to resolve and publish at `/bootstrap-dns`.
    #[arg(long)]
    bootstrap_dns_names: Option<String>,
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
        derp_map: build_derp_map(args),
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

/// Build the DERP map advertising the embedded relay region.
///
/// The region and node IDs come from the CLI so they stay stable across
/// restarts (Spec-DERP-STUN section 7). A STUN port of 0 is advertised as
/// `-1` (STUN disabled) so clients do not attempt binding requests.
fn build_derp_map(args: &Args) -> DerpMap {
    let node = DerpNode {
        name: args.derp_node_name.clone(),
        region_id: args.derp_region_id,
        host_name: args.derp_hostname.clone(),
        derp_port: args.derp_port,
        stun_port: if args.stun_port == 0 {
            -1
        } else {
            args.stun_port
        },
        ..Default::default()
    };
    let region = DerpRegion {
        region_id: args.derp_region_id,
        region_code: args.derp_region_code.clone(),
        region_name: args.derp_region_name.clone(),
        nodes: vec![node],
        ..Default::default()
    };
    let mut map = DerpMap {
        omit_default_regions: true,
        ..Default::default()
    };
    map.regions.insert(args.derp_region_id.to_string(), region);
    map
}

/// Build an OIDC client from CLI arguments, if OIDC is configured.
///
/// Discovery is fetched and validated here so a misconfigured provider aborts
/// startup instead of failing at the first registration. Returns `Ok(None)`
/// when the issuer flag is absent.
fn build_oidc(args: &Args) -> Result<Option<OidcClient>, Box<dyn std::error::Error>> {
    let Some(issuer) = args.oidc_issuer.clone() else {
        if args.oidc_client_id.is_some() || args.oidc_client_secret.is_some() {
            return Err("--oidc-client-id/--oidc-client-secret require --oidc-issuer".into());
        }
        return Ok(None);
    };
    let client_id = args
        .oidc_client_id
        .clone()
        .ok_or("--oidc-client-id is required with --oidc-issuer")?;
    let client_secret = args
        .oidc_client_secret
        .clone()
        .ok_or("--oidc-client-secret is required with --oidc-issuer")?;
    let server_url = control_config(args).server_url;
    let redirect_uri = args
        .oidc_redirect_uri
        .clone()
        .unwrap_or_else(|| format!("{server_url}/oidc/callback"));
    let config = OidcConfig {
        issuer,
        client_id,
        client_secret,
        redirect_uri,
        scope: args.oidc_scope.clone(),
    };
    let client = OidcClient::discover(config)?;
    println!("OIDC provider discovered: {}", client.issuer());
    Ok(Some(client))
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
    let mut router = ControlRouter::with_control(server_key.public_key(), control);
    if let Some(oidc) = build_oidc(&args)? {
        router = router.with_oidc(oidc);
    }

    // Serve the embedded relay's STUN port (Spec-DERP-STUN section 6) unless
    // the operator disabled it with `--stun-port 0`.
    let stun_handle = if args.stun_port != 0 {
        let stun_addr = std::net::SocketAddr::new(args.stun_bind, args.stun_port as u16);
        let (stun_local, handle) = serve_stun(stun_addr).await?;
        println!("STUN listening on udp://{stun_local}");
        Some(handle)
    } else {
        println!("STUN disabled (--stun-port 0)");
        None
    };

    // Publish the bootstrap DNS snapshot at `/bootstrap-dns`.
    if let Some(names) = args.bootstrap_dns_names.as_deref() {
        let names: Vec<String> = names
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let dns = BootstrapDns::resolve(&names).await;
        println!("bootstrap DNS: {}", names.join(", "));
        router = router.with_bootstrap_dns(dns);
    }

    router.spawn_reaper();

    let (addr, handle) = serve_on_addr(args.listen, router, server_key.clone()).await?;

    println!("server machine key: {}", server_key.public_key());
    println!("key file: {}", args.key_file.display());
    println!("control server listening on http://{addr}");

    tokio::signal::ctrl_c().await?;
    handle.shutdown();
    if let Some(stun) = stun_handle {
        stun.shutdown();
    }
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
    fn parses_derp_options() {
        let args = Args::try_parse_from([
            "crabscale-server",
            "--derp-region-id",
            "900",
            "--derp-region-code",
            "sfo",
            "--derp-region-name",
            "San Francisco",
            "--derp-node-name",
            "sfo-1",
            "--derp-hostname",
            "derp.example.net",
            "--derp-port",
            "8443",
            "--stun-port",
            "4444",
            "--stun-bind",
            "0.0.0.0",
        ])
        .unwrap();
        let config = control_config(&args);
        let region = &config.derp_map.regions["900"];
        assert_eq!(region.region_id, 900);
        assert_eq!(region.region_code, "sfo");
        assert_eq!(region.region_name, "San Francisco");
        let node = &region.nodes[0];
        assert_eq!(node.name, "sfo-1");
        assert_eq!(node.host_name, "derp.example.net");
        assert_eq!(node.derp_port, 8443);
        assert_eq!(node.stun_port, 4444);
        assert!(config.derp_map.omit_default_regions);
    }

    #[test]
    fn derp_map_disables_stun_with_zero_port() {
        let args = Args::try_parse_from(["crabscale-server", "--stun-port", "0"]).unwrap();
        let config = control_config(&args);
        let node = &config.derp_map.regions["1"].nodes[0];
        assert_eq!(
            node.stun_port, -1,
            "port 0 must be advertised as -1 (STUN off)"
        );
        let config2 = control_config(&Args::try_parse_from(["crabscale-server"]).unwrap());
        assert_eq!(config2.derp_map.regions["1"].nodes[0].stun_port, 3478);
    }

    #[test]
    fn parses_bootstrap_dns_names() {
        let args =
            Args::try_parse_from(["crabscale-server", "--bootstrap-dns-names", "a.com,b.com"])
                .unwrap();
        assert_eq!(args.bootstrap_dns_names.as_deref(), Some("a.com,b.com"));
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

    #[test]
    fn parses_oidc_options() {
        let args = Args::try_parse_from([
            "crabscale-server",
            "--oidc-issuer",
            "https://issuer.example",
            "--oidc-client-id",
            "client-1",
            "--oidc-client-secret",
            "secret-1",
            "--oidc-redirect-uri",
            "https://control.example/custom-callback",
            "--oidc-scope",
            "openid email",
        ])
        .unwrap();
        assert_eq!(args.oidc_issuer.as_deref(), Some("https://issuer.example"));
        assert_eq!(args.oidc_client_id.as_deref(), Some("client-1"));
        assert_eq!(args.oidc_client_secret.as_deref(), Some("secret-1"));
        assert_eq!(
            args.oidc_redirect_uri.as_deref(),
            Some("https://control.example/custom-callback")
        );
        assert_eq!(args.oidc_scope, "openid email");
    }

    #[test]
    fn oidc_client_flags_require_issuer() {
        // Client id without an issuer is a configuration error.
        let args =
            Args::try_parse_from(["crabscale-server", "--oidc-client-id", "client-1"]).unwrap();
        assert!(build_oidc(&args).is_err());
        // No OIDC flags at all means the feature stays off.
        let args = Args::try_parse_from(["crabscale-server"]).unwrap();
        assert!(build_oidc(&args).unwrap().is_none());
    }
}
