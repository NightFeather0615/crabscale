//! Server binary: wiring, config, HTTP serving, and shutdown.
//!
//! Milestone M4-03 (#26) adds deployment support: rustls TLS (files or ACME),
//! an HTTP-to-HTTPS redirect listener, trusted reverse-proxy CIDRs for client
//! IP resolution, and a TOML config file with `CRABSCALE_*` overrides. The
//! precedence is CLI > environment > config file > defaults.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use crabscale_control::{ControlConfig, ControlPlane, DnsSettings};
use crabscale_proto::{DerpMap, DerpNode, DerpRegion};
use crabscale_server::{
    BootstrapDns, CliOverrides, ControlRouter, DEFAULT_MAX_RATE_KEYS, RateLimitConfig, RawConfig,
    ServerConfig, ServerOptions, TrustedProxies, load_or_create_machine_key,
    serve_on_addr_with_options, serve_redirect_on_addr, serve_stun,
};
use url::Url;

/// crabscale control server.
#[derive(Parser, Clone)]
#[command(
    name = "crabscale-server",
    about = "crabscale control server",
    version = env!("CARGO_PKG_VERSION")
)]
struct Args {
    /// Path to a TOML config file. CLI flags and `CRABSCALE_*` env vars
    /// override it.
    #[arg(long)]
    config: Option<std::path::PathBuf>,

    /// Address the outer HTTP(S) server listens on.
    #[arg(long)]
    listen: Option<std::net::SocketAddr>,

    /// Address of the plain-HTTP listener that redirects to HTTPS (used with
    /// `--tls-mode files|acme` and `--http-redirect`).
    #[arg(long)]
    listen_http: Option<std::net::SocketAddr>,

    /// Enable the HTTP->HTTPS redirect listener.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    http_redirect: Option<bool>,

    /// Disable the HTTP->HTTPS redirect listener (overrides `http_redirect`).
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_http_redirect: Option<bool>,

    /// Path to the server machine key file.
    #[arg(long)]
    key_file: Option<std::path::PathBuf>,

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
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_magic_dns: Option<bool>,

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
    #[arg(long)]
    oidc_scope: Option<String>,

    /// DERP region ID for the embedded relay (stable across restarts).
    #[arg(long)]
    derp_region_id: Option<u64>,

    /// Short DERP region code advertised to clients.
    #[arg(long)]
    derp_region_code: Option<String>,

    /// Long DERP region name advertised to clients.
    #[arg(long)]
    derp_region_name: Option<String>,

    /// Node name of the embedded relay inside the advertised region.
    #[arg(long)]
    derp_node_name: Option<String>,

    /// Public hostname of the embedded relay.
    #[arg(long)]
    derp_hostname: Option<String>,

    /// DERP HTTPS port of the embedded relay.
    #[arg(long)]
    derp_port: Option<i32>,

    /// STUN UDP port of the embedded relay; 0 disables the STUN listener and
    /// advertises `-1` in the DERP map so clients skip STUN.
    #[arg(long)]
    stun_port: Option<i32>,

    /// Address the STUN UDP listener binds to (combined with `--stun-port`).
    #[arg(long)]
    stun_bind: Option<std::net::IpAddr>,

    /// Maximum `/ts2021` upgrade requests per minute per client IP; 0 disables.
    #[arg(long)]
    ts2021_rate_per_min: Option<u64>,

    /// Token-bucket burst (capacity) for `/ts2021` upgrades per client IP.
    #[arg(long)]
    ts2021_burst: Option<u32>,

    /// Maximum `/machine/register` requests per minute per machine key; 0 disables.
    #[arg(long)]
    register_rate_per_min: Option<u64>,

    /// Token-bucket burst (capacity) for `/machine/register` per machine key.
    #[arg(long)]
    register_burst: Option<u32>,

    /// Comma-separated hostnames to resolve and publish at `/bootstrap-dns`.
    #[arg(long)]
    bootstrap_dns_names: Option<String>,

    /// TLS mode: `off`, `files` (cert/key files) or `acme`.
    #[arg(long)]
    tls_mode: Option<String>,

    /// PEM certificate chain file (used with `--tls-mode files`).
    #[arg(long)]
    tls_cert_file: Option<std::path::PathBuf>,

    /// PEM private key file (used with `--tls-mode files`).
    #[arg(long)]
    tls_key_file: Option<std::path::PathBuf>,

    /// ACME domain to request a certificate for. Repeatable.
    #[arg(long)]
    acme_domain: Vec<String>,

    /// ACME contact email. Repeatable.
    #[arg(long)]
    acme_email: Vec<String>,

    /// Directory for the persistent ACME account/cert cache.
    #[arg(long)]
    acme_cache_dir: Option<std::path::PathBuf>,

    /// ACME directory URL override (e.g. Let's Encrypt staging).
    #[arg(long)]
    acme_directory_url: Option<String>,

    /// Trusted reverse-proxy CIDR whose `X-Forwarded-For` is honored.
    /// Repeatable.
    #[arg(long)]
    trusted_proxy: Vec<String>,
}

impl From<Args> for CliOverrides {
    fn from(a: Args) -> Self {
        Self {
            config: a.config,
            listen: a.listen,
            listen_http: a.listen_http,
            // `--no-http-redirect` wins over `--http-redirect`.
            http_redirect: a.http_redirect.or_else(|| a.no_http_redirect.map(|no| !no)),
            key_file: a.key_file,
            store: a.store,
            auth_key: a.auth_key,
            tailnet_domain: a.tailnet_domain,
            server_url: a.server_url,
            no_magic_dns: a.no_magic_dns,
            dns_search_domains: if a.dns_search_domain.is_empty() {
                None
            } else {
                Some(a.dns_search_domain)
            },
            dns_split: if a.dns_split.is_empty() {
                None
            } else {
                Some(a.dns_split)
            },
            dns_extra_records: a.dns_extra_records,
            oidc_issuer: a.oidc_issuer,
            oidc_client_id: a.oidc_client_id,
            oidc_client_secret: a.oidc_client_secret,
            oidc_redirect_uri: a.oidc_redirect_uri,
            oidc_scope: a.oidc_scope,
            derp_region_id: a.derp_region_id,
            derp_region_code: a.derp_region_code,
            derp_region_name: a.derp_region_name,
            derp_node_name: a.derp_node_name,
            derp_hostname: a.derp_hostname,
            derp_port: a.derp_port,
            stun_port: a.stun_port,
            stun_bind: a.stun_bind,
            ts2021_rate_per_min: a.ts2021_rate_per_min,
            ts2021_burst: a.ts2021_burst,
            register_rate_per_min: a.register_rate_per_min,
            register_burst: a.register_burst,
            bootstrap_dns_names: a.bootstrap_dns_names,
            tls: crabscale_server::TlsSettings {
                mode: a.tls_mode.unwrap_or_default(),
                cert_file: a.tls_cert_file,
                key_file: a.tls_key_file,
                acme_domains: a.acme_domain,
                acme_contact: a.acme_email,
                acme_cache_dir: a.acme_cache_dir,
                acme_directory_url: a.acme_directory_url,
            },
            trusted_proxies: if a.trusted_proxy.is_empty() {
                None
            } else {
                Some(a.trusted_proxy)
            },
        }
    }
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

/// Resolve the layered configuration (file + env + CLI).
fn resolve_config(args: &Args) -> Result<ServerConfig, String> {
    let raw = RawConfig::load(args.config.as_ref()).map_err(|e| format!("config: {e}"))?;
    let overrides: CliOverrides = args.clone().into();
    ServerConfig::resolve(&raw, &overrides)
}

/// Build the control plane configuration from the resolved config.
fn control_config(config: &ServerConfig) -> ControlConfig {
    let defaults = ControlConfig::default();
    let mut split_dns = std::collections::BTreeMap::new();
    for rule in &config.dns_split {
        let Some((suffix, addr)) = rule.split_once('=') else {
            continue;
        };
        split_dns
            .entry(suffix.to_string())
            .or_insert_with(Vec::new)
            .push(addr.to_string());
    }
    let dns = DnsSettings {
        magic_dns: config.magic_dns,
        search_domains: config.dns_search_domains.clone(),
        split_dns,
        extra_records_path: config.dns_extra_records.clone(),
        ..Default::default()
    };
    ControlConfig {
        derp_map: build_derp_map(config),
        auth_key: config
            .auth_key
            .clone()
            .unwrap_or_else(|| defaults.auth_key.clone()),
        tailnet_domain: config
            .tailnet_domain
            .clone()
            .unwrap_or_else(|| defaults.tailnet_domain.clone()),
        server_url: config
            .server_url
            .clone()
            .unwrap_or_else(|| defaults.server_url.clone()),
        dns,
        ..defaults
    }
}

/// Build the DERP map advertising the embedded relay region.
///
/// The region and node IDs come from the config so they stay stable across
/// restarts (Spec-DERP-STUN section 7). A STUN port of 0 is advertised as
/// `-1` (STUN disabled) so clients do not attempt binding requests.
fn build_derp_map(config: &ServerConfig) -> DerpMap {
    let node = DerpNode {
        name: config.derp_node_name.clone(),
        region_id: config.derp_region_id,
        host_name: config.derp_hostname.clone(),
        derp_port: config.derp_port,
        stun_port: if config.stun_port == 0 {
            -1
        } else {
            config.stun_port
        },
        ..Default::default()
    };
    let region = DerpRegion {
        region_id: config.derp_region_id,
        region_code: config.derp_region_code.clone(),
        region_name: config.derp_region_name.clone(),
        nodes: vec![node],
        ..Default::default()
    };
    let mut map = DerpMap {
        omit_default_regions: true,
        ..Default::default()
    };
    map.regions
        .insert(config.derp_region_id.to_string(), region);
    map
}

/// Build an OIDC client from the resolved config, if OIDC is configured.
///
/// Discovery is fetched and validated here so a misconfigured provider aborts
/// startup instead of failing at the first registration. Returns `Ok(None)`
/// when the issuer is absent.
fn build_oidc(
    config: &ServerConfig,
) -> Result<Option<crabscale_server::OidcClient>, Box<dyn std::error::Error>> {
    let Some(issuer) = config.oidc_issuer.clone() else {
        if config.oidc_client_id.is_some() || config.oidc_client_secret.is_some() {
            return Err("oidc client id/secret require oidc_issuer".into());
        }
        return Ok(None);
    };
    let client_id = config
        .oidc_client_id
        .clone()
        .ok_or("oidc_client_id is required with oidc_issuer")?;
    let client_secret = config
        .oidc_client_secret
        .clone()
        .ok_or("oidc_client_secret is required with oidc_issuer")?;
    let server_url = control_config(config).server_url;
    let redirect_uri = config
        .oidc_redirect_uri
        .clone()
        .unwrap_or_else(|| format!("{server_url}/oidc/callback"));
    let oidc_config = crabscale_server::OidcConfig {
        issuer,
        client_id,
        client_secret,
        redirect_uri,
        scope: config.oidc_scope.clone(),
    };
    let client = crabscale_server::OidcClient::discover(oidc_config)?;
    println!("OIDC provider discovered: {}", client.issuer());
    Ok(Some(client))
}

/// The authority (host[:port]) used for the HTTP->HTTPS redirect fallback.
fn redirect_fallback_host(config: &ServerConfig) -> String {
    config
        .server_url
        .as_ref()
        .and_then(|u| Url::parse(u).ok())
        .and_then(|u| {
            let host = u.host_str()?.to_string();
            match u.port() {
                Some(port) => Some(format!("{host}:{port}")),
                None => Some(host),
            }
        })
        .unwrap_or_else(|| "localhost".to_string())
}

/// Load the machine key, build the control plane and router, and serve the
/// outer HTTP endpoints until a shutdown signal arrives.
async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let config = resolve_config(&args)?;
    let server_key = load_or_create_machine_key(&config.key_file)?;

    let control = match &config.store {
        Some(path) => ControlPlane::open_sqlite(control_config(&config), path)?,
        None => ControlPlane::try_new(control_config(&config))?,
    };
    let mut router = ControlRouter::with_control(server_key.public_key(), control);
    if let Some(oidc) = build_oidc(&config)? {
        router = router.with_oidc(oidc);
    }

    // Serve the embedded relay's STUN port (Spec-DERP-STUN section 6) unless
    // the operator disabled it with `--stun-port 0`.
    let stun_handle = if config.stun_port != 0 {
        let stun_addr = std::net::SocketAddr::new(config.stun_bind, config.stun_port as u16);
        let (stun_local, handle) = serve_stun(stun_addr).await?;
        println!("STUN listening on udp://{stun_local}");
        Some(handle)
    } else {
        println!("STUN disabled (--stun-port 0)");
        None
    };

    // Publish the bootstrap DNS snapshot at `/bootstrap-dns`.
    if !config.bootstrap_dns_names.is_empty() {
        let names: Vec<String> = config
            .bootstrap_dns_names
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let dns = BootstrapDns::resolve(&names).await;
        println!("bootstrap DNS: {}", names.join(", "));
        router = router.with_bootstrap_dns(dns);
    }

    // Rate limit `/ts2021` (per client IP) and `/machine/register` (per
    // Noise machine key) with the configured token buckets (M4-02).
    router = router.with_rate_limits(RateLimitConfig {
        ts2021_per_min: config.ts2021_rate_per_min,
        ts2021_burst: config.ts2021_burst,
        register_per_min: config.register_rate_per_min,
        register_burst: config.register_burst,
        max_entries: DEFAULT_MAX_RATE_KEYS,
    });
    router.spawn_reaper();

    // TLS (M4-03): rustls from files or ACME; the plain default stays `off`.
    let tls = if config.tls.is_off() {
        None
    } else {
        Some(Arc::new(crabscale_server::load_tls_acceptor(&config.tls)?))
    };

    // Trusted reverse proxies (M4-03): only their `X-Forwarded-For` is honored.
    let trusted_proxies = if config.trusted_proxies.is_empty() {
        None
    } else {
        Some(Arc::new(TrustedProxies::from_cidrs(
            &config.trusted_proxies,
        )?))
    };

    let options = ServerOptions {
        trusted_proxies,
        tls,
    };
    let (addr, handle) =
        serve_on_addr_with_options(config.listen, router, server_key.clone(), options.clone())
            .await?;

    // HTTP->HTTPS redirect listener (M4-03), only meaningful when TLS is on.
    let redirect_handle = if let Some(listen_http) = config.listen_http {
        if options.tls.is_some() && config.http_redirect {
            let fallback_host = redirect_fallback_host(&config);
            let (http_addr, http_handle) =
                serve_redirect_on_addr(listen_http, fallback_host).await?;
            println!("redirecting http://{http_addr} -> https");
            Some(http_handle)
        } else if options.tls.is_none() {
            println!("listen_http set but TLS is off; not redirecting");
            None
        } else {
            println!("http_redirect disabled; skipping redirect");
            None
        }
    } else {
        None
    };

    let scheme = if options.tls.is_some() {
        "https"
    } else {
        "http"
    };
    println!("server machine key: {}", server_key.public_key());
    println!("key file: {}", config.key_file.display());
    println!("control server listening on {scheme}://{addr}");
    if !config.trusted_proxies.is_empty() {
        println!("trusted proxies: {}", config.trusted_proxies.join(", "));
    }

    tokio::signal::ctrl_c().await?;
    handle.shutdown();
    if let Some(redirect) = redirect_handle {
        redirect.shutdown();
    }
    if let Some(stun) = stun_handle {
        stun.shutdown();
    }
    println!("shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabscale_server::{
        DEFAULT_REGISTER_BURST, DEFAULT_REGISTER_RATE_PER_MIN, DEFAULT_TS2021_BURST,
        DEFAULT_TS2021_RATE_PER_MIN,
    };

    fn resolve_from(argv: &[&str]) -> ServerConfig {
        let args = Args::try_parse_from(argv).unwrap();
        resolve_config(&args).unwrap()
    }

    #[test]
    fn defaults_to_default_key_file_and_listen_addr() {
        let config = resolve_from(&["crabscale-server"]);
        assert_eq!(config.key_file, std::path::PathBuf::from("crabscale.key"));
        assert_eq!(config.listen.to_string(), "127.0.0.1:8080");
        assert!(config.store.is_none());
        assert!(config.tls.is_off());
    }

    #[test]
    fn parses_configured_options() {
        let config = resolve_from(&[
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
        ]);
        assert_eq!(config.listen.to_string(), "127.0.0.1:9000");
        assert_eq!(config.key_file, std::path::PathBuf::from("custom.key"));
        assert_eq!(
            config.store.as_deref(),
            Some(std::path::Path::new("data/crabscale.db"))
        );
        assert_eq!(config.auth_key.as_deref(), Some("hskey-auth-test-other"));
        assert_eq!(config.tailnet_domain.as_deref(), Some("example.com"));
        assert_eq!(
            config.server_url.as_deref(),
            Some("https://control.example.com")
        );
    }

    #[test]
    fn parses_dns_options() {
        let config = resolve_from(&[
            "crabscale-server",
            "--no-magic-dns",
            "--dns-search-domain",
            "corp.example",
            "--dns-split",
            "corp.example.=10.0.0.53",
            "--dns-extra-records",
            "records.json",
        ]);
        assert!(!config.magic_dns);
        assert_eq!(config.dns_search_domains, vec!["corp.example".to_string()]);
        assert_eq!(
            config.dns_split,
            vec!["corp.example.=10.0.0.53".to_string()]
        );
        assert_eq!(
            config.dns_extra_records,
            Some(std::path::PathBuf::from("records.json"))
        );
        let cc = control_config(&config);
        assert!(!cc.dns.magic_dns);
        assert_eq!(cc.dns.search_domains, vec!["corp.example".to_string()]);
        assert_eq!(
            cc.dns.split_dns.get("corp.example.").unwrap(),
            &vec!["10.0.0.53".to_string()]
        );
        assert_eq!(
            cc.dns.extra_records_path,
            Some(std::path::PathBuf::from("records.json"))
        );
    }

    #[test]
    fn parses_derp_options() {
        let config = resolve_from(&[
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
        ]);
        let cc = control_config(&config);
        let region = &cc.derp_map.regions["900"];
        assert_eq!(region.region_id, 900);
        assert_eq!(region.region_code, "sfo");
        assert_eq!(region.region_name, "San Francisco");
        let node = &region.nodes[0];
        assert_eq!(node.name, "sfo-1");
        assert_eq!(node.host_name, "derp.example.net");
        assert_eq!(node.derp_port, 8443);
        assert_eq!(node.stun_port, 4444);
        assert!(cc.derp_map.omit_default_regions);
    }

    #[test]
    fn derp_map_disables_stun_with_zero_port() {
        let config = resolve_from(&["crabscale-server", "--stun-port", "0"]);
        let cc = control_config(&config);
        let node = &cc.derp_map.regions["1"].nodes[0];
        assert_eq!(
            node.stun_port, -1,
            "port 0 must be advertised as -1 (STUN off)"
        );
        let default = resolve_from(&["crabscale-server"]);
        assert_eq!(
            control_config(&default).derp_map.regions["1"].nodes[0].stun_port,
            3478
        );
    }

    #[test]
    fn parses_bootstrap_dns_names() {
        let config = resolve_from(&["crabscale-server", "--bootstrap-dns-names", "a.com,b.com"]);
        assert_eq!(config.bootstrap_dns_names, "a.com,b.com");
    }

    #[test]
    fn parses_rate_limit_options() {
        let config = resolve_from(&[
            "crabscale-server",
            "--ts2021-rate-per-min",
            "120",
            "--ts2021-burst",
            "20",
            "--register-rate-per-min",
            "10",
            "--register-burst",
            "2",
        ]);
        assert_eq!(config.ts2021_rate_per_min, 120);
        assert_eq!(config.ts2021_burst, 20);
        assert_eq!(config.register_rate_per_min, 10);
        assert_eq!(config.register_burst, 2);

        // Defaults come from the shared constants.
        let config = resolve_from(&["crabscale-server"]);
        assert_eq!(config.ts2021_rate_per_min, DEFAULT_TS2021_RATE_PER_MIN);
        assert_eq!(config.ts2021_burst, DEFAULT_TS2021_BURST);
        assert_eq!(config.register_rate_per_min, DEFAULT_REGISTER_RATE_PER_MIN);
        assert_eq!(config.register_burst, DEFAULT_REGISTER_BURST);
    }

    #[test]
    fn config_respects_overrides() {
        let config = resolve_from(&[
            "crabscale-server",
            "--auth-key",
            "hskey-auth-custom-secret",
            "--server-url",
            "https://control.example.com",
        ]);
        let cc = control_config(&config);
        assert_eq!(cc.auth_key, "hskey-auth-custom-secret");
        assert_eq!(cc.server_url, "https://control.example.com");
        assert_eq!(cc.tailnet_domain, "tailnet.example");
    }

    #[test]
    fn parses_oidc_options() {
        let config = resolve_from(&[
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
        ]);
        assert_eq!(
            config.oidc_issuer.as_deref(),
            Some("https://issuer.example")
        );
        assert_eq!(config.oidc_client_id.as_deref(), Some("client-1"));
        assert_eq!(
            config.oidc_redirect_uri.as_deref(),
            Some("https://control.example/custom-callback")
        );
        assert_eq!(config.oidc_scope, "openid email");
    }

    #[test]
    fn oidc_client_flags_require_issuer() {
        let config = resolve_from(&["crabscale-server", "--oidc-client-id", "client-1"]);
        assert!(build_oidc(&config).is_err());
        let config = resolve_from(&["crabscale-server"]);
        assert!(build_oidc(&config).unwrap().is_none());
    }

    #[test]
    fn parses_deployment_options() {
        let config = resolve_from(&[
            "crabscale-server",
            "--listen",
            "0.0.0.0:443",
            "--listen-http",
            "0.0.0.0:80",
            "--tls-mode",
            "files",
            "--tls-cert-file",
            "/certs/cert.pem",
            "--tls-key-file",
            "/certs/key.pem",
            "--trusted-proxy",
            "127.0.0.1/32",
            "--trusted-proxy",
            "10.0.0.0/8",
        ]);
        assert_eq!(config.listen.to_string(), "0.0.0.0:443");
        assert_eq!(config.listen_http.unwrap().to_string(), "0.0.0.0:80");
        assert!(config.tls.is_files());
        assert_eq!(
            config.tls.cert_file.as_deref(),
            Some(std::path::Path::new("/certs/cert.pem"))
        );
        assert_eq!(
            config.trusted_proxies,
            vec!["127.0.0.1/32".to_string(), "10.0.0.0/8".to_string()]
        );
    }

    #[test]
    fn parses_acme_options() {
        let config = resolve_from(&[
            "crabscale-server",
            "--tls-mode",
            "acme",
            "--acme-domain",
            "control.example.com",
            "--acme-email",
            "admin@example.com",
            "--acme-cache-dir",
            "/data/acme",
        ]);
        assert!(config.tls.is_acme());
        assert_eq!(
            config.tls.acme_domains,
            vec!["control.example.com".to_string()]
        );
        assert_eq!(
            config.tls.acme_contact,
            vec!["admin@example.com".to_string()]
        );
        assert_eq!(
            config.tls.acme_cache_dir.as_deref(),
            Some(std::path::Path::new("/data/acme"))
        );
    }

    #[test]
    fn http_redirect_flag_overrides_enable() {
        let config = resolve_from(&["crabscale-server", "--http-redirect"]);
        assert!(config.http_redirect);
        let config = resolve_from(&["crabscale-server", "--no-http-redirect"]);
        assert!(!config.http_redirect);
    }
}
