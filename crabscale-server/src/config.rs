//! Server configuration: config file + environment overrides + CLI merge.
//!
//! The server is deployable behind standard infrastructure by
//! adding a TOML config file (`--config crabscale.toml`) and an environment
//! override mechanism. The precedence is:
//!
//! 1. built-in defaults
//! 2. config file values
//! 3. `CRABSCALE_*` environment variables
//! 4. explicit CLI flags
//!
//! Every environment override is derived from the exact field name, upper-cased
//! with `CRABSCALE_` prefixed (e.g. `key_file` -> `CRABSCALE_KEY_FILE`,
//! `ts2021_rate_per_min` -> `CRABSCALE_TS2021_RATE_PER_MIN`). List fields take a
//! comma-separated value; booleans take `true`/`false`.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::rate_limit::{
    DEFAULT_REGISTER_BURST, DEFAULT_REGISTER_RATE_PER_MIN, DEFAULT_TS2021_BURST,
    DEFAULT_TS2021_RATE_PER_MIN,
};
use crate::tls::TlsSettings;

/// Default address the outer HTTP server listens on (plain HTTP).
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";

/// The environment-variable prefix for config overrides.
pub const ENV_PREFIX: &str = "CRABSCALE_";

/// Raw config as read from the TOML file and/or environment. All fields are
/// optional; `None` means "not supplied, take a lower-precedence layer".
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RawConfig {
    pub listen: Option<SocketAddr>,
    /// Plain-HTTP listener that redirects to HTTPS. Used together with TLS.
    pub listen_http: Option<SocketAddr>,
    /// Whether to run the HTTP->HTTPS redirect listener when TLS is enabled.
    pub http_redirect: Option<bool>,
    pub key_file: Option<PathBuf>,
    pub store: Option<PathBuf>,
    pub auth_key: Option<String>,
    pub tailnet_domain: Option<String>,
    pub server_url: Option<String>,
    pub magic_dns: Option<bool>,
    pub dns_search_domains: Option<Vec<String>>,
    pub dns_split: Option<Vec<String>>,
    pub dns_extra_records: Option<PathBuf>,
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_uri: Option<String>,
    pub oidc_scope: Option<String>,
    pub derp_region_id: Option<u64>,
    pub derp_region_code: Option<String>,
    pub derp_region_name: Option<String>,
    pub derp_node_name: Option<String>,
    pub derp_hostname: Option<String>,
    pub derp_port: Option<i32>,
    pub stun_port: Option<i32>,
    pub stun_bind: Option<IpAddr>,
    pub ts2021_rate_per_min: Option<u64>,
    pub ts2021_burst: Option<u32>,
    pub register_rate_per_min: Option<u64>,
    pub register_burst: Option<u32>,
    pub bootstrap_dns_names: Option<String>,
    pub tls: TlsSettings,
    pub trusted_proxies: Option<Vec<String>>,
    /// Path to the config file itself (kept for error messages / reporting).
    #[serde(skip)]
    pub config_path: Option<PathBuf>,
}

impl RawConfig {
    /// Load a TOML config file, if `path` is given, then apply environment
    /// overrides on top of it.
    pub fn load(path: Option<&PathBuf>) -> Result<Self, String> {
        let mut raw = match path {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;
                let parsed: RawConfig = toml::from_str(&text)
                    .map_err(|e| format!("failed to parse config {}: {e}", path.display()))?;
                parsed
            }
            None => RawConfig::default(),
        };
        raw.config_path = path.cloned();
        raw.apply_env()?;
        Ok(raw)
    }

    /// Apply `CRABSCALE_*` environment overrides. Only variables that are set
    /// are applied; an unset variable never overrides a config-file value.
    ///
    /// Returns an error naming the offending variable when its value cannot be
    /// parsed, so a typo aborts startup instead of silently using a default.
    pub fn apply_env(&mut self) -> Result<(), String> {
        macro_rules! env_typed {
            ($field:ident, $kind:ty) => {
                if let Some(v) = env_value(stringify!($field)) {
                    let parsed: $kind = v.parse().map_err(|e| {
                        format!(
                            "invalid CRABSCALE_{}={v:?}: {e}",
                            stringify!($field).to_ascii_uppercase()
                        )
                    })?;
                    self.$field = Some(parsed);
                }
            };
        }
        env_typed!(listen, SocketAddr);
        env_typed!(listen_http, SocketAddr);
        env_typed!(http_redirect, bool);
        env_typed!(magic_dns, bool);
        env_typed!(derp_region_id, u64);
        env_typed!(derp_port, i32);
        env_typed!(stun_port, i32);
        env_typed!(stun_bind, IpAddr);
        env_typed!(ts2021_rate_per_min, u64);
        env_typed!(ts2021_burst, u32);
        env_typed!(register_rate_per_min, u64);
        env_typed!(register_burst, u32);

        if let Some(v) = env_value("key_file") {
            self.key_file = Some(PathBuf::from(v));
        }
        if let Some(v) = env_value("store") {
            self.store = Some(PathBuf::from(v));
        }
        if let Some(v) = env_value("auth_key") {
            self.auth_key = Some(v);
        }
        if let Some(v) = env_value("tailnet_domain") {
            self.tailnet_domain = Some(v);
        }
        if let Some(v) = env_value("server_url") {
            self.server_url = Some(v);
        }
        if let Some(v) = env_value("dns_extra_records") {
            self.dns_extra_records = Some(PathBuf::from(v));
        }
        if let Some(v) = env_value("dns_search_domains") {
            self.dns_search_domains = Some(split_list(&v));
        }
        if let Some(v) = env_value("dns_split") {
            self.dns_split = Some(split_list(&v));
        }
        if let Some(v) = env_value("oidc_issuer") {
            self.oidc_issuer = Some(v);
        }
        if let Some(v) = env_value("oidc_client_id") {
            self.oidc_client_id = Some(v);
        }
        if let Some(v) = env_value("oidc_client_secret") {
            self.oidc_client_secret = Some(v);
        }
        if let Some(v) = env_value("oidc_redirect_uri") {
            self.oidc_redirect_uri = Some(v);
        }
        if let Some(v) = env_value("oidc_scope") {
            self.oidc_scope = Some(v);
        }
        if let Some(v) = env_value("derp_region_code") {
            self.derp_region_code = Some(v);
        }
        if let Some(v) = env_value("derp_region_name") {
            self.derp_region_name = Some(v);
        }
        if let Some(v) = env_value("derp_node_name") {
            self.derp_node_name = Some(v);
        }
        if let Some(v) = env_value("derp_hostname") {
            self.derp_hostname = Some(v);
        }
        if let Some(v) = env_value("bootstrap_dns_names") {
            self.bootstrap_dns_names = Some(v);
        }
        if let Some(v) = env_value("trusted_proxies") {
            self.trusted_proxies = Some(split_list(&v));
        }

        // TLS subsection overrides.
        if let Ok(v) = std::env::var("CRABSCALE_TLS_MODE") {
            self.tls.mode = v;
        }
        if let Ok(v) = std::env::var("CRABSCALE_TLS_CERT_FILE") {
            self.tls.cert_file = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("CRABSCALE_TLS_KEY_FILE") {
            self.tls.key_file = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("CRABSCALE_ACME_CACHE_DIR") {
            self.tls.acme_cache_dir = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("CRABSCALE_ACME_DIRECTORY_URL") {
            self.tls.acme_directory_url = Some(v);
        }
        if let Ok(v) = std::env::var("CRABSCALE_ACME_DOMAINS") {
            self.tls.acme_domains = split_list(&v);
        }
        if let Ok(v) = std::env::var("CRABSCALE_ACME_CONTACT") {
            self.tls.acme_contact = split_list(&v);
        }
        Ok(())
    }
}

/// The final, resolved configuration the server runs with.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub listen_http: Option<SocketAddr>,
    pub http_redirect: bool,
    pub key_file: PathBuf,
    pub store: Option<PathBuf>,
    pub auth_key: Option<String>,
    pub tailnet_domain: Option<String>,
    pub server_url: Option<String>,
    pub magic_dns: bool,
    pub dns_search_domains: Vec<String>,
    pub dns_split: Vec<String>,
    pub dns_extra_records: Option<PathBuf>,
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_uri: Option<String>,
    pub oidc_scope: String,
    pub derp_region_id: u64,
    pub derp_region_code: String,
    pub derp_region_name: String,
    pub derp_node_name: String,
    pub derp_hostname: String,
    pub derp_port: i32,
    pub stun_port: i32,
    pub stun_bind: IpAddr,
    pub ts2021_rate_per_min: u64,
    pub ts2021_burst: u32,
    pub register_rate_per_min: u64,
    pub register_burst: u32,
    pub bootstrap_dns_names: String,
    pub tls: TlsSettings,
    pub trusted_proxies: Vec<String>,
    /// Original config file path for reporting.
    pub config_path: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN_ADDR.parse().expect("default listen addr"),
            listen_http: None,
            http_redirect: true,
            key_file: PathBuf::from(crate::key::DEFAULT_KEY_FILE),
            store: None,
            auth_key: None,
            tailnet_domain: None,
            server_url: None,
            magic_dns: true,
            dns_search_domains: Vec::new(),
            dns_split: Vec::new(),
            dns_extra_records: None,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_redirect_uri: None,
            oidc_scope: "openid profile email".to_string(),
            derp_region_id: 1,
            derp_region_code: "crab".to_string(),
            derp_region_name: "Crabscale".to_string(),
            derp_node_name: "crab-1".to_string(),
            derp_hostname: "derp.example.com".to_string(),
            derp_port: 443,
            stun_port: 3478,
            stun_bind: "0.0.0.0".parse().expect("default stun bind"),
            ts2021_rate_per_min: DEFAULT_TS2021_RATE_PER_MIN,
            ts2021_burst: DEFAULT_TS2021_BURST,
            register_rate_per_min: DEFAULT_REGISTER_RATE_PER_MIN,
            register_burst: DEFAULT_REGISTER_BURST,
            bootstrap_dns_names: String::new(),
            tls: TlsSettings::default(),
            trusted_proxies: Vec::new(),
            config_path: None,
        }
    }
}

/// Command-line overrides, all optional so "not supplied" can be
/// distinguished from an explicit default. `main.rs` converts its clap
/// `Args` into this value before resolving.
#[derive(Clone, Debug, Default)]
pub struct CliOverrides {
    pub config: Option<PathBuf>,
    pub listen: Option<SocketAddr>,
    pub listen_http: Option<SocketAddr>,
    pub http_redirect: Option<bool>,
    pub key_file: Option<PathBuf>,
    pub store: Option<PathBuf>,
    pub auth_key: Option<String>,
    pub tailnet_domain: Option<String>,
    pub server_url: Option<String>,
    pub no_magic_dns: Option<bool>,
    pub dns_search_domains: Option<Vec<String>>,
    pub dns_split: Option<Vec<String>>,
    pub dns_extra_records: Option<PathBuf>,
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_uri: Option<String>,
    pub oidc_scope: Option<String>,
    pub derp_region_id: Option<u64>,
    pub derp_region_code: Option<String>,
    pub derp_region_name: Option<String>,
    pub derp_node_name: Option<String>,
    pub derp_hostname: Option<String>,
    pub derp_port: Option<i32>,
    pub stun_port: Option<i32>,
    pub stun_bind: Option<IpAddr>,
    pub ts2021_rate_per_min: Option<u64>,
    pub ts2021_burst: Option<u32>,
    pub register_rate_per_min: Option<u64>,
    pub register_burst: Option<u32>,
    pub bootstrap_dns_names: Option<String>,
    pub tls: TlsSettings,
    pub trusted_proxies: Option<Vec<String>>,
}

impl ServerConfig {
    /// Merge raw (file + env) configuration with explicit CLI overrides.
    ///
    /// Precedence: CLI > env/file > built-in defaults. Fields not supplied at
    /// any layer fall back to the defaults in [`ServerConfig::default`].
    pub fn resolve(raw: &RawConfig, cli: &CliOverrides) -> Result<Self, String> {
        let defaults = Self::default();

        macro_rules! pick {
            ($field:ident) => {
                cli.$field
                    .clone()
                    .or_else(|| raw.$field.clone())
                    .unwrap_or(defaults.$field)
            };
        }
        macro_rules! pick_opt {
            ($field:ident) => {
                cli.$field.clone().or_else(|| raw.$field.clone())
            };
        }

        Ok(Self {
            listen: pick!(listen),
            listen_http: pick_opt!(listen_http),
            http_redirect: pick!(http_redirect),
            key_file: pick!(key_file),
            store: pick_opt!(store),
            auth_key: pick_opt!(auth_key),
            tailnet_domain: pick_opt!(tailnet_domain),
            server_url: pick_opt!(server_url),
            magic_dns: cli
                .no_magic_dns
                .map(|no| !no)
                .or(raw.magic_dns)
                .unwrap_or(defaults.magic_dns),
            dns_search_domains: pick!(dns_search_domains),
            dns_split: pick!(dns_split),
            dns_extra_records: pick_opt!(dns_extra_records),
            oidc_issuer: pick_opt!(oidc_issuer),
            oidc_client_id: pick_opt!(oidc_client_id),
            oidc_client_secret: pick_opt!(oidc_client_secret),
            oidc_redirect_uri: pick_opt!(oidc_redirect_uri),
            oidc_scope: pick!(oidc_scope),
            derp_region_id: pick!(derp_region_id),
            derp_region_code: pick!(derp_region_code),
            derp_region_name: pick!(derp_region_name),
            derp_node_name: pick!(derp_node_name),
            derp_hostname: pick!(derp_hostname),
            derp_port: pick!(derp_port),
            stun_port: pick!(stun_port),
            stun_bind: pick!(stun_bind),
            ts2021_rate_per_min: pick!(ts2021_rate_per_min),
            ts2021_burst: pick!(ts2021_burst),
            register_rate_per_min: pick!(register_rate_per_min),
            register_burst: pick!(register_burst),
            bootstrap_dns_names: pick!(bootstrap_dns_names),
            tls: merge_tls(&raw.tls, &cli.tls),
            trusted_proxies: pick!(trusted_proxies),
            config_path: raw.config_path.clone(),
        })
    }
}

/// Merge TLS settings: CLI wins, then env/file, then defaults.
fn merge_tls(lower: &TlsSettings, higher: &TlsSettings) -> TlsSettings {
    let mut tls = lower.clone();
    if !higher.mode.trim().is_empty() {
        tls.mode = higher.mode.clone();
    }
    if higher.cert_file.is_some() {
        tls.cert_file = higher.cert_file.clone();
    }
    if higher.key_file.is_some() {
        tls.key_file = higher.key_file.clone();
    }
    if !higher.acme_domains.is_empty() {
        tls.acme_domains = higher.acme_domains.clone();
    }
    if !higher.acme_contact.is_empty() {
        tls.acme_contact = higher.acme_contact.clone();
    }
    if higher.acme_cache_dir.is_some() {
        tls.acme_cache_dir = higher.acme_cache_dir.clone();
    }
    if higher.acme_directory_url.is_some() {
        tls.acme_directory_url = higher.acme_directory_url.clone();
    }
    tls
}

fn env_value(field: &str) -> Option<String> {
    std::env::var(format!("{ENV_PREFIX}{}", field.to_ascii_uppercase())).ok()
}

/// Split a comma-separated list, trimming whitespace and dropping empties.
fn split_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_env(features: &[(&str, &str)], body: impl FnOnce()) {
        let keys: Vec<String> = features
            .iter()
            .map(|(k, _)| format!("{ENV_PREFIX}{k}"))
            .collect();
        for (k, v) in features {
            // Tests are single-threaded for these cases; setting process env
            // is sound here.
            unsafe { std::env::set_var(format!("{ENV_PREFIX}{k}"), *v) };
        }
        body();
        for k in keys {
            unsafe { std::env::remove_var(k) };
        }
    }

    #[test]
    fn parses_list_env_values() {
        with_env(
            &[
                ("DNS_SEARCH_DOMAINS", "corp.example, dc.example"),
                ("TRUSTED_PROXIES", "127.0.0.1/32, 10.0.0.0/8"),
            ],
            || {
                let mut raw = RawConfig::default();
                raw.apply_env().unwrap();
                assert_eq!(
                    raw.dns_search_domains,
                    Some(vec!["corp.example".to_string(), "dc.example".to_string()])
                );
                assert_eq!(
                    raw.trusted_proxies,
                    Some(vec!["127.0.0.1/32".to_string(), "10.0.0.0/8".to_string()])
                );
            },
        );
    }

    #[test]
    fn parses_scalar_env_values() {
        with_env(
            &[
                ("LISTEN", "0.0.0.0:443"),
                ("STUN_PORT", "0"),
                ("REGISTER_BURST", "7"),
            ],
            || {
                let mut raw = RawConfig::default();
                raw.apply_env().unwrap();
                assert_eq!(raw.listen, Some("0.0.0.0:443".parse().unwrap()));
                assert_eq!(raw.stun_port, Some(0));
                assert_eq!(raw.register_burst, Some(7));
            },
        );
    }

    #[test]
    fn applies_tls_env_overrides() {
        with_env(
            &[
                ("TLS_MODE", "files"),
                ("TLS_CERT_FILE", "/certs/cert.pem"),
                ("TLS_KEY_FILE", "/certs/key.pem"),
                ("ACME_CACHE_DIR", "/certs/cache"),
                ("ACME_DOMAINS", "a.example,b.example"),
            ],
            || {
                let mut raw = RawConfig::default();
                raw.apply_env().unwrap();
                let tls = &raw.tls;
                assert_eq!(tls.mode, "files");
                assert_eq!(
                    tls.cert_file.as_deref(),
                    Some(std::path::Path::new("/certs/cert.pem"))
                );
                assert_eq!(
                    tls.acme_cache_dir.as_deref(),
                    Some(std::path::Path::new("/certs/cache"))
                );
                assert_eq!(
                    tls.acme_domains,
                    vec!["a.example".to_string(), "b.example".to_string()]
                );
            },
        );
    }

    #[test]
    fn resolve_applies_cli_over_file_and_defaults() {
        let raw = RawConfig {
            listen: Some("0.0.0.0:443".parse().unwrap()),
            listen_http: Some("0.0.0.0:80".parse().unwrap()),
            key_file: Some(PathBuf::from("/data/key")),
            derp_region_id: Some(900),
            ..Default::default()
        };
        let cli = CliOverrides {
            key_file: Some(PathBuf::from("/cli/key")),
            ..Default::default()
        };
        let resolved = ServerConfig::resolve(&raw, &cli).unwrap();
        // CLI wins over file.
        assert_eq!(resolved.key_file, PathBuf::from("/cli/key"));
        // File wins where CLI is silent.
        assert_eq!(resolved.listen.to_string(), "0.0.0.0:443");
        assert_eq!(resolved.derp_region_id, 900);
        assert_eq!(resolved.listen_http.unwrap().to_string(), "0.0.0.0:80");
        // Defaults fill gaps.
        assert_eq!(resolved.derp_region_code, "crab");
        assert!(resolved.magic_dns);
    }

    #[test]
    fn resolve_treats_no_magic_dns_as_override() {
        let raw = RawConfig {
            magic_dns: Some(true),
            ..Default::default()
        };
        let cli = CliOverrides {
            no_magic_dns: Some(true),
            ..Default::default()
        };
        let resolved = ServerConfig::resolve(&raw, &cli).unwrap();
        assert!(!resolved.magic_dns);
    }

    #[test]
    fn parses_representative_toml_file() {
        let text = r#"
listen = "0.0.0.0:8080"
listen_http = "0.0.0.0:80"
key_file = "/data/key"
store = "/data/db.sqlite"
tailnet_domain = "tailnet.example"
trusted_proxies = ["127.0.0.1/32", "10.0.0.0/8"]
dns_split = ["corp.example.=10.0.0.53"]
stun_port = 3478

[tls]
mode = "files"
cert_file = "/data/cert.pem"
key_file = "/data/key.pem"
"#;
        let raw: RawConfig = toml::from_str(text).unwrap();
        assert_eq!(raw.listen.unwrap().to_string(), "0.0.0.0:8080");
        assert_eq!(raw.listen_http.unwrap().to_string(), "0.0.0.0:80");
        assert_eq!(
            raw.key_file.as_deref(),
            Some(std::path::Path::new("/data/key"))
        );
        assert_eq!(raw.tailnet_domain.as_deref(), Some("tailnet.example"));
        assert_eq!(
            raw.trusted_proxies,
            Some(vec!["127.0.0.1/32".to_string(), "10.0.0.0/8".to_string()])
        );
        assert_eq!(raw.stun_port, Some(3478));
        assert_eq!(raw.tls.mode, "files");
        assert_eq!(
            raw.tls.cert_file.as_deref(),
            Some(std::path::Path::new("/data/cert.pem"))
        );
    }

    #[test]
    fn default_config_matches_historical_defaults() {
        let defaults = ServerConfig::default();
        assert_eq!(defaults.listen.to_string(), DEFAULT_LISTEN_ADDR);
        assert_eq!(defaults.key_file, PathBuf::from("crabscale.key"));
        assert_eq!(defaults.derp_region_id, 1);
        assert_eq!(defaults.derp_hostname, "derp.example.com");
        assert_eq!(defaults.stun_port, 3478);
        assert_eq!(defaults.register_burst, DEFAULT_REGISTER_BURST);
        assert!(defaults.magic_dns);
    }
}
