//! Server library: control router, machine key persistence, and wiring.
//!
//! This crate owns the server-side control plane: the outer `/key` endpoint,
//! the inner `/machine/*` router served over HTTP/2-over-Noise, and the
//! persisted server machine key.

pub mod bootstrap_dns;
pub mod config;
pub mod http;
pub mod key;
pub mod oidc;
pub mod proxy;
pub mod rate_limit;
pub mod router;
pub mod stun;
pub mod tls;

pub use bootstrap_dns::BootstrapDns;
pub use config::{CliOverrides, ENV_PREFIX, RawConfig, ServerConfig};
pub use http::{
    ServerHandle, ServerOptions, serve, serve_on_addr, serve_on_addr_with_options,
    serve_redirect_on_addr,
};
pub use key::{DEFAULT_KEY_FILE, ServerKey, load_or_create_machine_key, persist_machine_key};
pub use oidc::{
    DEFAULT_OIDC_FLOW_LIMIT, DEFAULT_OIDC_FLOW_TTL_SECONDS, OidcClient, OidcConfig, OidcError,
    OidcFlow, OidcFlowStore,
};
pub use proxy::TrustedProxies;
pub use rate_limit::{
    DEFAULT_MAX_RATE_KEYS, DEFAULT_REGISTER_BURST, DEFAULT_REGISTER_RATE_PER_MIN,
    DEFAULT_TS2021_BURST, DEFAULT_TS2021_RATE_PER_MIN, RateLimitConfig, RateLimiter,
};
pub use router::{ControlRouter, serve_control_as};
pub use stun::{StunServerHandle, serve_stun};
pub use tls::{TlsAcceptor, TlsSettings, load_tls_acceptor};
