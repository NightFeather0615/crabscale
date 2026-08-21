//! Server library: control router, machine key persistence, and wiring.
//!
//! This crate owns the server-side control plane: the outer `/key` endpoint,
//! the inner `/machine/*` router served over HTTP/2-over-Noise, and the
//! persisted server machine key.

pub mod bootstrap_dns;
pub mod http;
pub mod key;
pub mod oidc;
pub mod rate_limit;
pub mod router;
pub mod stun;

pub use bootstrap_dns::BootstrapDns;
pub use http::{ServerHandle, serve, serve_on_addr};
pub use key::{DEFAULT_KEY_FILE, ServerKey, load_or_create_machine_key, persist_machine_key};
pub use oidc::{
    DEFAULT_OIDC_FLOW_LIMIT, DEFAULT_OIDC_FLOW_TTL_SECONDS, OidcClient, OidcConfig, OidcError,
    OidcFlow, OidcFlowStore,
};
pub use rate_limit::{
    DEFAULT_MAX_RATE_KEYS, DEFAULT_REGISTER_BURST, DEFAULT_REGISTER_RATE_PER_MIN,
    DEFAULT_TS2021_BURST, DEFAULT_TS2021_RATE_PER_MIN, RateLimitConfig, RateLimiter,
};
pub use router::{ControlRouter, serve_control_as};
pub use stun::{StunServerHandle, serve_stun};
