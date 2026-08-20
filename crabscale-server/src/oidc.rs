//! OpenID Connect (OIDC) relying-party support for interactive registration.
//!
//! M2-07 turns the browser approval source into an OIDC provider. The browser
//! opens the `AuthURL` from `Spec-Registration` (`/register/{authId}`), which
//! redirects to the provider when OIDC is configured. The provider sends the
//! user back to `/oidc/callback`; this module validates the CSRF `state` and
//! `nonce`, exchanges the authorization code for tokens, verifies the ID
//! token (`iss`, `aud`, `exp`, signature), and returns the verified user
//! profile so the control plane can upsert it and approve the pending
//! registration through the same auth cache the CLI uses.
//!
//! Design notes:
//! - The discovery document is fetched once at startup and validated against
//!   the configured issuer before the server starts accepting connections.
//! - The OIDC flow store is a bounded, TTL'd, single-use map keyed by the
//!   CSRF `state`. A callback may only consume a state once, so replaying or
//!   reusing an old authorization response is rejected.
//! - ID tokens are verified with `jsonwebtoken`: `RS256` (and friends) via
//!   the issuer's JWKS, and `HS256` via the shared client secret (used by the
//!   mock provider in tests).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crabscale_control::{ControlError, OidcProfile, generate_secret};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode_header};
use serde::Deserialize;
use ureq::Agent;
use ureq::config::Config as UreqConfig;
use url::Url;

/// Default time-to-live for an authorized-code flow's CSRF state.
pub const DEFAULT_OIDC_FLOW_TTL_SECONDS: i64 = 10 * 60;
/// Default maximum number of outstanding OIDC flows kept in memory.
pub const DEFAULT_OIDC_FLOW_LIMIT: usize = 512;
/// How long a fetched JWKS set is trusted before it is refetched.
const JWKS_CACHE_TTL: Duration = Duration::from_secs(3600);
/// Default outbound HTTP timeout for discovery, token, and JWKS requests.
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// Configuration for an OpenID Connect relying party.
#[derive(Clone, Debug)]
pub struct OidcConfig {
    /// Issuer URL, e.g. `https://accounts.example.com`.
    pub issuer: String,
    /// OAuth client id registered with the provider.
    pub client_id: String,
    /// OAuth client secret registered with the provider.
    pub client_secret: String,
    /// Callback URL the provider redirects to after login.
    pub redirect_uri: String,
    /// Space-separated OAuth scopes; an identity scope is required.
    pub scope: String,
}

/// Errors produced by the OIDC relying party.
#[derive(Debug)]
pub enum OidcError {
    /// An outbound HTTP operation (discovery, token, JWKS) failed.
    Network(String),
    /// The provider discovery document was missing or inconsistent.
    Discovery(String),
    /// The token endpoint rejected or failed the code exchange.
    Token(String),
    /// The ID token failed signature or claim validation.
    InvalidIdToken(String),
    /// A CSRF state was unknown, expired, or already consumed.
    InvalidState,
    /// The underlying control plane rejected the profile or approval.
    Control(ControlError),
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "oidc network error: {e}"),
            Self::Discovery(e) => write!(f, "oidc discovery error: {e}"),
            Self::Token(e) => write!(f, "oidc token exchange error: {e}"),
            Self::InvalidIdToken(e) => write!(f, "invalid OIDC ID token: {e}"),
            Self::InvalidState => write!(f, "invalid, expired, or reused OIDC state"),
            Self::Control(e) => write!(f, "oidc control error: {e}"),
        }
    }
}

impl std::error::Error for OidcError {}

impl From<ControlError> for OidcError {
    fn from(e: ControlError) -> Self {
        Self::Control(e)
    }
}

/// The subset of the OpenID Connect discovery document we consume.
#[derive(Debug, Clone, Deserialize)]
struct ProviderMetadata {
    /// Must exactly match the configured issuer.
    issuer: String,
    #[serde(default)]
    authorization_endpoint: String,
    #[serde(default)]
    token_endpoint: String,
    #[serde(default)]
    jwks_uri: String,
    #[serde(default)]
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}

/// The token endpoint response; only `id_token` is required by this flow.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: String,
}

/// Claims we read from a verified ID token.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// A cached JWKS set with its fetch time.
struct JwkCache {
    fetched_at: SystemTime,
    set: JwkSet,
}

/// An OIDC relying-party client bound to a discovered provider.
pub struct OidcClient {
    config: OidcConfig,
    metadata: ProviderMetadata,
    agent: Agent,
    jwks_cache: Mutex<Option<JwkCache>>,
}

impl OidcClient {
    /// Fetch and validate the provider's discovery document.
    ///
    /// Fails if the document cannot be fetched, the declared issuer does not
    /// match the configured issuer, or required endpoints are missing. This is
    /// called at server startup so a misconfiguration aborts startup.
    pub fn discover(config: OidcConfig) -> Result<Self, OidcError> {
        if config.issuer.trim().is_empty() {
            return Err(OidcError::Discovery("issuer must not be empty".to_string()));
        }
        if config.client_id.trim().is_empty() {
            return Err(OidcError::Discovery(
                "client id must not be empty".to_string(),
            ));
        }
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        );
        let agent = Agent::new_with_config(
            UreqConfig::builder()
                .timeout_global(Some(HTTP_TIMEOUT))
                .build(),
        );
        let body = match agent.get(&discovery_url).call() {
            Ok(resp) => resp
                .into_body()
                .read_to_string()
                .map_err(|e| OidcError::Network(e.to_string()))?,
            Err(e) => return Err(OidcError::Network(format!("discovery request failed: {e}"))),
        };
        let metadata: ProviderMetadata = serde_json::from_str(&body)
            .map_err(|e| OidcError::Discovery(format!("invalid discovery document: {e}")))?;
        if metadata.issuer != config.issuer {
            return Err(OidcError::Discovery(format!(
                "issuer mismatch: configured `{}` but provider advertises `{}`",
                config.issuer, metadata.issuer
            )));
        }
        if metadata.authorization_endpoint.is_empty() || metadata.token_endpoint.is_empty() {
            return Err(OidcError::Discovery(
                "discovery document is missing authorization or token endpoint".to_string(),
            ));
        }
        Ok(Self {
            config,
            metadata,
            agent,
            jwks_cache: Mutex::new(None),
        })
    }

    /// The discovered issuer, for logging.
    pub fn issuer(&self) -> &str {
        &self.metadata.issuer
    }

    /// Build the provider authorization URL for a new CSRF state and nonce.
    pub fn authorization_url(&self, state: &str, nonce: &str) -> Result<String, OidcError> {
        let mut url = Url::parse(&self.metadata.authorization_endpoint)
            .map_err(|e| OidcError::Discovery(format!("invalid authorization endpoint: {e}")))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &self.config.scope)
            .append_pair("state", state)
            .append_pair("nonce", nonce);
        Ok(url.to_string())
    }

    /// Exchange an authorization code and return the verified user profile.
    ///
    /// Verifies the ID token signature and the `iss`, `aud`, `exp`, and
    /// `nonce` claims against the flow the state was issued for.
    pub fn complete(&self, flow: &OidcFlow, code: &str) -> Result<OidcProfile, OidcError> {
        let id_token = self.exchange_code(code)?;
        self.validate_id_token(flow, &id_token)
    }

    fn exchange_code(&self, code: &str) -> Result<String, OidcError> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];
        let body = match self
            .agent
            .post(&self.metadata.token_endpoint)
            .send_form(form)
        {
            Ok(resp) => resp
                .into_body()
                .read_to_string()
                .map_err(|e| OidcError::Network(e.to_string()))?,
            Err(ureq::Error::StatusCode(code)) => {
                return Err(OidcError::Token(format!(
                    "provider returned HTTP {code} during code exchange"
                )));
            }
            Err(e) => {
                return Err(OidcError::Network(format!("token request failed: {e}")));
            }
        };
        let token: TokenResponse = serde_json::from_str(&body)
            .map_err(|e| OidcError::Token(format!("invalid token response: {e}")))?;
        if token.id_token.is_empty() {
            return Err(OidcError::Token(
                "token response contains no id_token".to_string(),
            ));
        }
        Ok(token.id_token)
    }

    fn validate_id_token(&self, flow: &OidcFlow, id_token: &str) -> Result<OidcProfile, OidcError> {
        let header = decode_header(id_token)
            .map_err(|e| OidcError::InvalidIdToken(format!("cannot parse header: {e}")))?;
        let (key, alg) = match header.alg {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                let set = self.jwks()?;
                let kid = header.kid.clone().ok_or_else(|| {
                    OidcError::InvalidIdToken("RSA token missing kid".to_string())
                })?;
                let jwk = set
                    .find(&kid)
                    .ok_or_else(|| OidcError::InvalidIdToken(format!("no JWK for kid {kid}")))?;
                (
                    DecodingKey::from_jwk(jwk)
                        .map_err(|e| OidcError::InvalidIdToken(format!("bad JWK: {e}")))?,
                    header.alg,
                )
            }
            Algorithm::HS256 => (
                DecodingKey::from_secret(self.config.client_secret.as_bytes()),
                Algorithm::HS256,
            ),
            other => {
                return Err(OidcError::InvalidIdToken(format!(
                    "unsupported signing algorithm {other:?}"
                )));
            }
        };
        // Cross-check against the algorithms the provider declares it uses.
        if let Some(supported) = &self.metadata.id_token_signing_alg_values_supported {
            if !supported.iter().any(|a| a == alg_name(alg)) {
                return Err(OidcError::InvalidIdToken(format!(
                    "provider does not support algorithm {}",
                    alg_name(alg)
                )));
            }
        }
        let mut validation = Validation::new(alg);
        validation.set_audience(&[self.config.client_id.as_str()]);
        validation.set_issuer(&[self.metadata.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        let data = jsonwebtoken::decode::<IdTokenClaims>(id_token, &key, &validation)
            .map_err(|e| OidcError::InvalidIdToken(format!("token validation failed: {e}")))?;
        if data.claims.nonce.as_deref() != Some(flow.nonce.as_str()) {
            return Err(OidcError::InvalidIdToken("nonce mismatch".to_string()));
        }
        let email = data
            .claims
            .email
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| data.claims.sub.clone());
        let display_name = data
            .claims
            .name
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| email.clone());
        Ok(OidcProfile {
            subject: data.claims.sub,
            email,
            display_name,
        })
    }

    /// Fetch (with a short cache) the issuer's JSON Web Key Set.
    fn jwks(&self) -> Result<JwkSet, OidcError> {
        if let Some(cached) = self.jwks_cache.lock().unwrap().as_ref() {
            if cached.fetched_at.elapsed().ok() < Some(JWKS_CACHE_TTL) {
                return Ok(cached.set.clone());
            }
        }
        if self.metadata.jwks_uri.is_empty() {
            return Err(OidcError::InvalidIdToken(
                "provider did not advertise a JWKS URI".to_string(),
            ));
        }
        let body = match self.agent.get(&self.metadata.jwks_uri).call() {
            Ok(resp) => resp
                .into_body()
                .read_to_string()
                .map_err(|e| OidcError::Network(e.to_string()))?,
            Err(e) => {
                return Err(OidcError::Network(format!("JWKS request failed: {e}")));
            }
        };
        let set: JwkSet = serde_json::from_str(&body)
            .map_err(|e| OidcError::InvalidIdToken(format!("invalid JWKS: {e}")))?;
        if set.keys.is_empty() {
            return Err(OidcError::InvalidIdToken(
                "JWKS contains no keys".to_string(),
            ));
        }
        *self.jwks_cache.lock().unwrap() = Some(JwkCache {
            fetched_at: SystemTime::now(),
            set: set.clone(),
        });
        Ok(set)
    }
}

/// An outstanding authorization-code flow bound to a pending registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidcFlow {
    /// The pending registration auth id this flow approves.
    pub auth_id: String,
    /// The nonce the ID token must echo to prevent replay.
    pub nonce: String,
    /// Unix seconds after which the flow may no longer be consumed.
    pub expires_at: i64,
}

/// A bounded, TTL'd, single-use store mapping CSRF states to [`OidcFlow`]s.
pub struct OidcFlowStore {
    entries: HashMap<String, OidcFlow>,
    order: VecDeque<String>,
    limit: usize,
    ttl_seconds: i64,
}

impl OidcFlowStore {
    /// Create an empty store with the given bounds.
    pub fn new(limit: usize, ttl_seconds: i64) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            limit,
            ttl_seconds,
        }
    }

    /// Start a flow for a pending registration and return its CSRF state.
    ///
    /// The state and nonce are unguessable. The store evicts the
    /// least-recently-used flow when the bound is exceeded.
    pub fn begin(&mut self, auth_id: &str, now: i64) -> (String, OidcFlow) {
        let state = generate_secret();
        let flow = OidcFlow {
            auth_id: auth_id.to_string(),
            nonce: generate_secret(),
            expires_at: now + self.ttl_seconds,
        };
        self.insert(state.clone(), flow.clone());
        (state, flow)
    }

    /// Consume a CSRF state, returning its flow if valid and not expired.
    ///
    /// Consumption removes the entry, so a replayed callback cannot reuse it.
    pub fn take(&mut self, state: &str, now: i64) -> Option<OidcFlow> {
        let flow = self.entries.remove(state)?;
        self.order.retain(|s| s != state);
        if flow.expires_at <= now {
            return None;
        }
        Some(flow)
    }

    /// Number of outstanding flows.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn insert(&mut self, state: String, flow: OidcFlow) {
        if let Some(old) = self.entries.get_mut(&state) {
            *old = flow;
            self.touch(&state);
            return;
        }
        if self.entries.len() >= self.limit {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(state.clone());
        self.entries.insert(state, flow);
    }

    fn touch(&mut self, state: &str) {
        if let Some(pos) = self.order.iter().position(|s| s == state) {
            let id = self.order.remove(pos).unwrap();
            self.order.push_back(id);
        }
    }
}

/// Current time as Unix seconds.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// The JWS algorithm name string for the cross-check against the provider's
/// advertised `id_token_signing_alg_values_supported`.
fn alg_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::HS256 => "HS256",
        Algorithm::HS384 => "HS384",
        Algorithm::HS512 => "HS512",
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        Algorithm::EdDSA => "EdDSA",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_store_issues_and_consumes_once() {
        let mut store = OidcFlowStore::new(10, 60);
        let (state, flow) = store.begin("auth-1", 100);
        assert_eq!(flow.auth_id, "auth-1");
        let taken = store.take(&state, 100).unwrap();
        assert_eq!(taken, flow);
        assert!(store.take(&state, 100).is_none(), "reuse must be rejected");
    }

    #[test]
    fn flow_store_rejects_expired_state() {
        let mut store = OidcFlowStore::new(10, 60);
        let (state, _flow) = store.begin("auth-1", 100);
        // expires_at = 160; the state is still valid one second before.
        assert!(store.take(&state, 159).is_some(), "within ttl");
        // A fresh flow is rejected on or after its expiry instant.
        let (state2, _flow2) = store.begin("auth-2", 100);
        assert!(store.take(&state2, 160).is_none(), "past ttl");
    }

    #[test]
    fn flow_store_evicts_least_recently_used() {
        let mut store = OidcFlowStore::new(2, 60);
        store.begin("a", 0);
        store.begin("b", 0);
        store.begin("c", 0);
        assert_eq!(store.len(), 2);
        assert_eq!(store.entries.len(), 2);
    }

    #[test]
    fn authorization_url_contains_flow_params() {
        let config = OidcConfig {
            issuer: "https://issuer.example".to_string(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: "https://control.example/oidc/callback".to_string(),
            scope: "openid profile email".to_string(),
        };
        let client = OidcClient {
            config: config.clone(),
            metadata: ProviderMetadata {
                issuer: config.issuer.clone(),
                authorization_endpoint: "https://issuer.example/auth".to_string(),
                token_endpoint: "https://issuer.example/token".to_string(),
                jwks_uri: "https://issuer.example/jwks".to_string(),
                id_token_signing_alg_values_supported: None,
            },
            agent: Agent::new_with_config(
                UreqConfig::builder()
                    .timeout_global(Some(HTTP_TIMEOUT))
                    .build(),
            ),
            jwks_cache: Mutex::new(None),
        };
        let url = client.authorization_url("state-1", "nonce-1").unwrap();
        let parsed = Url::parse(&url).unwrap();
        let pairs: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["client_id"], "client");
        assert_eq!(
            pairs["redirect_uri"],
            "https://control.example/oidc/callback"
        );
        assert_eq!(pairs["scope"], "openid profile email");
        assert_eq!(pairs["state"], "state-1");
        assert_eq!(pairs["nonce"], "nonce-1");
    }

    #[test]
    fn now_unix_is_positive() {
        assert!(now_unix() > 1_700_000_000);
    }
}
