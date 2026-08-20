//! Control plane: registration, MapRequest handling, and MapResponse
//! building backed by a durable domain model.
//!
//! This crate owns the server-side domain logic that sits behind the
//! `/machine/register` and `/machine/map` endpoints. It persists users,
//! logins, nodes, pre-auth keys, policies, and sessions through the [`Store`]
//! trait, assigns tailnet IPs with a random allocator, and builds the first
//! complete MapResponse frame.

mod ip_allocator;
mod model;
mod pending;
mod preauth;
mod store;
mod time;

use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crabscale_proto::{
    DerpMap, FilterRule, MachineKey, MapRequest, MapResponse, NetPortRange, Node, NodeKey,
    RegisterRequest, RegisterResponse, UserProfile, encode_map_response_frame,
};

pub use ip_allocator::{IpAllocator, IpAllocatorError};
pub use model::{Login, Node as DomainNode, Policy, PreAuthKey, Session, User};
pub use pending::{
    DEFAULT_PENDING_CACHE_LIMIT, DEFAULT_PENDING_TTL_SECONDS, PendingRegistration, PendingVerdict,
};
pub use preauth::{
    AUTH_KEY_PREFIX, format_auth_key, generate_secret, hash_secret, parse_auth_key, verify_secret,
};
pub use store::{SqliteStore, Store, StoreError};

/// Minimum capability version accepted by the control plane.
pub const MIN_SUPPORTED_CAPVER: u32 = 113;

/// Default IPv4 tailnet prefix.
pub const DEFAULT_IPV4_PREFIX: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
/// Default IPv4 prefix length.
pub const DEFAULT_IPV4_PREFIX_LEN: u8 = 10;
/// Default IPv6 tailnet prefix.
pub const DEFAULT_IPV6_PREFIX: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0);
/// Default IPv6 prefix length.
pub const DEFAULT_IPV6_PREFIX_LEN: u8 = 48;

/// Static timestamp used for the M0 static MapResponse. A real clock is
/// layered on in M1 when persistence and sessions are introduced.
const CONTROL_TIME: &str = "2026-08-20T00:00:00Z";

/// Configuration for the control plane.
#[derive(Clone, Debug)]
pub struct ControlConfig {
    /// The single static pre-auth key accepted by this server.
    pub auth_key: String,
    /// Tailnet domain, e.g. `tailnet.example`.
    pub tailnet_domain: String,
    /// DERP regions advertised to clients.
    pub derp_map: DerpMap,
    /// User ID assigned to registered nodes.
    pub user_id: u64,
    /// Login ID assigned to registered nodes.
    pub login_id: u64,
    /// Login name shown in user profiles.
    pub user_login_name: String,
    /// Display name shown in user profiles.
    pub user_display_name: String,
    /// IPv4 prefix used for node address allocation.
    pub ipv4_prefix: Ipv4Addr,
    /// IPv4 prefix length.
    pub ipv4_prefix_len: u8,
    /// IPv6 prefix used for node address allocation.
    pub ipv6_prefix: Ipv6Addr,
    /// IPv6 prefix length.
    pub ipv6_prefix_len: u8,
    /// Base URL used to build interactive registration AuthURLs.
    pub server_url: String,
    /// Time-to-live in seconds for pending interactive registrations.
    pub pending_ttl_seconds: i64,
    /// Maximum number of pending interactive registrations kept in memory.
    pub pending_cache_limit: usize,
}

impl Default for ControlConfig {
    fn default() -> Self {
        let mut derp_map = DerpMap::default();
        derp_map.regions.insert(
            "1".to_string(),
            crabscale_proto::DerpRegion {
                region_id: 1,
                region_code: "test".to_string(),
                region_name: "Test".to_string(),
                nodes: vec![crabscale_proto::DerpNode {
                    name: "test-1".to_string(),
                    region_id: 1,
                    host_name: "derp.example.com".to_string(),
                    derp_port: 443,
                    stun_port: 3478,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        Self {
            auth_key: "hskey-auth-test-secret".to_string(),
            tailnet_domain: "tailnet.example".to_string(),
            derp_map,
            user_id: 1,
            login_id: 1,
            user_login_name: "owner@example.com".to_string(),
            user_display_name: "Owner".to_string(),
            ipv4_prefix: DEFAULT_IPV4_PREFIX,
            ipv4_prefix_len: DEFAULT_IPV4_PREFIX_LEN,
            ipv6_prefix: DEFAULT_IPV6_PREFIX,
            ipv6_prefix_len: DEFAULT_IPV6_PREFIX_LEN,
            server_url: "https://tailnet.example".to_string(),
            pending_ttl_seconds: DEFAULT_PENDING_TTL_SECONDS,
            pending_cache_limit: DEFAULT_PENDING_CACHE_LIMIT,
        }
    }
}

/// Errors returned by the control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// The node key is unknown or the machine key does not match.
    NotFound,
    /// The client capability version is below the supported minimum.
    UnsupportedVersion(u32),
    /// A persistence operation failed.
    Store(String),
    /// The IP allocator could not find a free address.
    IpAllocation,
    /// JSON serialization failed.
    Json,
    /// MapResponse framing failed.
    Frame,
    /// zstd compression failed.
    Zstd,
    /// A pre-auth key prefix is invalid.
    InvalidAuthKey(String),
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "node not found or machine key mismatch"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported capability version {v}"),
            Self::Store(e) => write!(f, "store error: {e}"),
            Self::IpAllocation => write!(f, "no free tailnet IP available"),
            Self::Json => write!(f, "failed to serialize JSON"),
            Self::Frame => write!(f, "failed to frame MapResponse"),
            Self::Zstd => write!(f, "failed to compress MapResponse"),
            Self::InvalidAuthKey(e) => write!(f, "invalid auth key: {e}"),
        }
    }
}

impl std::error::Error for ControlError {}

/// The result of handling a MapRequest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapOutcome {
    /// A lite update: respond `200` with an empty body.
    LiteUpdate,
    /// A single framed MapResponse body.
    FullFrame(Vec<u8>),
    /// A streaming response: first frame followed by keepalives.
    Stream {
        /// The first complete MapResponse frame.
        first_frame: Vec<u8>,
        /// Whether the client requested keepalives.
        keep_alive: bool,
        /// Whether frames should be zstd-compressed.
        compress: bool,
    },
}

/// Control plane shared by the server router.
pub struct ControlPlane {
    config: ControlConfig,
    store: Arc<dyn Store>,
    pending: Mutex<pending::PendingCache>,
}

impl Clone for ControlPlane {
    fn clone(&self) -> Self {
        // The store is shared via `Arc`; the pending cache is a read-through
        // cache backed by the store, so a fresh cache is created on clone.
        Self::with_store(self.config.clone(), self.store.clone())
    }
}

impl ControlPlane {
    /// Create a control plane with an in-memory SQLite store.
    ///
    /// Panics if the in-memory store cannot be created; use [`Self::try_new`]
    /// when the caller needs to handle that failure.
    pub fn new(config: ControlConfig) -> Self {
        Self::try_new(config).expect("in-memory SQLite store")
    }

    /// Create a control plane with an in-memory SQLite store, returning an
    /// error if the store cannot be initialized.
    pub fn try_new(config: ControlConfig) -> Result<Self, StoreError> {
        let store = SqliteStore::open_in_memory()?;
        Ok(Self::with_store(config, Arc::new(store)))
    }

    /// Open a control plane backed by a SQLite database file.
    pub fn open_sqlite(config: ControlConfig, path: &Path) -> Result<Self, StoreError> {
        let store = SqliteStore::open(path)?;
        Ok(Self::with_store(config, Arc::new(store)))
    }

    /// Create a control plane with an explicit store.
    pub fn with_store(config: ControlConfig, store: Arc<dyn Store>) -> Self {
        let pending = Mutex::new(pending::PendingCache::new(config.pending_cache_limit));
        Self {
            config,
            store,
            pending,
        }
    }

    /// Register a node key for the given Noise machine key.
    ///
    /// If the node already exists and the machine key matches, the existing
    /// registration state is returned without consuming the auth key. This
    /// makes client restarts re-register without error.
    pub fn register(
        &self,
        machine_key: MachineKey,
        request: RegisterRequest,
    ) -> Result<RegisterResponse, ControlError> {
        self.ensure_default_user()?;
        self.ensure_bootstrap_key()?;
        let now = time::now_rfc3339();

        // Followup long-poll: return the current verdict for the pending id.
        if !request.followup.is_empty() {
            return self.poll_followup(machine_key, &request, &now);
        }

        if let Some(node) = self
            .store
            .get_node_by_node_key(&request.node_key)
            .map_err(|e| ControlError::Store(e.to_string()))?
        {
            if node.machine_key != machine_key {
                return Ok(
                    self.unauthorized_response("node key is already registered to another machine")
                );
            }

            // A past expiry is a logout; a future expiry is a client trying to
            // extend its own key, which is rejected (Spec-Registration §5).
            if !request.expiry.is_empty() {
                if time::is_past(&request.expiry, &now) {
                    return self.logout_node(node, true);
                }
                if time::is_future(&request.expiry, &now) {
                    return Ok(self.unauthorized_response("clients may not extend their own key"));
                }
            }

            // Existing node with a matching machine key.
            if let Some(auth) = &request.auth {
                if node.machine_authorized {
                    // Restart relogin: already authorized, do not consume the key.
                    return Ok(self.authorized_response());
                }
                if let Some(key) = self.validated_auth_key(auth, &now)? {
                    let mut updated = node;
                    updated.machine_authorized = true;
                    updated.tags = key.tags.clone();
                    updated.ephemeral = key.ephemeral;
                    self.store
                        .upsert_node(&updated)
                        .map_err(|e| ControlError::Store(e.to_string()))?;
                    if !key.reusable {
                        self.store
                            .mark_pre_auth_key_used(key.id)
                            .map_err(|e| ControlError::Store(e.to_string()))?;
                    }
                    return Ok(self.authorized_response());
                }
                // Invalid auth key: fall through to interactive registration.
            } else if node.machine_authorized {
                // No auth key supplied and already authorized: return current state.
                return Ok(self.authorized_response());
            }

            // Existing but unauthorized node: start interactive registration.
            return self.start_interactive(machine_key, request, &now);
        }

        // New node registration.
        if !request.expiry.is_empty() {
            if time::is_past(&request.expiry, &now) {
                return Ok(self.expired_response("node key is expired"));
            }
            if time::is_future(&request.expiry, &now) {
                return Ok(self.unauthorized_response("clients may not extend their own key"));
            }
        }
        if let Some(auth) = &request.auth {
            if let Some(key) = self.validated_auth_key(auth, &now)? {
                let node = self.create_node_from_request(
                    machine_key,
                    &request,
                    key.user_id,
                    key.tags.clone(),
                    key.ephemeral,
                    &now,
                )?;
                self.store
                    .upsert_node(&node)
                    .map_err(|e| ControlError::Store(e.to_string()))?;
                if !key.reusable {
                    self.store
                        .mark_pre_auth_key_used(key.id)
                        .map_err(|e| ControlError::Store(e.to_string()))?;
                }
                return Ok(self.authorized_response());
            }
            // Invalid auth key: fall through to interactive registration.
        }

        // No valid auth key: start interactive registration.
        self.start_interactive(machine_key, request, &now)
    }

    /// Start an interactive registration and return an `AuthURL`.
    fn start_interactive(
        &self,
        machine_key: MachineKey,
        request: RegisterRequest,
        now: &str,
    ) -> Result<RegisterResponse, ControlError> {
        let auth_id = generate_secret();
        let entry = PendingRegistration {
            auth_id: auth_id.clone(),
            machine_key,
            node_key: request.node_key,
            hostinfo: request.hostinfo.clone(),
            expiry: request.expiry.clone(),
            version: request.version,
            ephemeral: request.ephemeral,
            created_at: now.to_string(),
            expires_at: time::now_plus_seconds(self.config.pending_ttl_seconds),
            verdict: PendingVerdict::Pending,
        };
        self.pending.lock().unwrap().insert(entry.clone());
        self.store
            .save_pending(&entry)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        Ok(RegisterResponse {
            machine_authorized: false,
            auth_url: format!("{}/register/{auth_id}", self.config.server_url),
            ..Default::default()
        })
    }

    /// Return the current verdict for a followup registration request.
    ///
    /// The followup path is authenticated by the unguessable auth id and the
    /// original machine key: a different machine key can never authorize a
    /// pending registration (Spec-Registration §6).
    fn poll_followup(
        &self,
        machine_key: MachineKey,
        request: &RegisterRequest,
        now: &str,
    ) -> Result<RegisterResponse, ControlError> {
        let Some(auth_id) = auth_id_from_followup(&request.followup) else {
            return Ok(self.unauthorized_response("invalid followup URL"));
        };
        let Some(entry) = self.get_pending_entry(&auth_id)? else {
            return Ok(self.unauthorized_response("registration expired; start a new registration"));
        };
        if entry.machine_key != machine_key {
            return Ok(self.unauthorized_response("auth id does not match machine key"));
        }
        if time::is_past(&entry.expires_at, now) {
            self.remove_pending_entry(&auth_id);
            return Ok(self.unauthorized_response("registration expired; start a new registration"));
        }
        match entry.verdict {
            PendingVerdict::Pending => Ok(RegisterResponse {
                machine_authorized: false,
                auth_url: format!("{}/register/{}", self.config.server_url, entry.auth_id),
                ..Default::default()
            }),
            PendingVerdict::Rejected => {
                self.remove_pending_entry(&auth_id);
                Ok(self.unauthorized_response("registration rejected"))
            }
            PendingVerdict::Approved { user_id, tags } => {
                self.remove_pending_entry(&auth_id);
                // A duplicate followup after approval must still succeed.
                if let Some(node) = self
                    .store
                    .get_node_by_node_key(&entry.node_key)
                    .map_err(|e| ControlError::Store(e.to_string()))?
                {
                    if node.machine_key == machine_key && node.machine_authorized {
                        return Ok(self.authorized_response());
                    }
                }
                let pending_request = RegisterRequest {
                    version: entry.version,
                    node_key: entry.node_key,
                    expiry: entry.expiry.clone(),
                    hostinfo: entry.hostinfo.clone(),
                    ephemeral: entry.ephemeral,
                    ..Default::default()
                };
                let node = self.create_node_from_request(
                    machine_key,
                    &pending_request,
                    user_id,
                    tags,
                    entry.ephemeral,
                    now,
                )?;
                self.store
                    .upsert_node(&node)
                    .map_err(|e| ControlError::Store(e.to_string()))?;
                Ok(self.authorized_response())
            }
        }
    }

    /// Approve a pending interactive registration for the given user.
    pub fn approve_pending(&self, auth_id: &str, user_name: &str) -> Result<(), ControlError> {
        let now = time::now_rfc3339();
        let Some(mut entry) = self.get_pending_entry(auth_id)? else {
            return Err(ControlError::NotFound);
        };
        if time::is_past(&entry.expires_at, &now) {
            self.remove_pending_entry(auth_id);
            return Err(ControlError::NotFound);
        }
        let user_id = self.resolve_user_id(user_name)?;
        entry.verdict = PendingVerdict::Approved {
            user_id,
            tags: None,
        };
        self.pending.lock().unwrap().insert(entry.clone());
        self.store
            .save_pending(&entry)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        Ok(())
    }

    /// Reject a pending interactive registration.
    pub fn reject_pending(&self, auth_id: &str) -> Result<(), ControlError> {
        let now = time::now_rfc3339();
        let Some(mut entry) = self.get_pending_entry(auth_id)? else {
            return Err(ControlError::NotFound);
        };
        if time::is_past(&entry.expires_at, &now) {
            self.remove_pending_entry(auth_id);
            return Err(ControlError::NotFound);
        }
        entry.verdict = PendingVerdict::Rejected;
        self.pending.lock().unwrap().insert(entry.clone());
        self.store
            .save_pending(&entry)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        Ok(())
    }

    /// Return a copy of a pending registration for the approval page.
    pub fn pending_info(&self, auth_id: &str) -> Option<PendingRegistration> {
        let now = time::now_rfc3339();
        let entry = self.get_pending_entry(auth_id).ok()??;
        if time::is_past(&entry.expires_at, &now) {
            self.remove_pending_entry(auth_id);
            return None;
        }
        Some(entry)
    }

    /// Fetch a pending registration from the durable store, which is the
    /// source of truth so that a separate process (e.g. the CLI opening the
    /// same database) can approve it. The in-memory cache is updated as a
    /// side effect for bounded LRU bookkeeping.
    fn get_pending_entry(
        &self,
        auth_id: &str,
    ) -> Result<Option<PendingRegistration>, ControlError> {
        let entry = self
            .store
            .get_pending(auth_id)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        if let Some(entry) = &entry {
            self.pending.lock().unwrap().insert(entry.clone());
        }
        Ok(entry)
    }

    /// Remove a pending registration from both the in-memory cache and the
    /// durable store.
    fn remove_pending_entry(&self, auth_id: &str) {
        self.pending.lock().unwrap().remove(auth_id);
        let _ = self.store.delete_pending(auth_id);
    }

    /// Resolve a user by login name, creating the user on first approval.
    fn resolve_user_id(&self, user_name: &str) -> Result<i64, ControlError> {
        if let Some(user) = self
            .store
            .get_user_by_login_name(user_name)
            .map_err(|e| ControlError::Store(e.to_string()))?
        {
            return Ok(user.id);
        }
        let user = self
            .store
            .create_user(&User {
                id: 0,
                login_name: user_name.to_string(),
                display_name: user_name.to_string(),
                created_at: time::now_rfc3339(),
            })
            .map_err(|e| ControlError::Store(e.to_string()))?;
        Ok(user.id)
    }

    /// Allocate addresses and build a durable node for a registration.
    fn create_node_from_request(
        &self,
        machine_key: MachineKey,
        request: &RegisterRequest,
        user_id: i64,
        tags: Option<Vec<String>>,
        ephemeral: bool,
        now: &str,
    ) -> Result<DomainNode, ControlError> {
        let nodes = self
            .store
            .list_nodes()
            .map_err(|e| ControlError::Store(e.to_string()))?;
        let mut used_ipv4 = HashSet::new();
        let mut used_ipv6 = HashSet::new();
        for address in nodes.iter().flat_map(|n| n.addresses.iter()) {
            let host = address.split('/').next().unwrap_or(address);
            if let Ok(v4) = host.parse::<Ipv4Addr>() {
                used_ipv4.insert(v4);
            } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
                used_ipv6.insert(v6);
            }
        }

        let allocator = IpAllocator::new(
            self.config.ipv4_prefix,
            self.config.ipv4_prefix_len,
            self.config.ipv6_prefix,
            self.config.ipv6_prefix_len,
        );
        let (ipv4, ipv6) = allocator
            .allocate(&used_ipv4, &used_ipv6)
            .map_err(|_| ControlError::IpAllocation)?;

        let hostname = request
            .hostinfo
            .as_ref()
            .and_then(|h| {
                if h.hostname.is_empty() {
                    None
                } else {
                    Some(h.hostname.clone())
                }
            })
            .unwrap_or_else(|| "node".to_string());

        let addresses = vec![format!("{ipv4}/32"), format!("{ipv6}/128")];
        Ok(DomainNode {
            id: 0,
            stable_id: String::new(),
            name: format!("{hostname}.{}.", self.config.tailnet_domain),
            user_id,
            node_key: request.node_key,
            machine_key,
            disco_key: crabscale_proto::DiscoKey::from_bytes([0u8; 32]),
            addresses: addresses.clone(),
            allowed_ips: Some(addresses),
            endpoints: Vec::new(),
            endpoint_types: Vec::new(),
            home_derp: 1,
            hostinfo: request.hostinfo.clone(),
            created: now.to_string(),
            cap: request.version,
            tags,
            machine_authorized: true,
            ephemeral,
        })
    }

    /// Validate a pre-auth key against the store and current time.
    ///
    /// Returns `None` when the key is malformed, unknown, revoked, expired,
    /// or already consumed (for single-use keys).
    fn validated_auth_key(
        &self,
        auth: &crabscale_proto::RegisterAuth,
        now: &str,
    ) -> Result<Option<PreAuthKey>, ControlError> {
        let Some((prefix, secret)) = parse_auth_key(&auth.auth_key) else {
            return Ok(None);
        };
        let Some(key) = self
            .store
            .get_pre_auth_key(&prefix)
            .map_err(|e| ControlError::Store(e.to_string()))?
        else {
            return Ok(None);
        };
        if !verify_secret(&secret, &key.secret_hash) {
            return Ok(None);
        }
        if key.revoked {
            return Ok(None);
        }
        if let Some(expiration) = &key.expiration {
            if time::is_past(expiration, now) {
                return Ok(None);
            }
        }
        if !key.reusable && key.used {
            return Ok(None);
        }
        Ok(Some(key))
    }

    /// Log out a node.
    ///
    /// Tagged nodes are never logged out (no-expiry). Ephemeral nodes are
    /// deleted entirely. All other nodes are deauthorized and must re-auth.
    pub fn logout(&self, node_key: &NodeKey) -> Result<RegisterResponse, ControlError> {
        let Some(node) = self
            .store
            .get_node_by_node_key(node_key)
            .map_err(|e| ControlError::Store(e.to_string()))?
        else {
            return Ok(self.unauthorized_response("node not found"));
        };
        self.logout_node(node, false)
    }

    /// Apply logout semantics to a node.
    ///
    /// Tagged nodes are never logged out (no-expiry). Ephemeral nodes are
    /// deleted entirely. All other nodes are deauthorized and must re-auth.
    /// When `node_key_expired` is set, the response advertises the expired
    /// node key so the client re-authenticates.
    fn logout_node(
        &self,
        node: DomainNode,
        node_key_expired: bool,
    ) -> Result<RegisterResponse, ControlError> {
        if node.tags.is_some() {
            return Ok(self.authorized_response());
        }
        if node.ephemeral {
            self.store
                .delete_node(&node.node_key)
                .map_err(|e| ControlError::Store(e.to_string()))?;
            return Ok(RegisterResponse {
                machine_authorized: false,
                node_key_expired,
                error: "node logged out".to_string(),
                ..Default::default()
            });
        }
        let mut updated = node;
        updated.machine_authorized = false;
        self.store
            .upsert_node(&updated)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        Ok(RegisterResponse {
            machine_authorized: false,
            node_key_expired,
            error: "node logged out".to_string(),
            ..Default::default()
        })
    }

    /// Create a pre-auth key and return the full `hskey-auth-...` string.
    pub fn create_pre_auth_key(
        &self,
        prefix: &str,
        reusable: bool,
        ephemeral: bool,
        expiration: Option<String>,
        tags: Option<Vec<String>>,
    ) -> Result<String, ControlError> {
        self.ensure_default_user()?;
        if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(ControlError::InvalidAuthKey(
                "prefix must be non-empty alphanumeric".to_string(),
            ));
        }
        let secret = generate_secret();
        let key = PreAuthKey {
            id: 0,
            prefix: prefix.to_string(),
            secret_hash: hash_secret(&secret),
            reusable,
            ephemeral,
            expiration,
            revoked: false,
            used: false,
            tags,
            user_id: self.config.user_id as i64,
            created_at: time::now_rfc3339(),
        };
        self.store
            .create_pre_auth_key(&key)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        Ok(format_auth_key(prefix, &secret))
    }

    /// List all stored pre-auth keys.
    pub fn list_pre_auth_keys(&self) -> Result<Vec<PreAuthKey>, ControlError> {
        self.store
            .list_pre_auth_keys()
            .map_err(|e| ControlError::Store(e.to_string()))
    }

    /// Revoke a pre-auth key by prefix.
    pub fn revoke_pre_auth_key(&self, prefix: &str) -> Result<(), ControlError> {
        self.store
            .revoke_pre_auth_key(prefix)
            .map_err(|e| ControlError::Store(e.to_string()))
    }

    /// Seed the configured bootstrap auth key if it is not already present.
    fn ensure_bootstrap_key(&self) -> Result<(), ControlError> {
        if self.config.auth_key.is_empty() {
            return Ok(());
        }
        let Some((prefix, secret)) = parse_auth_key(&self.config.auth_key) else {
            return Ok(());
        };
        if self
            .store
            .get_pre_auth_key(&prefix)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .is_some()
        {
            return Ok(());
        }
        let key = PreAuthKey {
            id: 0,
            prefix,
            secret_hash: hash_secret(&secret),
            reusable: true,
            ephemeral: false,
            expiration: None,
            revoked: false,
            used: false,
            tags: None,
            user_id: self.config.user_id as i64,
            created_at: time::now_rfc3339(),
        };
        self.store
            .create_pre_auth_key(&key)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        Ok(())
    }

    fn unauthorized_response(&self, error: &str) -> RegisterResponse {
        RegisterResponse {
            machine_authorized: false,
            error: error.to_string(),
            ..Default::default()
        }
    }

    fn expired_response(&self, error: &str) -> RegisterResponse {
        RegisterResponse {
            machine_authorized: false,
            node_key_expired: true,
            error: error.to_string(),
            ..Default::default()
        }
    }

    fn ensure_default_user(&self) -> Result<(), ControlError> {
        let user_id = self.config.user_id as i64;
        if self
            .store
            .get_user(user_id)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .is_none()
        {
            self.store
                .create_user(&User {
                    id: user_id,
                    login_name: self.config.user_login_name.clone(),
                    display_name: self.config.user_display_name.clone(),
                    created_at: CONTROL_TIME.to_string(),
                })
                .map_err(|e| ControlError::Store(e.to_string()))?;
        }
        let login_id = self.config.login_id as i64;
        if self
            .store
            .get_login(login_id)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .is_none()
        {
            self.store
                .create_login(&Login {
                    id: login_id,
                    user_id,
                    provider: "authkey".to_string(),
                    login_name: self.config.user_login_name.clone(),
                    created_at: CONTROL_TIME.to_string(),
                })
                .map_err(|e| ControlError::Store(e.to_string()))?;
        }
        Ok(())
    }

    /// Handle a MapRequest for the given Noise machine key.
    pub fn handle_map(
        &self,
        machine_key: MachineKey,
        request: MapRequest,
    ) -> Result<MapOutcome, ControlError> {
        if request.version < MIN_SUPPORTED_CAPVER {
            return Err(ControlError::UnsupportedVersion(request.version));
        }

        let mut node = self
            .store
            .get_node_by_node_key(&request.node_key)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .filter(|n| n.machine_key == machine_key)
            .ok_or(ControlError::NotFound)?;

        let streaming = request.stream;
        let lite_update = !streaming && request.omit_peers && !request.read_only;

        // The disco key is only carried in MapRequest, not RegisterRequest, so
        // apply it unconditionally: a streaming-first client still needs its
        // real disco key advertised in the first MapResponse (Spec-NetMap §3).
        // The read-only rule below is scoped to Hostinfo and Endpoints only.
        node.disco_key = request.disco_key;

        // Streaming requests (version >= 68) are read-only for Hostinfo and
        // Endpoints: they must not clear or clobber the state a client already
        // reported through a non-streaming update. The `version >= 68` clause
        // is redundant today because handle_map rejects versions below
        // MIN_SUPPORTED_CAPVER, but it documents the spec rule.
        let read_only = streaming && request.version >= 68;
        if !read_only {
            if let Some(hostinfo) = &request.hostinfo {
                node.hostinfo = Some(hostinfo.clone());
                if let Some(net_info) = &hostinfo.net_info {
                    if net_info.preferred_derp != 0 {
                        node.home_derp = net_info.preferred_derp;
                    }
                }
            }
            node.endpoints = request.endpoints.clone();
            node.endpoint_types = request.endpoint_types.clone();
        }
        self.store
            .upsert_node(&node)
            .map_err(|e| ControlError::Store(e.to_string()))?;

        if lite_update {
            return Ok(MapOutcome::LiteUpdate);
        }

        let proto_node = node.to_proto();
        let compress = request.compress == "zstd";
        let response = self.build_initial_map(&proto_node, &request)?;
        let frame = self.encode_frame(&response, compress)?;

        if streaming {
            Ok(MapOutcome::Stream {
                first_frame: frame,
                keep_alive: request.keep_alive,
                compress,
            })
        } else {
            Ok(MapOutcome::FullFrame(frame))
        }
    }

    /// Build the first complete MapResponse for a node.
    ///
    /// The peer list is built from every other registered node, sorted by node
    /// ID, and user profiles are emitted for the requesting user and each peer
    /// user (Spec-NetMap section 3).
    pub fn build_initial_map(
        &self,
        node: &Node,
        _request: &MapRequest,
    ) -> Result<MapResponse, ControlError> {
        let mut packet_filters = BTreeMap::new();
        packet_filters.insert(
            "base".to_string(),
            vec![FilterRule {
                src_ips: vec!["*".to_string()],
                dst_ports: vec![NetPortRange {
                    first: 0,
                    last: 65535,
                }],
                ..Default::default()
            }],
        );

        let mut peers = Vec::new();
        let mut user_ids = std::collections::BTreeSet::new();
        user_ids.insert(self.config.user_id as i64);
        for stored in self
            .store
            .list_nodes()
            .map_err(|e| ControlError::Store(e.to_string()))?
        {
            if stored.node_key == node.key {
                continue;
            }
            user_ids.insert(stored.user_id);
            peers.push(stored.to_proto());
        }
        // Spec-NetMap section 4: keep peer arrays sorted by node ID.
        peers.sort_by_key(|p| p.id);

        let mut user_profiles = Vec::new();
        for user_id in user_ids {
            let Some(user) = self
                .store
                .get_user(user_id)
                .map_err(|e| ControlError::Store(e.to_string()))?
            else {
                continue;
            };
            user_profiles.push(UserProfile {
                id: user.id as u64,
                login_name: user.login_name,
                display_name: user.display_name,
                ..Default::default()
            });
        }

        Ok(MapResponse {
            node: Some(node.clone()),
            derp_map: Some(self.config.derp_map.clone()),
            domain: self.config.tailnet_domain.clone(),
            peers: Some(peers),
            packet_filters: Some(packet_filters),
            user_profiles,
            control_time: CONTROL_TIME.to_string(),
            ..Default::default()
        })
    }

    /// Serialize and frame a MapResponse, optionally zstd-compressing the
    /// JSON payload first.
    pub fn encode_frame(
        &self,
        response: &MapResponse,
        compress: bool,
    ) -> Result<Vec<u8>, ControlError> {
        let json = serde_json::to_vec(response).map_err(|_| ControlError::Json)?;
        let payload = if compress {
            zstd::stream::encode_all(&json[..], 0).map_err(|_| ControlError::Zstd)?
        } else {
            json
        };
        encode_map_response_frame(&payload).map_err(|_| ControlError::Frame)
    }

    /// Build a keepalive frame, optionally zstd-compressed.
    pub fn keepalive_frame(&self, compress: bool) -> Result<Vec<u8>, ControlError> {
        let response = MapResponse {
            keep_alive: true,
            ..Default::default()
        };
        self.encode_frame(&response, compress)
    }

    fn authorized_response(&self) -> RegisterResponse {
        RegisterResponse {
            user: self.config.user_id,
            login: self.config.login_id,
            machine_authorized: true,
            ..Default::default()
        }
    }
}

/// Extract the auth id from a followup URL of the form
/// `https://<server>/register/<authId>`.
pub fn auth_id_from_followup(followup: &str) -> Option<String> {
    let marker = "/register/";
    let idx = followup.rfind(marker)?;
    let id = &followup[idx + marker.len()..];
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabscale_proto::{DiscoKey, Hostinfo, MapRequest, NetInfo, NodeKey, RegisterRequest};

    fn test_plane() -> ControlPlane {
        ControlPlane::new(ControlConfig::default())
    }

    fn test_machine_key() -> MachineKey {
        MachineKey::from_bytes([0x11; 32])
    }

    fn test_node_key() -> NodeKey {
        NodeKey::from_bytes([0x22; 32])
    }

    fn test_register_request() -> RegisterRequest {
        RegisterRequest {
            version: 130,
            node_key: test_node_key(),
            auth: Some(crabscale_proto::RegisterAuth {
                auth_key: "hskey-auth-test-secret".to_string(),
            }),
            hostinfo: Some(Hostinfo {
                hostname: "node1".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn registers_and_re_registers_without_error() {
        let plane = test_plane();
        let first = plane
            .register(test_machine_key(), test_register_request())
            .unwrap();
        assert!(first.machine_authorized);
        let second = plane
            .register(test_machine_key(), test_register_request())
            .unwrap();
        assert!(second.machine_authorized);
    }

    #[test]
    fn invalid_auth_key_starts_interactive_registration() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.auth = Some(crabscale_proto::RegisterAuth {
            auth_key: "wrong".to_string(),
        });
        let response = plane.register(test_machine_key(), request).unwrap();
        assert!(!response.machine_authorized);
        assert!(response.error.is_empty());
        assert!(!response.auth_url.is_empty());
        assert!(response.auth_url.contains("/register/"));
    }

    #[test]
    fn map_returns_complete_first_frame() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();
        let request = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            ..Default::default()
        };
        let outcome = plane.handle_map(test_machine_key(), request).unwrap();
        let MapOutcome::FullFrame(frame) = outcome else {
            panic!("expected full frame");
        };
        let (payload, consumed) = crabscale_proto::decode_map_response_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        let json: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert!(json.get("Node").is_some());
        assert!(json.get("DERPMap").is_some());
        assert!(json.get("Peers").is_some());
        assert_eq!(json["Peers"], serde_json::json!([]));
        assert_eq!(
            json["Node"]["DiscoKey"],
            serde_json::json!(
                "discokey:3333333333333333333333333333333333333333333333333333333333333333"
            )
        );
        assert_eq!(
            json["Node"]["StableID"],
            serde_json::json!("n00000000000000000000001")
        );
    }

    #[test]
    fn initial_map_lists_peers_sorted_and_user_profiles() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();

        // Register a second node with a distinct node and machine key.
        let second_machine = MachineKey::from_bytes([0x12; 32]);
        let second_node = NodeKey::from_bytes([0x23; 32]);
        let mut second_request = test_register_request();
        second_request.node_key = second_node;
        let response = plane.register(second_machine, second_request).unwrap();
        assert!(response.machine_authorized);

        // Map as the first node: the second node must appear as a peer.
        let request = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            ..Default::default()
        };
        let outcome = plane.handle_map(test_machine_key(), request).unwrap();
        let MapOutcome::FullFrame(frame) = outcome else {
            panic!("expected full frame");
        };
        let (payload, consumed) = crabscale_proto::decode_map_response_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        let json: serde_json::Value = serde_json::from_slice(payload).unwrap();

        let peers = json["Peers"].as_array().expect("Peers must be an array");
        assert_eq!(peers.len(), 1, "one peer expected");
        assert_eq!(
            peers[0]["StableID"],
            serde_json::json!("n00000000000000000000002")
        );
        assert_eq!(
            peers[0]["Name"],
            serde_json::json!("node1.tailnet.example.")
        );

        // User profiles include the requesting user (and the peer's user,
        // which is the same default user here).
        let profiles = json["UserProfiles"]
            .as_array()
            .expect("UserProfiles must be an array");
        assert!(!profiles.is_empty());
        assert_eq!(profiles[0]["ID"], serde_json::json!(1));
        assert_eq!(
            profiles[0]["LoginName"],
            serde_json::json!("owner@example.com")
        );
    }

    #[test]
    fn initial_map_peers_are_sorted_by_node_id() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();

        // Register two more nodes so the requesting node has two peers.
        let mut req_b = test_register_request();
        req_b.node_key = NodeKey::from_bytes([0x24; 32]);
        plane
            .register(MachineKey::from_bytes([0x13; 32]), req_b)
            .unwrap();
        let mut req_c = test_register_request();
        req_c.node_key = NodeKey::from_bytes([0x25; 32]);
        plane
            .register(MachineKey::from_bytes([0x14; 32]), req_c)
            .unwrap();

        let request = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            ..Default::default()
        };
        let outcome = plane.handle_map(test_machine_key(), request).unwrap();
        let MapOutcome::FullFrame(frame) = outcome else {
            panic!("expected full frame");
        };
        let (payload, _) = crabscale_proto::decode_map_response_frame(&frame).unwrap();
        let json: serde_json::Value = serde_json::from_slice(payload).unwrap();
        let peers = json["Peers"].as_array().expect("Peers must be an array");
        assert_eq!(peers.len(), 2);
        let ids: Vec<u64> = peers.iter().map(|p| p["ID"].as_u64().unwrap()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "peers must be sorted by node ID");
    }

    #[test]
    fn lite_update_returns_empty() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();
        let request = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            omit_peers: true,
            ..Default::default()
        };
        let outcome = plane.handle_map(test_machine_key(), request).unwrap();
        assert_eq!(outcome, MapOutcome::LiteUpdate);
    }

    #[test]
    fn map_merges_endpoint_types_and_preferred_derp() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();
        let request = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x44; 32]),
            stream: false,
            endpoints: vec!["198.51.100.10:41641".to_string()],
            endpoint_types: vec![2],
            hostinfo: Some(Hostinfo {
                hostname: "node1".to_string(),
                net_info: Some(NetInfo {
                    preferred_derp: 7,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let outcome = plane.handle_map(test_machine_key(), request).unwrap();
        assert!(matches!(outcome, MapOutcome::FullFrame(_)));

        let stored = plane
            .store
            .get_node_by_node_key(&test_node_key())
            .unwrap()
            .expect("node should exist");
        assert_eq!(stored.endpoints, vec!["198.51.100.10:41641"]);
        assert_eq!(stored.endpoint_types, vec![2]);
        assert_eq!(stored.home_derp, 7);
        assert_eq!(stored.disco_key, DiscoKey::from_bytes([0x44; 32]));
        assert_eq!(stored.hostinfo.as_ref().unwrap().hostname, "node1");
    }

    #[test]
    fn streaming_request_is_read_only_and_does_not_clear_state() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();

        // Establish state through a non-streaming update.
        let update = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            endpoints: vec!["1.2.3.4:41641".to_string()],
            endpoint_types: vec![2],
            hostinfo: Some(Hostinfo {
                hostname: "node1".to_string(),
                net_info: Some(NetInfo {
                    preferred_derp: 5,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        plane.handle_map(test_machine_key(), update).unwrap();

        // A streaming request must not clear or clobber endpoints/hostinfo,
        // but the disco key is still applied (Spec-NetMap §3).
        let stream = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x99; 32]),
            stream: true,
            endpoints: Vec::new(),
            endpoint_types: Vec::new(),
            hostinfo: Some(Hostinfo {
                hostname: "other".to_string(),
                net_info: Some(NetInfo {
                    preferred_derp: 9,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let outcome = plane.handle_map(test_machine_key(), stream).unwrap();
        let MapOutcome::Stream { first_frame, .. } = outcome else {
            panic!("expected stream");
        };
        let (payload, consumed) = crabscale_proto::decode_map_response_frame(&first_frame).unwrap();
        assert_eq!(consumed, first_frame.len());
        let json: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert!(json.get("Node").is_some());

        let stored = plane
            .store
            .get_node_by_node_key(&test_node_key())
            .unwrap()
            .expect("node should exist");
        assert_eq!(stored.endpoints, vec!["1.2.3.4:41641"]);
        assert_eq!(stored.endpoint_types, vec![2]);
        assert_eq!(stored.home_derp, 5);
        assert_eq!(stored.disco_key, DiscoKey::from_bytes([0x99; 32]));
        assert_eq!(stored.hostinfo.as_ref().unwrap().hostname, "node1");
    }

    #[test]
    fn streaming_first_request_sets_disco_key_but_not_endpoints_or_hostinfo() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();

        // A real client's first map request is often the streaming long-poll.
        // The disco key must still be applied, while endpoints/hostinfo stay
        // read-only for stream=true, version>=68.
        let stream = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x44; 32]),
            stream: true,
            endpoints: vec!["198.51.100.10:41641".to_string()],
            endpoint_types: vec![2],
            hostinfo: Some(Hostinfo {
                hostname: "other".to_string(),
                net_info: Some(NetInfo {
                    preferred_derp: 9,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let outcome = plane.handle_map(test_machine_key(), stream).unwrap();
        let MapOutcome::Stream { first_frame, .. } = outcome else {
            panic!("expected stream");
        };
        let (payload, consumed) = crabscale_proto::decode_map_response_frame(&first_frame).unwrap();
        assert_eq!(consumed, first_frame.len());
        let json: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert_eq!(
            json["Node"]["DiscoKey"],
            serde_json::json!(
                "discokey:4444444444444444444444444444444444444444444444444444444444444444"
            )
        );

        let stored = plane
            .store
            .get_node_by_node_key(&test_node_key())
            .unwrap()
            .expect("node should exist");
        assert_eq!(stored.disco_key, DiscoKey::from_bytes([0x44; 32]));
        assert!(stored.endpoints.is_empty());
        assert!(stored.endpoint_types.is_empty());
        assert_eq!(stored.home_derp, 1);
        assert_eq!(stored.hostinfo.as_ref().unwrap().hostname, "node1");
    }

    #[test]
    fn lite_update_changes_endpoints_while_stream_open() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();

        // Establish state and open a long-poll stream.
        let update = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            endpoints: vec!["old.example:41641".to_string()],
            endpoint_types: vec![1],
            ..Default::default()
        };
        plane.handle_map(test_machine_key(), update).unwrap();
        let stream = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: true,
            ..Default::default()
        };
        let stream_outcome = plane.handle_map(test_machine_key(), stream).unwrap();
        let MapOutcome::Stream { first_frame, .. } = stream_outcome else {
            panic!("expected stream");
        };
        let (_payload, consumed) =
            crabscale_proto::decode_map_response_frame(&first_frame).unwrap();
        assert_eq!(consumed, first_frame.len());

        // A lite update while the stream is open changes peer endpoints and
        // returns an empty-body update without disturbing the stream.
        let lite = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            omit_peers: true,
            endpoints: vec!["new.example:41641".to_string()],
            endpoint_types: vec![3],
            ..Default::default()
        };
        let outcome = plane.handle_map(test_machine_key(), lite).unwrap();
        assert_eq!(outcome, MapOutcome::LiteUpdate);

        let stored = plane
            .store
            .get_node_by_node_key(&test_node_key())
            .unwrap()
            .expect("node should exist");
        assert_eq!(stored.endpoints, vec!["new.example:41641"]);
        assert_eq!(stored.endpoint_types, vec![3]);
    }

    #[test]
    fn machine_key_mismatch_returns_not_found() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();
        let request = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            ..Default::default()
        };
        assert_eq!(
            plane.handle_map(MachineKey::from_bytes([0x77; 32]), request),
            Err(ControlError::NotFound)
        );
    }

    #[test]
    fn keepalive_frame_is_well_formed() {
        let plane = test_plane();
        let frame = plane.keepalive_frame(false).unwrap();
        let (payload, _) = crabscale_proto::decode_map_response_frame(&frame).unwrap();
        let json: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert_eq!(json["KeepAlive"], true);
    }

    #[test]
    fn zstd_frame_round_trips() {
        let plane = test_plane();
        let frame = plane.keepalive_frame(true).unwrap();
        let (payload, _) = crabscale_proto::decode_map_response_frame(&frame).unwrap();
        let json = zstd::stream::decode_all(payload).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["KeepAlive"], true);
    }

    #[test]
    fn restart_preserves_registered_node_and_map() {
        let dir = std::env::temp_dir().join(format!("crabscale-control-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("restart.sqlite");

        {
            let plane = ControlPlane::open_sqlite(ControlConfig::default(), &db_path).unwrap();
            let response = plane
                .register(test_machine_key(), test_register_request())
                .unwrap();
            assert!(response.machine_authorized);
        }

        // Reopen the same database file and map with the same machine key.
        let plane = ControlPlane::open_sqlite(ControlConfig::default(), &db_path).unwrap();
        let request = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            ..Default::default()
        };
        let outcome = plane.handle_map(test_machine_key(), request).unwrap();
        let MapOutcome::FullFrame(frame) = outcome else {
            panic!("expected full frame after restart");
        };
        let (payload, consumed) = crabscale_proto::decode_map_response_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        let json: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert!(json.get("Node").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_node_returns_not_found() {
        let plane = test_plane();
        let request = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            ..Default::default()
        };
        assert_eq!(
            plane.handle_map(test_machine_key(), request),
            Err(ControlError::NotFound)
        );
    }

    fn request_with(node_key: NodeKey, auth_key: &str) -> RegisterRequest {
        RegisterRequest {
            version: 130,
            node_key,
            auth: Some(crabscale_proto::RegisterAuth {
                auth_key: auth_key.to_string(),
            }),
            hostinfo: Some(Hostinfo {
                hostname: "node".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn one_time_key_cannot_register_two_distinct_nodes() {
        let plane = test_plane();
        let key = plane
            .create_pre_auth_key("single", false, false, None, None)
            .unwrap();
        let node1 = NodeKey::from_bytes([0x41; 32]);
        let node2 = NodeKey::from_bytes([0x42; 32]);
        let first = plane
            .register(test_machine_key(), request_with(node1, &key))
            .unwrap();
        assert!(first.machine_authorized);
        let second = plane
            .register(test_machine_key(), request_with(node2, &key))
            .unwrap();
        assert!(!second.machine_authorized);
    }

    #[test]
    fn restart_relogin_does_not_consume_one_time_key() {
        let plane = test_plane();
        let key = plane
            .create_pre_auth_key("single2", false, false, None, None)
            .unwrap();
        let node = NodeKey::from_bytes([0x43; 32]);
        let first = plane
            .register(test_machine_key(), request_with(node, &key))
            .unwrap();
        assert!(first.machine_authorized);
        // Re-register the same node with the same key: still authorized.
        let second = plane
            .register(test_machine_key(), request_with(node, &key))
            .unwrap();
        assert!(second.machine_authorized);
    }

    #[test]
    fn logout_returns_client_to_needs_login() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();
        let response = plane.logout(&test_node_key()).unwrap();
        assert!(!response.machine_authorized);
        // Re-register without auth: still logged out.
        let mut request = test_register_request();
        request.auth = None;
        let response = plane.register(test_machine_key(), request).unwrap();
        assert!(!response.machine_authorized);
    }

    #[test]
    fn tagged_node_survives_logout() {
        let plane = test_plane();
        let key = plane
            .create_pre_auth_key(
                "tagged",
                true,
                false,
                None,
                Some(vec!["tag:server".to_string()]),
            )
            .unwrap();
        let node = NodeKey::from_bytes([0x44; 32]);
        let response = plane
            .register(test_machine_key(), request_with(node, &key))
            .unwrap();
        assert!(response.machine_authorized);
        let response = plane.logout(&node).unwrap();
        assert!(response.machine_authorized);
    }

    #[test]
    fn ephemeral_node_is_deleted_on_logout() {
        let plane = test_plane();
        let key = plane
            .create_pre_auth_key("eph", true, true, None, None)
            .unwrap();
        let node = NodeKey::from_bytes([0x45; 32]);
        let response = plane
            .register(test_machine_key(), request_with(node, &key))
            .unwrap();
        assert!(response.machine_authorized);
        let response = plane.logout(&node).unwrap();
        assert!(!response.machine_authorized);
        assert!(plane.store.get_node_by_node_key(&node).unwrap().is_none());
    }

    #[test]
    fn database_contains_no_plaintext_auth_secret() {
        let plane = test_plane();
        let key = plane
            .create_pre_auth_key("nosecret", true, false, None, None)
            .unwrap();
        let (_, secret) = parse_auth_key(&key).unwrap();
        for stored in plane.list_pre_auth_keys().unwrap() {
            assert!(!stored.secret_hash.contains(&secret));
            assert!(!stored.secret_hash.contains("hskey-auth-"));
        }
    }

    #[test]
    fn revoked_key_is_rejected() {
        let plane = test_plane();
        let key = plane
            .create_pre_auth_key("revoked", true, false, None, None)
            .unwrap();
        let (prefix, _) = parse_auth_key(&key).unwrap();
        plane.revoke_pre_auth_key(&prefix).unwrap();
        let node = NodeKey::from_bytes([0x46; 32]);
        let response = plane
            .register(test_machine_key(), request_with(node, &key))
            .unwrap();
        assert!(!response.machine_authorized);
    }

    #[test]
    fn expired_key_is_rejected() {
        let plane = test_plane();
        let key = plane
            .create_pre_auth_key(
                "expired",
                true,
                false,
                Some("2000-01-01T00:00:00Z".to_string()),
                None,
            )
            .unwrap();
        let node = NodeKey::from_bytes([0x47; 32]);
        let response = plane
            .register(test_machine_key(), request_with(node, &key))
            .unwrap();
        assert!(!response.machine_authorized);
    }

    #[test]
    fn reusable_key_registers_multiple_nodes() {
        let plane = test_plane();
        let key = plane
            .create_pre_auth_key("reusable", true, false, None, None)
            .unwrap();
        let node1 = NodeKey::from_bytes([0x48; 32]);
        let node2 = NodeKey::from_bytes([0x49; 32]);
        let first = plane
            .register(test_machine_key(), request_with(node1, &key))
            .unwrap();
        assert!(first.machine_authorized);
        let second = plane
            .register(test_machine_key(), request_with(node2, &key))
            .unwrap();
        assert!(second.machine_authorized);
    }

    #[test]
    fn single_use_key_is_consumed_on_re_auth() {
        let plane = test_plane();
        let first_key = plane
            .create_pre_auth_key("reauth1", false, false, None, None)
            .unwrap();
        let node_a = NodeKey::from_bytes([0x51; 32]);
        let node_b = NodeKey::from_bytes([0x52; 32]);

        // Register node A with a single-use key.
        let first = plane
            .register(test_machine_key(), request_with(node_a, &first_key))
            .unwrap();
        assert!(first.machine_authorized);

        // Log out node A, then re-auth with a fresh single-use key.
        let logout = plane.logout(&node_a).unwrap();
        assert!(!logout.machine_authorized);
        let second_key = plane
            .create_pre_auth_key("reauth2", false, false, None, None)
            .unwrap();
        let reauth = plane
            .register(test_machine_key(), request_with(node_a, &second_key))
            .unwrap();
        assert!(reauth.machine_authorized);

        // The same single-use key must not authorize a second distinct node.
        let second = plane
            .register(test_machine_key(), request_with(node_b, &second_key))
            .unwrap();
        assert!(!second.machine_authorized);
    }

    #[test]
    fn past_expiry_logs_out_node() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();
        let mut request = test_register_request();
        request.expiry = "2000-01-01T00:00:00Z".to_string();
        let response = plane.register(test_machine_key(), request).unwrap();
        assert!(!response.machine_authorized);
        assert!(response.node_key_expired);
    }

    #[test]
    fn future_expiry_is_rejected() {
        let plane = test_plane();
        plane
            .register(test_machine_key(), test_register_request())
            .unwrap();
        let mut request = test_register_request();
        request.expiry = "2999-01-01T00:00:00Z".to_string();
        let response = plane.register(test_machine_key(), request).unwrap();
        assert!(!response.machine_authorized);
        assert!(!response.error.is_empty());
    }

    #[test]
    fn new_node_with_past_expiry_is_rejected() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.node_key = NodeKey::from_bytes([0x53; 32]);
        request.expiry = "2000-01-01T00:00:00Z".to_string();
        let response = plane.register(test_machine_key(), request).unwrap();
        assert!(!response.machine_authorized);
        assert!(response.node_key_expired);
    }

    #[test]
    fn new_node_with_future_expiry_is_rejected() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.node_key = NodeKey::from_bytes([0x54; 32]);
        request.expiry = "2999-01-01T00:00:00Z".to_string();
        let response = plane.register(test_machine_key(), request).unwrap();
        assert!(!response.machine_authorized);
        assert!(!response.error.is_empty());
    }

    #[test]
    fn create_pre_auth_key_rejects_non_alphanumeric_prefix() {
        let plane = test_plane();
        let result = plane.create_pre_auth_key("bad-prefix", true, false, None, None);
        assert!(matches!(result, Err(ControlError::InvalidAuthKey(_))));
    }

    #[test]
    fn interactive_registration_approve_followup_authorizes() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.auth = None;
        let pending = plane.register(test_machine_key(), request).unwrap();
        assert!(!pending.machine_authorized);
        assert!(!pending.auth_url.is_empty());
        assert!(pending.error.is_empty());

        let auth_id = auth_id_from_followup(&pending.auth_url).unwrap();
        plane
            .approve_pending(&auth_id, "owner@example.com")
            .unwrap();

        let mut followup = test_register_request();
        followup.auth = None;
        followup.followup = pending.auth_url.clone();
        let response = plane.register(test_machine_key(), followup).unwrap();
        assert!(response.machine_authorized);
        assert!(
            plane
                .store
                .get_node_by_node_key(&test_node_key())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn unknown_auth_id_cannot_authorize_different_machine_key() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.auth = None;
        let pending = plane.register(test_machine_key(), request).unwrap();
        let auth_id = auth_id_from_followup(&pending.auth_url).unwrap();
        plane
            .approve_pending(&auth_id, "owner@example.com")
            .unwrap();

        // A different machine key polling the same auth id must be rejected.
        let mut followup = test_register_request();
        followup.auth = None;
        followup.followup = pending.auth_url.clone();
        let response = plane
            .register(MachineKey::from_bytes([0x99; 32]), followup)
            .unwrap();
        assert!(!response.machine_authorized);
        assert!(!response.error.is_empty());
        assert!(
            plane
                .store
                .get_node_by_node_key(&test_node_key())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejected_pending_returns_error() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.auth = None;
        let pending = plane.register(test_machine_key(), request).unwrap();
        let auth_id = auth_id_from_followup(&pending.auth_url).unwrap();
        plane.reject_pending(&auth_id).unwrap();

        let mut followup = test_register_request();
        followup.auth = None;
        followup.followup = pending.auth_url.clone();
        let response = plane.register(test_machine_key(), followup).unwrap();
        assert!(!response.machine_authorized);
        assert!(!response.error.is_empty());
    }

    #[test]
    fn expired_pending_returns_new_registration_prompt() {
        let config = ControlConfig {
            pending_ttl_seconds: -1,
            ..Default::default()
        };
        let plane = ControlPlane::new(config);
        let mut request = test_register_request();
        request.auth = None;
        let pending = plane.register(test_machine_key(), request).unwrap();
        assert!(!pending.machine_authorized);

        let mut followup = test_register_request();
        followup.auth = None;
        followup.followup = pending.auth_url.clone();
        let response = plane.register(test_machine_key(), followup).unwrap();
        assert!(!response.machine_authorized);
        assert!(response.error.contains("expired"));
    }
}
