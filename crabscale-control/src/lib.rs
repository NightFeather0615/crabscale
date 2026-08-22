//! Control plane: registration, MapRequest handling, and MapResponse
//! building backed by a durable domain model.
//!
//! This crate owns the server-side domain logic that sits behind the
//! `/machine/register` and `/machine/map` endpoints. It persists users,
//! logins, nodes, pre-auth keys, policies, and sessions through the [`Store`]
//! trait, assigns tailnet IPs with a random allocator, and builds the first
//! complete MapResponse frame.

pub mod backup;
mod delta;
mod derp;
mod dns;
mod events;
mod ip_allocator;
mod model;
mod pending;
mod preauth;
mod session;
mod ssh;
mod store;
mod time;

use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crabscale_proto::{
    DerpMap, Hostinfo, MIN_SUPPORTED_CAPVER, MachineKey, MapRequest, MapResponse, NodeKey,
    RegisterRequest, RegisterResponse, UserProfile, encode_map_response_frame,
};

pub use backup::{BACKUP_FORMAT, BACKUP_TABLES, BackupError};
pub use delta::SessionPeers;
pub use dns::{DnsError, DnsSettings};
pub use events::{
    ChangeBatch, ChangeBus, ChangeEvent, DEFAULT_CHANGE_BATCH_MAX, DEFAULT_CHANGE_BATCH_WINDOW,
};
pub use ip_allocator::{IpAllocator, IpAllocatorError};
pub use model::{Login, Node as DomainNode, Policy, PreAuthKey, Session, User};
pub use pending::{
    DEFAULT_PENDING_CACHE_LIMIT, DEFAULT_PENDING_TTL_SECONDS, PendingRegistration, PendingVerdict,
};
pub use preauth::{
    AUTH_KEY_PREFIX, format_auth_key, generate_secret, hash_secret, parse_auth_key, verify_secret,
};
pub use session::{DEFAULT_RECONNECT_GRACE_SECONDS, SessionEvent, SessionRegistry};
pub use ssh::{
    DEFAULT_SSH_AUTH_LIMIT, DEFAULT_SSH_AUTH_TTL_SECONDS, DEFAULT_SSH_WAIT_TIMEOUT, SshAuth,
    SshVerdict,
};
pub use store::{SqliteStore, Store, StoreError};

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
    /// Protocol version advertised to clients by `/machine/whoami`.
    pub protocol_version: u16,
    /// Tailnet domain, e.g. `tailnet.example`.
    pub tailnet_domain: String,
    /// DERP regions advertised to clients.
    pub derp_map: DerpMap,
    /// The access-control policy compiled into per-node packet filters.
    pub policy: crabscale_policy::Policy,
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
    /// Reconnect grace in seconds before a node is marked offline after its
    /// last live map session closes.
    pub reconnect_grace_seconds: i64,
    /// DNS configuration (MagicDNS, split DNS, search domains, extra records)
    /// delivered to clients in the MapResponse `DNS` field.
    pub dns: DnsSettings,
    /// How long node/policy/DNS/DERP changes are coalesced before a single
    /// delta batch is pushed to live map sessions (M3-03).
    pub change_batch_window: std::time::Duration,
    /// Maximum number of distinct coalesced changes in one batch before an
    /// early flush (M3-03).
    pub change_batch_max: usize,
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
            protocol_version: 130,
            tailnet_domain: "tailnet.example".to_string(),
            derp_map,
            // No rules configured by default: everything is denied.
            policy: crabscale_policy::Policy::default(),
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
            reconnect_grace_seconds: DEFAULT_RECONNECT_GRACE_SECONDS,
            dns: DnsSettings::default(),
            change_batch_window: DEFAULT_CHANGE_BATCH_WINDOW,
            change_batch_max: DEFAULT_CHANGE_BATCH_MAX,
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
    /// The `endpoint_types` payload does not match the `endpoints` payload.
    InvalidEndpointTypes,
    /// A policy check failed (for example a tag is not owned by its creator).
    Policy(String),
    /// A node requested tags it is not authorized to hold. Carries the
    /// rejected tags. The node's state is left unchanged.
    UnauthorizedTags(Vec<String>),
    /// A route string is not a valid IP or CIDR.
    InvalidRoute(String),
    /// DNS extra records could not be read, parsed, or pushed.
    ExtraRecords(String),
    /// The Noise machine key did not match the node it claimed.
    Unauthorized,
    /// An SSH followup presented a binding that did not match the auth record.
    SshBinding(String),
    /// An SSH followup wait timed out before an admin verdict arrived.
    Timeout,
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
            Self::InvalidEndpointTypes => {
                write!(f, "endpoint_types length does not match endpoints length")
            }
            Self::Policy(e) => write!(f, "policy error: {e}"),
            Self::UnauthorizedTags(tags) => {
                write!(f, "requested tags are not permitted: {}", tags.join(", "))
            }
            Self::InvalidRoute(route) => {
                write!(f, "invalid route `{route}`: expected an IP or CIDR")
            }
            Self::ExtraRecords(e) => write!(f, "DNS extra records: {e}"),
            Self::Unauthorized => write!(f, "unauthorized: machine key mismatch"),
            Self::SshBinding(auth_id) => {
                write!(f, "SSH auth binding mismatch for `{auth_id}`")
            }
            Self::Timeout => write!(f, "timed out waiting for an SSH approval"),
        }
    }
}

impl std::error::Error for ControlError {}

/// A user profile extracted from a verified OpenID Connect ID token.
///
/// The server hands these claims to the control plane so the identity is
/// upserted into the durable store before the pending registration is
/// approved through the same auth cache the CLI uses (Spec-Registration §7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidcProfile {
    /// The provider's stable subject identifier (`sub` claim).
    pub subject: String,
    /// The email used as the user's login name when present.
    pub email: String,
    /// Display name shown in user profiles.
    pub display_name: String,
}

/// The result of handling a MapRequest.
#[derive(Debug, Clone, PartialEq)]
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
        /// The live map session id to close when the stream ends.
        session_id: i64,
        /// The id of the node the stream belongs to; used to derive deltas.
        node_id: i64,
        /// The peer snapshots delivered in the complete first frame, so the
        /// first delta only carries changes since then.
        initial_peers: SessionPeers,
        /// The client's advertised capability version, used to gate every
        /// later delta for this session.
        client_version: u32,
    },
}

/// Control plane shared by the server router.
pub struct ControlPlane {
    pub(crate) config: ControlConfig,
    pub(crate) store: Arc<dyn Store>,
    pending: Mutex<pending::PendingCache>,
    sessions: Mutex<SessionRegistry>,
    reaper_started: AtomicBool,
    dns_state: Arc<dns::DnsState>,
    derp_state: Arc<derp::DerpMapState>,
    /// The change bus that coalesces node/policy/DNS/DERP changes and fans
    /// delta batches out to live map sessions (shared across clones).
    events: Arc<ChangeBus>,
    /// Broadcast channel that wakes SSH followup waiters when an auth id
    /// resolves. Clones of a plane share the channel so an approval on any
    /// clone notifies waiters on every clone.
    ssh_waiters: tokio::sync::broadcast::Sender<String>,
}

impl Clone for ControlPlane {
    fn clone(&self) -> Self {
        // The store and DNS state are shared via `Arc`; the pending cache is
        // a read-through cache backed by the store, so a fresh cache is
        // created on clone. Sessions are per-clone.
        Self {
            config: self.config.clone(),
            store: self.store.clone(),
            pending: Mutex::new(pending::PendingCache::new(self.config.pending_cache_limit)),
            sessions: Mutex::new(SessionRegistry::new(self.config.reconnect_grace_seconds)),
            reaper_started: AtomicBool::new(false),
            dns_state: self.dns_state.clone(),
            derp_state: self.derp_state.clone(),
            events: self.events.clone(),
            ssh_waiters: self.ssh_waiters.clone(),
        }
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
        let derp_map = config.derp_map.clone();
        let pending = Mutex::new(pending::PendingCache::new(config.pending_cache_limit));
        let sessions = Mutex::new(SessionRegistry::new(config.reconnect_grace_seconds));
        let change_batch_window = config.change_batch_window;
        let change_batch_max = config.change_batch_max;
        let plane = Self {
            config,
            store,
            pending,
            sessions,
            reaper_started: AtomicBool::new(false),
            dns_state: Arc::new(dns::DnsState::new(Vec::new())),
            derp_state: Arc::new(derp::DerpMapState::new(derp_map)),
            events: Arc::new(ChangeBus::new(change_batch_window, change_batch_max)),
            ssh_waiters: tokio::sync::broadcast::channel(128).0,
        };
        if plane.config.dns.extra_records_path.is_some() {
            if let Err(e) = plane.reload_dns_extra_records() {
                eprintln!("warning: {e}; starting with no DNS extra records");
            }
        }
        plane
    }

    /// Open a live map session for a node.
    ///
    /// Returns a session id that the caller must pass to [`Self::close_session`]
    /// when the streaming map connection ends.
    pub fn open_session(&self, node_id: i64, ephemeral: bool) -> i64 {
        crabscale_metrics::registry().sessions_opened_total.inc();
        crabscale_metrics::registry().sessions_active.add(1);
        let now = time::now_unix();
        let mut sessions = self.sessions.lock().unwrap();
        let (session_id, events) = sessions.open(node_id, ephemeral, now);
        drop(sessions);
        for event in events {
            if let SessionEvent::Online(id) = event {
                self.publish_change(ChangeEvent::OnlineChanged {
                    node_id: id,
                    online: true,
                });
            }
        }
        session_id
    }

    /// Close a live map session by id.
    pub fn close_session(&self, session_id: i64) {
        let now = time::now_unix();
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.close(session_id, now) {
            crabscale_metrics::registry().sessions_closed_total.inc();
            crabscale_metrics::registry().sessions_active.add(-1);
        }
    }

    /// Atomically claim the single background reaper slot.
    ///
    /// Returns `true` for exactly one caller; the caller should then spawn the
    /// periodic task that calls [`Self::reap_sessions`]. Subsequent callers
    /// receive `false` and must not spawn a second reaper.
    pub fn claim_reaper(&self) -> bool {
        !self.reaper_started.swap(true, Ordering::SeqCst)
    }

    /// Advance session lifecycle timers, emitting offline transitions and
    /// deleting ephemeral nodes whose grace period has elapsed.
    pub fn reap_sessions(&self) -> Vec<SessionEvent> {
        self.reap_sessions_at(time::now_unix())
    }

    /// Like [`Self::reap_sessions`] but with an explicit clock, for tests.
    fn reap_sessions_at(&self, now: i64) -> Vec<SessionEvent> {
        let events = self.sessions.lock().unwrap().tick(now);
        for event in &events {
            match event {
                SessionEvent::Offline(node_id) => {
                    self.publish_change(ChangeEvent::OnlineChanged {
                        node_id: *node_id,
                        online: false,
                    });
                }
                SessionEvent::EphemeralExpired(node_id) => {
                    if let Ok(Some(node)) = self.store.get_node_by_id(*node_id) {
                        let _ = self.store.delete_node(&node.node_key);
                    }
                    self.publish_change(ChangeEvent::NodeRemoved(*node_id));
                }
                SessionEvent::Online(_) => {}
            }
        }
        events
    }

    /// Whether a node currently has a live session or is inside its reconnect
    /// grace window.
    pub fn is_node_online(&self, node_id: i64) -> bool {
        self.sessions.lock().unwrap().is_online(node_id)
    }

    /// Number of live map sessions currently open for a node.
    ///
    /// This is the counter harness used by the performance/concurrency smoke
    /// tests to prove that every connect is paired with a disconnect: after a
    /// session closes the count must return to zero, so a leaked stream cannot
    /// hide inside the reconnect grace window (M3-04).
    pub fn live_session_count(&self, node_id: i64) -> usize {
        self.sessions.lock().unwrap().live_sessions(node_id)
    }

    /// The protocol version advertised to clients by `/machine/whoami`.
    pub fn protocol_version(&self) -> u16 {
        self.config.protocol_version
    }

    /// Register a node key for the given Noise machine key.
    ///
    /// If the node already exists and the machine key matches, the existing
    /// registration state is returned without consuming the auth key. This
    /// makes client restarts re-register without error.
    pub fn register(&self, machine_key: MachineKey, request: RegisterRequest) -> RegisterResponse {
        // Record the registration request before any early-return path
        // (observability, M4-04).
        crabscale_metrics::registry().registrations_total.inc();
        let result = (|| -> Result<RegisterResponse, ControlError> {
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
                    return Ok(self.unauthorized_response(
                        "node key is already registered to another machine",
                    ));
                }

                // A past expiry is a logout; a future expiry is a client trying to
                // extend its own key, which is rejected (Spec-Registration §5).
                if !request.expiry.is_empty() {
                    if time::is_past(&request.expiry, &now) {
                        return self.logout_node(node, true);
                    }
                    if time::is_future(&request.expiry, &now) {
                        return Ok(
                            self.unauthorized_response("clients may not extend their own key")
                        );
                    }
                }

                // Existing node with a matching machine key.
                if let Some(auth) = &request.auth {
                    if node.machine_authorized {
                        // Restart relogin: already authorized, do not consume the
                        // key. Process any RequestTags transition advertised by
                        // the client (e.g. `tailscale up --advertise-tags`).
                        let mut updated = node;
                        let owner = self.node_owner_login(&updated)?;
                        let requested = Self::requested_tags(request.hostinfo.as_ref());
                        if self.apply_request_tags(&mut updated, owner.as_deref(), &requested)? {
                            self.store
                                .upsert_node(&updated)
                                .map_err(|e| ControlError::Store(e.to_string()))?;
                            // Other peers must see the tag/ownership transition.
                            self.publish_change(ChangeEvent::NodeChanged(updated.id));
                        }
                        return Ok(self.authorized_response());
                    }
                    if let Some(key) = self.validated_auth_key(auth, &now)? {
                        let mut updated = node;
                        updated.machine_authorized = true;
                        // Tags come from the pre-auth key on re-auth (and from
                        // the initial key on first registration); client
                        // RequestTags are not honored for pre-auth keys
                        // (Spec-Policy §4).
                        updated.tags = key.tags.clone();
                        updated.ephemeral = key.ephemeral;
                        self.store
                            .upsert_node(&updated)
                            .map_err(|e| ControlError::Store(e.to_string()))?;
                        self.publish_change(ChangeEvent::NodeChanged(updated.id));
                        if !key.reusable {
                            self.store
                                .mark_pre_auth_key_used(key.id)
                                .map_err(|e| ControlError::Store(e.to_string()))?;
                        }
                        return Ok(self.authorized_response());
                    }
                    // Invalid auth key: fall through to interactive registration.
                } else if node.machine_authorized {
                    // No auth key supplied and already authorized: process any
                    // RequestTags transition then return current state.
                    let mut updated = node;
                    let owner = self.node_owner_login(&updated)?;
                    let requested = Self::requested_tags(request.hostinfo.as_ref());
                    if self.apply_request_tags(&mut updated, owner.as_deref(), &requested)? {
                        self.store
                            .upsert_node(&updated)
                            .map_err(|e| ControlError::Store(e.to_string()))?;
                        // Other peers must see the tag/ownership transition.
                        self.publish_change(ChangeEvent::NodeChanged(updated.id));
                    }
                    return Ok(self.authorized_response());
                }

                // Existing but unauthorized node: start interactive registration.
                return self.start_interactive(machine_key, request, &now);
            }

            // New node registration.
            let key = match &request.auth {
                Some(auth) => self.validated_auth_key(auth, &now)?,
                None => None,
            };
            let is_tagged_key = key
                .as_ref()
                .and_then(|k| k.tags.as_ref())
                .is_some_and(|t| !t.is_empty());

            // Tagged nodes have no key expiry, so a tagged key bypasses the
            // expiry gate entirely (Spec-Policy §4).
            if !is_tagged_key && !request.expiry.is_empty() {
                if time::is_past(&request.expiry, &now) {
                    return Ok(self.expired_response("node key is expired"));
                }
                if time::is_future(&request.expiry, &now) {
                    return Ok(self.unauthorized_response("clients may not extend their own key"));
                }
            }

            if let Some(key) = key {
                // Pre-auth key registration: a non-tagged key cannot have the
                // client claim tags, and a tagged key is authoritative for the
                // tags (headscale parity; Spec-Policy §4).
                if key.tags.is_none() && !Self::requested_tags(request.hostinfo.as_ref()).is_empty()
                {
                    return Err(ControlError::Policy(
                        "pre-auth key registrations may not request tags".to_string(),
                    ));
                }
                let mut node = self.create_node_from_request(
                    machine_key,
                    &request,
                    key.user_id,
                    key.tags.clone(),
                    key.ephemeral,
                    &now,
                )?;
                node = self
                    .store
                    .upsert_node(&node)
                    .map_err(|e| ControlError::Store(e.to_string()))?;
                // Existing peers must learn about the new node.
                self.publish_change(ChangeEvent::NodeChanged(node.id));
                if !key.reusable {
                    self.store
                        .mark_pre_auth_key_used(key.id)
                        .map_err(|e| ControlError::Store(e.to_string()))?;
                }
                return Ok(self.authorized_response());
            }

            // No valid auth key: start interactive registration. RequestTags
            // are validated at approval time against the approving user.
            self.start_interactive(machine_key, request, &now)
        })();
        match result {
            Ok(response) => response,
            Err(e) => RegisterResponse {
                machine_authorized: false,
                error: e.to_string(),
                ..Default::default()
            },
        }
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
            self.remove_pending_entry(&auth_id)?;
            return Ok(self.unauthorized_response("registration expired; start a new registration"));
        }
        match entry.verdict {
            PendingVerdict::Pending => Ok(RegisterResponse {
                machine_authorized: false,
                auth_url: format!("{}/register/{}", self.config.server_url, entry.auth_id),
                ..Default::default()
            }),
            PendingVerdict::Rejected => {
                self.remove_pending_entry(&auth_id)?;
                Ok(self.unauthorized_response("registration rejected"))
            }
            PendingVerdict::Approved { user_id, tags } => {
                self.remove_pending_entry(&auth_id)?;
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
                let mut node = self.create_node_from_request(
                    machine_key,
                    &pending_request,
                    user_id,
                    tags,
                    entry.ephemeral,
                    now,
                )?;
                node = self
                    .store
                    .upsert_node(&node)
                    .map_err(|e| ControlError::Store(e.to_string()))?;
                // Existing peers must learn about the new node.
                self.publish_change(ChangeEvent::NodeChanged(node.id));
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
            self.remove_pending_entry(auth_id)?;
            return Err(ControlError::NotFound);
        }
        let user_id = self.resolve_user_id(user_name)?;
        // If the client advertised RequestTags, authorize them against the
        // approving user and carry the approved tags into the verdict so the
        // resulting node is created tag-owned (Spec-Policy §4).
        let requested = Self::requested_tags(entry.hostinfo.as_ref());
        let approved_tags = if requested.is_empty() {
            None
        } else {
            let rejected = crabscale_policy::unauthorized_tags(
                &self.config.policy,
                Some(user_name),
                &requested,
            );
            if !rejected.is_empty() {
                return Err(ControlError::UnauthorizedTags(rejected));
            }
            Some(requested)
        };
        entry.verdict = PendingVerdict::Approved {
            user_id,
            tags: approved_tags,
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
            self.remove_pending_entry(auth_id)?;
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
    pub fn pending_info(&self, auth_id: &str) -> Result<Option<PendingRegistration>, ControlError> {
        let now = time::now_rfc3339();
        let Some(entry) = self.get_pending_entry(auth_id)? else {
            return Ok(None);
        };
        if time::is_past(&entry.expires_at, &now) {
            self.remove_pending_entry(auth_id)?;
            return Ok(None);
        }
        Ok(Some(entry))
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
    fn remove_pending_entry(&self, auth_id: &str) -> Result<(), ControlError> {
        self.pending.lock().unwrap().remove(auth_id);
        self.store
            .delete_pending(auth_id)
            .map_err(|e| ControlError::Store(e.to_string()))
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

    /// Upsert a user from verified OIDC claims and return the user id.
    ///
    /// The user is keyed by the provider email (used as the unique login
    /// name) and the login identity is recorded as an `oidc` login under the
    /// provider subject, so the same subject always maps back to the same
    /// user. Re-authentication updates the display name in place
    /// (Spec-Registration §7).
    pub fn upsert_oidc_user(&self, profile: &OidcProfile) -> Result<i64, ControlError> {
        let now = time::now_rfc3339();
        let user = match self
            .store
            .get_user_by_login_name(&profile.email)
            .map_err(|e| ControlError::Store(e.to_string()))?
        {
            Some(mut user) => {
                if user.display_name != profile.display_name {
                    self.store
                        .update_user_display_name(user.id, &profile.display_name)
                        .map_err(|e| ControlError::Store(e.to_string()))?;
                    user.display_name = profile.display_name.clone();
                }
                user
            }
            None => self
                .store
                .create_user(&User {
                    id: 0,
                    login_name: profile.email.clone(),
                    display_name: profile.display_name.clone(),
                    created_at: now.clone(),
                })
                .map_err(|e| ControlError::Store(e.to_string()))?,
        };
        if self
            .store
            .get_login_by_provider_subject("oidc", &profile.subject)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .is_none()
        {
            self.store
                .create_login(&Login {
                    id: 0,
                    user_id: user.id,
                    provider: "oidc".to_string(),
                    login_name: profile.subject.clone(),
                    created_at: now.clone(),
                })
                .map_err(|e| ControlError::Store(e.to_string()))?;
        }
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
        // A tagged node is owned by its tags, not by a user (Spec-Policy §4):
        // the node carries no owner, and tagged nodes have no key expiry.
        let user_id = if tags.as_ref().is_some_and(|t| !t.is_empty()) {
            None
        } else {
            Some(user_id)
        };
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
            advertised_routes: Self::route_list(request.hostinfo.as_ref()),
            approved_routes: Vec::new(),
            machine_authorized: true,
            ephemeral,
            // A freshly registered node is deemed seen at creation. Key
            // expiry is administratively granted (never set by clients,
            // Spec-Registration §5), so default nodes carry no expiry.
            last_seen: Some(now.to_string()),
            key_expiry: None,
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
    /// The caller must present the Noise machine key that owns the node;
    /// otherwise the request is rejected with [`ControlError::NotFound`] so a
    /// client cannot deauthorize a node it does not own.
    ///
    /// Tagged nodes are never logged out (no-expiry). Ephemeral nodes are
    /// deleted entirely. All other nodes are deauthorized and must re-auth.
    pub fn logout(
        &self,
        machine_key: MachineKey,
        node_key: &NodeKey,
    ) -> Result<RegisterResponse, ControlError> {
        let Some(node) = self
            .store
            .get_node_by_node_key(node_key)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .filter(|n| n.machine_key == machine_key)
        else {
            return Err(ControlError::NotFound);
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
            self.publish_change(ChangeEvent::NodeRemoved(node.id));
            return Ok(RegisterResponse {
                machine_authorized: false,
                node_key_expired,
                error: "node logged out".to_string(),
                ..Default::default()
            });
        }
        let mut updated = node;
        updated.machine_authorized = false;
        let updated = self
            .store
            .upsert_node(&updated)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        // A deauthorized node disappears from peers' maps.
        self.publish_change(ChangeEvent::NodeChanged(updated.id));
        Ok(RegisterResponse {
            machine_authorized: false,
            node_key_expired,
            error: "node logged out".to_string(),
            ..Default::default()
        })
    }

    /// The requested tags carried by a request's `Hostinfo`, if any.
    fn requested_tags(hostinfo: Option<&Hostinfo>) -> Vec<String> {
        hostinfo
            .and_then(|h| h.request_tags.clone())
            .unwrap_or_default()
    }

    /// Resolve the login name that owns a node, if the node has an owner.
    /// Tagged nodes carry no owner and therefore resolve to `None`.
    fn node_owner_login(&self, node: &DomainNode) -> Result<Option<String>, ControlError> {
        let Some(user_id) = node.user_id else {
            return Ok(None);
        };
        Ok(self
            .store
            .get_user(user_id)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .map(|u| u.login_name))
    }

    /// Apply a `RequestTags` transition to a node.
    ///
    /// `requested` is the client's `Hostinfo.RequestTags`; an empty slice
    /// means "no tags". For a node that keeps its existing owner (a
    /// user-owned node untagging to stay user-owned) this is a no-op; for a
    /// tag-owned node it returns the node to the user that `auth_user_login`
    /// identifies. If a tag-owned node presents no authorizing user (as in a
    /// map update, where `node_owner_login` is `None`), untagging is rejected
    /// rather than leaving the node ownerless.
    ///
    /// Tags are authorized against `auth_user_login`, the identity presenting
    /// the credential (the node's owner, or the approving user during
    /// registration). Every requested tag must be listed in the policy's
    /// `tagOwners` for that user; an unauthorized transition is rejected with
    /// [`ControlError::UnauthorizedTags`] and the node is left unchanged
    /// (Spec-Policy §4). Returns `true` when the node changed.
    fn apply_request_tags(
        &self,
        node: &mut DomainNode,
        auth_user_login: Option<&str>,
        requested: &[String],
    ) -> Result<bool, ControlError> {
        let mut current: Vec<String> = node.tags.clone().unwrap_or_default();
        current.sort();
        current.dedup();
        let mut requested = requested.to_vec();
        requested.sort();
        requested.dedup();

        if requested == current {
            return Ok(false);
        }

        if requested.is_empty() {
            // Untag: return the node to user ownership. A tagged node carries
            // no user, so the authorizing user supplies the ownership.
            let user_id = match node.user_id {
                Some(id) => id,
                None => {
                    let login = auth_user_login.ok_or_else(|| {
                        ControlError::Policy(
                            "cannot return a tagged node to user ownership without a user"
                                .to_string(),
                        )
                    })?;
                    self.resolve_user_id(login)?
                }
            };
            node.tags = None;
            node.user_id = Some(user_id);
            return Ok(true);
        }

        // Adding or changing tags requires ownership of every requested tag.
        let rejected =
            crabscale_policy::unauthorized_tags(&self.config.policy, auth_user_login, &requested);
        if !rejected.is_empty() {
            return Err(ControlError::UnauthorizedTags(rejected));
        }
        node.tags = Some(requested);
        node.user_id = None;
        Ok(true)
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
        // A pre-auth key may only carry tags its creator is allowed to use:
        // only principals listed in `tagOwners` may approve a tag
        // (Spec-Policy §4).
        if let Some(tags) = &tags {
            let rejected = crabscale_policy::unauthorized_tags(
                &self.config.policy,
                Some(&self.config.user_login_name),
                tags,
            );
            if !rejected.is_empty() {
                return Err(ControlError::Policy(format!(
                    "creator may not approve tags: {}",
                    rejected.join(", ")
                )));
            }
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

    /// Fetch a registered node by its node key.
    pub fn node_by_key(&self, node_key: &NodeKey) -> Result<Option<DomainNode>, ControlError> {
        self.store
            .get_node_by_node_key(node_key)
            .map_err(|e| ControlError::Store(e.to_string()))
    }

    /// Revoke a pre-auth key by prefix.
    pub fn revoke_pre_auth_key(&self, prefix: &str) -> Result<(), ControlError> {
        self.store
            .revoke_pre_auth_key(prefix)
            .map_err(|e| ControlError::Store(e.to_string()))
    }

    /// Approve a route for a node, making it available to peers.
    ///
    /// The route is validated and canonicalized to CIDR form (host bits
    /// zeroed) before it is stored. Approving a route the node is not
    /// currently advertising is allowed: it becomes effective as soon as
    /// the node advertises it. Approving a route already in the set is a
    /// no-op.
    pub fn approve_route(&self, node_key: &NodeKey, route: &str) -> Result<(), ControlError> {
        let canonical = crabscale_policy::canonical_route(route)
            .ok_or_else(|| ControlError::InvalidRoute(route.to_string()))?;
        let mut node = self
            .store
            .get_node_by_node_key(node_key)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .ok_or(ControlError::NotFound)?;
        if !node.approved_routes.iter().any(|r| r == &canonical) {
            node.approved_routes.push(canonical);
            node.approved_routes.sort();
            node.approved_routes.dedup();
            let updated = self
                .store
                .upsert_node(&node)
                .map_err(|e| ControlError::Store(e.to_string()))?;
            // Peers' routed AllowedIPs change.
            self.publish_change(ChangeEvent::NodeChanged(updated.id));
        }
        Ok(())
    }

    /// Remove an approved route from a node. Removing a route that is not
    /// in the set is a no-op.
    pub fn disapprove_route(&self, node_key: &NodeKey, route: &str) -> Result<(), ControlError> {
        let canonical = crabscale_policy::canonical_route(route)
            .ok_or_else(|| ControlError::InvalidRoute(route.to_string()))?;
        let mut node = self
            .store
            .get_node_by_node_key(node_key)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .ok_or(ControlError::NotFound)?;
        let before = node.approved_routes.len();
        node.approved_routes.retain(|r| r != &canonical);
        if node.approved_routes.len() != before {
            let updated = self
                .store
                .upsert_node(&node)
                .map_err(|e| ControlError::Store(e.to_string()))?;
            // Peers' routed AllowedIPs change.
            self.publish_change(ChangeEvent::NodeChanged(updated.id));
        }
        Ok(())
    }

    /// Canonicalize and validate the routes a client advertised in its
    /// `Hostinfo.RoutableIPs`.
    ///
    /// Malformed entries are dropped so a misbehaving client cannot corrupt
    /// the stored route set: only valid IPs and CIDRs are accepted, and they
    /// are normalized to CIDR form (a bare IP becomes `/32` or `/128`).
    fn route_list(hostinfo: Option<&Hostinfo>) -> Vec<String> {
        let mut routes = Vec::new();
        if let Some(hostinfo) = hostinfo {
            if let Some(routable) = &hostinfo.routable_ips {
                for route in routable {
                    if let Some(canonical) = crabscale_policy::canonical_route(route) {
                        routes.push(canonical);
                    }
                }
            }
        }
        routes.sort();
        routes.dedup();
        routes
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
        if request.endpoint_types.len() != request.endpoints.len() {
            return Err(ControlError::InvalidEndpointTypes);
        }

        let mut node = self
            .store
            .get_node_by_node_key(&request.node_key)
            .map_err(|e| ControlError::Store(e.to_string()))?
            .filter(|n| n.machine_key == machine_key)
            .ok_or(ControlError::NotFound)?;
        let before = node.clone();

        let streaming = request.stream;
        let lite_update = !streaming && request.omit_peers && !request.read_only;

        // The disco key is only carried in MapRequest, not RegisterRequest, so
        // apply it unconditionally: a streaming-first client still needs its
        // real disco key advertised in the first MapResponse (Spec-NetMap §3).
        // The read-only rule below is scoped to Hostinfo and Endpoints only.
        node.disco_key = request.disco_key;

        // Mark the node seen: any map request observes the node, which peers
        // observe as a last-seen/peer-seen delta.
        node.last_seen = Some(time::now_rfc3339());

        // Streaming requests are read-only for Hostinfo and Endpoints once
        // the client reaches capver 68: they must not clear or clobber the
        // state a client already reported through a non-streaming update.
        // The `streaming_read_only` clause is redundant today because
        // handle_map rejects versions below MIN_SUPPORTED_CAPVER, but it
        // documents the spec rule (Spec-Compatibility table row 68).
        let read_only = streaming && crabscale_proto::capver::streaming_read_only(request.version);
        if !read_only {
            if let Some(hostinfo) = &request.hostinfo {
                node.hostinfo = Some(hostinfo.clone());
                node.advertised_routes = Self::route_list(Some(hostinfo));
                if let Some(net_info) = &hostinfo.net_info {
                    if net_info.preferred_derp != 0 {
                        node.home_derp = net_info.preferred_derp;
                    }
                }
            }
            node.endpoints = request.endpoints.clone();
            node.endpoint_types = request.endpoint_types.clone();
        }
        // Process a RequestTags transition advertised in Hostinfo on an
        // authorizing (non-read-only) update. Unauthorized changes are
        // rejected and leave the stored node untouched (Spec-Policy §4). The
        // single upsert below persists any successful transition.
        if !read_only && request.hostinfo.is_some() {
            let owner = self.node_owner_login(&node)?;
            let requested = Self::requested_tags(request.hostinfo.as_ref());
            self.apply_request_tags(&mut node, owner.as_deref(), &requested)?;
        }
        self.store
            .upsert_node(&node)
            .map_err(|e| ControlError::Store(e.to_string()))?;

        // Peers observe both the peer-visible state change and the fact that
        // this node was seen. The change bus coalesces duplicates within the
        // batch window before any session builds a delta.
        if node != before {
            self.publish_change(ChangeEvent::NodeChanged(node.id));
        }
        self.publish_change(ChangeEvent::PeerSeen(node.id));

        if lite_update {
            return Ok(MapOutcome::LiteUpdate);
        }

        let compress = request.compress == "zstd";
        let response = self.build_initial_map(&node, &request)?;
        let frame = self.encode_frame(&response, compress)?;

        if streaming {
            let session_id = self.open_session(node.id, node.ephemeral);
            // Track the peers that were just sent so the first delta only
            // carries changes since this complete frame.
            let initial_peers = SessionPeers::from_peers(response.peers.iter().flatten());
            Ok(MapOutcome::Stream {
                first_frame: frame,
                keep_alive: request.keep_alive,
                compress,
                session_id,
                node_id: node.id,
                initial_peers,
                client_version: request.version,
            })
        } else {
            Ok(MapOutcome::FullFrame(frame))
        }
    }

    /// Build the first complete MapResponse for a node.
    ///
    /// The access-control policy is compiled against the current node set to
    /// derive this node's base filter and the set of peers it may see. The
    /// peer list is built from every visible, authorized node, sorted by node
    /// ID, and user profiles are emitted for the requesting user and each
    /// peer user (Spec-NetMap section 3, Spec-Policy section 3).
    ///
    /// Route handling: a node's effective routes are the union of the routes
    /// an administrator explicitly approved and the routes the policy's
    /// `autoApprovers` auto-approves for the node's advertised routes. The
    /// node's own map carries them in `PrimaryRoutes`; a peer's map appends
    /// them to the peer's `AllowedIPs` (which always includes the peer's own
    /// addresses), so clients can reach subnets behind the router. Exit nodes
    /// fall out of the same mechanism: an approved default route (`0.0.0.0/0`
    /// or `::/0`) is propagated to peers exactly like a subnet route.
    pub fn build_initial_map(
        &self,
        node: &DomainNode,
        request: &MapRequest,
    ) -> Result<MapResponse, ControlError> {
        let version = request.version;
        let compile_nodes = self.compile_nodes()?;
        crabscale_metrics::registry().policy_compiles_total.inc();
        let compiled = crabscale_policy::compile_policy(&self.config.policy, &compile_nodes);
        let self_routes = self.effective_approved_routes(node)?;

        // Per-node Tailscale SSH policy (Spec-Policy §7): the policy's ssh
        // rules are compiled and reduced to this node, then converted into
        // the wire SSHPolicy carried in the map.
        let ssh_policy = {
            crabscale_metrics::registry().policy_compiles_total.inc();
            let ssh_compiled =
                crabscale_policy::compile_ssh_policy(&self.config.policy, &compile_nodes);
            crabscale_policy::build_wire_ssh_policy(
                &ssh_compiled,
                node.id as u64,
                &self.config.server_url,
                &compile_nodes,
            )
        };

        // Emit the policy-derived node attributes on the self node's CapMap
        // (Spec-Policy §6), and advertise this node's own approved routes as
        // PrimaryRoutes (the self address values are never part of it).
        let mut proto_node = node.to_proto();
        proto_node.primary_routes = Self::non_address_routes(&self_routes, &node.addresses);
        // Apply the AllowedIPs wire gate to the self node: at capver >= 112
        // an `AllowedIPs` identical to `Addresses` is emitted as `null` (the
        // shared "same as Addresses" shorthand), shrinking the frame.
        proto_node.allowed_ips =
            Self::allowed_ips_for(version, &node.addresses, proto_node.allowed_ips.as_deref());

        if let Some(self_compile) = compile_nodes.iter().find(|n| n.id == node.id as u64) {
            if !self.config.policy.node_attrs.is_empty() {
                proto_node.cap_map = crabscale_policy::node_attributes(
                    &self.config.policy,
                    self_compile,
                    &compile_nodes,
                );
            }
        }

        // Per-node reduced base filter; empty means deny all.
        let base = compiled
            .node_filters
            .get(&(node.id as u64))
            .cloned()
            .unwrap_or_default();
        // At capver >= 81 prefer the incremental `PacketFilters` map; older
        // clients receive the legacy singular `PacketFilter` fallback
        // (Spec-Compatibility table row 81). Below-minimum versions are
        // rejected before this branch, but the gate is still enforced so the
        // behavior is centralized in one documented decision.
        let mut packet_filters = BTreeMap::new();
        packet_filters.insert("base".to_string(), base.clone());
        let (packet_filter, packet_filters) =
            if crabscale_proto::capver::prefers_incremental_packet_filters(version) {
                (None, Some(packet_filters))
            } else {
                (Some(base), None)
            };

        let visible = compiled
            .peer_visibility
            .get(&(node.id as u64))
            .cloned()
            .unwrap_or_default();

        let mut peers = Vec::new();
        let mut user_ids = std::collections::BTreeSet::new();
        user_ids.insert(node.user_id.unwrap_or(0));
        for stored in self
            .store
            .list_nodes()
            .map_err(|e| ControlError::Store(e.to_string()))?
        {
            // Do not advertise a node to itself.
            if stored.node_key == node.node_key {
                continue;
            }
            // A logged-out node must not be advertised as a peer.
            if !stored.machine_authorized {
                continue;
            }
            // A peer invisible in both directions is absent from the map
            // (Spec-Policy section 3).
            if !visible.contains(&(stored.id as u64)) {
                continue;
            }
            if let Some(uid) = stored.user_id {
                user_ids.insert(uid);
            }
            // Build the peer with its live online/last-seen state and the
            // effective routed AllowedIPs, matching the shape used by deltas
            // and gated on the requesting client's capability version.
            let peer = self.peer_node(&stored, version)?;
            peers.push(peer);
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
            node: Some(proto_node),
            derp_map: Some(self.derp_state.map()),
            domain: self.config.tailnet_domain.clone(),
            peers: Some(peers),
            packet_filter,
            packet_filters,
            user_profiles,
            ssh_policy,
            control_time: CONTROL_TIME.to_string(),
            dns: self.build_dns_config()?,
            ..Default::default()
        })
    }

    /// Apply the `AllowedIPs` wire gate for the given client capability
    /// version.
    ///
    /// At capver >= 112 a value identical to the node's `Addresses` is
    /// omitted (`AllowedIPs: null` means "same as Addresses"); older clients
    /// always receive an explicit list. The effective value is the passed
    /// `allowed` when present (routed subnets extend it) or the node's own
    /// addresses when absent.
    fn allowed_ips_for(
        version: u32,
        addresses: &[String],
        allowed: Option<&[String]>,
    ) -> Option<Vec<String>> {
        let effective = match allowed {
            Some(allowed) => allowed.to_vec(),
            None => addresses.to_vec(),
        };
        if crabscale_proto::capver::allowed_ips_null_means_addresses(version)
            && effective == addresses
        {
            None
        } else {
            Some(effective)
        }
    }

    /// Snapshot the registered nodes in the shape the policy compiler needs.
    pub(crate) fn compile_nodes(&self) -> Result<Vec<crabscale_policy::CompileNode>, ControlError> {
        let mut nodes = Vec::new();
        for stored in self
            .store
            .list_nodes()
            .map_err(|e| ControlError::Store(e.to_string()))?
        {
            nodes.push(self.compile_node(&stored)?);
        }
        Ok(nodes)
    }

    /// Snapshot one stored node in the shape the policy helpers need.
    pub(crate) fn compile_node(
        &self,
        node: &DomainNode,
    ) -> Result<crabscale_policy::CompileNode, ControlError> {
        let user_login = match node.user_id {
            Some(user_id) => self
                .store
                .get_user(user_id)
                .map_err(|e| ControlError::Store(e.to_string()))?
                .map(|u| u.login_name),
            None => None,
        };
        Ok(crabscale_policy::CompileNode {
            id: node.id as u64,
            stable_id: node.stable_id.clone(),
            user_login,
            addresses: node.addresses.clone(),
            tags: node.tags.clone().unwrap_or_default(),
        })
    }

    /// The routes effective for `node`: the routes an administrator
    /// explicitly approved *and* that the node is still advertising, plus
    /// the routes the policy's `autoApprovers` auto-approves for the node's
    /// advertised routes.
    ///
    /// An explicit approval alone is not enough: a route is only propagated
    /// while the node advertises it. The intersection with
    /// `advertised_routes` is what makes a client removing a route trigger
    /// a map update even when the admin approval stays in place.
    fn effective_approved_routes(&self, node: &DomainNode) -> Result<Vec<String>, ControlError> {
        let compile = self.compile_node(node)?;
        let approved: std::collections::BTreeSet<String> = node
            .approved_routes
            .iter()
            .filter(|route| node.advertised_routes.contains(route))
            .cloned()
            .collect();
        let mut routes: Vec<String> = approved.into_iter().collect();
        routes.extend(crabscale_policy::auto_approved_routes(
            &self.config.policy,
            &compile,
            &node.advertised_routes,
        ));
        routes.sort();
        routes.dedup();
        Ok(routes)
    }

    /// The routes that are not one of the node's own tailnet addresses.
    /// `PrimaryRoutes` must never contain the self address values that are
    /// already in `AllowedIPs`.
    fn non_address_routes(routes: &[String], addresses: &[String]) -> Vec<String> {
        routes
            .iter()
            .filter(|route| !addresses.contains(route))
            .cloned()
            .collect()
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

    /// Hot-reload the DNS extra-records file and push the new revision to
    /// every subscribed map session.
    ///
    /// Returns the number of records loaded. Errors if no path is configured
    /// or the file is unreadable/invalid; on error the previous records stay
    /// in effect.
    pub fn reload_dns_extra_records(&self) -> Result<usize, ControlError> {
        let Some(path) = &self.config.dns.extra_records_path else {
            return Err(ControlError::ExtraRecords(
                "no DNS extra records path configured".to_string(),
            ));
        };
        let records =
            dns::load_extra_records(path).map_err(|e| ControlError::ExtraRecords(e.to_string()))?;
        let count = records.len();
        self.dns_state.set_extra_records(records);
        // Push a DNS delta to every live map session (Spec-NetMap section 7.3).
        self.publish_change(ChangeEvent::DnsChanged);
        Ok(count)
    }

    /// Snapshot of the current DNS extra records.
    pub fn dns_extra_records(&self) -> Vec<crabscale_proto::DnsRecord> {
        self.dns_state.extra_records()
    }

    /// Subscribe to DNS configuration changes. The receiver yields a new
    /// revision number for every successful hot reload.
    pub fn subscribe_dns_changes(&self) -> tokio::sync::broadcast::Receiver<u64> {
        self.dns_state.subscribe()
    }

    /// The current DNS revision; increments on every hot reload.
    pub fn dns_revision(&self) -> u64 {
        self.dns_state.revision()
    }

    /// Build the tailnet-wide DNS config delivered in the `DNS` field.
    ///
    /// Returns `None` when there is nothing meaningful to send (MagicDNS off
    /// and no split DNS, search domains, or extra records configured).
    pub fn build_dns_config(&self) -> Result<Option<crabscale_proto::DnsConfig>, ControlError> {
        let dns = &self.config.dns;
        let extra_records = self.dns_state.extra_records();
        if !dns.magic_dns
            && dns.split_dns.is_empty()
            && dns.search_domains.is_empty()
            && extra_records.is_empty()
        {
            return Ok(None);
        }
        let magic_dns_ipv4 = dns.magic_dns_ipv4.unwrap_or_else(|| {
            dns::derive_magic_dns_ipv4(self.config.ipv4_prefix, self.config.ipv4_prefix_len)
        });
        let magic_dns_ipv6 = dns.magic_dns_ipv6.unwrap_or_else(|| {
            dns::derive_magic_dns_ipv6(self.config.ipv6_prefix, self.config.ipv6_prefix_len)
        });

        let mut nodes = Vec::new();
        for stored in self
            .store
            .list_nodes()
            .map_err(|e| ControlError::Store(e.to_string()))?
        {
            nodes.push(stored.to_proto());
        }

        Ok(Some(dns.build(
            &self.config.tailnet_domain,
            magic_dns_ipv4,
            magic_dns_ipv6,
            &nodes,
            &extra_records,
        )))
    }

    /// Build a MapResponse delta frame carrying only the DNS config, used to
    /// push DNS changes to live map sessions.
    pub fn build_dns_delta_frame(&self, compress: bool) -> Result<Vec<u8>, ControlError> {
        let Some(dns) = self.build_dns_config()? else {
            return Err(ControlError::ExtraRecords(
                "no DNS config to push".to_string(),
            ));
        };
        let response = MapResponse {
            dns: Some(dns),
            ..Default::default()
        };
        self.encode_frame(&response, compress)
    }

    /// The current DERP map advertised to clients.
    ///
    /// This is the runtime snapshot, so a `set_derp_map` replacement is
    /// visible to any later map response.
    pub fn derp_map(&self) -> DerpMap {
        self.derp_state.map()
    }

    /// Atomically replace the DERP map advertised to clients.
    ///
    /// The replacement bumps the DERP map revision and notifies every live
    /// streaming map session, which pushes a `DERPMap` delta frame
    /// (Spec-DERP-STUN §7). Returns the new revision number.
    pub fn set_derp_map(&self, map: DerpMap) -> u64 {
        let revision = self.derp_state.set_map(map);
        // Push a DERP map delta to every live map session (Spec-DERP-STUN §7).
        self.publish_change(ChangeEvent::DerpMapChanged);
        revision
    }

    /// Subscribe to DERP map changes. The receiver yields a new revision for
    /// every `set_derp_map` replacement.
    pub fn subscribe_derp_map_changes(&self) -> tokio::sync::broadcast::Receiver<u64> {
        self.derp_state.subscribe()
    }

    /// The current DERP map revision (0 = startup config, no replacements).
    pub fn derp_map_revision(&self) -> u64 {
        self.derp_state.revision()
    }

    /// Build a MapResponse delta frame carrying only the DERP map, used to
    /// push a map change to live map sessions.
    pub fn build_derp_map_delta_frame(&self, compress: bool) -> Result<Vec<u8>, ControlError> {
        let response = MapResponse {
            derp_map: Some(self.derp_state.map()),
            ..Default::default()
        };
        self.encode_frame(&response, compress)
    }

    /// Whether a node key is authorized to use the tailnet and its relay.
    ///
    /// This is the decision the `/verify` endpoint and the DERP relay's
    /// admission callback rely on: a node is only allowed when it has
    /// registered and is `machine_authorized`. Unknown or logged-out nodes
    /// return `false` (Spec-Control-API `POST /verify`).
    pub fn node_is_authorized(&self, node_key: &NodeKey) -> bool {
        match self
            .store
            .get_node_by_node_key(node_key)
            .map_err(|e| ControlError::Store(e.to_string()))
        {
            Ok(Some(node)) => node.machine_authorized,
            _ => false,
        }
    }

    /// Publish a single change to the shared change bus.
    ///
    /// The bus coalesces events per node within the configured batch window
    /// and broadcasts a [`ChangeBatch`] to every live map session (M3-03).
    pub fn publish_change(&self, event: ChangeEvent) {
        self.events.publish(event);
    }

    /// Subscribe to coalesced change batches for live map sessions.
    ///
    /// The receiver yields one [`ChangeBatch`] per flush; a lagged receiver
    /// observes `Lagged` and should fall back to a full refresh.
    pub fn subscribe_changes(&self) -> tokio::sync::broadcast::Receiver<ChangeBatch> {
        self.events.subscribe()
    }

    /// Flush any pending changes now, broadcasting a batch if any are queued.
    ///
    /// The background sweep normally flushes on the configured window; callers
    /// (tests, shutdown paths) can force a flush directly.
    pub fn flush_changes(&self) {
        self.events.flush();
    }

    /// Number of distinct changes currently awaiting a batch flush.
    pub fn pending_change_count(&self) -> usize {
        self.events.pending_count()
    }

    /// Spawn the background change-batch sweeper for this control plane, if
    /// one is not already running. Must be called from inside a Tokio runtime.
    ///
    /// Returns `None` when a sweeper is already active (like
    /// [`Self::claim_reaper`], only the first caller wins).
    pub fn spawn_change_batcher(&self) -> Option<tokio::task::JoinHandle<()>> {
        self.events.spawn_sweeper()
    }

    /// Signal that the access-control policy changed so live map sessions
    /// re-derive peer visibility, filters, and SSH policy.
    ///
    /// The caller owns the policy snapshot and swaps it (e.g. through a
    /// mutable config); this only fans the typed `PolicyChanged` event out to
    /// sessions through the change bus.
    pub fn publish_policy_changed(&self) {
        self.publish_change(ChangeEvent::PolicyChanged);
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

    /// The allow-all policy used by tests that exercise registration, map
    /// building, and streaming mechanics (the historical default behavior).
    fn allow_all_policy() -> crabscale_policy::Policy {
        crabscale_policy::parse_policy(
            r#"{ "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*"] } ] }"#,
        )
        .expect("allow-all policy must parse")
    }

    fn test_plane() -> ControlPlane {
        ControlPlane::new(ControlConfig {
            policy: allow_all_policy(),
            ..ControlConfig::default()
        })
    }

    /// A policy that lets the default user (`owner@example.com`) approve
    /// `tag:server`, used by tag and `RequestTags` tests.
    fn tagged_policy() -> crabscale_policy::Policy {
        crabscale_policy::parse_policy(
            r#"{
                "tagOwners": { "tag:server": ["owner@example.com"] },
                "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*"] } ]
            }"#,
        )
        .expect("tagged policy must parse")
    }

    /// A control plane whose policy lets the default user approve `tag:server`.
    fn tagged_plane() -> ControlPlane {
        ControlPlane::new(ControlConfig {
            policy: tagged_policy(),
            ..ControlConfig::default()
        })
    }

    fn test_machine_key() -> MachineKey {
        MachineKey::from_bytes([0x11; 32])
    }

    fn test_node_key() -> NodeKey {
        NodeKey::from_bytes([0x22; 32])
    }

    fn register_extra_node(plane: &ControlPlane, machine: [u8; 32], node: [u8; 32]) {
        let mut request = test_register_request();
        request.node_key = NodeKey::from_bytes(node);
        let response = plane.register(MachineKey::from_bytes(machine), request);
        assert!(response.machine_authorized);
    }

    /// Map as `node_id` and return the decoded MapResponse JSON.
    fn map_json(plane: &ControlPlane, node_id: u64) -> serde_json::Value {
        let stored = plane.store.list_nodes().unwrap();
        let node = stored
            .into_iter()
            .find(|n| n.id as u64 == node_id)
            .expect("node must exist");
        let request = MapRequest {
            version: 130,
            node_key: node.node_key,
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            ..Default::default()
        };
        let outcome = plane.handle_map(node.machine_key, request).unwrap();
        let MapOutcome::FullFrame(frame) = outcome else {
            panic!("expected full frame");
        };
        let (payload, consumed) = crabscale_proto::decode_map_response_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        serde_json::from_slice(payload).unwrap()
    }

    /// Extract the stable IDs of a MapResponse's peer array, sorted.
    fn peer_stable_ids(json: &serde_json::Value) -> Vec<String> {
        json["Peers"]
            .as_array()
            .expect("Peers must be an array")
            .iter()
            .map(|p| {
                p["StableID"]
                    .as_str()
                    .expect("StableID must be a string")
                    .to_string()
            })
            .collect()
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
        let first = plane.register(test_machine_key(), test_register_request());
        assert!(first.machine_authorized);
        let second = plane.register(test_machine_key(), test_register_request());
        assert!(second.machine_authorized);
    }

    #[test]
    fn invalid_auth_key_starts_interactive_registration() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.auth = Some(crabscale_proto::RegisterAuth {
            auth_key: "wrong".to_string(),
        });
        let response = plane.register(test_machine_key(), request);
        assert!(!response.machine_authorized);
        assert!(response.error.is_empty());
        assert!(!response.auth_url.is_empty());
        assert!(response.auth_url.contains("/register/"));
    }

    #[test]
    fn map_returns_complete_first_frame() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
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
    fn configured_derp_region_reaches_client_map() {
        let mut input = crabscale_proto::DerpMap {
            omit_default_regions: true,
            ..Default::default()
        };
        input.regions.insert(
            "900".to_string(),
            crabscale_proto::DerpRegion {
                region_id: 900,
                region_code: "crab".to_string(),
                region_name: "Crabscale".to_string(),
                nodes: vec![crabscale_proto::DerpNode {
                    name: "crab-1".to_string(),
                    region_id: 900,
                    host_name: "derp.example.com".to_string(),
                    derp_port: 443,
                    stun_port: 3478,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let plane = ControlPlane::new(ControlConfig {
            derp_map: input,
            policy: allow_all_policy(),
            ..ControlConfig::default()
        });
        plane.register(test_machine_key(), test_register_request());

        let json = map_json(&plane, 1);
        let regions = &json["DERPMap"]["Regions"];
        assert_eq!(
            regions["900"]["RegionID"],
            serde_json::json!(900),
            "the configured region id must be delivered"
        );
        assert_eq!(regions["900"]["RegionCode"], serde_json::json!("crab"));
        assert_eq!(
            regions["900"]["Nodes"][0]["HostName"],
            serde_json::json!("derp.example.com")
        );
        assert_eq!(
            regions["900"]["Nodes"][0]["STUNPort"],
            serde_json::json!(3478)
        );
    }

    #[test]
    fn node_is_authorized_after_registration_denies_unknown() {
        let plane = test_plane();
        // Unknown key is denied before registration.
        assert!(!plane.node_is_authorized(&test_node_key()));

        plane.register(test_machine_key(), test_register_request());
        assert!(plane.node_is_authorized(&test_node_key()));

        // A random unrelated key stays denied.
        assert!(!plane.node_is_authorized(&NodeKey::from_bytes([0x77; 32])));

        // After logout the same key is denied again.
        plane.logout(test_machine_key(), &test_node_key()).unwrap();
        assert!(!plane.node_is_authorized(&test_node_key()));
    }

    #[test]
    fn derp_map_change_broadcasts_and_builds_delta() {
        let plane = test_plane();
        let mut rx = plane.subscribe_derp_map_changes();
        assert_eq!(plane.derp_map_revision(), 0);

        let mut updated = plane.derp_map();
        updated.regions.insert(
            "999".to_string(),
            crabscale_proto::DerpRegion {
                region_id: 999,
                region_code: "new".to_string(),
                region_name: "New region".to_string(),
                ..Default::default()
            },
        );
        let revision = plane.set_derp_map(updated);
        assert_eq!(revision, 1);
        assert_eq!(plane.derp_map_revision(), 1);
        assert_eq!(
            rx.try_recv().unwrap(),
            1,
            "subscriber must see the revision"
        );
        assert!(plane.derp_map().regions.contains_key("999"));

        // A delta frame carries only the DERP map.
        let frame = plane.build_derp_map_delta_frame(false).unwrap();
        let (payload, consumed) = crabscale_proto::decode_map_response_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        let json: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert!(json.get("DERPMap").is_some());
        assert!(
            json.get("KeepAlive").is_none(),
            "delta must not be a keepalive"
        );
        assert!(
            json.get("Node").is_none(),
            "delta must omit unchanged fields"
        );
        assert!(json["DERPMap"]["Regions"].get("999").is_some());
    }

    #[test]
    fn initial_map_lists_peers_sorted_and_user_profiles() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());

        // Register a second node with a distinct node and machine key.
        let second_machine = MachineKey::from_bytes([0x12; 32]);
        let second_node = NodeKey::from_bytes([0x23; 32]);
        let mut second_request = test_register_request();
        second_request.node_key = second_node;
        let response = plane.register(second_machine, second_request);
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
        plane.register(test_machine_key(), test_register_request());

        // Register two more nodes so the requesting node has two peers.
        let mut req_b = test_register_request();
        req_b.node_key = NodeKey::from_bytes([0x24; 32]);
        plane.register(MachineKey::from_bytes([0x13; 32]), req_b);
        let mut req_c = test_register_request();
        req_c.node_key = NodeKey::from_bytes([0x25; 32]);
        plane.register(MachineKey::from_bytes([0x14; 32]), req_c);

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
        plane.register(test_machine_key(), test_register_request());
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
        plane.register(test_machine_key(), test_register_request());
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
        plane.register(test_machine_key(), test_register_request());

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
        plane.register(test_machine_key(), test_register_request());

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
    fn handle_map_rejects_below_minimum_version() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        let request = MapRequest {
            version: MIN_SUPPORTED_CAPVER - 1,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            ..Default::default()
        };
        assert!(matches!(
            plane.handle_map(test_machine_key(), request),
            Err(ControlError::UnsupportedVersion(v)) if v == MIN_SUPPORTED_CAPVER - 1
        ));
    }

    #[test]
    fn initial_map_prefers_packet_filters_at_and_above_81() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        let node = plane
            .store
            .get_node_by_node_key(&test_node_key())
            .unwrap()
            .expect("node must exist");
        let base_map = |version| {
            let request = MapRequest {
                version,
                node_key: test_node_key(),
                disco_key: DiscoKey::from_bytes([0x44; 32]),
                ..Default::default()
            };
            plane.build_initial_map(&node, &request).unwrap()
        };

        let modern = base_map(crabscale_proto::capver::PACKET_FILTERS_CAPVER);
        assert!(
            modern.packet_filters.is_some(),
            ">=81 prefers the incremental PacketFilters map"
        );
        assert!(
            modern.packet_filter.is_none(),
            ">=81 must not use the singular PacketFilter fallback"
        );

        let legacy = base_map(crabscale_proto::capver::PACKET_FILTERS_CAPVER - 1);
        assert!(
            legacy.packet_filter.is_some(),
            "<81 uses the legacy singular PacketFilter field"
        );
        assert!(
            legacy.packet_filters.is_none(),
            "<81 must not use the incremental PacketFilters map"
        );
    }

    #[test]
    fn initial_map_omits_allowed_ips_when_same_as_addresses_at_112() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        let node = plane
            .store
            .get_node_by_node_key(&test_node_key())
            .unwrap()
            .expect("node must exist");
        assert!(!node.addresses.is_empty());

        let modern = MapRequest {
            version: crabscale_proto::capver::ALLOWED_IPS_NULL_CAPVER,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x44; 32]),
            ..Default::default()
        };
        let response = plane.build_initial_map(&node, &modern).unwrap();
        assert_eq!(
            response.node.as_ref().unwrap().allowed_ips,
            None,
            ">=112 omits AllowedIPs when it equals Addresses"
        );

        let legacy = MapRequest {
            version: crabscale_proto::capver::ALLOWED_IPS_NULL_CAPVER - 1,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x44; 32]),
            ..Default::default()
        };
        let response = plane.build_initial_map(&node, &legacy).unwrap();
        assert_eq!(
            response.node.as_ref().unwrap().allowed_ips.as_deref(),
            Some(node.addresses.as_slice()),
            "<112 always carries an explicit AllowedIPs list"
        );
    }

    #[test]
    fn initial_map_home_derp_serializes_as_integer() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        let node = plane
            .store
            .get_node_by_node_key(&test_node_key())
            .unwrap()
            .expect("node must exist");
        let request = MapRequest {
            version: MIN_SUPPORTED_CAPVER,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x44; 32]),
            ..Default::default()
        };
        let response = plane.build_initial_map(&node, &request).unwrap();
        let frame = plane.encode_frame(&response, false).unwrap();
        let (payload, consumed) = crabscale_proto::decode_map_response_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        let json: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert!(
            json["Node"]["HomeDERP"].is_number(),
            "HomeDERP must be an integer for supported clients: {}",
            json["Node"]["HomeDERP"]
        );
    }

    #[test]
    fn lite_update_changes_endpoints_while_stream_open() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());

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
        plane.register(test_machine_key(), test_register_request());
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
        // Remove any stale directory left by an interrupted previous run so a
        // leftover database cannot trip the UNIQUE constraint on create_user.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("restart.sqlite");

        {
            let plane = ControlPlane::open_sqlite(ControlConfig::default(), &db_path).unwrap();
            let response = plane.register(test_machine_key(), test_register_request());
            assert!(response.machine_authorized);
        }

        // Reopen the same database file and map with the same machine key.
        {
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
        } // plane dropped here, releasing the SQLite handle before cleanup.

        std::fs::remove_dir_all(&dir).unwrap();
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
        let first = plane.register(test_machine_key(), request_with(node1, &key));
        assert!(first.machine_authorized);
        let second = plane.register(test_machine_key(), request_with(node2, &key));
        assert!(!second.machine_authorized);
    }

    #[test]
    fn restart_relogin_does_not_consume_one_time_key() {
        let plane = test_plane();
        let key = plane
            .create_pre_auth_key("single2", false, false, None, None)
            .unwrap();
        let node = NodeKey::from_bytes([0x43; 32]);
        let first = plane.register(test_machine_key(), request_with(node, &key));
        assert!(first.machine_authorized);
        // Re-register the same node with the same key: still authorized.
        let second = plane.register(test_machine_key(), request_with(node, &key));
        assert!(second.machine_authorized);
    }

    #[test]
    fn logout_returns_client_to_needs_login() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        let response = plane.logout(test_machine_key(), &test_node_key()).unwrap();
        assert!(!response.machine_authorized);
        // Re-register without auth: still logged out.
        let mut request = test_register_request();
        request.auth = None;
        let response = plane.register(test_machine_key(), request);
        assert!(!response.machine_authorized);
    }

    #[test]
    fn logout_rejects_wrong_machine_key() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        // A different Noise machine key must not be able to log out the node.
        let other = MachineKey::from_bytes([0x99; 32]);
        let err = plane.logout(other, &test_node_key()).unwrap_err();
        assert!(matches!(err, ControlError::NotFound));
        // The node is still authorized.
        let node = plane
            .store
            .get_node_by_node_key(&test_node_key())
            .unwrap()
            .unwrap();
        assert!(node.machine_authorized);
    }

    #[test]
    fn tagged_node_survives_logout() {
        let plane = tagged_plane();
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
        let response = plane.register(test_machine_key(), request_with(node, &key));
        assert!(response.machine_authorized);
        let response = plane.logout(test_machine_key(), &node).unwrap();
        assert!(response.machine_authorized);
    }

    #[test]
    fn ephemeral_node_is_deleted_on_logout() {
        let plane = test_plane();
        let key = plane
            .create_pre_auth_key("eph", true, true, None, None)
            .unwrap();
        let node = NodeKey::from_bytes([0x45; 32]);
        let response = plane.register(test_machine_key(), request_with(node, &key));
        assert!(response.machine_authorized);
        let response = plane.logout(test_machine_key(), &node).unwrap();
        assert!(!response.machine_authorized);
        assert!(plane.store.get_node_by_node_key(&node).unwrap().is_none());
    }

    #[test]
    fn reap_sessions_deletes_expired_ephemeral_node() {
        let plane = test_plane();
        let key = plane
            .create_pre_auth_key("ephgc", true, true, None, None)
            .unwrap();
        let node_key = NodeKey::from_bytes([0x46; 32]);
        let response = plane.register(test_machine_key(), request_with(node_key, &key));
        assert!(response.machine_authorized);

        let node = plane
            .store
            .get_node_by_node_key(&node_key)
            .unwrap()
            .unwrap();
        let session_id = plane.open_session(node.id, true);
        assert!(plane.is_node_online(node.id));

        // A live session cancels ephemeral GC even far in the future.
        let now = time::now_unix();
        assert!(plane.reap_sessions_at(now + 1000).is_empty());
        assert!(
            plane
                .store
                .get_node_by_node_key(&node_key)
                .unwrap()
                .is_some()
        );

        // After the last session closes and the grace elapses, the ephemeral
        // node is deleted from the store.
        plane.close_session(session_id);
        let events = plane.reap_sessions_at(now + 1000);
        assert!(events.contains(&SessionEvent::EphemeralExpired(node.id)));
        assert!(
            plane
                .store
                .get_node_by_node_key(&node_key)
                .unwrap()
                .is_none()
        );
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
        let response = plane.register(test_machine_key(), request_with(node, &key));
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
        let response = plane.register(test_machine_key(), request_with(node, &key));
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
        let first = plane.register(test_machine_key(), request_with(node1, &key));
        assert!(first.machine_authorized);
        let second = plane.register(test_machine_key(), request_with(node2, &key));
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
        let first = plane.register(test_machine_key(), request_with(node_a, &first_key));
        assert!(first.machine_authorized);

        // Log out node A, then re-auth with a fresh single-use key.
        let logout = plane.logout(test_machine_key(), &node_a).unwrap();
        assert!(!logout.machine_authorized);
        let second_key = plane
            .create_pre_auth_key("reauth2", false, false, None, None)
            .unwrap();
        let reauth = plane.register(test_machine_key(), request_with(node_a, &second_key));
        assert!(reauth.machine_authorized);

        // The same single-use key must not authorize a second distinct node.
        let second = plane.register(test_machine_key(), request_with(node_b, &second_key));
        assert!(!second.machine_authorized);
    }

    #[test]
    fn past_expiry_logs_out_node() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        let mut request = test_register_request();
        request.expiry = "2000-01-01T00:00:00Z".to_string();
        let response = plane.register(test_machine_key(), request);
        assert!(!response.machine_authorized);
        assert!(response.node_key_expired);
    }

    #[test]
    fn future_expiry_is_rejected() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        let mut request = test_register_request();
        request.expiry = "2999-01-01T00:00:00Z".to_string();
        let response = plane.register(test_machine_key(), request);
        assert!(!response.machine_authorized);
        assert!(!response.error.is_empty());
    }

    #[test]
    fn new_node_with_past_expiry_is_rejected() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.node_key = NodeKey::from_bytes([0x53; 32]);
        request.expiry = "2000-01-01T00:00:00Z".to_string();
        let response = plane.register(test_machine_key(), request);
        assert!(!response.machine_authorized);
        assert!(response.node_key_expired);
    }

    #[test]
    fn new_node_with_future_expiry_is_rejected() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.node_key = NodeKey::from_bytes([0x54; 32]);
        request.expiry = "2999-01-01T00:00:00Z".to_string();
        let response = plane.register(test_machine_key(), request);
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
        let pending = plane.register(test_machine_key(), request);
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
        let response = plane.register(test_machine_key(), followup);
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
    fn oidc_user_upsert_creates_user_and_login() {
        let plane = test_plane();
        let user_id = plane
            .upsert_oidc_user(&OidcProfile {
                subject: "sub-123".to_string(),
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
            })
            .unwrap();
        let user = plane.store.get_user(user_id).unwrap().unwrap();
        assert_eq!(user.login_name, "alice@example.com");
        assert_eq!(user.display_name, "Alice");
        let login = plane
            .store
            .get_login_by_provider_subject("oidc", "sub-123")
            .unwrap()
            .expect("oidc login must exist");
        assert_eq!(login.user_id, user_id);
        // The second callback for the same subject must be idempotent.
        let again = plane
            .upsert_oidc_user(&OidcProfile {
                subject: "sub-123".to_string(),
                email: "alice@example.com".to_string(),
                display_name: "Alice Renamed".to_string(),
            })
            .unwrap();
        assert_eq!(again, user_id);
        assert_eq!(
            plane.store.get_user(user_id).unwrap().unwrap().display_name,
            "Alice Renamed"
        );
        assert_eq!(
            plane
                .store
                .get_login_by_provider_subject("oidc", "sub-123")
                .unwrap()
                .unwrap()
                .user_id,
            user_id
        );
    }

    #[test]
    fn oidc_approved_pending_authorizes_followup() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.auth = None;
        let pending = plane.register(test_machine_key(), request);
        let auth_id = auth_id_from_followup(&pending.auth_url).unwrap();

        plane
            .upsert_oidc_user(&OidcProfile {
                subject: "sub-456".to_string(),
                email: "bob@example.com".to_string(),
                display_name: "Bob".to_string(),
            })
            .unwrap();
        // Approval flows through the same auth cache the CLI uses.
        plane.approve_pending(&auth_id, "bob@example.com").unwrap();

        let mut followup = test_register_request();
        followup.auth = None;
        followup.followup = pending.auth_url.clone();
        let response = plane.register(test_machine_key(), followup);
        assert!(response.machine_authorized);
        let node = plane
            .store
            .get_node_by_node_key(&test_node_key())
            .unwrap()
            .unwrap();
        let user = plane
            .store
            .get_user(node.user_id.unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(user.login_name, "bob@example.com");
        assert_eq!(user.display_name, "Bob");
    }

    #[test]
    fn unknown_auth_id_cannot_authorize_different_machine_key() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.auth = None;
        let pending = plane.register(test_machine_key(), request);
        let auth_id = auth_id_from_followup(&pending.auth_url).unwrap();
        plane
            .approve_pending(&auth_id, "owner@example.com")
            .unwrap();

        // A different machine key polling the same auth id must be rejected.
        let mut followup = test_register_request();
        followup.auth = None;
        followup.followup = pending.auth_url.clone();
        let response = plane.register(MachineKey::from_bytes([0x99; 32]), followup);
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
        let pending = plane.register(test_machine_key(), request);
        let auth_id = auth_id_from_followup(&pending.auth_url).unwrap();
        plane.reject_pending(&auth_id).unwrap();

        let mut followup = test_register_request();
        followup.auth = None;
        followup.followup = pending.auth_url.clone();
        let response = plane.register(test_machine_key(), followup);
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
        let pending = plane.register(test_machine_key(), request);
        assert!(!pending.machine_authorized);

        let mut followup = test_register_request();
        followup.auth = None;
        followup.followup = pending.auth_url.clone();
        let response = plane.register(test_machine_key(), followup);
        assert!(!response.machine_authorized);
        assert!(response.error.contains("expired"));
    }

    #[test]
    fn logged_out_node_is_not_advertised_as_peer() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());

        // Register a second node with a distinct node and machine key.
        let second_machine = MachineKey::from_bytes([0x12; 32]);
        let second_node = NodeKey::from_bytes([0x23; 32]);
        let mut second_request = test_register_request();
        second_request.node_key = second_node;
        let response = plane.register(second_machine, second_request);
        assert!(response.machine_authorized);

        // Log the second node out; it must no longer be advertised.
        let logout = plane.logout(second_machine, &second_node).unwrap();
        assert!(!logout.machine_authorized);

        // Map as the first node: the logged-out node must not appear as a peer.
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
        assert!(peers.is_empty(), "logged-out node must not be advertised");
    }

    #[test]
    fn non_default_user_gets_correct_requesting_profile() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.auth = None;
        let pending = plane.register(test_machine_key(), request);
        assert!(!pending.machine_authorized);

        // Approve the registration under a non-default user.
        let auth_id = auth_id_from_followup(&pending.auth_url).unwrap();
        plane
            .approve_pending(&auth_id, "alice@example.com")
            .unwrap();

        let mut followup = test_register_request();
        followup.auth = None;
        followup.followup = pending.auth_url.clone();
        let response = plane.register(test_machine_key(), followup);
        assert!(response.machine_authorized);

        // Map as the requesting node: its user profile must be the non-default
        // user, not the control plane's default user.
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

        let profiles = json["UserProfiles"]
            .as_array()
            .expect("UserProfiles must be an array");
        assert_eq!(profiles.len(), 1, "only the requesting user is expected");
        assert_eq!(
            profiles[0]["LoginName"],
            serde_json::json!("alice@example.com")
        );
        assert_ne!(profiles[0]["ID"], serde_json::json!(plane.config.user_id));
    }

    #[test]
    fn mismatched_endpoint_types_are_rejected() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());

        let request = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            endpoints: vec!["1.2.3.4:41641".to_string()],
            endpoint_types: vec![1, 2],
            stream: false,
            ..Default::default()
        };
        let err = plane.handle_map(test_machine_key(), request).unwrap_err();
        assert!(matches!(err, ControlError::InvalidEndpointTypes));
    }

    #[test]
    fn deny_all_policy_serializes_empty_base_filter() {
        // A fresh plane uses the default deny-all policy.
        let plane = ControlPlane::new(ControlConfig::default());
        plane.register(test_machine_key(), test_register_request());

        let json = map_json(&plane, 1);
        assert_eq!(
            json["PacketFilters"]["base"],
            serde_json::json!([]),
            "deny-all must serialize an empty base filter as []"
        );
    }

    #[test]
    fn packet_filters_are_per_node_reduced() {
        let mut plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        register_extra_node(&plane, [0x12; 32], [0x23; 32]);

        // Allocated addresses are random, so build the policy from the
        // addresses actually assigned to the nodes on this plane.
        let nodes = plane.store.list_nodes().unwrap();
        let n1_addr = nodes.iter().find(|n| n.id == 1).unwrap().addresses[0].clone();
        let n2_addr = nodes.iter().find(|n| n.id == 2).unwrap().addresses[0].clone();
        plane.config.policy = crabscale_policy::parse_policy(&format!(
            r#"{{ "acls": [ {{ "action": "accept", "src": ["{n1_addr}"], "dst": ["{n2_addr}:22"] }} ] }}"#
        ))
        .expect("policy must parse");

        // Node 1 (the source) has no rules on its own filter.
        let n1 = map_json(&plane, 1);
        assert_eq!(n1["PacketFilters"]["base"], serde_json::json!([]));
        assert_eq!(
            peer_stable_ids(&n1),
            vec!["n00000000000000000000002".to_string()]
        );

        // Node 2 (the destination) carries the compiled rule.
        let n2 = map_json(&plane, 2);
        assert_eq!(
            n2["PacketFilters"]["base"],
            serde_json::json!([
                {
                    "SrcIPs": [n1_addr],
                    "DstPorts": [{ "First": 22, "Last": 22 }]
                }
            ])
        );
        assert_eq!(
            peer_stable_ids(&n2),
            vec!["n00000000000000000000001".to_string()]
        );
    }

    #[test]
    fn peer_invisible_in_both_directions_is_absent_from_map() {
        let mut plane = test_plane();
        plane.register(test_machine_key(), test_register_request()); // node 1
        register_extra_node(&plane, [0x12; 32], [0x23; 32]); // node 2
        register_extra_node(&plane, [0x13; 32], [0x24; 32]); // node 3

        let nodes = plane.store.list_nodes().unwrap();
        let n1_addr = nodes.iter().find(|n| n.id == 1).unwrap().addresses[0].clone();
        let n2_addr = nodes.iter().find(|n| n.id == 2).unwrap().addresses[0].clone();
        plane.config.policy = crabscale_policy::parse_policy(&format!(
            r#"{{ "acls": [ {{ "action": "accept", "src": ["{n1_addr}"], "dst": ["{n2_addr}:*"] }} ] }}"#
        ))
        .expect("policy must parse");

        // Node 3 is invisible in both directions and must not appear anywhere.
        let n1 = map_json(&plane, 1);
        assert_eq!(
            peer_stable_ids(&n1),
            vec!["n00000000000000000000002".to_string()]
        );
        let n2 = map_json(&plane, 2);
        assert_eq!(
            peer_stable_ids(&n2),
            vec!["n00000000000000000000001".to_string()]
        );
        let n3 = map_json(&plane, 3);
        assert_eq!(n3["Peers"], serde_json::json!([]));
    }

    /// Map as `node` with the given `Hostinfo.RequestTags`, returning the raw
    /// outcome so tests can assert both success and error paths.
    fn map_with_request_tags(
        plane: &ControlPlane,
        node: &DomainNode,
        request_tags: Vec<String>,
    ) -> Result<MapOutcome, ControlError> {
        let request = MapRequest {
            version: 130,
            node_key: node.node_key,
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            hostinfo: Some(Hostinfo {
                request_tags: Some(request_tags),
                ..Default::default()
            }),
            ..Default::default()
        };
        plane.handle_map(node.machine_key, request)
    }

    #[test]
    fn tagged_pre_auth_key_creates_node_without_user_ownership() {
        let plane = tagged_plane();
        let key = plane
            .create_pre_auth_key(
                "tm1",
                true,
                false,
                None,
                Some(vec!["tag:server".to_string()]),
            )
            .unwrap();
        let node_key = NodeKey::from_bytes([0x61; 32]);
        let response = plane.register(test_machine_key(), request_with(node_key, &key));
        assert!(response.machine_authorized);
        let node = plane
            .store
            .get_node_by_node_key(&node_key)
            .unwrap()
            .unwrap();
        assert_eq!(node.tags, Some(vec!["tag:server".to_string()]));
        assert_eq!(node.user_id, None, "tagged nodes carry no user ownership");
    }

    #[test]
    fn create_pre_auth_key_rejects_tags_not_owned_by_creator() {
        let plane = tagged_plane(); // the owner may only approve tag:server
        let err = plane
            .create_pre_auth_key(
                "tm2",
                true,
                false,
                None,
                Some(vec!["tag:other".to_string()]),
            )
            .unwrap_err();
        assert!(
            matches!(err, ControlError::Policy(_)),
            "unowned tags must be rejected at key creation"
        );
    }

    #[test]
    fn tagged_node_has_no_key_expiry_by_default() {
        let plane = tagged_plane();
        let key = plane
            .create_pre_auth_key(
                "tm3",
                true,
                false,
                None,
                Some(vec!["tag:server".to_string()]),
            )
            .unwrap();
        let node_key = NodeKey::from_bytes([0x62; 32]);

        // A past expiry in the registration is ignored for a tagged node:
        // tagged nodes never expire.
        let mut request = request_with(node_key, &key);
        request.expiry = "2000-01-01T00:00:00Z".to_string();
        let response = plane.register(test_machine_key(), request);
        assert!(response.machine_authorized, "tagged node must not expire");

        // Re-registration with a past expiry keeps the tagged node authorized
        // (logout is a no-op for tagged nodes).
        let mut reauth = request_with(node_key, &key);
        reauth.expiry = "2000-01-01T00:00:00Z".to_string();
        let response = plane.register(test_machine_key(), reauth);
        assert!(response.machine_authorized);
    }

    #[test]
    fn pre_auth_key_registration_rejects_client_request_tags() {
        let plane = tagged_plane();
        let key = plane
            .create_pre_auth_key("tm4", true, false, None, None)
            .unwrap();
        let node_key = NodeKey::from_bytes([0x63; 32]);
        let mut request = request_with(node_key, &key);
        request.hostinfo.as_mut().unwrap().request_tags = Some(vec!["tag:server".to_string()]);
        let response = plane.register(test_machine_key(), request);
        assert!(!response.machine_authorized);
        assert!(!response.error.is_empty());
        assert!(
            plane
                .store
                .get_node_by_node_key(&node_key)
                .unwrap()
                .is_none(),
            "rejected registration must not create a node"
        );
    }

    #[test]
    fn unauthorized_request_tags_transition_fails_and_does_not_change_node() {
        let plane = tagged_plane();
        // A user-owned node owned by the default user.
        plane.register(test_machine_key(), test_register_request());
        let node = plane.store.list_nodes().unwrap().remove(0);

        let err = map_with_request_tags(&plane, &node, vec!["tag:other".to_string()]).unwrap_err();
        assert!(matches!(err, ControlError::UnauthorizedTags(_)));

        let after = plane
            .store
            .get_node_by_node_key(&node.node_key)
            .unwrap()
            .unwrap();
        assert_eq!(
            after.tags, node.tags,
            "unauthorized transition must not change tags"
        );
        assert_eq!(
            after.user_id, node.user_id,
            "unauthorized transition must not change ownership"
        );
    }

    #[test]
    fn authorized_request_tags_transition_tags_node() {
        let plane = tagged_plane();
        plane.register(test_machine_key(), test_register_request());
        let node = plane.store.list_nodes().unwrap().remove(0);

        // The default user owns tag:server, so the transition is authorized.
        map_with_request_tags(&plane, &node, vec!["tag:server".to_string()]).unwrap();

        let after = plane
            .store
            .get_node_by_node_key(&node.node_key)
            .unwrap()
            .unwrap();
        assert_eq!(after.tags, Some(vec!["tag:server".to_string()]));
        assert_eq!(after.user_id, None, "tagged nodes carry no user ownership");
    }

    #[test]
    fn node_attrs_appear_in_self_node_cap_map() {
        let mut plane = test_plane();
        plane.config.policy = crabscale_policy::parse_policy(
            r#"{
                "tagOwners": { "tag:server": ["owner@example.com"] },
                "nodeAttrs": [
                    { "target": ["autogroup:member"], "attr": ["randomize-client-port"] }
                ],
                "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*"] } ]
            }"#,
        )
        .expect("policy must parse");
        plane.register(test_machine_key(), test_register_request());
        let json = map_json(&plane, 1);
        assert_eq!(
            json["Node"]["CapMap"],
            serde_json::json!({ "randomize-client-port": [] }),
            "nodeAttrs must appear in the self node CapMap"
        );
    }

    #[test]
    fn node_attrs_cap_map_updates_on_policy_change() {
        let mut plane = test_plane();
        // Start with a policy that grants no attributes.
        plane.config.policy = allow_all_policy();
        plane.register(test_machine_key(), test_register_request());
        let before = map_json(&plane, 1);
        assert!(
            before["Node"].get("CapMap").is_none(),
            "no attributes configured means no CapMap"
        );

        // Add an attribute grant and re-map: the self node CapMap must appear.
        plane.config.policy = crabscale_policy::parse_policy(
            r#"{
                "tagOwners": { "tag:server": ["owner@example.com"] },
                "nodeAttrs": [
                    { "target": ["autogroup:member"], "attr": ["drive:share"] }
                ],
                "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*"] } ]
            }"#,
        )
        .expect("policy must parse");
        let after = map_json(&plane, 1);
        assert_eq!(
            after["Node"]["CapMap"],
            serde_json::json!({ "drive:share": [] }),
            "a policy change must be reflected in the next map's CapMap"
        );
    }

    #[test]
    fn ssh_policy_is_delivered_per_node_in_map() {
        let mut plane = test_plane();
        plane.config.policy = crabscale_policy::parse_policy(
            r#"{
                "tagOwners": { "tag:web": ["owner@example.com"] },
                "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*"] } ],
                "ssh": [
                    { "action": "check", "src": ["autogroup:member"], "dst": ["tag:web"],
                      "users": ["root"], "checkPeriod": "12h" }
                ]
            }"#,
        )
        .expect("policy must parse");
        // An ordinary user-owned node (no SSH rules target it).
        plane.register(test_machine_key(), test_register_request());
        // A tagged destination node targeted by the ssh check rule.
        let key = plane
            .create_pre_auth_key(
                "sshmap",
                true,
                false,
                None,
                Some(vec!["tag:web".to_string()]),
            )
            .unwrap();
        let mut request = test_register_request();
        request.node_key = NodeKey::from_bytes([0x27; 32]);
        request.auth = Some(crabscale_proto::RegisterAuth { auth_key: key });
        request.hostinfo = Some(Hostinfo {
            hostname: "web".to_string(),
            ..Default::default()
        });
        assert!(
            plane
                .register(MachineKey::from_bytes([0x17; 32]), request)
                .machine_authorized
        );

        // The plain node has no applicable ssh rule, so no SSHPolicy is sent.
        let plain = map_json(&plane, 1);
        assert!(
            plain.get("SSHPolicy").is_none(),
            "nodes with no ssh rules must not receive an SSHPolicy"
        );
        // The tagged node receives its per-node SSHPolicy.
        let web = map_json(&plane, 2);
        let policy = web.get("SSHPolicy").expect("tagged node carries SSHPolicy");
        // Wire field names are the camelCase client vocabulary.
        assert_eq!(policy["rules"][0]["sshUsers"]["root"], "=");
        let action = &policy["rules"][0]["action"];
        assert_eq!(action["message"], "approval required");
        assert!(
            action["holdAndDelegate"]
                .as_str()
                .unwrap()
                .contains("/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID"),
            "check-mode rules carry a delegate URL with placeholders"
        );
        // The autogroup:member source resolves to the plain node's stable id.
        assert_eq!(
            policy["rules"][0]["principals"][0]["node"],
            serde_json::json!("n00000000000000000000001")
        );
        // `any` is omitted for a concrete node principal (omitzero semantics).
        assert!(policy["rules"][0]["principals"][0]["any"].is_null());
    }

    /// Register a node whose Hostinfo advertises `routable_ips`.
    fn register_router(
        plane: &ControlPlane,
        machine: [u8; 32],
        node: [u8; 32],
        routable_ips: &[&str],
    ) {
        let mut request = test_register_request();
        request.node_key = NodeKey::from_bytes(node);
        request.hostinfo = Some(Hostinfo {
            hostname: "router".to_string(),
            routable_ips: Some(routable_ips.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        });
        let response = plane.register(MachineKey::from_bytes(machine), request);
        assert!(response.machine_authorized);
    }

    /// Map as `node_id` after an update that advertises `routable_ips`,
    /// returning the decoded MapResponse JSON.
    fn map_with_routes(
        plane: &ControlPlane,
        node_id: u64,
        routable_ips: &[&str],
    ) -> serde_json::Value {
        let stored = plane.store.list_nodes().unwrap();
        let node = stored
            .into_iter()
            .find(|n| n.id as u64 == node_id)
            .expect("node must exist");
        let request = MapRequest {
            version: 130,
            node_key: node.node_key,
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            hostinfo: Some(Hostinfo {
                hostname: "router".to_string(),
                routable_ips: Some(routable_ips.iter().map(|s| s.to_string()).collect()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let outcome = plane.handle_map(node.machine_key, request).unwrap();
        let MapOutcome::FullFrame(frame) = outcome else {
            panic!("expected full frame");
        };
        let (payload, consumed) = crabscale_proto::decode_map_response_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        serde_json::from_slice(payload).unwrap()
    }

    /// The effective `AllowedIPs` of `peer_id` in a decoded MapResponse, as
    /// strings.
    ///
    /// At capver >= 112 an absent `AllowedIPs` (`null`) means "same as
    /// `Addresses`", so the helper falls back to the peer's `Addresses`
    /// (Spec-Compatibility table row 112).
    fn peer_allowed_ips(plane_map: &serde_json::Value, peer_id: u64) -> Vec<String> {
        let peer = plane_map["Peers"]
            .as_array()
            .expect("Peers must be an array")
            .iter()
            .find(|p| p["ID"] == serde_json::json!(peer_id))
            .unwrap_or_else(|| panic!("peer {peer_id} not in map"));
        let values = match peer.get("AllowedIPs") {
            Some(serde_json::Value::Array(values)) => values,
            _ => peer["Addresses"]
                .as_array()
                .expect("peer Addresses must be an array"),
        };
        values
            .iter()
            .map(|v| {
                v.as_str()
                    .expect("AllowedIP entry must be a string")
                    .to_string()
            })
            .collect()
    }

    /// Fetch a stored node by its numeric id.
    fn stored_node(plane: &ControlPlane, id: u64) -> DomainNode {
        plane
            .store
            .list_nodes()
            .unwrap()
            .into_iter()
            .find(|n| n.id as u64 == id)
            .expect("node must exist")
    }

    #[test]
    fn advertised_routes_are_parsed_and_stored() {
        let plane = test_plane();
        register_router(
            &plane,
            [0x12; 32],
            [0x23; 32],
            &["192.168.1.0/24", "10.0.0.5"],
        );
        let node = stored_node(&plane, 1);
        assert_eq!(
            node.advertised_routes,
            vec!["10.0.0.5/32".to_string(), "192.168.1.0/24".to_string()],
            "advertised routes must be canonicalized and stored"
        );
        assert!(node.approved_routes.is_empty());
    }

    #[test]
    fn peer_ping_across_subnet_router() {
        let plane = test_plane();
        // Node 1 is the subnet router advertising a LAN subnet.
        register_router(&plane, [0x12; 32], [0x23; 32], &["192.168.42.0/24"]);
        let router = stored_node(&plane, 1);
        plane
            .approve_route(&router.node_key, "192.168.42.0/24")
            .unwrap();
        // Node 2 joins the tailnet as an ordinary host.
        register_extra_node(&plane, [0x13; 32], [0x24; 32]);

        // Node 2's map routes the subnet through the router: an ICMP ping to
        // e.g. 192.168.42.7 would be forwarded via the router's AllowedIPs.
        let n2 = map_json(&plane, 2);
        let allowed = peer_allowed_ips(&n2, 1);
        assert!(
            allowed.contains(&"192.168.42.0/24".to_string()),
            "peer AllowedIPs must include the approved subnet: {allowed:?}"
        );

        // The router's own map names the subnet in PrimaryRoutes so it knows
        // to enable forwarding.
        let n1 = map_json(&plane, 1);
        let primary: Vec<String> = n1["Node"]["PrimaryRoutes"]
            .as_array()
            .expect("PrimaryRoutes must be an array")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(
            primary.contains(&"192.168.42.0/24".to_string()),
            "self PrimaryRoutes must list the approved subnet: {primary:?}"
        );
    }

    #[test]
    fn route_approval_matches_when_host_bits_differ() {
        let plane = test_plane();
        // The client advertises the subnet with a host address whose host bits
        // are set; canonicalization zeroes them, so the stored advertised
        // route is the network form.
        register_router(&plane, [0x12; 32], [0x23; 32], &["10.0.0.5/24"]);
        let router = stored_node(&plane, 1);
        assert_eq!(
            router.advertised_routes,
            vec!["10.0.0.0/24".to_string()],
            "advertised routes must be canonicalized to the network"
        );
        // The administrator approves the same network in canonical form; the
        // string equality in the effective-route intersection must still match.
        plane
            .approve_route(&router.node_key, "10.0.0.0/24")
            .unwrap();
        register_extra_node(&plane, [0x13; 32], [0x24; 32]);

        let n2 = map_json(&plane, 2);
        assert!(
            peer_allowed_ips(&n2, 1).contains(&"10.0.0.0/24".to_string()),
            "an approval matching the network must reach peers"
        );
    }

    #[test]
    fn auto_approvers_propagate_route_without_admin_action() {
        let mut plane = test_plane();
        plane.config.policy = crabscale_policy::parse_policy(
            r#"{
                "autoApprovers": { "routes": { "10.0.0.0/8": ["owner@example.com"] } },
                "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*"] } ]
            }"#,
        )
        .expect("policy must parse");
        // The router is registered by the default user, which matches the
        // autoApprovers entry, so the route needs no explicit approval.
        register_router(&plane, [0x12; 32], [0x23; 32], &["10.1.0.0/16"]);
        register_extra_node(&plane, [0x13; 32], [0x24; 32]);

        let n2 = map_json(&plane, 2);
        let allowed = peer_allowed_ips(&n2, 1);
        assert!(
            allowed.contains(&"10.1.0.0/16".to_string()),
            "autoApprovers must propagate the route to peers: {allowed:?}"
        );
    }

    #[test]
    fn exit_node_default_routes_propagate_to_peers() {
        let plane = test_plane();
        register_router(&plane, [0x12; 32], [0x23; 32], &["0.0.0.0/0", "::/0"]);
        let router = stored_node(&plane, 1);
        plane.approve_route(&router.node_key, "0.0.0.0/0").unwrap();
        plane.approve_route(&router.node_key, "::/0").unwrap();
        register_extra_node(&plane, [0x13; 32], [0x24; 32]);

        let n2 = map_json(&plane, 2);
        let allowed = peer_allowed_ips(&n2, 1);
        assert!(
            allowed.contains(&"0.0.0.0/0".to_string()),
            "peer must receive the IPv4 default route (exit node): {allowed:?}"
        );
        assert!(
            allowed.contains(&"::/0".to_string()),
            "peer must receive the IPv6 default route (exit node): {allowed:?}"
        );

        let n1 = map_json(&plane, 1);
        let primary: Vec<String> = n1["Node"]["PrimaryRoutes"]
            .as_array()
            .expect("PrimaryRoutes must be an array")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(
            primary.contains(&"0.0.0.0/0".to_string()),
            "the exit node's own map must mark PrimaryRoutes: {primary:?}"
        );
    }

    #[test]
    fn route_removal_triggers_map_update() {
        let plane = test_plane();
        register_router(&plane, [0x12; 32], [0x23; 32], &["192.168.42.0/24"]);
        let router = stored_node(&plane, 1);
        plane
            .approve_route(&router.node_key, "192.168.42.0/24")
            .unwrap();
        register_extra_node(&plane, [0x13; 32], [0x24; 32]);

        // The peer sees the route while the router advertises it.
        let before = map_json(&plane, 2);
        assert!(peer_allowed_ips(&before, 1).contains(&"192.168.42.0/24".to_string()));

        // The router stops advertising the route: the next peer map must drop
        // it even though the admin approval remains.
        map_with_routes(&plane, 1, &[]);
        let after = map_json(&plane, 2);
        assert!(
            !peer_allowed_ips(&after, 1).contains(&"192.168.42.0/24".to_string()),
            "removing an advertised route must update the peer map"
        );

        // An explicit admin disapproval also removes it once it is advertised
        // again.
        map_with_routes(&plane, 1, &["192.168.42.0/24"]);
        plane
            .disapprove_route(&router.node_key, "192.168.42.0/24")
            .unwrap();
        let again = map_json(&plane, 2);
        assert!(
            !peer_allowed_ips(&again, 1).contains(&"192.168.42.0/24".to_string()),
            "disapproving a route must update the peer map"
        );
    }

    #[test]
    fn approve_route_rejects_invalid_input() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        let node = stored_node(&plane, 1);
        let err = plane
            .approve_route(&node.node_key, "not-a-route")
            .unwrap_err();
        assert!(matches!(err, ControlError::InvalidRoute(_)));
        let err = plane
            .disapprove_route(&node.node_key, "10.0.0.0/33")
            .unwrap_err();
        assert!(matches!(err, ControlError::InvalidRoute(_)));
    }

    #[test]
    fn route_approval_persists_across_restart() {
        let dir = std::env::temp_dir().join(format!("crabscale-routes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("routes.sqlite");

        let node_key = NodeKey::from_bytes([0x23; 32]);
        let machine_key = MachineKey::from_bytes([0x12; 32]);
        let config = ControlConfig {
            policy: allow_all_policy(),
            ..ControlConfig::default()
        };
        {
            let plane = ControlPlane::open_sqlite(config.clone(), &db_path).unwrap();
            register_router(
                &plane,
                machine_key.to_bytes(),
                node_key.to_bytes(),
                &["10.20.0.0/16"],
            );
            let router = stored_node(&plane, 1);
            plane
                .approve_route(&router.node_key, "10.20.0.0/16")
                .unwrap();
        }
        {
            let plane = ControlPlane::open_sqlite(config, &db_path).unwrap();
            let router = plane
                .store
                .get_node_by_node_key(&node_key)
                .unwrap()
                .expect("node must survive restart");
            assert_eq!(
                router.approved_routes,
                vec!["10.20.0.0/16".to_string()],
                "approved routes must survive restart"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn initial_map_includes_magic_dns_config() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        let json = map_json(&plane, 1);
        let dns = &json["DNS"];
        assert_eq!(
            dns["MagicDNSSuffix"],
            serde_json::json!("tailnet.example."),
            "the tailnet suffix must be advertised"
        );
        assert_eq!(dns["Proxied"], serde_json::json!(true));
        assert!(
            dns["Domains"]
                .as_array()
                .expect("search domains")
                .contains(&serde_json::json!("tailnet.example")),
            "the tailnet search domain must be delivered in Domains"
        );
        assert!(
            dns["Resolvers"]
                .as_array()
                .expect("resolvers")
                .iter()
                .any(|r| r["Addr"] == serde_json::json!("100.100.100.100")),
            "the MagicDNS resolver must be advertised"
        );
        // The node profile yields an A/AAAA record for the requesting node,
        // so its own MagicDNS name resolves.
        let names: Vec<&str> = dns["ExtraRecords"]
            .as_array()
            .expect("extra records")
            .iter()
            .map(|r| r["Name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"node1.tailnet.example."),
            "self node MagicDNS record must be present: {names:?}"
        );
    }

    #[test]
    fn peer_is_resolvable_by_magic_dns_name() {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        register_extra_node(&plane, [0x13; 32], [0x24; 32]);
        // Register a third peer with a distinct hostname so its record name
        // is clearly attributable to the peer.
        let mut request = test_register_request();
        request.node_key = NodeKey::from_bytes([0x26; 32]);
        request.hostinfo = Some(Hostinfo {
            hostname: "peer".to_string(),
            ..Default::default()
        });
        assert!(
            plane
                .register(MachineKey::from_bytes([0x15; 32]), request)
                .machine_authorized
        );

        let json = map_json(&plane, 1);
        let records = json["DNS"]["ExtraRecords"]
            .as_array()
            .expect("extra records")
            .clone();
        let peer_record = records
            .iter()
            .find(|r| r["Name"] == serde_json::json!("peer.tailnet.example."))
            .expect("peer MagicDNS record must be present");
        assert_eq!(
            peer_record["Type"],
            serde_json::json!("A"),
            "peer A record resolves through MagicDNS"
        );
        let peer_value = peer_record["Value"].as_str().expect("value");
        assert!(
            peer_value.starts_with("100."),
            "peer record value must be the peer's tailnet IPv4 address: {peer_value}"
        );
        assert!(
            peer_value.parse::<std::net::Ipv4Addr>().is_ok(),
            "peer A record value must be an IPv4 literal: {peer_value}"
        );
    }

    #[test]
    fn split_dns_and_search_domains_reach_client() {
        let mut config = ControlConfig {
            policy: allow_all_policy(),
            ..ControlConfig::default()
        };
        config
            .dns
            .split_dns
            .insert("corp.example.".to_string(), vec!["10.0.0.53".to_string()]);
        config.dns.search_domains.push("corp.example".to_string());
        let plane = ControlPlane::new(config);
        plane.register(test_machine_key(), test_register_request());

        let json = map_json(&plane, 1);
        let dns = &json["DNS"];
        assert_eq!(
            dns["Routes"]["corp.example."][0]["Addr"],
            serde_json::json!("10.0.0.53"),
            "split DNS must route the suffix to the configured resolver"
        );
        assert!(
            dns["Domains"]
                .as_array()
                .expect("search domains")
                .contains(&serde_json::json!("corp.example")),
            "configured search domains must reach the client in Domains"
        );
    }

    #[test]
    fn disabling_magic_dns_omits_dns_field() {
        let config = ControlConfig {
            policy: allow_all_policy(),
            dns: DnsSettings {
                magic_dns: false,
                ..Default::default()
            },
            ..ControlConfig::default()
        };
        let plane = ControlPlane::new(config);
        plane.register(test_machine_key(), test_register_request());

        let json = map_json(&plane, 1);
        assert!(
            json.get("DNS").is_none(),
            "with MagicDNS and split/search disabled there is no DNS config to send"
        );
    }

    #[test]
    fn extra_records_hot_reload_updates_map_and_notifies_sessions() {
        let dir =
            std::env::temp_dir().join(format!("crabscale-dns-records-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("records.json");
        std::fs::write(
            &path,
            br#"[{ "name": "db.tailnet.example.", "type": "A", "value": "100.64.0.9" }]"#,
        )
        .unwrap();

        let mut config = ControlConfig {
            policy: allow_all_policy(),
            ..ControlConfig::default()
        };
        config.dns.extra_records_path = Some(path.clone());
        let plane = ControlPlane::new(config);
        plane.register(test_machine_key(), test_register_request());
        assert_eq!(plane.dns_revision(), 1, "startup load bumps to revision 1");
        assert_eq!(plane.dns_extra_records().len(), 1);

        let before = map_json(&plane, 1);
        let before_names: Vec<&str> = before["DNS"]["ExtraRecords"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["Name"].as_str().unwrap())
            .collect();
        assert!(before_names.contains(&"db.tailnet.example."));

        // A subscriber representing a live map session must be notified.
        let mut rx = plane.subscribe_dns_changes();

        // Hot reload with an updated file.
        std::fs::write(
            &path,
            br#"[
                { "name": "db.tailnet.example.", "type": "A", "value": "100.64.0.9" },
                { "name": "wiki.tailnet.example.", "type": "AAAA", "value": "fd7a:115c:a1e0::9" }
            ]"#,
        )
        .unwrap();
        let count = plane.reload_dns_extra_records().unwrap();
        assert_eq!(count, 2);
        assert_eq!(plane.dns_revision(), 2);
        assert_eq!(
            rx.try_recv().unwrap(),
            2,
            "the subscriber must observe the new revision"
        );

        let after = map_json(&plane, 1);
        let after_names: Vec<&str> = after["DNS"]["ExtraRecords"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["Name"].as_str().unwrap())
            .collect();
        assert!(
            after_names.contains(&"wiki.tailnet.example."),
            "reloaded records must appear in the next map: {after_names:?}"
        );

        // A failed reload leaves the previous snapshot in place.
        std::fs::write(&path, b"not-json").unwrap();
        assert!(plane.reload_dns_extra_records().is_err());
        assert_eq!(plane.dns_revision(), 2);
        assert_eq!(plane.dns_extra_records().len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Open a streaming map session for node 1 (with node 2 as a peer),
    /// returning the session node id and the session's last-sent tracking.
    fn open_stream_with_peer() -> (ControlPlane, i64, SessionPeers) {
        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        register_extra_node(&plane, [0x13; 32], [0x24; 32]);
        let request = MapRequest {
            version: 130,
            node_key: test_node_key(),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: true,
            ..Default::default()
        };
        let outcome = plane.handle_map(test_machine_key(), request).unwrap();
        let MapOutcome::Stream {
            node_id,
            first_frame,
            initial_peers,
            ..
        } = outcome
        else {
            panic!("expected a streaming outcome");
        };
        // The complete first frame must already exist: deltas only ever come
        // after it (Spec-NetMap section 4).
        assert!(!first_frame.is_empty());
        assert_eq!(initial_peers.len(), 1, "node 2 is the only peer");
        (plane, node_id, initial_peers)
    }

    #[test]
    fn endpoint_change_produces_a_patch_not_a_full_peer_list() {
        let (plane, node_id, mut last_sent) = open_stream_with_peer();
        let mut rx = plane.subscribe_changes();

        // Node 2 reports a new endpoint via a lite (non-streaming) update.
        let lite = MapRequest {
            version: 130,
            node_key: NodeKey::from_bytes([0x24; 32]),
            disco_key: DiscoKey::from_bytes([0x44; 32]),
            stream: false,
            omit_peers: true,
            endpoints: vec!["203.0.113.10:41641".to_string()],
            endpoint_types: vec![3],
            ..Default::default()
        };
        assert_eq!(
            plane
                .handle_map(MachineKey::from_bytes([0x13; 32]), lite)
                .unwrap(),
            MapOutcome::LiteUpdate
        );
        plane.flush_changes();
        let batch = rx.try_recv().expect("a batch after the endpoint change");

        let delta = plane
            .build_delta(node_id, &batch, &mut last_sent, 130)
            .unwrap()
            .expect("a delta frame");
        assert!(
            delta.peers_changed.is_none(),
            "an endpoint change must never resend the full peer list"
        );
        assert!(delta.peers_removed.is_none());
        assert!(delta.peers.is_none());

        let patches = delta
            .peers_changed_patch
            .expect("a PeersChangedPatch must be generated");
        assert_eq!(patches.len(), 1);
        assert_eq!(
            patches[0].endpoints.as_deref(),
            Some(&["203.0.113.10:41641".to_string()][..])
        );
        // The seen signal and the endpoint patch coalesce into one ordered
        // frame, so the client receives no duplicate/conflicting deltas.
        assert_eq!(
            delta.peer_seen_change.as_ref().and_then(|m| m.get(&2)),
            Some(&true)
        );
        assert!(!delta.keep_alive);
    }

    #[test]
    fn peer_disappearance_produces_peers_removed_delta() {
        let (plane, node_id, mut last_sent) = open_stream_with_peer();
        let mut rx = plane.subscribe_changes();

        // Logging out node 2 deauthorizes it, so it disappears from peer maps.
        let response = plane
            .logout(
                MachineKey::from_bytes([0x13; 32]),
                &NodeKey::from_bytes([0x24; 32]),
            )
            .unwrap();
        assert!(!response.machine_authorized);
        plane.flush_changes();
        let batch = rx.try_recv().expect("a batch after the logout");

        let delta = plane
            .build_delta(node_id, &batch, &mut last_sent, 130)
            .unwrap()
            .expect("a delta frame");
        assert_eq!(delta.peers_removed.as_deref(), Some(&[2u64][..]));
        assert!(delta.peers_changed.is_none());
        assert!(delta.peers_changed_patch.is_none());
        assert!(last_sent.is_empty(), "the removed peer leaves tracking");
    }

    #[test]
    fn online_transition_produces_online_change_delta() {
        let (plane, node_id, mut last_sent) = open_stream_with_peer();
        let mut rx = plane.subscribe_changes();

        // Node 2 starts a streaming session of its own: it goes online.
        let request = MapRequest {
            version: 130,
            node_key: NodeKey::from_bytes([0x24; 32]),
            disco_key: DiscoKey::from_bytes([0x44; 32]),
            stream: true,
            ..Default::default()
        };
        let outcome = plane
            .handle_map(MachineKey::from_bytes([0x13; 32]), request)
            .unwrap();
        assert!(matches!(outcome, MapOutcome::Stream { .. }));
        plane.flush_changes();
        let batch = rx.try_recv().expect("a batch after the online transition");

        let delta = plane
            .build_delta(node_id, &batch, &mut last_sent, 130)
            .unwrap()
            .expect("a delta frame");
        assert_eq!(
            delta.online_change.as_ref().and_then(|m| m.get(&2)),
            Some(&true),
            "the stream session sees its peer come online"
        );
    }

    #[test]
    fn empty_batch_produces_no_delta_frame() {
        let (plane, node_id, mut last_sent) = open_stream_with_peer();
        let empty = ChangeBatch::default();
        let delta = plane
            .build_delta(node_id, &empty, &mut last_sent, 130)
            .unwrap();
        assert!(delta.is_none(), "no changes means no delta frame");
    }

    // ---------------------------------------------------------------------
    // M3-04 performance and concurrency smoke tests.
    //
    // These follow the wiki "Performance smoke test": smoke thresholds that
    // catch pathological regressions, not benchmarks for tuning. The
    // 200-node build/encode benchmark is #[ignore]d so the normal suite
    // stays fast and timing-independent; the CI perf-smoke job runs it under
    // a time budget via `scripts/perf-smoke.sh` and reports build time and
    // peak memory. The concurrency and session-leak scenarios are
    // deterministic and run in the regular suite.
    // ---------------------------------------------------------------------

    /// Register `count` nodes, each with a distinct machine/node key.
    fn register_nodes(plane: &ControlPlane, count: usize) {
        for i in 0..count as u8 {
            let mut request = test_register_request();
            let mut node_bytes = [0x22u8; 32];
            node_bytes[0] = i;
            request.node_key = NodeKey::from_bytes(node_bytes);
            let mut machine_bytes = [0x11u8; 32];
            machine_bytes[0] = i;
            let machine = MachineKey::from_bytes(machine_bytes);
            let response = plane.register(machine, request);
            assert!(
                response.machine_authorized,
                "node {i} must register, got {:?}",
                response
            );
        }
    }

    /// A non-streaming map request for `node` that asks for a complete frame.
    fn full_map_request(node: &DomainNode) -> MapRequest {
        MapRequest {
            version: 130,
            node_key: node.node_key,
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: false,
            ..Default::default()
        }
    }

    /// Decode a full MapResponse frame and return the parsed peer count.
    ///
    /// When `compressed` is set the payload is first zstd-decompressed, since
    /// the wire layer frames the compressed bytes as-is (Spec-NetMap §6).
    fn decoded_peer_count(frame: &[u8], compressed: bool) -> usize {
        let (payload, consumed) =
            crabscale_proto::decode_map_response_frame(frame).expect("frame must decode");
        assert_eq!(consumed, frame.len(), "frame must be exactly one message");
        let json = if compressed {
            zstd::stream::decode_all(payload).expect("zstd payload must decompress")
        } else {
            payload.to_vec()
        };
        let response: MapResponse =
            serde_json::from_slice(&json).expect("frame payload must parse as MapResponse");
        response.peers.as_ref().map(Vec::len).unwrap_or(0)
    }

    #[test]
    fn perf_50_concurrent_lite_updates_do_not_panic() {
        const NODES: usize = 50;
        let plane = Arc::new(test_plane());
        register_nodes(&plane, NODES);

        let stored = Arc::new(plane.store.list_nodes().unwrap());
        assert_eq!(stored.len(), NODES);

        let mut handles = Vec::new();
        for i in 0..NODES {
            let plane = plane.clone();
            let stored = stored.clone();
            handles.push(std::thread::spawn(move || {
                let node = &stored[i];
                let request = MapRequest {
                    version: 130,
                    node_key: node.node_key,
                    disco_key: DiscoKey::from_bytes([0x40 | i as u8; 32]),
                    stream: false,
                    omit_peers: true,
                    read_only: false,
                    hostinfo: Some(Hostinfo {
                        hostname: format!("node-{i}"),
                        ..Default::default()
                    }),
                    endpoints: vec![format!("192.0.2.{i}:41641")],
                    endpoint_types: vec![1],
                    ..Default::default()
                };
                let outcome = plane.handle_map(node.machine_key, request).unwrap();
                assert!(
                    matches!(outcome, MapOutcome::LiteUpdate),
                    "concurrent update must be a lite update"
                );
            }));
        }
        for handle in handles {
            handle
                .join()
                .expect("concurrent lite update thread must not panic");
        }

        // Every node still maps a complete frame and sees every other peer.
        let stored = plane.store.list_nodes().unwrap();
        for node in &stored {
            let outcome = plane
                .handle_map(node.machine_key, full_map_request(node))
                .unwrap();
            let MapOutcome::FullFrame(frame) = outcome else {
                panic!("expected a full frame");
            };
            assert_eq!(
                decoded_peer_count(&frame, false),
                NODES - 1,
                "node {} must still see every peer after concurrent updates",
                node.id
            );
        }
    }

    #[test]
    fn perf_100_connect_disconnect_cycles_do_not_leak_sessions() {
        // A zero reconnect grace makes the offline transition land immediately,
        // so the counter harness can prove that every close releases the
        // session without waiting out the default 10s window.
        let plane = ControlPlane::new(ControlConfig {
            policy: allow_all_policy(),
            reconnect_grace_seconds: 0,
            ..ControlConfig::default()
        });
        register_nodes(&plane, 1);
        let node = plane.store.list_nodes().unwrap().remove(0);

        for cycle in 0..100usize {
            let session_id = plane.open_session(node.id, false);
            assert_eq!(
                plane.live_session_count(node.id),
                1,
                "cycle {cycle}: exactly one live session while connected"
            );
            plane.close_session(session_id);
            assert_eq!(
                plane.live_session_count(node.id),
                0,
                "cycle {cycle}: closing the session must release it"
            );
        }

        // After the final cycle nothing may remain hidden in the registry.
        assert_eq!(plane.live_session_count(node.id), 0);
        let events = plane.reap_sessions();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SessionEvent::Offline(id) if *id == node.id)),
            "the node must be marked offline once its sessions are gone"
        );
        assert!(!plane.is_node_online(node.id), "node must not stay online");
    }

    #[tokio::test]
    async fn perf_background_tasks_are_spawned_exactly_once() {
        let plane = Arc::new(test_plane());

        // Only the first caller may own the single reaper slot...
        assert!(plane.claim_reaper(), "first reaper claim wins");
        assert!(!plane.claim_reaper(), "second reaper claim must be a no-op");

        // ...and at most one change-batcher sweeper runs per plane.
        assert!(
            plane.spawn_change_batcher().is_some(),
            "first sweeper spawns"
        );
        assert!(
            plane.spawn_change_batcher().is_none(),
            "a second sweeper must not be spawned (no duplicate tasks)"
        );

        // The single sweeper coalesces a burst into one ordered batch.
        let mut rx = plane.subscribe_changes();
        plane.publish_change(ChangeEvent::NodeChanged(1));
        plane.publish_change(ChangeEvent::PeerSeen(2));
        let batch = tokio::time::timeout(std::time::Duration::from_millis(1000), rx.recv())
            .await
            .expect("sweeper delivers within the batch window")
            .expect("a batch broadcast");
        assert_eq!(
            batch.events,
            vec![ChangeEvent::NodeChanged(1), ChangeEvent::PeerSeen(2)]
        );
    }

    #[test]
    #[ignore = "timing-sensitive; run under the CI perf-smoke time budget (scripts/perf-smoke.sh)"]
    fn perf_200_node_full_map_build_and_encode() {
        const NODES: usize = 200;
        const SAMPLES: usize = 25;
        const MAP_BUILD_BUDGET_MS: f64 = 500.0;
        const ENCODE_RAW_BUDGET_MS: f64 = 300.0;
        const ENCODE_ZSTD_BUDGET_MS: f64 = 500.0;

        let plane = test_plane();
        register_nodes(&plane, NODES);

        let stored = plane.store.list_nodes().unwrap();
        assert_eq!(stored.len(), NODES);
        // The last registered node observes every other node (199 peers).
        let observer = &stored[NODES - 1];
        let request = full_map_request(observer);

        // Warm up caches and SQLite pages before sampling.
        let warm = plane.build_initial_map(observer, &request).unwrap();
        assert_eq!(
            warm.peers.as_ref().map(Vec::len).unwrap_or(0),
            NODES - 1,
            "warm-up map must include every peer"
        );

        let mut build_min = f64::INFINITY;
        let mut build_totals = 0.0f64;
        let mut encode_raw_min = f64::INFINITY;
        let mut encode_zstd_min = f64::INFINITY;
        let mut first_raw_len = 0usize;
        let mut first_zstd_len = 0usize;

        for sample in 0..SAMPLES {
            let start = std::time::Instant::now();
            let response = plane.build_initial_map(observer, &request).unwrap();
            let build_ms = start.elapsed().as_secs_f64() * 1000.0;
            build_min = build_min.min(build_ms);
            build_totals += build_ms;
            assert_eq!(
                response.peers.as_ref().map(Vec::len).unwrap_or(0),
                NODES - 1,
                "sample {sample} must carry the full peer set"
            );

            let start = std::time::Instant::now();
            let raw = plane.encode_frame(&response, false).unwrap();
            encode_raw_min = encode_raw_min.min(start.elapsed().as_secs_f64() * 1000.0);
            let _ = decoded_peer_count(&raw, false);
            first_raw_len = raw.len();

            let start = std::time::Instant::now();
            let zstd = plane.encode_frame(&response, true).unwrap();
            encode_zstd_min = encode_zstd_min.min(start.elapsed().as_secs_f64() * 1000.0);
            let _ = decoded_peer_count(&zstd, true);
            first_zstd_len = zstd.len();
        }

        let build_avg_ms = build_totals / SAMPLES as f64;
        // Machine-parseable lines the perf-smoke script reports to CI.
        println!("perf_nodes={NODES}");
        println!("perf_peer_count={}", NODES - 1);
        println!("perf_samples={SAMPLES}");
        println!("perf_map_build_min_ms={build_min:.2}");
        println!("perf_map_build_avg_ms={build_avg_ms:.2}");
        println!("perf_encode_raw_min_ms={encode_raw_min:.2}");
        println!("perf_encode_zstd_min_ms={encode_zstd_min:.2}");
        println!("perf_first_frame_raw_bytes={first_raw_len}");
        println!("perf_first_frame_zstd_bytes={first_zstd_len}");

        // Smoke budgets: generous enough for a shared CI runner, but tight
        // enough to catch a regression that costs an order of magnitude.
        assert!(
            build_min < MAP_BUILD_BUDGET_MS,
            "200-node map build crossed the {MAP_BUILD_BUDGET_MS:.0}ms smoke budget ({build_min:.2}ms)"
        );
        assert!(
            encode_raw_min < ENCODE_RAW_BUDGET_MS,
            "raw encode crossed the {ENCODE_RAW_BUDGET_MS:.0}ms smoke budget ({encode_raw_min:.2}ms)"
        );
        assert!(
            encode_zstd_min < ENCODE_ZSTD_BUDGET_MS,
            "zstd encode crossed the {ENCODE_ZSTD_BUDGET_MS:.0}ms smoke budget ({encode_zstd_min:.2}ms)"
        );
        assert!(
            first_raw_len < crabscale_proto::MAX_MAP_RESPONSE_PAYLOAD_LEN,
            "raw 200-node frame ({first_raw_len}B) must fit the frame payload limit"
        );
        assert!(
            first_zstd_len < crabscale_proto::MAX_MAP_RESPONSE_PAYLOAD_LEN,
            "zstd 200-node frame ({first_zstd_len}B) must fit the frame payload limit"
        );
    }

    #[test]
    fn operational_metrics_fire_on_register_session_and_map() {
        // M4-04 (#27): the Prometheus counters for registrations, sessions and
        // policy compiles must move as the control plane is used. Comparisons
        // use deltas because the process-global registry is shared.
        let metrics = crabscale_metrics::registry();
        let reg_before = metrics.registrations_total.get();
        let opened_before = metrics.sessions_opened_total.get();
        let closed_before = metrics.sessions_closed_total.get();
        let policy_before = metrics.policy_compiles_total.get();

        let plane = test_plane();
        plane.register(test_machine_key(), test_register_request());
        assert!(
            metrics.registrations_total.get() > reg_before,
            "registration must increment the registrations counter"
        );

        // Map with a live streaming session: opening it is counted and
        // building the initial map compiles the policy.
        let stored = plane.store.list_nodes().unwrap();
        let node = stored.first().cloned().expect("node registered");
        let request = MapRequest {
            version: 130,
            node_key: node.node_key,
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            stream: true,
            ..Default::default()
        };
        let MapOutcome::Stream { session_id, .. } =
            plane.handle_map(node.machine_key, request).unwrap()
        else {
            panic!("expected streaming outcome");
        };
        assert!(
            metrics.sessions_opened_total.get() > opened_before,
            "opening a session must increment opened_total"
        );
        assert!(
            metrics.policy_compiles_total.get() > policy_before,
            "building the initial map must increment policy compiles"
        );

        // Closing the session is counted. (The `sessions_active` gauge is only
        // asserted in `crabscale-metrics` because gauges are shared across all
        // parallel control/harness tests and are not reliable for exact
        // equality under concurrency.)
        plane.close_session(session_id);
        assert!(
            metrics.sessions_closed_total.get() > closed_before,
            "closing a session must increment closed_total"
        );
    }
}
