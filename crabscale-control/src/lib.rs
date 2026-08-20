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
mod preauth;
mod store;
mod time;

use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

use crabscale_proto::{
    DerpMap, FilterRule, MachineKey, MapRequest, MapResponse, NetPortRange, Node, NodeKey,
    RegisterRequest, RegisterResponse, UserProfile, encode_map_response_frame,
};

pub use ip_allocator::{IpAllocator, IpAllocatorError};
pub use model::{Login, Node as DomainNode, Policy, PreAuthKey, Session, User};
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
        Self { config, store }
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
                    self.store
                        .upsert_node(&updated)
                        .map_err(|e| ControlError::Store(e.to_string()))?;
                    return Ok(self.authorized_response());
                }
                return Ok(self.unauthorized_response("invalid or missing auth key"));
            }

            // No auth key supplied: return the current authorization state.
            if node.machine_authorized {
                return Ok(self.authorized_response());
            }
            return Ok(self.unauthorized_response("node is logged out"));
        }

        // New node registration.
        let Some(auth) = &request.auth else {
            return Ok(self.unauthorized_response("invalid or missing auth key"));
        };
        let Some(key) = self.validated_auth_key(auth, &now)? else {
            return Ok(self.unauthorized_response("invalid or missing auth key"));
        };

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
        let domain_node = DomainNode {
            id: 0,
            stable_id: String::new(),
            name: format!("{hostname}.{}.", self.config.tailnet_domain),
            user_id: key.user_id,
            node_key: request.node_key,
            machine_key,
            disco_key: crabscale_proto::DiscoKey::from_bytes([0u8; 32]),
            addresses: addresses.clone(),
            allowed_ips: Some(addresses),
            endpoints: Vec::new(),
            home_derp: 1,
            hostinfo: request.hostinfo.clone(),
            created: now,
            cap: request.version,
            tags: key.tags.clone(),
            machine_authorized: true,
            ephemeral: key.ephemeral,
        };
        self.store
            .upsert_node(&domain_node)
            .map_err(|e| ControlError::Store(e.to_string()))?;

        if !key.reusable {
            self.store
                .mark_pre_auth_key_used(key.id)
                .map_err(|e| ControlError::Store(e.to_string()))?;
        }

        Ok(self.authorized_response())
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
        if node.tags.is_some() {
            return Ok(self.authorized_response());
        }
        if node.ephemeral {
            self.store
                .delete_node(node_key)
                .map_err(|e| ControlError::Store(e.to_string()))?;
            return Ok(self.unauthorized_response("node logged out"));
        }
        let mut updated = node;
        updated.machine_authorized = false;
        self.store
            .upsert_node(&updated)
            .map_err(|e| ControlError::Store(e.to_string()))?;
        Ok(self.unauthorized_response("node logged out"))
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

        // The disco key is only carried in MapRequest, not RegisterRequest, so
        // apply it here so the first MapResponse advertises the client's real
        // disco key (Spec-NetMap §3).
        node.disco_key = request.disco_key;

        let streaming = request.stream;
        let lite_update = !streaming && request.omit_peers && !request.read_only;

        // Streaming requests (version >= 68) are read-only: ignore hostinfo
        // and endpoints for state updates.
        if !streaming {
            if let Some(hostinfo) = &request.hostinfo {
                node.hostinfo = Some(hostinfo.clone());
            }
            if !request.endpoints.is_empty() {
                node.endpoints = request.endpoints.clone();
            }
        }
        self.store
            .upsert_node(&node)
            .map_err(|e| ControlError::Store(e.to_string()))?;

        if lite_update {
            return Ok(MapOutcome::LiteUpdate);
        }

        let proto_node = node.to_proto();
        let compress = request.compress == "zstd";
        let response = self.build_initial_map(&proto_node, &request);
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
    pub fn build_initial_map(&self, node: &Node, _request: &MapRequest) -> MapResponse {
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

        MapResponse {
            node: Some(node.clone()),
            derp_map: Some(self.config.derp_map.clone()),
            domain: self.config.tailnet_domain.clone(),
            peers: Some(Vec::new()),
            packet_filters: Some(packet_filters),
            user_profiles: vec![UserProfile {
                id: self.config.user_id,
                login_name: self.config.user_login_name.clone(),
                display_name: self.config.user_display_name.clone(),
                ..Default::default()
            }],
            control_time: CONTROL_TIME.to_string(),
            ..Default::default()
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crabscale_proto::{DiscoKey, Hostinfo, MapRequest, NodeKey, RegisterRequest};

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
    fn rejects_invalid_auth_key() {
        let plane = test_plane();
        let mut request = test_register_request();
        request.auth = Some(crabscale_proto::RegisterAuth {
            auth_key: "wrong".to_string(),
        });
        let response = plane.register(test_machine_key(), request).unwrap();
        assert!(!response.machine_authorized);
        assert!(!response.error.is_empty());
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
}
