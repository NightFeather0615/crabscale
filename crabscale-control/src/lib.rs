//! In-memory control plane: registration, MapRequest handling, and
//! MapResponse building for the M0 protocol spike.
//!
//! This crate owns the server-side domain logic that sits behind the
//! `/machine/register` and `/machine/map` endpoints. It keeps an in-memory
//! node table, validates a single configured static auth key, assigns
//! tailnet IPs, and builds the first complete MapResponse frame.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crabscale_proto::{
    DerpMap, FilterRule, Hostinfo, MachineKey, MapRequest, MapResponse, NetPortRange, Node,
    NodeKey, RegisterRequest, RegisterResponse, UserProfile, encode_map_response_frame,
};

/// Minimum capability version accepted by the control plane.
pub const MIN_SUPPORTED_CAPVER: u32 = 113;

/// Static timestamp used for the M0 static MapResponse. A real clock is
/// layered on in M1 when persistence and sessions are introduced.
const CONTROL_TIME: &str = "2026-08-20T00:00:00Z";

/// Configuration for the in-memory control plane.
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
        }
    }
}

/// A registered node held in the in-memory table.
#[derive(Clone, Debug)]
struct NodeRecord {
    node: Node,
    machine_key: MachineKey,
    hostinfo: Option<Hostinfo>,
    endpoints: Vec<String>,
}

/// Errors returned by the control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// The node key is unknown or the machine key does not match.
    NotFound,
    /// The client capability version is below the supported minimum.
    UnsupportedVersion(u32),
    /// The supplied auth key is invalid.
    InvalidAuth,
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
            Self::InvalidAuth => write!(f, "invalid auth key"),
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

/// In-memory control plane shared by the server router.
pub struct ControlPlane {
    config: ControlConfig,
    nodes: Mutex<BTreeMap<NodeKey, NodeRecord>>,
    next_id: AtomicU64,
    next_ipv4: AtomicU32,
    next_ipv6: AtomicU32,
}

impl ControlPlane {
    /// Create a control plane with the given configuration.
    pub fn new(config: ControlConfig) -> Self {
        Self {
            config,
            nodes: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            next_ipv4: AtomicU32::new(1),
            next_ipv6: AtomicU32::new(1),
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
        let mut nodes = self.nodes.lock().unwrap();

        if let Some(record) = nodes.get(&request.node_key) {
            if record.machine_key == machine_key {
                return Ok(self.authorized_response());
            }
            return Ok(RegisterResponse {
                machine_authorized: false,
                error: "node key is already registered to another machine".to_string(),
                ..Default::default()
            });
        }

        let auth_ok = request
            .auth
            .as_ref()
            .map(|auth| auth.auth_key == self.config.auth_key)
            .unwrap_or(false);
        if !auth_ok {
            return Ok(RegisterResponse {
                machine_authorized: false,
                error: "invalid or missing auth key".to_string(),
                ..Default::default()
            });
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let ipv4 = self.next_ipv4.fetch_add(1, Ordering::Relaxed);
        let ipv6 = self.next_ipv6.fetch_add(1, Ordering::Relaxed);

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
            .unwrap_or_else(|| format!("node{id}"));

        let addresses = vec![
            format!("100.64.0.{ipv4}/32"),
            format!("fd7a:115c:a1e0::{ipv6:x}/128"),
        ];

        let node = Node {
            id,
            stable_id: format!("n{id:023}"),
            name: format!("{hostname}.{}.", self.config.tailnet_domain),
            user: self.config.user_id,
            key: request.node_key,
            machine: machine_key,
            disco_key: crabscale_proto::DiscoKey::from_bytes([0u8; 32]),
            addresses: addresses.clone(),
            allowed_ips: Some(addresses),
            endpoints: Vec::new(),
            home_derp: 1,
            hostinfo: request.hostinfo.clone(),
            created: CONTROL_TIME.to_string(),
            cap: request.version,
            machine_authorized: true,
            ..Default::default()
        };

        let record = NodeRecord {
            node: node.clone(),
            machine_key,
            hostinfo: request.hostinfo.clone(),
            endpoints: Vec::new(),
        };
        nodes.insert(request.node_key, record);

        Ok(self.authorized_response())
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

        let mut nodes = self.nodes.lock().unwrap();
        let record = nodes
            .get_mut(&request.node_key)
            .filter(|r| r.machine_key == machine_key)
            .ok_or(ControlError::NotFound)?;

        let streaming = request.stream;
        let lite_update = !streaming && request.omit_peers && !request.read_only;

        // Streaming requests (version >= 68) are read-only: ignore hostinfo
        // and endpoints for state updates.
        if !streaming {
            if let Some(hostinfo) = &request.hostinfo {
                record.hostinfo = Some(hostinfo.clone());
                record.node.hostinfo = Some(hostinfo.clone());
            }
            if !request.endpoints.is_empty() {
                record.endpoints = request.endpoints.clone();
                record.node.endpoints = request.endpoints.clone();
            }
        }

        if lite_update {
            return Ok(MapOutcome::LiteUpdate);
        }

        let node = record.node.clone();
        let compress = request.compress == "zstd";
        let response = self.build_initial_map(&node, &request);
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
    use crabscale_proto::{DiscoKey, MapRequest, RegisterRequest};

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
}
