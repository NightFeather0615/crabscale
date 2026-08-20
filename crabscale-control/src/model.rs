//! Domain model for the control plane.
//!
//! These structs are the durable, storage-facing representation of the
//! entities owned by `crabscale-control`. They are deliberately separate
//! from the wire types in `crabscale-proto` so persistence can evolve
//! without changing the protocol vocabulary.

use crabscale_proto::{DiscoKey, Hostinfo, MachineKey, NodeKey};

/// A tailnet user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: i64,
    pub login_name: String,
    pub display_name: String,
    pub created_at: String,
}

/// A login identity belonging to a user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Login {
    pub id: i64,
    pub user_id: i64,
    pub provider: String,
    pub login_name: String,
    pub created_at: String,
}

/// A registered node in the tailnet.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub id: i64,
    pub stable_id: String,
    pub name: String,
    pub user_id: i64,
    pub node_key: NodeKey,
    pub machine_key: MachineKey,
    pub disco_key: DiscoKey,
    pub addresses: Vec<String>,
    pub allowed_ips: Option<Vec<String>>,
    pub endpoints: Vec<String>,
    pub home_derp: u64,
    pub hostinfo: Option<Hostinfo>,
    pub created: String,
    pub cap: u32,
    pub tags: Option<Vec<String>>,
    pub machine_authorized: bool,
}

impl Node {
    /// Convert this domain node into the wire [`crabscale_proto::Node`] used
    /// in MapResponse bodies.
    pub fn to_proto(&self) -> crabscale_proto::Node {
        crabscale_proto::Node {
            id: self.id as u64,
            stable_id: self.stable_id.clone(),
            name: self.name.clone(),
            user: self.user_id as u64,
            key: self.node_key,
            machine: self.machine_key,
            disco_key: self.disco_key,
            addresses: self.addresses.clone(),
            allowed_ips: self.allowed_ips.clone(),
            endpoints: self.endpoints.clone(),
            home_derp: self.home_derp,
            hostinfo: self.hostinfo.clone(),
            created: self.created.clone(),
            cap: self.cap,
            tags: self.tags.clone(),
            machine_authorized: self.machine_authorized,
            ..Default::default()
        }
    }
}

/// A pre-auth key used to authorize node registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreAuthKey {
    pub id: i64,
    pub prefix: String,
    pub secret_hash: String,
    pub reusable: bool,
    pub ephemeral: bool,
    pub expiration: Option<String>,
    pub revoked: bool,
    pub used: bool,
    pub tags: Option<Vec<String>>,
    pub user_id: i64,
    pub created_at: String,
}

/// A stored policy document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub id: i64,
    pub name: String,
    pub body: String,
    pub created_at: String,
}

/// A live map session for a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: i64,
    pub node_id: i64,
    pub machine_key: MachineKey,
    pub created_at: String,
    pub last_seen: String,
    pub closed_at: Option<String>,
}
