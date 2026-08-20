//! JSON wire types, key parsing, and frame encode/decode helpers.
//!
//! This crate owns the server-side control protocol vocabulary: the JSON
//! request/response types exchanged with Tailscale-compatible clients, the
//! typed public keys used inside those messages, and the length-prefixed
//! framing used for [`MapResponse`] bodies.
//!
//! Wire rules are documented in the project wiki:
//! - [Spec-Control-API](https://github.com/NightFeather0615/crabscale/wiki/Spec-Control-API.md)
//! - [Spec-NetMap](https://github.com/NightFeather0615/crabscale/wiki/Spec-NetMap.md)
//! - [Spec-Registration](https://github.com/NightFeather0615/crabscale/wiki/Spec-Registration.md)
//! - [Spec-Transport](https://github.com/NightFeather0615/crabscale/wiki/Spec-Transport.md)

/// Minimum capability version accepted by the control plane.
///
/// This is the single source of truth shared by the control and transport
/// crates so the supported client floor is defined in exactly one place.
pub const MIN_SUPPORTED_CAPVER: u32 = 113;

mod derp;
mod dns;
mod early;
mod frame;
mod hostinfo;
mod key;
mod logout;
mod netmap;
mod ping;
mod register;
mod ssh;

pub use derp::{DerpMap, DerpNode, DerpRegion};
pub use dns::{DnsConfig, DnsRecord, DnsResolver};
pub use early::EarlyNoise;
pub use frame::{
    FrameError, MAP_RESPONSE_FRAME_HEADER_LEN, MAX_MAP_RESPONSE_PAYLOAD_LEN,
    decode_map_response_frame, encode_map_response_frame,
};
pub use hostinfo::{Hostinfo, NetInfo};
pub use key::{ChallengeKey, DiscoKey, KeyParseError, MachineKey, NodeKey};
pub use logout::LogoutRequest;
pub use netmap::{
    CapGrant, FilterRule, MapRequest, MapResponse, NetPortRange, Node, PeerChange, UserProfile,
};
pub use ping::PingRequest;
pub use register::{RegisterAuth, RegisterRequest, RegisterResponse};
pub use ssh::{SshAction, SshPolicy, SshPrincipal, SshRule};

pub(crate) mod serde_util {
    /// `skip_serializing_if` helper for `false` booleans.
    pub(crate) fn is_false(value: &bool) -> bool {
        !*value
    }

    /// `skip_serializing_if` helper for zero `u64` values.
    pub(crate) fn is_zero_u64(value: &u64) -> bool {
        *value == 0
    }

    /// `skip_serializing_if` helper for zero `i64` values.
    pub(crate) fn is_zero_i64(value: &i64) -> bool {
        *value == 0
    }

    /// `skip_serializing_if` helper for zero `u32` values.
    pub(crate) fn is_zero_u32(value: &u32) -> bool {
        *value == 0
    }

    /// `skip_serializing_if` helper for zero `u16` values.
    pub(crate) fn is_zero_u16(value: &u16) -> bool {
        *value == 0
    }

    /// `skip_serializing_if` helper for zero `i32` values.
    pub(crate) fn is_zero_i32(value: &i32) -> bool {
        *value == 0
    }
}
