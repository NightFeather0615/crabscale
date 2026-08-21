//! Capability version policy (Spec-Compatibility).
//!
//! The capability version ("capver") is the unsigned integer a client
//! advertises in `GET /key`, `RegisterRequest`, and `MapRequest`. The server
//! rejects versions below [`MIN_SUPPORTED_CAPVER`] at `/key` and
//! `/machine/map`, and gates individual wire fields and behaviors by version.
//!
//! Every gate listed in the wiki `Spec-Compatibility` table has exactly one
//! predicate in this module and at least one test. A new gate is only added
//! together with its test, keeping the "new gates are added with tests"
//! acceptance criterion of M4-01 (#24).

/// The minimum capability version accepted by the control plane. Versions
/// below this are rejected with `400` at `/key` and `/machine/map`.
pub const MIN_SUPPORTED_CAPVER: u32 = crate::MIN_SUPPORTED_CAPVER;

/// Streaming `MapRequest`s became read-only for `Hostinfo`/`Endpoints`
/// (Spec-Compatibility §2, table row 68).
pub const STREAMING_READ_ONLY_CAPVER: u32 = 68;

/// The incremental `PacketFilters` map became preferred over the legacy
/// singular `PacketFilter` field (Spec-Compatibility §2, table row 81).
pub const PACKET_FILTERS_CAPVER: u32 = 81;

/// `Node.HomeDERP` became an integer instead of a legacy DERP string
/// (Spec-Compatibility §2, table row 111).
pub const HOME_DERP_INTEGER_CAPVER: u32 = 111;

/// `AllowedIPs: null` came to mean "same as `Addresses`"
/// (Spec-Compatibility §2, table row 112).
pub const ALLOWED_IPS_NULL_CAPVER: u32 = 112;

/// Structured display messages may be emitted to the client; absence is
/// acceptable (Spec-Compatibility §2, table row 117).
pub const DISPLAY_MESSAGES_CAPVER: u32 = 117;

/// The server may read hardware attestation fields and ignore them
/// (Spec-Compatibility §2, table row 130).
pub const HARDWARE_ATTESTATION_CAPVER: u32 = 130;

/// Whether a streaming `MapRequest` must be treated as read-only for
/// `Hostinfo` and `Endpoints` state updates.
pub fn streaming_read_only(version: u32) -> bool {
    version >= STREAMING_READ_ONLY_CAPVER
}

/// Whether the incremental `PacketFilters` map is preferred over the legacy
/// singular `PacketFilter` field.
pub fn prefers_incremental_packet_filters(version: u32) -> bool {
    version >= PACKET_FILTERS_CAPVER
}

/// Whether `Node.HomeDERP` is encoded as an integer rather than a legacy
/// DERP string.
pub fn uses_integer_home_derp(version: u32) -> bool {
    version >= HOME_DERP_INTEGER_CAPVER
}

/// Whether a peer may receive `AllowedIPs: null` meaning "same as
/// `Addresses`" instead of an explicit (redundant) list.
pub fn allowed_ips_null_means_addresses(version: u32) -> bool {
    version >= ALLOWED_IPS_NULL_CAPVER
}

/// Whether the server may emit structured display messages to the client.
pub fn may_emit_structured_display_messages(version: u32) -> bool {
    version >= DISPLAY_MESSAGES_CAPVER
}

/// Whether the server may read hardware attestation fields from the client
/// (the server may still ignore them).
pub fn may_read_hardware_attestation(version: u32) -> bool {
    version >= HARDWARE_ATTESTATION_CAPVER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behavioral_gates_hold_at_the_minimum_supported_version() {
        // MIN_SUPPORTED_CAPVER (113) sits at/above every *definite* gate the
        // server must honor for an accepted client (68, 81, 111, 112). A
        // below-minimum client is rejected before any of these predicates
        // matter, but they must hold for every accepted version so the
        // server can rely on them unconditionally. The 117/130 gates are
        // optional "may" gates whose absence is acceptable at 113.
        assert_eq!(MIN_SUPPORTED_CAPVER, 113);
        assert!(streaming_read_only(MIN_SUPPORTED_CAPVER));
        assert!(prefers_incremental_packet_filters(MIN_SUPPORTED_CAPVER));
        assert!(uses_integer_home_derp(MIN_SUPPORTED_CAPVER));
        assert!(allowed_ips_null_means_addresses(MIN_SUPPORTED_CAPVER));
    }

    #[test]
    fn streaming_read_only_turns_on_at_68() {
        assert!(!streaming_read_only(67));
        assert!(streaming_read_only(68));
    }

    #[test]
    fn incremental_packet_filters_turn_on_at_81() {
        assert!(!prefers_incremental_packet_filters(80));
        assert!(prefers_incremental_packet_filters(81));
    }

    #[test]
    fn integer_home_derp_turns_on_at_111() {
        assert!(!uses_integer_home_derp(110));
        assert!(uses_integer_home_derp(111));
    }

    #[test]
    fn allowed_ips_null_turns_on_at_112() {
        assert!(!allowed_ips_null_means_addresses(111));
        assert!(allowed_ips_null_means_addresses(112));
    }

    #[test]
    fn display_messages_turn_on_at_117() {
        assert!(!may_emit_structured_display_messages(116));
        assert!(may_emit_structured_display_messages(117));
    }

    #[test]
    fn hardware_attestation_turns_on_at_130() {
        assert!(!may_read_hardware_attestation(129));
        assert!(may_read_hardware_attestation(130));
    }
}
