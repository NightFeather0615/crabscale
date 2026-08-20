# Spec: Compatibility and capability versions

## 1. Capability version

A capability version is an unsigned integer advertised by clients in `/key`, RegisterRequest, and MapRequest.

Crabscale policy:

- `MIN_SUPPORTED_CAPVER = 113`.
- Versions below the minimum are rejected with `400` at `/key` and `/machine/map`.
- Versions at or above the minimum are accepted; the server gates individual fields by version.
- There is no maximum rejection in v0.1, but the compatibility matrix only guarantees tested versions.

## 2. Capability-gated fields

The server must branch on the client's advertised version for these behaviors:

| Version | Gate |
| --- | --- |
| 68 | Streaming MapRequest is read-only: ignore `Hostinfo`/`Endpoints` for state. |
| 81 | Prefer `PacketFilters` incremental map; support old singular `PacketFilter` fallback. |
| 111 | Use `HomeDERP` integer instead of legacy DERP string. |
| 112 | `AllowedIPs: null` means "same as `Addresses`". |
| 117 | May emit structured display messages; absence is acceptable. |
| 130 | May read hardware attestation fields; server may ignore them. |

New gates must be added to this table in the PR that implements them.

## 3. Client matrix

Supported test matrix, run in CI:

1. Latest stable client binary.
2. Previous stable client binary.
3. Oldest supported stable client binary that implements capability 113.
4. Development/head client binary, when available.
5. Rust client library test peer.

Each matrix entry must pass:

- auth-key registration;
- status and self ping;
- peer ping through a relay;
- logout and relogin;
- lite update during an active stream.

A compatibility report is generated as a Markdown artifact.

## 4. Protocol stability rules

- JSON field names are PascalCase and never renamed after release.
- Existing fields are only deprecated, never removed in v0.x.
- Unknown JSON fields received from clients are ignored.
- Unknown fields emitted by the server are additive and version-gated.

## 5. New endpoint checklist

Adding an endpoint requires:

1. Spec section in this wiki.
2. Unit tests for request parsing and response serialization.
3. One integration test with a real client binary or a wire-recorded fixture.
4. Matrix note if the endpoint depends on capability version.
