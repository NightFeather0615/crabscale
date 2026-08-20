# Crabscale Wiki

Crabscale is a self-hosted control server for Tailscale-compatible clients, implemented in Rust.
This wiki is the canonical source for architecture, protocol standards, roadmap, and testing rules.

> Rule: implementation issues must be small, self-contained, and verifiable without reading any external repository. If an issue needs a rule or wire detail, that detail must be written in this wiki first.

## Pages

- [Roadmap](Roadmap)
- [Architecture](Architecture)
- Standards
  - [Transport: TS2021 and Noise](Spec-Transport)
  - [Control API](Spec-Control-API)
  - [NetMap protocol](Spec-NetMap)
  - [Registration and auth](Spec-Registration)
  - [Policy and packet filters](Spec-Policy)
  - [DERP and STUN](Spec-DERP-STUN)
  - [Compatibility and capability versions](Spec-Compatibility)
- Process
  - [Model implementation guide](Model-Implementation-Guide)
  - [Testing strategy](Testing-Strategy)

## Milestone overview

| Milestone | Goal | Exit criteria |
|---|---|---|
| M0 | Prove the Rust server can complete a secure control session end-to-end | `/key` -> `/ts2021` Noise -> HTTP/2 -> register -> first MapResponse works against one real client binary |
| M1 | Single-tailnet MVP | Auth keys, SQLite persistence, complete initial MapResponse, lite update, online/offline, interactive approval, CI client matrix |
| M2 | Policy and network features | HUJSON policy, ACL/grants, tags, routes/exit nodes, MagicDNS, Tailscale SSH check mode, OIDC |
| M3 | Relay and incremental updates | Embedded DERP/STUN, DERP map, incremental MapResponse, batching, scale validation |
| M4 | Hardening and release | Capability matrix, security limits, TLS/deployment, backup/observability, documentation |

## Definition of done for every issue

- The crate compiles with `cargo test -p <crate>`.
- All acceptance criteria in the issue are automated tests or a reproducible manual command.
- No new issue-level undocumented wire behavior: any new format rule is added to this wiki in the same PR.
- The change is reviewable in one session: one crate, one module or one endpoint at a time.
