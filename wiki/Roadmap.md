# Roadmap

## Phase M0: Protocol spike

Goal: prove the full secure control path works before building persistence or policy.

1. Workspace and CI skeleton.
2. Server-side wire JSON types (`RegisterRequest/Response`, `MapRequest/Response`, key types).
3. TS2021 upgrade endpoint and Noise responder.
4. HTTP/2 over Noise and `GET /key`.
5. In-memory registration and static MapResponse smoke test with real client binaries.

Exit criteria: a client registers and receives a valid initial map in CI.

## Phase M1: Single-tailnet MVP

Goal: make one tailnet usable with durable state and basic administration.

1. Domain model and SQLite migrations.
2. Pre-auth key issuance and registration lifecycle.
3. MapRequest state updates and lite update semantics.
4. Initial MapResponse builder and streaming keepalive.
5. Interactive registration approval flow.
6. Session lifecycle, online/offline, ephemeral cleanup.
7. End-to-end client compatibility harness.

Exit criteria: auth-key login, interactive login, persistence across restart, peer ping through public relays.

## Phase M2: Policy and network features

Goal: implement the policy language and network semantics in vertical slices.

1. HUJSON parser and policy model.
2. ACL/grants compiler and per-node packet filters.
3. Tags, autogroups, node attributes.
4. Subnet routes and exit nodes.
5. DNS configuration and MagicDNS.
6. Tailscale SSH check mode.
7. OIDC registration.

Exit criteria: golden policy fixtures produce expected filters and SSH verdicts; routes/DNS verified with clients.

## Phase M3: Relay and incremental updates

Goal: improve connectivity and scale.

1. DERP frame codec and relay core.
2. STUN, verify endpoint, DERP map distribution.
3. Incremental MapResponse and event batching.
4. Performance and concurrency validation.

Exit criteria: clients relay through embedded DERP; updates are deltas under load.

## Phase M4: Hardening and release

Goal: make the server safe and repeatable to deploy.

1. Capability version matrix and wire gating.
2. Security hardening.
3. TLS, reverse proxy, deployment artifacts.
4. Backup, observability, documentation, gap analysis.

Exit criteria: compatibility matrix report, security checklist, reproducible container image.


## Issue index

- M0: #1 workspace/CI, #2 wire types, #3 TS2021/Noise, #4 HTTP2 router + /key, #5 static register/map smoke.
- M1: #6 domain/SQLite, #7 auth keys, #8 map updates/lite, #9 initial map/stream, #10 interactive auth, #11 sessions, #12 client harness.
- M2: #13 HUJSON parser, #14 ACL/grants, #15 tags/autogroups/attrs, #16 routes/exit, #17 DNS/MagicDNS, #18 SSH check, #19 OIDC.
- M3: #20 DERP core, #21 STUN/verify/DERP map, #22 incremental maps/batcher, #23 performance.
- M4: #24 capability matrix, #25 security, #26 TLS/deployment, #27 backup/observability/docs.
- Coordination: #28 roadmap index, #29 architecture review.
