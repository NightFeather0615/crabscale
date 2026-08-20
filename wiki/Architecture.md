# Architecture

## Principles

- One crate owns one wire or domain concern. No crate may import the server binary.
- Protocol code must be pure: byte parsing/encoding has no database or async runtime dependency.
- Application code never trusts client-provided keys for authorization; it always resolves identity from the Noise session.
- All mutable shared state goes through a small number of owned managers (node store, session registry, policy engine, event bus).

## Crate boundaries

| Crate | Owns | May depend on |
|---|---|---|
| `crabscale-proto` | JSON wire types, key parsing, frame encode/decode helpers | `serde`, `serde_json`, key crypto crates |
| `crabscale-transport` | TS2021 upgrade, Noise responder, Noise-framed stream, HTTP/2 glue | `crabscale-proto`, `hyper`, `tokio`, Noise crates |
| `crabscale-control` | Registration, MapRequest handling, MapResponse building, sessions, events | `crabscale-proto`, `crabscale-transport` traits, store trait |
| `crabscale-policy` | HUJSON parser, policy model, filter compiler | `crabscale-proto` |
| `crabscale-derp` | DERP frames, relay state, STUN, verify callback | `crabscale-proto` |
| `crabscale-server` | Binary wiring, config, TLS, HTTP routers, metrics | all above |
| `crabscale-cli` | Admin commands | store/API client |

## Runtime data flow

```text
client
  -> HTTPS/HTTP1 outer server
  -> /ts2021 upgrade (or WebSocket)
  -> Noise handshake
  -> optional early payload
  -> HTTP/2 over Noise
  -> control router
  -> register / map handlers
  -> store + policy engine
  -> MapResponse encoder
  -> framed stream back to client
```

DERP is a separate listener path on the same HTTP server: `/derp` upgrades to the relay protocol.

## Concurrency model

- One Tokio task per accepted control connection.
- One stream writer task per map session; updates arrive on a bounded MPSC channel.
- The node store is behind an `Arc<RwLock<...>>` or equivalent single owner in M1; replace with a store trait so persistence can evolve.
- Policy compilation is synchronous and cached; a policy reload swaps an `Arc` snapshot.
- The event bus fans out one event per change, not one event per session.

## Invariants

1. A node is online only while at least one live map session exists, subject to a disconnect grace period.
2. The first frame on a streaming map session is always a complete MapResponse containing `Node`, `DERPMap`, and peers.
3. Delta frames are never sent before the initial full frame.
4. Machine key and node key must match the registered node; failures are not distinguishable to clients.
5. Secret material is never logged or serialized into backups in plaintext.
6. All wire limits are enforced at the byte layer before JSON parsing.
