# Crabscale

Crabscale is a self-hosted control server for Tailscale-compatible clients, written in Rust.

## Documentation

Developer documentation (architecture, protocol specs, roadmap, and testing strategy) lives in the project wiki:

- GitHub wiki: <https://github.com/NightFeather0615/crabscale/wiki>
- Local wiki clone: `crabscale.wiki/` (separate GitHub wiki repository)

## Workspace

This repository is a Cargo workspace. It contains the following crates:

| Crate | Type | Responsibility |
|---|---|---|
| `crabscale-proto` | library | Wire types, key parsing, frame encode/decode helpers |
| `crabscale-transport` | library | TS2021 upgrade, Noise responder, HTTP/2 glue |
| `crabscale-control` | library | Registration, map handling, sessions, events |
| `crabscale-policy` | library | Policy model and packet filter compilation |
| `crabscale-derp` | library | DERP frames, relay state, STUN |
| `crabscale-server` | binary | Server wiring, config, TLS, HTTP routers |
| `crabscale-cli` | binary | Admin commands |

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
