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

## DNS configuration

`crabscale-server` delivers DNS configuration (MagicDNS, split DNS, search
domains, and extra records) to clients in the MapResponse `DNS` field.

- MagicDNS is enabled by default and advertises the tailnet suffix plus an
  A/AAAA record per node, so peers resolve each other by name.
- `--no-magic-dns` disables MagicDNS while still delivering configured split
  DNS and search domains.
- `--dns-search-domain <name>` adds a search domain (repeatable).
- `--dns-split <suffix=addr>` adds a split-DNS route (repeatable).
- `--dns-extra-records <path>` loads extra records from a JSON file that is
  hot-reloaded at runtime; changes are pushed to all live map sessions. See
  `examples/dns-extra-records.json`.

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
