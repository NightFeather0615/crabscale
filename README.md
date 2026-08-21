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
| `crabscale-fuzz` | binary | Fuzz smoke targets for JSON, Noise, and DERP parsers |

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

## OIDC registration

Interactive registration can be approved through an OpenID Connect provider
instead of the CLI. Start the server with OIDC configured:

- `--oidc-issuer <url>` enables the feature (required).
- `--oidc-client-id <id>` and `--oidc-client-secret <secret>` identify the
  relying party.
- `--oidc-redirect-uri <url>` overrides the callback URL; default is
  `<server-url>/oidc/callback`.
- `--oidc-scope <scopes>` overrides the requested scopes; default is
  `openid profile email`.

Discovery is fetched and validated at startup; a mismatched issuer aborts
startup. Once enabled, the `/register/{id}` page redirects to the provider,
and `/oidc/callback` validates the CSRF state and nonce, exchanges the code,
verifies the ID token, upserts the user profile, and approves the pending
registration through the same auth cache the `crabscale auth` CLI uses.

## Security hardening

Public-deployment attack surface is reduced by (see the wiki
[Security](https://github.com/NightFeather0615/crabscale/wiki/Security) page
and `SECURITY.md`):

- All documented wire size limits are enforced at the byte layer before JSON
  parsing; the TS2021 Noise handshake is bounded by a 10-second timeout.
- `POST /ts2021` (per client IP) and `POST /machine/register` (per Noise
  machine key) are rate limited with `429` + `Retry-After`; configure with
  `--ts2021-rate-per-min`, `--ts2021-burst`, `--register-rate-per-min`, and
  `--register-burst`.
- Registration and SSH approval caches are bounded (TTL + cap), and secrets
  are never logged or echoed in error bodies.
- `cargo audit`, `cargo deny`, and the `fuzz-smoke` CI jobs gate dependency
  and parser robustness:

```sh
# Dependency audits (install cargo-audit / cargo-deny first)
cargo audit
cargo deny check

# Fuzz smoke over corpus + random seeds
./scripts/fuzz-smoke.sh
```

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
