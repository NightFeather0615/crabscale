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
| `crabscale-metrics` | library | Process-wide Prometheus counters, gauges, and text renderer |
| `crabscale-server` | binary | Server wiring, config, TLS, HTTP routers |
| `crabscale-cli` | binary | Admin commands |
| `crabscale-harness` | binary | Client compatibility / end-to-end harness |
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

## Quick start

Run a local control server with a pre-auth key and a durable SQLite store:

```sh
cargo run --release -p crabscale-server --   --store ./data/crabscale.db   --key-file ./data/crabscale.key   --auth-key hskey-auth-my-secret   --server-url http://localhost:8080   --listen 127.0.0.1:8080
```

Point a Tailscale-compatible client at the server, register a node with the
pre-auth key, and follow the interactive approval flow with the admin CLI:

```sh
# Register interactively, then approve from the approval URL's auth id:
crabscale --store ./data/crabscale.db auth approve --auth-id <id> --user owner@example.com

# List and approve advertised subnet/exit routes:
crabscale --store ./data/crabscale.db route list --node nodekey:<key>
```

The full configuration reference (TOML file, `CRABSCALE_*` environment
overrides, TLS, trusted proxies, containers) is in the
[Deployment](#deployment-tls-reverse-proxy-containers) section and the wiki
[Deployment](https://github.com/NightFeather0615/crabscale/wiki/Deployment)
page. The exact list of supported and unsupported behaviors for v0.1 is in the
[v0.1 gap analysis](docs/v0.1-gap.md) and the wiki
[Gap-Analysis](https://github.com/NightFeather0615/crabscale/wiki/Gap-Analysis)
page.

## Operations

### Backup and restore

The `crabscale` CLI snapshots the SQLite store and restores it, excluding
plaintext secrets by construction:

```sh
# Write a zstd-compressed backup of the store's allowed (non-secret) tables.
crabscale --store /var/lib/crabscale/data/crabscale.db   backup --output /backups/crabscale-2026-08-20.csb

# Restore into a fresh or empty database file. Existing nodes can log in again
# after a restore.
crabscale --store /var/lib/crabscale/data/restored.db   restore --force --input /backups/crabscale-2026-08-20.csb
```

Backups contain an explicit allowlist of domain tables (users, logins, nodes,
pre-auth keys with their salted hashes, policies, sessions, pending
registrations, SSH approvals) and never serialize plaintext secret material.
The format is versioned (`crabscale-backup/v1`) and restore rejects unknown
tables or format versions. See the wiki
[Operations](https://github.com/NightFeather0615/crabscale/wiki/Operations)
page for the full contract.

### Health, version, and metrics

The server exposes three operational HTTP endpoints (over the same listener as
`/key`):

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness probe; returns `200 {"status":"ok"}`. |
| `GET /version` | `{"name":"crabscale-server","version":"0.1.0","protocol_version":130}`. |
| `GET /metrics` | Prometheus text exposition of operational metrics. |

```sh
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/version
curl -s http://127.0.0.1:8080/metrics
```

These endpoints are intentionally unauthenticated in v0.1. In production,
protect them with a reverse-proxy allowlist (or scrape `/metrics` from an
internal network) so the version string and metric data are not exposed to
the public internet.

Metrics are rendered in the Prometheus text format with `text/plain;
version=0.0.4` content type. Every family appears even before it has fired
(with a `0` sample):

- `crabscale_sessions_active` (gauge), `crabscale_sessions_opened_total`,
  `crabscale_sessions_closed_total`
- `crabscale_registrations_total`
- `crabscale_policy_compiles_total`
- `crabscale_derp_packets_total`, `crabscale_derp_packets_dropped_total`

Point a Prometheus scraper at `GET /metrics`, or trigger a plain
`curl http://127.0.0.1:8080/metrics` and confirm the families above are
present (this is the documented local test of the endpoint).

## Compatibility and unsupported features

- Capability/protocol compatibility is governed by `MIN_SUPPORTED_CAPVER`
  (113) and the [capability matrix](https://github.com/NightFeather0615/crabscale/wiki/Spec-Compatibility);
  CI runs `scripts/capability-matrix.sh`.
- The scale the server is validated against is in
  [Supported scale](https://github.com/NightFeather0615/crabscale/wiki/Supported-Scale); anything beyond is
  unsupported for v0.1.
- Unsupported / out-of-scope v0.1 features (multi-tenant, DERP mesh, structured
  JSON logs, a production load guarantee) are itemized in the
  [v0.1 gap analysis](docs/v0.1-gap.md).

## Deployment (TLS, reverse proxy, containers)

`crabscale-server` is deployable behind standard
infrastructure. See the wiki [Deployment](https://github.com/NightFeather0615/crabscale/wiki/Deployment)
page for full details and proxy header requirements.

### Configuration file and environment overrides

Supply a TOML file with `--config crabscale.toml`; `CRABSCALE_*` environment
variables and explicit CLI flags override it. Precedence:

1. CLI flags
2. `CRABSCALE_<FIELD>` environment variables (e.g. `CRABSCALE_KEY_FILE`,
   `CRABSCALE_TRUSTED_PROXIES`, `CRABSCALE_TLS_MODE`)
3. config file values
4. built-in defaults

An annotated example lives at `deploy/crabscale.toml.example`.

### TLS (rustls) and HTTP redirect

- `--tls-mode off` — plain HTTP (default).
- `--tls-mode files --tls-cert-file cert.pem --tls-key-file key.pem` — static PEM.
- `--tls-mode acme --acme-domain control.example.com --acme-email admin@example.com
  --acme-cache-dir ./acme` — automatic certificates via ACME (TLS-ALPN-01);
  the cache directory persists the account key and issued certificates.

With TLS enabled, `--listen-http 0.0.0.0:80` starts a plain-HTTP listener that
`301`-redirects browsers to HTTPS. `/key` is only ever served on the TLS
listener.

### Trusted reverse proxies

When the server sits behind nginx/Caddy/a load balancer, tell it which networks
to trust so `/ts2021` rate limiting keys on the real client IP:

```sh
crabscale-server \
  --listen 0.0.0.0:8080 \
  --trusted-proxy 127.0.0.1/32 \
  --trusted-proxy 10.0.0.0/8
```

Only peers inside a listed CIDR may set `X-Forwarded-For` / `X-Real-IP`;
everyone else is treated as the direct client. Proxies must forward the
`Connection: upgrade` and `Upgrade` headers so `/ts2021` and `/derp` upgrades
are preserved end to end.

### Container image

A multi-stage `Dockerfile` builds a release binary in a Rust image and copies
it into a minimal Debian image that contains **no compiler** and runs as a
**non-root** `crabscale` user. Persistent state (machine key + SQLite) lives in
`/var/lib/crabscale/data` — mount it as a volume so the control key survives
container restarts.

```sh
docker build -t crabscale:latest .
docker run -d --name crabscale \
  -v crabscale_data:/var/lib/crabscale/data \
  -p 8080:8080 \
  crabscale:latest --listen 0.0.0.0:8080
```

`docker compose up -d --build` (see `compose.yaml`) starts the server behind a
Caddy reverse proxy with trusted proxies configured. `./scripts/docker-smoke.sh`
builds the image and verifies the non-root / no-compiler / key-persistence
requirements.


## Security hardening

Public-deployment attack surface is reduced by (see the wiki
[Security](https://github.com/NightFeather0615/crabscale/wiki/Security) page
and `SECURITY.md`):

- All documented wire size limits are enforced at the byte layer before JSON
  parsing; the TS2021 Noise handshake is bounded by a 10-second timeout.
- `POST /ts2021` (per client IP) and `POST /machine/register` (per Noise
  machine key) are rate limited with `429` + `Retry-After`; configure with
  `--ts2021-rate-per-min`, `--ts2021-burst`, `--register-rate-per-min`, and
  `--register-burst`. Behind a trusted reverse proxy the client IP is resolved
  from `X-Forwarded-For`/`X-Real-IP` (`--trusted-proxy <cidr>`).
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
