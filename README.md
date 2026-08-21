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

## Deployment (TLS, reverse proxy, containers)

M4-03 (#26) makes `crabscale-server` deployable behind standard
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
