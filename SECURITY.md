# Security Policy

Crabscale is a self-hosted control server for Tailscale-compatible clients.
This document describes how to report a vulnerability to the project and the
rules the project follows for handling secrets and hardening public-facing
attack surface.

## Supported versions

Only the current `master` tip is supported. There are no long-term-support
branches yet; v0.1 makes no production load guarantee (see the wiki
`Supported-Scale` page).

## Reporting a vulnerability

If you believe you have found a security vulnerability, **do not** open a
public issue with sensitive details. Please report it through the GitHub
Security Advisories flow for this repository
(<https://github.com/NightFeather0615/crabscale/security/advisories>) or,
if you cannot use that, open a private discussion / an issue titled
`[security]` with only a high-level description and offer to share the
reproduction steps privately with a maintainer.

Please include:

- The affected component (outer HTTP, TS2021/Noise transport, HTTP/2 control
  router, DERP relay, control plane, CLI, or dependencies).
- A minimal reproduction or the conditions under which the issue is reachable.
- The impact you observed and any suggested remediation.

The maintainers aim to acknowledge reports within 3 business days and to
author a fix on `master` with a regression test before publishing details.

## Secret handling rules

These rules are enforced by the codebase (and audited by the `audit` /
`deny` CI jobs):

1. **Pre-auth keys**: only the `prefix` and a salted hash of the `secret` are
   persisted. The plaintext secret is never stored, logged, or echoed in
   error bodies. A rejected registration response must not contain the
   attempted key material.
2. **Machine key**: the long-term server machine key is stored in a key file
   (`.local.key` by default) and is not logged. Operators should keep the
   file readable only by the service user.
3. **OIDC client secret**: passed via CLI/configuration file; it is never
   written to logs or included in redirect URLs or error bodies.
4. **Logs and error bodies**: secret material (auth key secrets, request
   `Auth` payloads, machine key private bytes) must never be logged.
   `eprintln!`/`println!` call sites must only print public identifiers such
   as hostnames, node names, and public keys.
5. **Backups**: persisted state (SQLite) contains hashes, not plaintext
   secrets. Take the same precautions with database backups as with the key
   file.

## Hardening measures

Public-deployment attack surface reduction:

- **Byte-level limits**: all documented wire size limits are enforced before
  any allocation or JSON parsing (Noise record frames ≤ 4096 bytes, init
  message exactly 101 bytes, early payload ≤ 1 MiB, inner bodies ≤ 1 MiB,
  `/verify` ≤ 4 KiB, DERP frame body ≤ 1 MiB, DERP packet ≤ 64 KiB).
- **Timeouts**: the TS2021 Noise handshake is bounded by the documented
  10-second timeout.
- **Rate limiting**: `POST /ts2021` is limited per client IP and
  `POST /machine/register` per Noise machine key, each returning HTTP `429`
  with a `Retry-After` header.
- **Bounded caches**: the interactive-registration cache and the SSH
  approval cache are bounded (TTL + cap).
- **Dependency auditing**: `cargo audit` (advisories) and `cargo deny`
  (bans/source policy) run in CI.
- **Fuzzing**: smoke fuzz targets for JSON wire types, Noise frames, and
  DERP frames run in CI over the checked-in corpus and random seeds.

### Known advisory

- `RUSTSEC-2023-0071` — `rsa` (via `jsonwebtoken` for OIDC RS256
  verification) has no patched upstream release; there is no safe upgrade
  available. It is recorded in both `deny.toml` and `audit.toml` so CI stays
  green while the upstream fix is tracked
  (https://github.com/RustCrypto/RSA/issues/626). Revisit when a
  constant-time `rsa` release lands.

## Questions

Questions about the security model belong in the project wiki
(`Architecture.md`), not in this file.
