# Changelog

All notable changes to Crabscale are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (M4-04, #27)
- `crabscale backup` / `crabscale restore` CLI commands. Backups are
  zstd-compressed snapshots of an explicit allowlist of store tables and
  never contain plaintext secrets; a restored database lets existing nodes
  log in again.
- Prometheus metrics at `GET /metrics` for sessions (active/opened/closed),
  registrations, policy compiles, and DERP packets (relayed/dropped), with a
  new `crabscale-metrics` workspace crate.
- `GET /health` (liveness) and `GET /version` (binary + protocol version)
  operational endpoints.
- `CHANGELOG.md` and a tag-based release CI workflow that builds and uploads
  release binaries.
- v0.1 gap analysis against the single-tailnet scope
  (`crabscale.wiki/Gap-Analysis.md`, `docs/v0.1-gap.md`).

### Changed
- `SessionRegistry::close` now reports whether a session was actually removed,
  enabling accurate close accounting in the metrics registry.

### Security
- Backup/restore enforce a strict table allowlist and reject documents that
  reference tables outside it or use an unknown format version, so an unsafe
  future table can never be silently restored.
