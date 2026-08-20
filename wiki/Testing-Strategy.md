# Testing strategy

## Test layers

1. **Unit tests**: crate-local, no network, no database.
2. **Golden tests**: checked-in JSON fixtures for wire encoding/decoding and policy compilation.
3. **Protocol loopback tests**: Rust client handshake against Rust server in the same process.
4. **Integration tests**: real client binaries against a running server.

## Fixtures

Location: `tests/fixtures/<area>/<case>.json`.

Each fixture has:

- `input`: request or policy file.
- `expected`: exact JSON output, or a compact expected-state file.
- `note`: which behavior the fixture locks.

Golden tests compare bytes after canonical serialization where possible; formatting differences do not fail tests unless the spec says formatting matters.

## Loopback harness

`crabscale-transport` must expose a test-only function that connects an in-process client and server over a duplex stream. Tests cover:

- valid handshake;
- bad init length;
- bad message type;
- oversized record frame;
- early payload round trip;
- HTTP/2 request through the tunnel.

## Integration harness

The harness starts the server on localhost with a test config:

- control URL: `http://127.0.0.1:<port>`;
- one test tailnet;
- one pre-auth key;
- public or localhost DERP configuration.

Client commands are executed in containers or as local test binaries. Each scenario asserts:

- registration success;
- assigned IPs are in configured prefixes;
- peer status is visible;
- peer ping succeeds;
- logout returns the client to needs-login.

## Policy tests

Every policy grammar feature has at least one accept case and one deny case. The `tests`/`sshTests` blocks from a policy file are executed by CI, not only manually.

## Performance smoke test

A CI job with a time budget validates:

- 200 fake nodes produce a complete map for one observer;
- 50 concurrent lite updates do not panic;
- memory stays below the configured CI container limit.

These are smoke thresholds, not benchmarks for tuning.
