#!/usr/bin/env bash
# M1-07 Rust client test peer.
#
# Runs the Rust client test peer against a running crabscale control server.
# The server must already be listening; pass its URL with --control-url.
#
# Usage:
#   ./scripts/run-rust-peer.sh --control-url http://127.0.0.1:8080
set -euo pipefail

cd "$(dirname "$0")/.."

cargo run -p crabscale-harness --bin rust-peer -- "$@"
