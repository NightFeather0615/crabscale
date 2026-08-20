#!/usr/bin/env bash
# M1-07 end-to-end client compatibility harness.
#
# Starts a crabscale control server on localhost, runs the Rust client test
# peer, and (when a Tailscale binary is available) exercises a stable Tailscale
# client. Emits a Markdown report to stdout or to --report <path>.
#
# Usage:
#   ./scripts/harness.sh [--tailscale-binary /path/to/tailscale] [--report out.md]
set -euo pipefail

cd "$(dirname "$0")/.."

cargo run -p crabscale-harness --bin harness -- "$@"
