#!/usr/bin/env bash
# Smoke test: register a node and receive a valid first MapResponse.
#
# This runs the in-process loopback smoke test over HTTP/2-over-Noise. A real
# Tailscale client binary can be pointed at the server once the outer HTTP
# server (TLS + /ts2021 upgrade) lands in a later milestone.
set -euo pipefail

cd "$(dirname "$0")/.."

cargo test -p crabscale-server --test control register_and_map_over_noise
