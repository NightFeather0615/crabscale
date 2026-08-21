#!/usr/bin/env bash
# M4-03 reverse-proxy integration smoke (issue #26, acceptance).
#
# Runs the trusted-proxy client-IP tests plus the HTTP->HTTPS redirect test:
#   - /ts2021 rate limiting keys on the X-Forwarded-For client IP when the
#     peer is a trusted proxy,
#   - forwarding headers are ignored when no proxy is trusted,
#   - the plain-HTTP listener 301-redirects browsers to HTTPS.
#
# Usage:
#   ./scripts/reverse-proxy-smoke.sh
set -euo pipefail

cd "$(dirname "$0")/.."

cargo test -p crabscale-server --test reverse_proxy
