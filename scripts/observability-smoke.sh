#!/usr/bin/env bash
# M4-04 (#27) observability smoke.
#
# Starts a local crabscale-server, curls /health, /version, and /metrics, and
# checks that the operational endpoints respond and the documented Prometheus
# metric families are present.
#
# Run from the repository root. Needs curl and jq (or python3 for parsing).
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Building release server"
cargo build --quiet --release -p crabscale-server
SERVER=./target/release/crabscale-server

DIR="$(mktemp -d)"
PORT_PORT="$DIR/port"      # not used; port chosen by OS via :0
LOG="$DIR/server.log"
trap 'kill ${SERVER_PID:-} 2>/dev/null || true; rm -rf "$DIR"' EXIT

# Bind an ephemeral port (0) so CI never collides; the server prints the
# actual address to stdout.
"$SERVER" --listen 127.0.0.1:0 --key-file "$DIR/key" --store "$DIR/db" >"$LOG" 2>&1 &
SERVER_PID=$!

# Wait for the server to report its bound address ("control server listening
# on http://127.0.0.1:PORT").
for _ in $(seq 1 50); do
  ADDR="$(grep -o 'http://[0-9.:]*' "$LOG" | head -n1 || true)"
  [ -n "$ADDR" ] && break
  sleep 0.1
done
BASE="${ADDR:-http://127.0.0.1:8080}"

health="$(curl -fsS "$BASE/health")"
version="$(curl -fsS "$BASE/version")"
metrics="$(curl -fsS "$BASE/metrics")"

echo "health: $health"
echo "version: $version"

case "$health" in
  *'"status":"ok"'*) ;;
  *) echo "unexpected /health body: $health" >&2; exit 1 ;;
esac

case "$version" in
  *'crabscale-server'*'"version":"0.1.0"'*) ;;
  *) echo "unexpected /version body: $version" >&2; exit 1 ;;
esac

for family in \
  crabscale_sessions_opened_total \
  crabscale_sessions_closed_total \
  crabscale_sessions_active \
  crabscale_registrations_total \
  crabscale_policy_compiles_total \
  crabscale_derp_packets_total \
  crabscale_derp_packets_dropped_total; do
  printf '%s' "$metrics" | grep -q "# TYPE $family" || {
    echo "missing metric family $family in /metrics" >&2
    exit 1
  }
done

echo "==> Observability smoke passed: /health, /version, /metrics OK"
