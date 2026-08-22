#!/usr/bin/env bash
# Fuzz smoke: drive the standalone fuzz targets over corpus inputs and
# random seeds, failing on any decoder panic.
#
# Each `crabscale-fuzz` target reads arbitrary bytes on stdin and must reject
# malformed input with an `Err`, never a panic. This job:
#
#  1. builds the fuzz targets,
#  2. runs every target against every checked-in corpus file,
#  3. runs every target against 16 randomly sized /dev/urandom seeds,
#
# and exits non-zero if any run panics (crash), exceeds the per-run timeout,
# or cannot be executed. This is a smoke gate, not a full libFuzzer campaign.
#
# Usage:
#   ./scripts/fuzz-smoke.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Building fuzz targets"
cargo build -p crabscale-fuzz

BIN_DIR="target/debug"
CORPUS="crabscale-fuzz/corpus"
TIMEOUT_SECONDS=15
FAILED=0

run_target() {
  local bin="$1"
  local input="$2"
  if ! timeout "$TIMEOUT_SECONDS" "$BIN_DIR/$bin" < "$input" >/dev/null 2>&1; then
    echo "FAIL: $bin crashed or timed out on $input" >&2
    FAILED=1
  fi
}

for bin in json_fuzz noise_fuzz derp_fuzz; do
  for file in "$CORPUS"/*/*; do
    [ -f "$file" ] || continue
    run_target "$bin" "$file"
  done

  # Random seeds at a spread of sizes, including empty and sub-header inputs.
  for i in $(seq 1 16); do
    size=$(( (i * 137) % 4096 ))
    tmp="$(mktemp)"
    head -c "$size" /dev/urandom > "$tmp"
    run_target "$bin" "$tmp"
    rm -f "$tmp"
  done

  echo "OK: $bin"
done

if [ "$FAILED" -ne 0 ]; then
  echo "fuzz smoke failed" >&2
  exit 1
fi
echo "fuzz smoke passed"
