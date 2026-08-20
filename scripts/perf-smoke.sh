#!/usr/bin/env bash
# M3-04 performance and concurrency smoke test.
#
# Validates the control plane under a small synthetic load with a time
# budget, then reports map build time, encode time, and peak memory as a
# Markdown report. Follows the wiki "Performance smoke test": smoke
# thresholds, not tuning benchmarks (Testing-Strategy.md).
#
#  1. builds the crabscale-control unit tests in release mode,
#  2. runs the perf_* smoke tests (the 200-node build/encode benchmark is
#     #[ignore]d by default, so only this job runs it),
#  3. wraps the timed run with GNU time to capture peak resident memory,
#  4. writes a summary report to stdout (and to --report <path> when given).
#
# Usage:
#   ./scripts/perf-smoke.sh [--report out.md]
set -euo pipefail

cd "$(dirname "$0")/.."

REPORT=""
if [ "${1:-}" = "--report" ]; then
  REPORT="${2:-perf-smoke-report.md}"
fi

# A tight total budget for the smoke job itself. The test binary runs in
# well under a minute in release; this only guards against a pathological
# regression that turns the smoke into a hang.
BUDGET_SECONDS=180
JOB_START="$(date +%s)"

# Build first so GNU time measures the test run, not the compiler.
cargo test -p crabscale-control --release --lib perf_ --no-run

# Compiled unit-test binary for the library crate.
BIN="$(find target/release/deps -maxdepth 1 -type f -name 'crabscale_control-*' -perm -u+x | head -n 1)"
if [ -z "$BIN" ]; then
  echo "error: crabscale-control test binary not found in target/release/deps" >&2
  exit 1
fi

OUT="$(mktemp)"
TIME_LOG="$(mktemp)"
cleanup() {
  rm -f "$OUT" "$TIME_LOG"
}
trap cleanup EXIT

# Run the perf smoke tests serially so the printed metrics stay ordered and
# reproducible. --include-ignored runs both the always-on concurrency/leak
# scenarios and the #[ignore]d 200-node benchmark under the same time budget;
# --nocapture surfaces the perf_* lines to the log.
echo "Running perf smoke tests: ${BIN##*/}" >&2
if command -v /usr/bin/time >/dev/null 2>&1; then
  /usr/bin/time -v -o "$TIME_LOG" \
    "$BIN" perf_ --include-ignored --nocapture --test-threads=1 >"$OUT" 2>&1
else
  "$BIN" perf_ --include-ignored --nocapture --test-threads=1 >"$OUT" 2>&1
fi

JOB_ELAPSED="$(( $(date +%s) - JOB_START ))"
if [ "$JOB_ELAPSED" -gt "$BUDGET_SECONDS" ]; then
  echo "error: perf smoke exceeded the $BUDGET_SECONDS s time budget (${JOB_ELAPSED}s)" >&2
  exit 1
fi

# Extract the machine-parseable metrics printed by the perf tests. The first
# println in a test shares its line with the test harness' banner, so values
# are matched anywhere in the line rather than at the line start.
PERF_METRIC() {
  sed -n "s/.*$1=//p" "$OUT" | head -n1
}
NODES="$(PERF_METRIC perf_nodes)"
PEERS="$(PERF_METRIC perf_peer_count)"
SAMPLES="$(PERF_METRIC perf_samples)"
BUILD_MIN_MS="$(PERF_METRIC perf_map_build_min_ms)"
BUILD_AVG_MS="$(PERF_METRIC perf_map_build_avg_ms)"
ENCODE_RAW_MIN_MS="$(PERF_METRIC perf_encode_raw_min_ms)"
ENCODE_ZSTD_MIN_MS="$(PERF_METRIC perf_encode_zstd_min_ms)"
RAW_BYTES="$(PERF_METRIC perf_first_frame_raw_bytes)"
ZSTD_BYTES="$(PERF_METRIC perf_first_frame_zstd_bytes)"

# Peak resident set size and wall time from GNU time, when available.
MAX_RSS_MB="n/a"
WALL_TIME="n/a"
if [ -s "$TIME_LOG" ]; then
  MAX_RSS_KB="$(grep 'Maximum resident set size' "$TIME_LOG" | awk '{print $NF}')"
  if [ -n "$MAX_RSS_KB" ]; then
    MAX_RSS_MB="$(awk -v kb="$MAX_RSS_KB" 'BEGIN { printf "%.1f", kb / 1024 }')"
  fi
  WALL_TIME="$(grep 'Elapsed (wall clock) time' "$TIME_LOG" | sed 's/.*) //')"
fi

SUMMARY="$(printf '%s\n' \
"# Crabscale performance smoke report (M3-04)" \
"" \
"- Nodes in tailnet: **${NODES:-n/a}**" \
"- Peers per observer map: **${PEERS:-n/a}**" \
"- Samples: **${SAMPLES:-n/a}**" \
"- Map build (min): **${BUILD_MIN_MS:-n/a} ms**" \
"- Map build (average): **${BUILD_AVG_MS:-n/a} ms**" \
"- Encode raw JSON (min): **${ENCODE_RAW_MIN_MS:-n/a} ms**" \
"- Encode zstd (min): **${ENCODE_ZSTD_MIN_MS:-n/a} ms**" \
"- First frame raw: **${RAW_BYTES:-n/a} bytes**" \
"- First frame zstd: **${ZSTD_BYTES:-n/a} bytes**" \
"- Peak process memory: **${MAX_RSS_MB} MB**" \
"- Test wall time: **${WALL_TIME}**" \
"- Smoke job budget: **${BUDGET_SECONDS}s**")"

if [ -n "$REPORT" ]; then
  printf '%s\n' "$SUMMARY" > "$REPORT"
  echo "Report written to $REPORT" >&2
fi
printf '%s\n' "$SUMMARY"

# The per-operation budgets are enforced inside the perf tests; surface them
# here too so the CI log is self-explanatory.
echo "perf_metrics:" >&2
grep -E 'perf_(nodes|peer_count|samples|map_build|encode|first_frame)=' "$OUT" | sed 's/^/  /' >&2
