#!/usr/bin/env bash
# M4-01 capability-version compatibility matrix (#24).
#
# Runs the Rust client test peer at every capability version in the supported
# matrix from the wiki Spec-Compatibility section 3, and emits a single
# Markdown compatibility report. Real Tailscale client binaries (latest,
# previous, oldest, development) are documented as "not exercised" because
# they cannot be fetched in this build environment; each failure is recorded
# in the report rather than silently dropped.
#
# Usage:
#   ./scripts/capability-matrix.sh [--report out.md]
set -euo pipefail

cd "$(dirname "$0")/.."

REPORT="capability-matrix.md"
if [ "${1:-}" = "--report" ]; then
  REPORT="${2:-capability-matrix.md}"
fi

# Supported matrix rows: version -> label (Spec-Compatibility section 3).
# 113 = oldest supported (MIN_SUPPORTED_CAPVER), 129 = previous stable,
# 130 = latest stable / Rust peer, 131 = development/head.
MATRIX=(113 129 130 131)
declare -A LABELS=(
  [113]="oldest supported (min capver)"
  [129]="previous stable"
  [130]="latest stable & Rust client peer"
  [131]="development/head"
)

rm -f "$REPORT"
{
  echo "# crabscale capability-version compatibility matrix"
  echo
  echo "Server: crabscale control plane, M4-01 (#24)."
  echo
  echo "Each row starts a fresh localhost server and runs the Rust client test"
  echo "peer at that capability version. The peer exercises auth-key"
  echo "registration, a non-streaming full map, DNS delivery, and logout"
  echo "(Spec-Compatibility section 3)."
  echo
  echo "## Client binaries"
  echo
  echo "- Latest stable Tailscale binary: not exercised (offline build environment)."
  echo "- Previous stable binary: not exercised (offline build environment)."
  echo "- Oldest supported binary: not exercised (offline build environment)."
  echo "- Development/head binary: not exercised (offline build environment)."
  echo "- Rust client library test peer: exercised below at every matrix version."
  echo
  echo "## Results"
  echo
} >> "$REPORT"

FAILED=""
for version in "${MATRIX[@]}"; do
  label="${LABELS[$version]}"
  echo "Running capability version $version ($label)..." >&2
  compat_file="compat-report-v${version}.md"
  if ./scripts/harness.sh --capability-version "$version" --report "$compat_file"; then
    {
      echo "### Capability version $version ($label): PASS"
      echo
      cat "$compat_file"
    } >> "$REPORT"
  else
    status=$?
    {
      echo "### Capability version $version ($label): FAILED (exit $status)"
      echo
      if [ -f "$compat_file" ]; then
        cat "$compat_file"
      else
        echo "No report produced by the harness for version $version."
      fi
    } >> "$REPORT"
    FAILED="${FAILED}${FAILED:+ }${version}"
  fi
  rm -f "$compat_file"
done

if [ -n "$FAILED" ]; then
  {
    echo
    echo "## Failures"
    echo
    echo "The following matrix versions failed and are documented above: $FAILED."
  } >> "$REPORT"
  echo "capability matrix: $FAILED failed (see $REPORT)" >&2
fi

echo "Capability matrix report written to $REPORT" >&2
