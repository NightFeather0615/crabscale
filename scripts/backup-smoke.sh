#!/usr/bin/env bash
# M4-04 (#27) backup/restore smoke.
#
# Demonstrates the documented `crabscale backup` / `crabscale restore`
# commands against real files and proves (via the crabscale-cli unit test)
# that a restored database lets an existing node log in again.
#
# Run from the repository root.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Building release CLI"
cargo build --quiet --release -p crabscale-cli
CLI=./target/release/crabscale

DIR="$(mktemp -d)"
DB="$DIR/smoke.db"
RESTORED="$DIR/restored.db"
BACKUP="$DIR/smoke.csb"
trap 'rm -rf "$DIR"' EXIT

# A backup on an empty (freshly migrated) store must succeed and be non-empty.
echo "==> Backup an empty store"
"$CLI" --store "$DB" backup --output "$BACKUP"
test -s "$BACKUP"

# Restoring into a fresh database must succeed.
echo "==> Restore into a fresh database"
"$CLI" --store "$RESTORED" restore --force --input "$BACKUP"

# The relogin acceptance is covered by the unit test that drives the exact
# SqliteStore operations the CLI commands invoke.
echo "==> Verify relogin after restore (crabscale-cli unit test)"
cargo test --quiet -p crabscale-cli backup_restore_cli_round_trip_allows_relogin

echo "==> Backup/restore smoke passed: restored DB preserves node authorization"
