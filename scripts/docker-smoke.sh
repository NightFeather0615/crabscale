#!/usr/bin/env bash
# M4-03 container smoke (issue #26, acceptance).
#
# Builds the multi-stage image and verifies:
#   - the image runs with a NON-ROOT user,
#   - there is NO compiler toolchain in the image,
#   - the machine key persists across a container restart (volume mount),
#   - the server actually serves /key over the network.
#
# Requires a working Docker daemon; skipped automatically when `docker` is not
# installed (CI runs the in-process smoke tests instead).
#
# Usage:
#   ./scripts/docker-smoke.sh [--image crabscale:smoke]
set -euo pipefail

IMAGE="${IMAGE:-crabscale:smoke}"
if ! command -v docker >/dev/null 2>&1; then
  echo "docker not available; skipping container smoke"
  exit 0
fi

cd "$(dirname "$0")/.."

# In CI the image is normally pre-built by docker/build-push-action with
# GitHub Actions layer cache. Local runs still build directly.
if [ "${CRABSCALE_DOCKER_SKIP_BUILD:-0}" != "1" ]; then
  echo "== building ${IMAGE} =="
  if [ "${GITHUB_ACTIONS:-false}" = "true" ]; then
    docker buildx build --load \
      --cache-from type=gha --cache-to type=gha,mode=max \
      -t "$IMAGE" .
  else
    docker build -t "$IMAGE" .
  fi
else
  echo "== using pre-built ${IMAGE} =="
fi

echo "== asserting non-root user =="
RUN_USER="$(docker run --rm --entrypoint id "$IMAGE" -u)"
if [ "$RUN_USER" = "0" ] || [ -z "$RUN_USER" ]; then
  echo "expected a non-root uid, got: '$RUN_USER'"
  exit 1
fi
echo "runs as uid $RUN_USER (non-root)" 

echo "== asserting no compiler toolchain =="
if docker run --rm --entrypoint sh "$IMAGE" -c 'command -v cc || command -v gcc || command -v rustc' | grep -q .; then
  echo "compiler found in runtime image; expected none"
  exit 1
fi

echo "== key persistence across restart =="
NET="crabscale-smoke-net-$(date +%s)"
TMP="$(mktemp -d)"
chmod 777 "$TMP"  # writable by the container's non-root user
trap 'docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT
docker network create "$NET" >/dev/null
docker run -d --name crabscale-smoke-1 \
  --network "$NET" \
  -v "$TMP:/var/lib/crabscale/data" \
  --entrypoint crabscale-server "$IMAGE" \
  --listen 0.0.0.0:8080 --key-file /var/lib/crabscale/data/crabscale.key >/dev/null
K1=""
for _ in $(seq 1 15); do
  K1="$(docker exec crabscale-smoke-1 cat /var/lib/crabscale/data/crabscale.key 2>/dev/null || true)"
  [ -n "$K1" ] && break
  sleep 1
done
docker rm -f crabscale-smoke-1 >/dev/null

docker run -d --name crabscale-smoke-2 \
  --network "$NET" \
  -v "$TMP:/var/lib/crabscale/data" \
  --entrypoint crabscale-server "$IMAGE" \
  --listen 0.0.0.0:8080 --key-file /var/lib/crabscale/data/crabscale.key >/dev/null
K2=""
for _ in $(seq 1 15); do
  K2="$(docker exec crabscale-smoke-2 cat /var/lib/crabscale/data/crabscale.key 2>/dev/null || true)"
  [ -n "$K2" ] && break
  sleep 1
done

if [ -z "$K1" ] || [ "$K1" != "$K2" ]; then
  echo "machine key did not persist across restart"
  docker rm -f crabscale-smoke-2 >/dev/null || true
  exit 1
fi
echo "key persisted (${#K1} bytes)"

echo "== serving /key over the network =="
docker run -d --name crabscale-smoke-probe \
  --network "$NET" \
  --entrypoint crabscale-server "$IMAGE" \
  --listen 0.0.0.0:8080 --key-file /var/lib/crabscale/data/crabscale.key >/dev/null
PROBE_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' crabscale-smoke-probe)"
for _ in $(seq 1 30); do
  if BODY="$(curl -fsS "http://${PROBE_IP}:8080/key?v=130" 2>/dev/null)"; then
    break
  fi
  sleep 1
done
echo "$BODY" | grep -q '"publicKey"' || {
  echo "crabscale /key did not return a public key"
  docker rm -f crabscale-smoke-probe >/dev/null || true
  exit 1
}
docker rm -f crabscale-smoke-probe >/dev/null || true
echo "ok: ${IMAGE} serves /key, non-root, no compiler, persistent key"
