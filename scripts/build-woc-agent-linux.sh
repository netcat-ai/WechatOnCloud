#!/usr/bin/env bash
# Build the Linux woc-agent binary for the WeChat container.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_DIR="${ROOT}/docker/woc-agent-rs"
OUT="${WOC_AGENT_OUT:-${AGENT_DIR}/target-linux/release/woc-agent}"
BUILDER_TAG="${WOC_AGENT_BUILDER_TAG:-woc-agent-builder-local:woc-agent}"
BUILDER_FROM="${WOC_AGENT_BUILDER_FROM:-}"

find_builder_image() {
  if [ -n "${BUILDER_FROM}" ]; then
    printf '%s\n' "${BUILDER_FROM}"
    return
  fi
  docker images --format '{{.Repository}}:{{.Tag}}' \
    | awk '/^woc-agent-builder-local:/ || /^woc-agent-builder:/ { print; exit }'
}

builder="$(find_builder_image || true)"
if [ -z "${builder}" ]; then
  docker build \
    -f "${ROOT}/docker/Dockerfile" \
    --target woc-agent-builder \
    -t "${BUILDER_TAG}" \
    "${ROOT}/docker"
  builder="${BUILDER_TAG}"
fi

tmp="woc-agent-build-$USER-$$"
cleanup() {
  docker rm -f "${tmp}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker create --name "${tmp}" "${builder}" sleep infinity >/dev/null
docker start "${tmp}" >/dev/null
docker exec "${tmp}" rm -rf /src/src
docker cp "${AGENT_DIR}/Cargo.toml" "${tmp}:/src/Cargo.toml"
docker cp "${AGENT_DIR}/Cargo.lock" "${tmp}:/src/Cargo.lock"
docker cp "${AGENT_DIR}/src" "${tmp}:/src/src"
docker exec "${tmp}" cargo build --release

mkdir -p "$(dirname "${OUT}")"
docker cp "${tmp}:/src/target/release/woc-agent" "${OUT}"
file "${OUT}"
shasum -a 256 "${OUT}"
