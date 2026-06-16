#!/usr/bin/env bash
# Build the Linux woc-agent binary for the WeChat container.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_DIR="${ROOT}/docker/woc-agent-rs"
TARGET_DIR="${WOC_AGENT_TARGET_DIR:-${AGENT_DIR}/target-linux}"
BUILD_OUT="${TARGET_DIR}/release/woc-agent"
OUT="${WOC_AGENT_OUT:-${BUILD_OUT}}"
RUST_IMAGE="${WOC_RUST_IMAGE:-rust:1-bookworm}"
CARGO_REGISTRY_VOL="${WOC_AGENT_CARGO_REGISTRY_VOL:-woc-agent-cargo-registry}"
CARGO_GIT_VOL="${WOC_AGENT_CARGO_GIT_VOL:-woc-agent-cargo-git}"

docker volume create "${CARGO_REGISTRY_VOL}" >/dev/null
docker volume create "${CARGO_GIT_VOL}" >/dev/null
mkdir -p "${TARGET_DIR}" "$(dirname "${OUT}")"

docker run --rm \
  -v "${AGENT_DIR}:/src" \
  -v "${CARGO_REGISTRY_VOL}:/usr/local/cargo/registry" \
  -v "${CARGO_GIT_VOL}:/usr/local/cargo/git" \
  -w /src \
  -e CARGO_TARGET_DIR=/src/target-linux \
  "${RUST_IMAGE}" \
  cargo build --release

if [ "${OUT}" != "${BUILD_OUT}" ]; then
  cp "${BUILD_OUT}" "${OUT}"
fi

file "${OUT}"
shasum -a 256 "${OUT}"
