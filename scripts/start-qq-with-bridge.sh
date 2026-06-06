#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRIDGE_SO="${ROOT_DIR}/sign_bridge/libsign_bridge.so"
QQ_BIN="${QQ_BIN:-/opt/QQ/qq}"
SIGN_OFFSET="${SIGN_OFFSET:-0x557A6A0}"
SIGN_BRIDGE_SOCK="${SIGN_BRIDGE_SOCK:-/tmp/nekogel_sign_bridge.sock}"

if [[ ! -f "${BRIDGE_SO}" ]]; then
  echo "Building sign bridge..."
  make -C "${ROOT_DIR}/sign_bridge"
fi

if [[ ! -x "${QQ_BIN}" ]]; then
  echo "QQ binary not found: ${QQ_BIN}"
  echo "Set QQ_BIN to your Linux QQ executable path."
  exit 1
fi

export SIGN_OFFSET
export SIGN_BRIDGE_SOCK

echo "Starting QQ with sign bridge..."
echo "  QQ_BIN=${QQ_BIN}"
echo "  SIGN_OFFSET=${SIGN_OFFSET}"
echo "  SIGN_BRIDGE_SOCK=${SIGN_BRIDGE_SOCK}"
echo "  LD_PRELOAD=${BRIDGE_SO}"

exec env LD_PRELOAD="${BRIDGE_SO}" "${QQ_BIN}" "$@"
