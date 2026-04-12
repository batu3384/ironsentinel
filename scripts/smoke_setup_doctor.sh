#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

export APPSEC_DATA_DIR="$TMP_DIR/data"
export APPSEC_OUTPUT_DIR="$TMP_DIR/output"
export APPSEC_MIRROR_DIR="$TMP_DIR/mirrors"
export IRONSENTINEL_TOOLS_DIR="$TMP_DIR/tools/bin"

echo "[smoke] isolated runtime root: $TMP_DIR"
echo "[smoke] running core setup"
(cd "$ROOT" && go run ./cmd/ironsentinel setup --target auto --coverage core --mirror=false --lang en >"$TMP_DIR/setup.out" 2>&1)

echo "[smoke] running safe-mode runtime doctor"
set +e
(cd "$ROOT" && go run ./cmd/ironsentinel runtime doctor --mode safe --lang en >"$TMP_DIR/doctor.out" 2>&1)
DOCTOR_STATUS=$?
set -e

if [[ $DOCTOR_STATUS -ne 0 ]]; then
  if ! grep -Eq "Runtime bundle doctor|runtime doctor failed|Missing tools" "$TMP_DIR/doctor.out"; then
    echo "[smoke] runtime doctor failed without expected diagnostics" >&2
    cat "$TMP_DIR/doctor.out" >&2
    exit 1
  fi
  echo "[smoke] runtime doctor reported an expected readiness failure on this machine"
else
  echo "[smoke] runtime doctor passed"
fi

echo "[smoke] smoke setup/doctor flow completed"
