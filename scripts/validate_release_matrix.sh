#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

HOST_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --host-only)
      HOST_ONLY=1
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

matrix=(
  "darwin/arm64"
  "darwin/amd64"
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
  "windows/arm64"
)

if [[ $HOST_ONLY -eq 1 ]]; then
  matrix=("${GOOS:-$(go env GOOS)}/${GOARCH:-$(go env GOARCH)}")
fi

echo "[release] validating support matrix builds in $TMP_DIR"
for target in "${matrix[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  ext=""
  if [[ "$goos" == "windows" ]]; then
    ext=".exe"
  fi

  out="$TMP_DIR/ironsentinel-${goos}-${goarch}${ext}"
  echo "[release] building ${goos}/${goarch}"
  (cd "$ROOT" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -o "$out" ./cmd/ironsentinel)
done

echo "[release] rendering host support matrix"
(cd "$ROOT" && go run ./cmd/ironsentinel runtime support --lang en)

echo "[release] running host setup/doctor smoke flow"
(cd "$ROOT" && bash scripts/smoke_setup_doctor.sh)

echo "[release] validating shell guard smoke flow"
(cd "$ROOT" && bash scripts/smoke_shell_guards.sh)

echo "[release] packaging host artifact set"
(cd "$ROOT" && bash scripts/package_release.sh --version validation --host-only)
test -f "$ROOT/dist/validation/release-manifest.json"
test -f "$ROOT/dist/validation/SHA256SUMS"
test -f "$ROOT/dist/validation/release-attestation.json"
(cd "$ROOT" && go run ./cmd/releasectl verify --dir "$ROOT/dist/validation" --lock "$ROOT/scanner-bundle.lock.json" --require-attestation)
(cd "$ROOT" && go run ./cmd/ironsentinel runtime release verify --lang en --version validation --require-signature=false --require-attestation)

echo "[release] release matrix validation completed"
