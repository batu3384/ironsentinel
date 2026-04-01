#!/usr/bin/env bash
set -euo pipefail

RELEASE_DIR=""
REQUIRE_SIGNING=0
REQUIRE_EXTERNAL_ATTESTATION=0

usage() {
  cat <<'EOF'
Usage: bash scripts/release_artifact_preflight.sh --dir <dist/version> [--require-signing] [--require-external-attestation]

Validates that a packaged release directory contains the expected sidecar files and at least one archive artifact.
EOF
}

require_flag_value() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    echo "Missing value for $flag" >&2
    exit 1
  fi
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "Required release file is missing: $path" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      require_flag_value "$1" "${2:-}"
      RELEASE_DIR="$2"
      shift 2
      ;;
    --require-signing)
      REQUIRE_SIGNING=1
      shift
      ;;
    --require-external-attestation)
      REQUIRE_EXTERNAL_ATTESTATION=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$RELEASE_DIR" ]]; then
  echo "Missing value for --dir" >&2
  exit 1
fi

if [[ ! -d "$RELEASE_DIR" ]]; then
  echo "Release directory not found: $RELEASE_DIR" >&2
  exit 1
fi

require_file "$RELEASE_DIR/release-manifest.json"
require_file "$RELEASE_DIR/SHA256SUMS"
require_file "$RELEASE_DIR/release-attestation.json"

if [[ $REQUIRE_SIGNING -eq 1 ]]; then
  require_file "$RELEASE_DIR/release-manifest.sig"
  require_file "$RELEASE_DIR/release-attestation.sig"
fi

if [[ $REQUIRE_EXTERNAL_ATTESTATION -eq 1 ]]; then
  require_file "$RELEASE_DIR/release-external-attestation.json"
fi

shopt -s nullglob
archives=("$RELEASE_DIR"/*.tar.gz "$RELEASE_DIR"/*.zip)
shopt -u nullglob
if [[ ${#archives[@]} -eq 0 ]]; then
  echo "No packaged release archives were found in $RELEASE_DIR" >&2
  exit 1
fi

echo "[release-artifacts] dir: $RELEASE_DIR"
echo "[release-artifacts] archives: ${#archives[@]}"
