#!/usr/bin/env bash
set -euo pipefail

ROOT="${AEGIS_RELEASE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VERSION=""
LOCK_PATH="${AEGIS_RELEASE_LOCK_PATH:-$ROOT/scanner-bundle.lock.json}"
REQUIRE_SIGNING=0
REQUIRE_TAG=0

usage() {
  cat <<'EOF'
Usage: bash scripts/release_publish_preflight.sh --version <vX.Y.Z> [--lock <path>] [--require-signing] [--require-tag]

Validates release publish preconditions before packaging or uploading artifacts.
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

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "$name is required" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      require_flag_value "$1" "${2:-}"
      VERSION="$2"
      shift 2
      ;;
    --lock)
      require_flag_value "$1" "${2:-}"
      LOCK_PATH="$2"
      shift 2
      ;;
    --require-signing)
      REQUIRE_SIGNING=1
      shift
      ;;
    --require-tag)
      REQUIRE_TAG=1
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

if [[ -z "$VERSION" ]]; then
  echo "Missing value for --version" >&2
  exit 1
fi

if [[ ! "$VERSION" =~ ^v[0-9]+(\.[0-9]+){2}([-.][0-9A-Za-z.-]+)?$ ]]; then
  echo "Release version must look like vX.Y.Z or include a prerelease/build suffix: $VERSION" >&2
  exit 1
fi

if [[ ! -f "$LOCK_PATH" ]]; then
  echo "Bundle lock not found: $LOCK_PATH" >&2
  exit 1
fi

if ! git -C "$ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
  echo "Git HEAD could not be resolved for release provenance" >&2
  exit 1
fi

if [[ $REQUIRE_TAG -eq 1 ]] && ! git -C "$ROOT" rev-parse --verify "refs/tags/$VERSION" >/dev/null 2>&1; then
  echo "Release tag was not found locally: $VERSION" >&2
  exit 1
fi

if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=normal 2>/dev/null)" ]]; then
  echo "Release publish requires a clean source tree" >&2
  exit 1
fi

if [[ "${GITHUB_REF_TYPE:-}" == "tag" && -n "${GITHUB_REF_NAME:-}" && "${GITHUB_REF_NAME}" != "$VERSION" ]]; then
  echo "Resolved release version does not match pushed tag: $VERSION vs ${GITHUB_REF_NAME}" >&2
  exit 1
fi

if [[ $REQUIRE_SIGNING -eq 1 ]]; then
  require_env AEGIS_RELEASE_PRIVATE_KEY_B64
fi

if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  require_env GITHUB_REPOSITORY
  require_env GITHUB_RUN_ID
  require_env GITHUB_SERVER_URL
fi

echo "[release-preflight] version: $VERSION"
echo "[release-preflight] lock: $LOCK_PATH"
echo "[release-preflight] source tree: clean"
