#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINERFILE="${APPSEC_CONTAINERFILE_PATH:-$ROOT_DIR/deploy/scanner-bundle.Containerfile}"
IMAGE="${AEGIS_CONTAINER_IMAGE:-ghcr.io/batu3384/ironsentinel-scanner-bundle:latest}"
ENGINE="${AEGIS_CONTAINER_ENGINE:-auto}"
PLATFORM="${AEGIS_CONTAINER_PLATFORM:-}"
PUSH=0

usage() {
  cat <<EOF
Usage: bash scripts/build_scanner_image.sh [--engine docker|podman|auto] [--image <tag>] [--platform <linux/amd64>] [--push]

Builds the pinned scanner bundle image used by IronSentinel container isolation.
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

resolve_engine() {
  local preferred="$1"
  if [[ "$preferred" == "docker" || "$preferred" == "podman" ]]; then
    if command -v "$preferred" >/dev/null 2>&1; then
      printf '%s\n' "$preferred"
      return 0
    fi
    echo "Requested container engine not found: $preferred" >&2
    return 1
  fi

  if command -v podman >/dev/null 2>&1; then
    printf '%s\n' "podman"
    return 0
  fi
  if command -v docker >/dev/null 2>&1; then
    printf '%s\n' "docker"
    return 0
  fi
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --engine)
      require_flag_value "$1" "${2:-}"
      ENGINE="${2:-}"
      shift 2
      ;;
    --image)
      require_flag_value "$1" "${2:-}"
      IMAGE="${2:-}"
      shift 2
      ;;
    --platform)
      require_flag_value "$1" "${2:-}"
      PLATFORM="${2:-}"
      shift 2
      ;;
    --push)
      PUSH=1
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

if [[ ! -f "$CONTAINERFILE" ]]; then
  echo "Containerfile not found: $CONTAINERFILE" >&2
  exit 1
fi

ENGINE_BIN="$(resolve_engine "$ENGINE")" || {
  if [[ "$ENGINE" == "docker" || "$ENGINE" == "podman" ]]; then
    exit 1
  fi
  echo "No supported container engine found. Install podman or docker." >&2
  exit 1
}

echo "Building scanner image with $ENGINE_BIN"
echo "Containerfile: $CONTAINERFILE"
echo "Image: $IMAGE"
if [[ -n "$PLATFORM" ]]; then
  echo "Platform: $PLATFORM"
fi

BUILD_ARGS=(
  build
  -f "$CONTAINERFILE"
  -t "$IMAGE"
)

if [[ -n "$PLATFORM" ]]; then
  BUILD_ARGS+=(--platform "$PLATFORM")
fi

BUILD_ARGS+=("$ROOT_DIR")

"$ENGINE_BIN" "${BUILD_ARGS[@]}"

if [[ "$PUSH" -eq 1 ]]; then
  echo "Pushing $IMAGE"
  "$ENGINE_BIN" push "$IMAGE"
fi
