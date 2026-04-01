#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=""
OUT_ROOT="$ROOT/dist"
HOST_ONLY=0
SIGN=0
LOCK_PATH="$ROOT/scanner-bundle.lock.json"

require_flag_value() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    echo "Missing value for $flag" >&2
    exit 1
  fi
}

package_target() {
  local target="$1"
  local goos goarch base stage package_dir binary_name

  goos="${target%/*}"
  goarch="${target#*/}"
  base="ironsentinel_${VERSION}_${goos}_${goarch}"
  stage="$(mktemp -d)"
  (
    trap 'rm -rf "$stage"' EXIT
    package_dir="$stage/$base"
    mkdir -p "$package_dir"

    binary_name="ironsentinel"
    if [[ "$goos" == "windows" ]]; then
      binary_name="ironsentinel.exe"
    fi

    echo "[package] building $goos/$goarch"
    (
      cd "$ROOT"
      CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -o "$package_dir/$binary_name" ./cmd/ironsentinel
    )

    cp "$ROOT/README.md" "$package_dir/README.md"
    cp "$ROOT/.env.example" "$package_dir/.env.example"

    if [[ "$goos" == "windows" ]]; then
      (
        cd "$stage"
        zip -rq "$OUT_DIR/${base}.zip" "$base"
      )
      return
    fi

    (
      cd "$stage"
      tar -czf "$OUT_DIR/${base}.tar.gz" "$base"
    )
  )
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      require_flag_value "$1" "${2:-}"
      VERSION="$2"
      shift 2
      ;;
    --out)
      require_flag_value "$1" "${2:-}"
      OUT_ROOT="$2"
      shift 2
      ;;
    --host-only)
      HOST_ONLY=1
      shift
      ;;
    --lock)
      require_flag_value "$1" "${2:-}"
      LOCK_PATH="$2"
      shift 2
      ;;
    --sign)
      SIGN=1
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  VERSION="dev-$(date -u +%Y%m%d%H%M%S)"
fi

if ! command -v zip >/dev/null 2>&1; then
  echo "zip is required for windows release archives" >&2
  exit 1
fi

OUT_DIR="$OUT_ROOT/$VERSION"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

GIT_COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
GIT_REF="$(git -C "$ROOT" describe --tags --always 2>/dev/null || true)"
GIT_REPOSITORY="$(git -C "$ROOT" config --get remote.origin.url 2>/dev/null || true)"
GO_VERSION="$(go env GOVERSION)"
HOST_PLATFORM="$(go env GOOS)/$(go env GOARCH)"
WORKFLOW_NAME="${GITHUB_WORKFLOW:-}"
RUN_ID="${GITHUB_RUN_ID:-}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-}"
EXTERNAL_PROVIDER="${AEGIS_EXTERNAL_ATTESTATION_PROVIDER:-}"
EXTERNAL_SOURCE_URI="${AEGIS_EXTERNAL_ATTESTATION_SOURCE_URI:-}"
if [[ -z "$EXTERNAL_PROVIDER" && -n "${GITHUB_ACTIONS:-}" ]]; then
  EXTERNAL_PROVIDER="github-actions"
fi
if [[ -z "$EXTERNAL_SOURCE_URI" && -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "${GITHUB_RUN_ID:-}" ]]; then
  EXTERNAL_SOURCE_URI="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
fi
SOURCE_DIRTY=0
if ! git -C "$ROOT" diff --quiet --ignore-submodules HEAD >/dev/null 2>&1; then
  SOURCE_DIRTY=1
fi

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

for target in "${matrix[@]}"; do
  package_target "$target"
done

manifest_args=(
  go run ./cmd/releasectl manifest
  --dir "$OUT_DIR"
  --version "$VERSION"
  --lock "$LOCK_PATH"
  --commit "$GIT_COMMIT"
  --ref "$GIT_REF"
  --builder "package_release.sh"
  --go-version "$GO_VERSION"
  --host-platform "$HOST_PLATFORM"
  --repository "$GIT_REPOSITORY"
  --workflow "$WORKFLOW_NAME"
  --run-id "$RUN_ID"
  --run-attempt "$RUN_ATTEMPT"
)
if [[ -n "$EXTERNAL_PROVIDER" ]]; then
  manifest_args+=(--external-provider "$EXTERNAL_PROVIDER")
fi
if [[ -n "$EXTERNAL_SOURCE_URI" ]]; then
  manifest_args+=(--external-source-uri "$EXTERNAL_SOURCE_URI")
fi
if [[ $SOURCE_DIRTY -eq 1 ]]; then
  manifest_args+=(--source-dirty)
fi
if [[ $SIGN -eq 1 ]]; then
  if [[ -z "${AEGIS_RELEASE_PRIVATE_KEY_B64:-}" ]]; then
    echo "AEGIS_RELEASE_PRIVATE_KEY_B64 is required when --sign is set" >&2
    exit 1
  fi
  manifest_args+=(--private-key-env AEGIS_RELEASE_PRIVATE_KEY_B64)
fi

(
  cd "$ROOT"
  "${manifest_args[@]}"
)

if [[ $SIGN -eq 1 ]]; then
  (
    cd "$ROOT"
    verify_args=(go run ./cmd/releasectl verify --dir "$OUT_DIR" --lock "$LOCK_PATH" --require-signature --require-attestation)
    if [[ -n "$EXTERNAL_PROVIDER" ]]; then
      verify_args+=(--require-external-attestation)
    fi
    "${verify_args[@]}"
  )
fi

echo "[package] release artifacts written to $OUT_DIR"
