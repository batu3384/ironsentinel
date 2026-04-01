#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

expect_failure() {
  local expected="$1"
  shift
  local output status

  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e

  if [[ $status -eq 0 ]]; then
    echo "[smoke] command unexpectedly succeeded: $*" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" <<<"$output"; then
    echo "[smoke] command failed without expected diagnostic: $*" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

create_preflight_repo() {
  local repo_dir="$1"
  mkdir -p "$repo_dir"
  (
    cd "$repo_dir"
    git init -q
    git config user.name smoke
    git config user.email smoke@example.invalid
    printf '{ "signing": { "type": "ed25519", "signer": "smoke", "publicKey": "c21va2U=" } }\n' > scanner-bundle.lock.json
    git add scanner-bundle.lock.json
    git commit -qm "init"
  )
}

echo "[smoke] validating shell flag guards"
expect_failure "Missing value for --version" bash "$ROOT/scripts/package_release.sh" --version
expect_failure "Missing value for --out" bash "$ROOT/scripts/package_release.sh" --out
expect_failure "Missing value for --lock" bash "$ROOT/scripts/package_release.sh" --lock
expect_failure "Missing value for --mode" bash "$ROOT/scripts/install_scanners.sh" --mode
expect_failure "Missing value for --engine" bash "$ROOT/scripts/build_scanner_image.sh" --engine
expect_failure "Missing value for --engine" bash "$ROOT/scripts/build_scanner_image.sh" --engine --push
expect_failure "Missing value for --image" bash "$ROOT/scripts/build_scanner_image.sh" --image
expect_failure "Missing value for --platform" bash "$ROOT/scripts/build_scanner_image.sh" --platform
expect_failure "Missing value for --version" bash "$ROOT/scripts/release_publish_preflight.sh" --version
expect_failure "Release version must look like vX.Y.Z" bash "$ROOT/scripts/release_publish_preflight.sh" --version not-a-tag
expect_failure "Missing value for --dir" bash "$ROOT/scripts/release_artifact_preflight.sh" --dir
EMPTY_BIN="$TMP_DIR/empty-bin"
mkdir -p "$EMPTY_BIN"
ln -s /usr/bin/dirname "$EMPTY_BIN/dirname"
expect_failure "Requested container engine not found: docker" env PATH="$EMPTY_BIN" /bin/bash "$ROOT/scripts/build_scanner_image.sh" --engine docker

echo "[smoke] validating package_release temp cleanup on build failure"
FAKE_BIN="$TMP_DIR/fake-bin"
STAGE_DIR="$TMP_DIR/package-stage"
mkdir -p "$FAKE_BIN"

cat >"$FAKE_BIN/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  env)
    case "${2:-}" in
      GOVERSION) printf 'go-test\n' ;;
      GOOS) printf '%s\n' "${GOOS:-linux}" ;;
      GOARCH) printf '%s\n' "${GOARCH:-amd64}" ;;
      *) exit 1 ;;
    esac
    ;;
  build)
    exit 42
    ;;
  *)
    echo "unexpected fake go invocation: $*" >&2
    exit 98
    ;;
esac
EOF
chmod +x "$FAKE_BIN/go"

cat >"$FAKE_BIN/mktemp" <<EOF
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$STAGE_DIR"
printf '%s\n' "$STAGE_DIR"
EOF
chmod +x "$FAKE_BIN/mktemp"

set +e
PATH="$FAKE_BIN:$PATH" GOOS=linux GOARCH=amd64 \
  bash "$ROOT/scripts/package_release.sh" --version smoke-shell-guards --host-only --out "$TMP_DIR/out" \
  >"$TMP_DIR/package-release.out" 2>&1
status=$?
set -e

if [[ $status -eq 0 ]]; then
  echo "[smoke] package_release unexpectedly succeeded with failing fake go build" >&2
  cat "$TMP_DIR/package-release.out" >&2
  exit 1
fi
if [[ -e "$STAGE_DIR" ]]; then
  echo "[smoke] package_release leaked stage directory after build failure: $STAGE_DIR" >&2
  exit 1
fi

echo "[smoke] validating container engine auto-resolution order"
AUTO_FAKE_BIN="$TMP_DIR/auto-fake-bin"
AUTO_LOG="$TMP_DIR/build-engine.log"
mkdir -p "$AUTO_FAKE_BIN"

cat >"$AUTO_FAKE_BIN/podman" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'podman %s\n' "\$*" >>"$AUTO_LOG"
exit 0
EOF
chmod +x "$AUTO_FAKE_BIN/podman"

cat >"$AUTO_FAKE_BIN/docker" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "\$*" >>"$AUTO_LOG"
exit 0
EOF
chmod +x "$AUTO_FAKE_BIN/docker"

PATH="$AUTO_FAKE_BIN:$PATH" bash "$ROOT/scripts/build_scanner_image.sh" --image smoke-engine-test >/dev/null 2>&1
if ! grep -Fq "podman build" "$AUTO_LOG"; then
  echo "[smoke] build_scanner_image did not prefer podman during auto resolution" >&2
  cat "$AUTO_LOG" >&2
  exit 1
fi
if grep -Fq "docker build" "$AUTO_LOG"; then
  echo "[smoke] build_scanner_image unexpectedly invoked docker during auto resolution" >&2
  cat "$AUTO_LOG" >&2
  exit 1
fi

echo "[smoke] validating release publish preflight"
PRECHECK_REPO="$TMP_DIR/preflight-repo"
create_preflight_repo "$PRECHECK_REPO"
AEGIS_RELEASE_ROOT="$PRECHECK_REPO" AEGIS_RELEASE_PRIVATE_KEY_B64=smoke-key \
  bash "$ROOT/scripts/release_publish_preflight.sh" --version v0.0.0-smoke --require-signing >/dev/null

expect_failure "Release tag was not found locally" \
  env AEGIS_RELEASE_ROOT="$PRECHECK_REPO" /bin/bash "$ROOT/scripts/release_publish_preflight.sh" --version v0.0.0-smoke --require-tag

(
  cd "$PRECHECK_REPO"
  git tag v0.0.0-smoke
)
AEGIS_RELEASE_ROOT="$PRECHECK_REPO" AEGIS_RELEASE_PRIVATE_KEY_B64=smoke-key \
  bash "$ROOT/scripts/release_publish_preflight.sh" --version v0.0.0-smoke --require-signing --require-tag >/dev/null

DIRTY_PRECHECK_REPO="$TMP_DIR/preflight-repo-dirty"
create_preflight_repo "$DIRTY_PRECHECK_REPO"
printf '# dirty\n' >>"$DIRTY_PRECHECK_REPO/scanner-bundle.lock.json"
expect_failure "Release publish requires a clean source tree" \
  env AEGIS_RELEASE_ROOT="$DIRTY_PRECHECK_REPO" /bin/bash "$ROOT/scripts/release_publish_preflight.sh" --version v0.0.0-smoke

UNTRACKED_PRECHECK_REPO="$TMP_DIR/preflight-repo-untracked"
create_preflight_repo "$UNTRACKED_PRECHECK_REPO"
printf 'untracked\n' >"$UNTRACKED_PRECHECK_REPO/untracked.txt"
expect_failure "Release publish requires a clean source tree" \
  env AEGIS_RELEASE_ROOT="$UNTRACKED_PRECHECK_REPO" /bin/bash "$ROOT/scripts/release_publish_preflight.sh" --version v0.0.0-smoke

TAGGED_PRECHECK_REPO="$TMP_DIR/preflight-repo-tagged"
create_preflight_repo "$TAGGED_PRECHECK_REPO"
expect_failure "Resolved release version does not match pushed tag" \
  env AEGIS_RELEASE_ROOT="$TAGGED_PRECHECK_REPO" GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v9.9.9 \
  /bin/bash "$ROOT/scripts/release_publish_preflight.sh" --version v0.0.0-smoke

expect_failure "AEGIS_RELEASE_PRIVATE_KEY_B64 is required" \
  env AEGIS_RELEASE_ROOT="$PRECHECK_REPO" /bin/bash "$ROOT/scripts/release_publish_preflight.sh" --version v0.0.0-smoke --require-signing

expect_failure "GITHUB_RUN_ID is required" \
  env AEGIS_RELEASE_ROOT="$PRECHECK_REPO" GITHUB_ACTIONS=true GITHUB_REPOSITORY=batuhanyuksel/security GITHUB_SERVER_URL=https://github.com \
  /bin/bash "$ROOT/scripts/release_publish_preflight.sh" --version v0.0.0-smoke

echo "[smoke] validating release artifact preflight"
ARTIFACT_DIR="$TMP_DIR/release-artifacts"
mkdir -p "$ARTIFACT_DIR"
printf '{}' >"$ARTIFACT_DIR/release-manifest.json"
printf 'checksums\n' >"$ARTIFACT_DIR/SHA256SUMS"
printf '{}' >"$ARTIFACT_DIR/release-attestation.json"
printf 'signature\n' >"$ARTIFACT_DIR/release-manifest.sig"
printf 'signature\n' >"$ARTIFACT_DIR/release-attestation.sig"
printf '{}' >"$ARTIFACT_DIR/release-external-attestation.json"
printf 'archive-bytes\n' >"$ARTIFACT_DIR/ironsentinel_v0.0.0_linux_amd64.tar.gz"

bash "$ROOT/scripts/release_artifact_preflight.sh" --dir "$ARTIFACT_DIR" --require-signing --require-external-attestation >/dev/null

ARTIFACT_MISSING_ARCHIVE_DIR="$TMP_DIR/release-artifacts-no-archive"
mkdir -p "$ARTIFACT_MISSING_ARCHIVE_DIR"
printf '{}' >"$ARTIFACT_MISSING_ARCHIVE_DIR/release-manifest.json"
printf 'checksums\n' >"$ARTIFACT_MISSING_ARCHIVE_DIR/SHA256SUMS"
printf '{}' >"$ARTIFACT_MISSING_ARCHIVE_DIR/release-attestation.json"
expect_failure "No packaged release archives were found" \
  bash "$ROOT/scripts/release_artifact_preflight.sh" --dir "$ARTIFACT_MISSING_ARCHIVE_DIR"

echo "[smoke] shell guard smoke flow completed"
