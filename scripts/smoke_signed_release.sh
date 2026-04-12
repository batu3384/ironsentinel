#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOCK_PATH="$TMP_DIR/scanner-bundle.lock.json"
PRIVATE_KEY_PATH="$TMP_DIR/private.key"
DIST_ROOT="$TMP_DIR/dist"
VERSION="signed-smoke"

echo "[signed-smoke] generating ephemeral release key"
(cd "$ROOT" && go run ./cmd/releasectl keygen --signer smoke-root --lock-out "$LOCK_PATH" --private-out "$PRIVATE_KEY_PATH")

export IRONSENTINEL_RELEASE_PRIVATE_KEY_B64
IRONSENTINEL_RELEASE_PRIVATE_KEY_B64="$(tr -d '\n' < "$PRIVATE_KEY_PATH")"
export IRONSENTINEL_EXTERNAL_ATTESTATION_PROVIDER="smoke-ci"
export IRONSENTINEL_EXTERNAL_ATTESTATION_SOURCE_URI="https://example.invalid/ironsentinel/signed-smoke"

echo "[signed-smoke] packaging signed host release"
(cd "$ROOT" && bash scripts/package_release.sh --version "$VERSION" --host-only --out "$DIST_ROOT" --lock "$LOCK_PATH" --sign)

echo "[signed-smoke] verifying signed manifest and attestation"
(cd "$ROOT" && go run ./cmd/releasectl verify --dir "$DIST_ROOT/$VERSION" --lock "$LOCK_PATH" --require-signature --require-attestation --require-external-attestation)

echo "[signed-smoke] verifying operator runtime view against ephemeral dist"
(cd "$ROOT" && APPSEC_BUNDLE_LOCK_PATH="$LOCK_PATH" IRONSENTINEL_DIST_DIR="$DIST_ROOT" go run ./cmd/ironsentinel runtime release verify --lang en --version "$VERSION" --require-signature --require-attestation --require-external-attestation)

echo "[signed-smoke] signed release smoke flow completed"
