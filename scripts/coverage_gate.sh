#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p coverage

PROFILE_FILE="coverage/internal.out"
SUMMARY_FILE="coverage/internal-summary.txt"
PACKAGES_FILE="coverage/internal-packages.txt"
MIN_COVERAGE="${COVERAGE_MIN:-45.0}"

PACKAGES=()
while IFS= read -r package; do
  PACKAGES+=("$package")
done < <(
  go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./internal/... |
    sed '/^$/d'
)

if [[ ${#PACKAGES[@]} -eq 0 ]]; then
  echo "[coverage] no internal packages with tests were discovered"
  exit 1
fi

printf '%s\n' "${PACKAGES[@]}" > "$PACKAGES_FILE"

echo "[coverage] testing ${#PACKAGES[@]} internal package(s)"
go test -coverprofile="$PROFILE_FILE" "${PACKAGES[@]}"

echo "[coverage] writing summary to $SUMMARY_FILE"
go tool cover -func="$PROFILE_FILE" | tee "$SUMMARY_FILE"

TOTAL_COVERAGE="$(
  awk '/^total:/ {gsub("%", "", $3); print $3}' "$SUMMARY_FILE"
)"

if [[ -z "$TOTAL_COVERAGE" ]]; then
  echo "[coverage] could not determine total coverage from $SUMMARY_FILE"
  exit 1
fi

if ! awk -v total="$TOTAL_COVERAGE" -v min="$MIN_COVERAGE" 'BEGIN { exit !(total + 0 >= min + 0) }'; then
  echo "[coverage] total internal coverage ${TOTAL_COVERAGE}% is below the minimum ${MIN_COVERAGE}%"
  exit 1
fi

echo "[coverage] total internal coverage ${TOTAL_COVERAGE}% meets the minimum ${MIN_COVERAGE}%"
