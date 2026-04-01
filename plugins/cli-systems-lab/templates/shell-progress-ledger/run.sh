#!/usr/bin/env bash
set -euo pipefail

steps=(
  "Validate prerequisites"
  "Prepare workspace"
  "Run the main job"
  "Publish the result"
)

say_step() {
  local index="$1"
  local total="$2"
  local label="$3"
  printf '[%s/%s] %s\n' "$index" "$total" "$label"
}

say_warn() {
  printf 'warning: %s\n' "$1" >&2
}

total="${#steps[@]}"

say_step 1 "$total" "${steps[0]}"
say_step 2 "$total" "${steps[1]}"
say_warn "demo warning: using local defaults"
say_step 3 "$total" "${steps[2]}"
say_step 4 "$total" "${steps[3]}"

printf '\nDone.\n'
printf 'Artifact: ./dist/__APP_SLUG__.tar.gz\n'
printf 'Next command: bash ./run.sh --verify\n'
