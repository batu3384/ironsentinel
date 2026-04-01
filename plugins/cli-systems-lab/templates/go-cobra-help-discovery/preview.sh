#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
__APP_SLUG__ keeps the top operator tasks visible and plain-output safe.

Top tasks:
  __APP_SLUG__ doctor        Validate local prerequisites
  __APP_SLUG__ init          Create the first project profile
  __APP_SLUG__ scan          Start the main workflow

Examples:
__APP_SLUG__ doctor
__APP_SLUG__ init --project demo
__APP_SLUG__ scan --target ./repo
EOF
