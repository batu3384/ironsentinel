#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
__APP_TITLE__ onboarding
Use j/k or arrows, Enter to continue, q to quit.

> Pick the active workspace
  Validate local dependencies
  Create the first project profile

Primary action stays visible; plain fallback is available outside interactive terminals.
EOF
