#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
__APP_TITLE__ operator cockpit

> Review the active workspace
  Validate local dependencies
  Start the first scan

q quit | j/k move | plain fallback outside TTY
EOF
