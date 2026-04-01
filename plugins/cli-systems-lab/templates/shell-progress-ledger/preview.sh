#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
[1/4] Validate prerequisites
[2/4] Prepare workspace
warning: demo warning: using local defaults
[3/4] Run the main job
[4/4] Publish the result

Done.
Artifact: ./dist/__APP_SLUG__.tar.gz
Next command: bash ./run.sh --verify
EOF
