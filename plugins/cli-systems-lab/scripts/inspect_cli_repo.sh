#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: inspect_cli_repo.sh [repo-root]

Detect likely CLI/TUI stacks and print a focused audit plan.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

repo_root="${1:-.}"
repo_root="$(cd "$repo_root" && pwd)"
cd "$repo_root"

have_rg=false
if command -v rg >/dev/null 2>&1; then
  have_rg=true
fi

has_file() {
  [[ -e "$1" ]]
}

match_repo_code() {
  local pattern="$1"
  shift

  if [[ "$have_rg" == true ]]; then
    local args=(--hidden --glob '!.git/**' --glob '!node_modules/**' --glob '!.agents/**' --glob '!plugins/cli-systems-lab/**')
    local glob
    for glob in "$@"; do
      args+=(--glob "$glob")
    done
    rg -l "${args[@]}" "$pattern" . >/dev/null 2>&1
  else
    grep -R -E "$pattern" . >/dev/null 2>&1
  fi
}

have_shell_files() {
  if [[ "$have_rg" == true ]]; then
    rg --files --glob '!.git/**' --glob '!node_modules/**' --glob '!.agents/**' --glob '!plugins/cli-systems-lab/**' -g '*.sh' . >/dev/null 2>&1
  else
    find . -type f -name '*.sh' | grep . >/dev/null 2>&1
  fi
}

go_repo=false
python_repo=false
node_repo=false
rust_repo=false
shell_repo=false

cobra_repo=false
bubbletea_repo=false
typer_repo=false
textual_repo=false
oclif_repo=false
ink_repo=false
clap_repo=false
ratatui_repo=false

if has_file "go.mod"; then
  go_repo=true
fi
if has_file "pyproject.toml" || has_file "requirements.txt" || has_file "requirements-dev.txt" || has_file "setup.py"; then
  python_repo=true
fi
if has_file "package.json" || has_file "package-lock.json" || has_file "pnpm-lock.yaml" || has_file "yarn.lock"; then
  node_repo=true
fi
if has_file "Cargo.toml"; then
  rust_repo=true
fi
if have_shell_files; then
  shell_repo=true
fi

if match_repo_code 'github.com/spf13/cobra|cobra\.Command' '*.go' 'go.mod'; then
  cobra_repo=true
fi
if match_repo_code 'github.com/charmbracelet/bubbletea|tea\.Model|tea\.Cmd' '*.go' 'go.mod'; then
  bubbletea_repo=true
fi
if match_repo_code 'import typer|from typer|typer\.Typer|Typer\(' '*.py' 'pyproject.toml'; then
  typer_repo=true
fi
if match_repo_code 'import textual|from textual' '*.py' 'pyproject.toml'; then
  textual_repo=true
fi
if match_repo_code '@oclif/|oclif' 'package.json' '*.js' '*.ts' '*.mjs' '*.cjs'; then
  oclif_repo=true
fi
if match_repo_code "from 'ink'|from \"ink\"|require\\(['\"]ink['\"]\\)|import \\{.*\\} from 'ink'" 'package.json' '*.js' '*.ts' '*.mjs' '*.cjs' '*.jsx' '*.tsx'; then
  ink_repo=true
fi
if match_repo_code '\bclap\b' 'Cargo.toml' '*.rs'; then
  clap_repo=true
fi
if match_repo_code '\bratatui\b' 'Cargo.toml' '*.rs'; then
  ratatui_repo=true
fi

print_true() {
  local label="$1"
  local value="$2"
  if [[ "$value" == true ]]; then
    printf '  - %s\n' "$label"
  fi
}

echo "Repository: $repo_root"
echo
echo "Detected languages and wrappers:"
print_true "Go" "$go_repo"
print_true "Python" "$python_repo"
print_true "Node.js" "$node_repo"
print_true "Rust" "$rust_repo"
print_true "Shell scripts" "$shell_repo"

echo
echo "Detected frameworks and libraries:"
print_true "Cobra" "$cobra_repo"
print_true "Bubble Tea" "$bubbletea_repo"
print_true "Typer" "$typer_repo"
print_true "Textual" "$textual_repo"
print_true "oclif" "$oclif_repo"
print_true "Ink" "$ink_repo"
print_true "clap" "$clap_repo"
print_true "ratatui" "$ratatui_repo"

echo
echo "Priority review areas:"
if [[ "$cobra_repo" == true ]]; then
  echo "  - Cobra: inspect command tree, help UX, shell completion, ExecuteContext, and cmd.Context() propagation."
fi
if [[ "$bubbletea_repo" == true ]]; then
  echo "  - Bubble Tea: inspect Model/Update/View separation, quit paths, key handling, and non-TTY rendering."
fi
if [[ "$typer_repo" == true ]]; then
  echo "  - Typer: inspect type-hint-driven params, prompts, CliRunner tests, and exit-code assertions."
fi
if [[ "$textual_repo" == true ]]; then
  echo "  - Textual: inspect async workflows, pytest-asyncio coverage, and snapshot tests for visual regressions."
fi
if [[ "$oclif_repo" == true ]]; then
  echo "  - oclif: inspect hooks, JSON mode, help generation, stdout/stderr capture, and command tests."
fi
if [[ "$ink_repo" == true ]]; then
  echo "  - Ink: inspect render loops, keyboard handling, cleanup paths, and plain fallbacks outside TTY."
fi
if [[ "$clap_repo" == true ]]; then
  echo "  - clap: inspect parser derivations, generated help, shell completion, and command-output tests."
fi
if [[ "$ratatui_repo" == true ]]; then
  echo "  - ratatui: inspect alternate-screen cleanup, resize handling, panic recovery, and plain fallback paths."
fi
if [[ "$shell_repo" == true ]]; then
  echo "  - Shell: inspect wrappers, release scripts, install scripts, and pipe-friendly behavior."
fi

echo
echo "High-value files:"
if [[ "$have_rg" == true ]]; then
  rg --files \
    --glob '!.git/**' \
    --glob '!node_modules/**' \
    --glob '!.agents/**' \
    --glob '!plugins/cli-systems-lab/**' \
    -g 'go.mod' \
    -g 'Cargo.toml' \
    -g 'package.json' \
    -g 'pyproject.toml' \
    -g 'requirements*.txt' \
    -g 'cmd/**' \
    -g 'internal/**' \
    -g 'src/**' \
    -g 'tests/**' \
    -g 'test/**' \
    -g '.golangci.*' \
    -g 'ruff.toml' \
    -g 'mypy.ini' \
    -g '.shellcheckrc' \
    -g '*.sh' . | head -n 40
else
  find . -maxdepth 3 -type f | sed 's#^\./##' | head -n 40
fi

echo
echo "Recommended commands:"
if [[ "$go_repo" == true ]]; then
  echo "  - go test ./..."
  echo "  - go vet ./..."
  echo "  - golangci-lint run"
fi
if [[ "$python_repo" == true ]]; then
  echo "  - pytest"
  echo "  - ruff check ."
  echo "  - mypy ."
fi
if [[ "$rust_repo" == true ]]; then
  echo "  - cargo test"
  echo "  - cargo clippy --all-targets --all-features -- -D warnings"
fi
if [[ "$shell_repo" == true ]]; then
  echo "  - shellcheck <shell-files>"
fi
if [[ "$node_repo" == true ]]; then
  echo "  - package-manager-native test and lint scripts"
fi
