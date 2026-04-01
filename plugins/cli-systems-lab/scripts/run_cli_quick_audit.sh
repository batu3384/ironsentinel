#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: run_cli_quick_audit.sh [repo-root]

Run safe, high-value CLI checks when the local toolchain is available.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

repo_root="${1:-.}"
repo_root="$(cd "$repo_root" && pwd)"
cd "$repo_root"

failures=0

has_command() {
  command -v "$1" >/dev/null 2>&1
}

has_file() {
  [[ -e "$1" ]]
}

run_step() {
  local label="$1"
  shift

  echo
  echo "==> $label"
  if "$@"; then
    echo "PASS: $label"
  else
    echo "FAIL: $label"
    failures=$((failures + 1))
  fi
}

have_rg=false
if has_command rg; then
  have_rg=true
fi

shell_files=()
if [[ "$have_rg" == true ]]; then
  while IFS= read -r file; do
    shell_files+=("$file")
  done < <(rg --files -g '*.sh' . || true)
else
  while IFS= read -r file; do
    shell_files+=("$file")
  done < <(find . -type f -name '*.sh' -print)
fi

if has_file "go.mod" && has_command go; then
  run_step "go test ./..." go test ./...
  run_step "go vet ./..." go vet ./...
  if has_command golangci-lint; then
    run_step "golangci-lint run" golangci-lint run
  else
    echo
    echo "SKIP: golangci-lint not installed"
  fi
fi

if has_file "Cargo.toml" && has_command cargo; then
  run_step "cargo test" cargo test
  if cargo clippy --version >/dev/null 2>&1; then
    run_step "cargo clippy --all-targets --all-features -- -D warnings" \
      cargo clippy --all-targets --all-features -- -D warnings
  else
    echo
    echo "SKIP: cargo clippy unavailable"
  fi
fi

if { has_file "pyproject.toml" || has_file "requirements.txt" || has_file "requirements-dev.txt"; } && has_command pytest; then
  if [[ -d tests || -d test ]] || { [[ "$have_rg" == true ]] && rg -l 'def test_|class Test' . >/dev/null 2>&1; }; then
    run_step "pytest" pytest
  else
    echo
    echo "SKIP: pytest installed but no test directory or obvious pytest tests were found"
  fi
fi

if { has_file "pyproject.toml" || has_file "ruff.toml"; } && has_command ruff; then
  run_step "ruff check ." ruff check .
fi

if has_command mypy; then
  if has_file "mypy.ini" || { has_file "pyproject.toml" && grep -q '^\[tool\.mypy\]' pyproject.toml 2>/dev/null; }; then
    run_step "mypy ." mypy .
  else
    echo
    echo "SKIP: mypy installed but no mypy configuration was found"
  fi
fi

if ((${#shell_files[@]} > 0)); then
  if has_command shellcheck; then
    run_step "shellcheck ${#shell_files[@]} shell file(s)" shellcheck "${shell_files[@]}"
  else
    echo
    echo "SKIP: shellcheck not installed"
  fi
fi

if has_file "package.json"; then
  echo
  echo "INFO: package.json detected. No package-manager-native test was run automatically."
  if has_command node; then
    node -e 'const fs=require("fs");const pkg=JSON.parse(fs.readFileSync("package.json","utf8"));const names=Object.keys(pkg.scripts||{});console.log("Available npm scripts:", names.length?names.join(", "):"none");'
  fi
fi

echo
if ((failures > 0)); then
  echo "Audit completed with ${failures} failing step(s)."
  exit 1
fi

echo "Audit completed without failing steps."
