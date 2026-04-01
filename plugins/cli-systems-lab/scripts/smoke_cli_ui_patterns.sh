#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pattern_script="$script_dir/generate_cli_ui_pattern_plan.sh"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if ! grep -Fq "$needle" <<<"$haystack"; then
    echo "Expected to find '$needle'" >&2
    echo "$haystack" >&2
    exit 1
  fi
}

make_fixture() {
  local root="$1"
  local kind="$2"
  mkdir -p "$root"

  case "$kind" in
    bubbletea)
      cat >"$root/go.mod" <<'EOF'
module example.com/demo

go 1.24

require (
  github.com/charmbracelet/bubbletea v1.3.4
  github.com/spf13/cobra v1.8.1
)
EOF
      cat >"$root/main.go" <<'EOF'
package main
import (
  tea "github.com/charmbracelet/bubbletea"
  "github.com/spf13/cobra"
)
func main(){ _, _ = tea.NewProgram(nil), cobra.Command{} }
EOF
      ;;
    cobra)
      cat >"$root/go.mod" <<'EOF'
module example.com/demo

go 1.24

require github.com/spf13/cobra v1.8.1
EOF
      cat >"$root/main.go" <<'EOF'
package main
import "github.com/spf13/cobra"
func main(){ _ = cobra.Command{} }
EOF
      ;;
    typer)
      cat >"$root/pyproject.toml" <<'EOF'
[project]
name = "demo"
version = "0.1.0"
EOF
      cat >"$root/app.py" <<'EOF'
import typer
app = typer.Typer()
EOF
      ;;
    textual)
      cat >"$root/pyproject.toml" <<'EOF'
[project]
name = "demo"
version = "0.1.0"
EOF
      cat >"$root/app.py" <<'EOF'
from textual.app import App
class Demo(App):
    pass
EOF
      ;;
    oclif)
      cat >"$root/package.json" <<'EOF'
{
  "name": "demo",
  "dependencies": {
    "@oclif/core": "^4.0.0"
  }
}
EOF
      cat >"$root/command.js" <<'EOF'
import {Command} from '@oclif/core'
export default class Demo extends Command {}
EOF
      ;;
    ratatui)
      cat >"$root/Cargo.toml" <<'EOF'
[package]
name = "demo"
version = "0.1.0"
edition = "2021"

[dependencies]
clap = { version = "4.5.23", features = ["derive"] }
ratatui = "0.29.0"
EOF
      cat >"$root/src_main.rs" <<'EOF'
use clap::Parser;
fn main() {}
EOF
      ;;
    shell)
      cat >"$root/run.sh" <<'EOF'
#!/usr/bin/env bash
echo demo
EOF
      chmod +x "$root/run.sh"
      ;;
    *)
      echo "Unknown fixture kind: $kind" >&2
      exit 1
      ;;
  esac
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

for kind in bubbletea cobra typer textual oclif ratatui shell; do
  fixture="$tmpdir/$kind"
  make_fixture "$fixture" "$kind"
  output="$(bash "$pattern_script" "$fixture")"
  case "$kind" in
    bubbletea)
      assert_contains "$output" 'Recommended template: `go-cobra-bubbletea-onboarding`'
      ;;
    cobra)
      assert_contains "$output" 'Recommended template: `go-cobra-help-discovery`'
      ;;
    typer)
      assert_contains "$output" 'Recommended template: `python-typer-repair-flow`'
      ;;
    textual)
      assert_contains "$output" 'Recommended template: `python-textual-console`'
      ;;
    oclif)
      assert_contains "$output" 'Recommended template: `node-oclif-ink-dashboard`'
      ;;
    ratatui)
      assert_contains "$output" 'Recommended template: `rust-clap-ratatui-dashboard`'
      ;;
    shell)
      assert_contains "$output" 'Recommended template: `shell-progress-ledger`'
      ;;
  esac
done

echo "CLI UI pattern smoke checks passed."
