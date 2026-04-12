#!/usr/bin/env bash
set -euo pipefail

MODE="safe"
APPLY="false"

require_flag_value() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    echo "Missing value for $flag" >&2
    exit 1
  fi
}

usage() {
  cat <<'EOF'
Usage: bash scripts/install_scanners.sh [--mode safe|deep|active|full] [--apply]

Without --apply, the script prints the pinned install plan.
With --apply, it installs POSIX-friendly wrappers and binaries into the IronSentinel managed tools directory.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      require_flag_value "$1" "${2:-}"
      MODE="$2"
      shift 2
      ;;
    --apply)
      APPLY="true"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="${IRONSENTINEL_TOOLS_DIR:-$ROOT_DIR/runtime/tools/bin}"
TOOLS_ROOT="$(dirname "$TOOLS_DIR")"
TEMP_ROOT="${TMPDIR:-/tmp}/ironsentinel-installer"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

ensure_dir() {
  mkdir -p "$1"
}

new_temp_dir() {
  ensure_dir "$TEMP_ROOT"
  mktemp -d "$TEMP_ROOT/XXXXXX"
}

require_cmd() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "Required command not found: $name" >&2
    exit 1
  fi
  command -v "$name"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

linux_arch() {
  case "$ARCH" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) echo "$ARCH" ;;
  esac
}

darwin_arch() {
  case "$ARCH" in
    x86_64|amd64) echo "amd64" ;;
    arm64) echo "arm64" ;;
    *) echo "$ARCH" ;;
  esac
}

resolve_python() {
  if have_cmd python3; then
    command -v python3
    return
  fi
  if have_cmd python; then
    command -v python
    return
  fi
  echo "Python 3 not found. Install Python first." >&2
  exit 1
}

resolve_npm() {
  if have_cmd npm; then
    command -v npm
    return
  fi
  echo "npm not found. Install Node.js first." >&2
  exit 1
}

resolve_python_user_base() {
  local python="$1"
  "$python" -c 'import site; print(site.USER_BASE)' | tr -d '\r'
}

find_first_existing() {
  local candidate
  for candidate in "$@"; do
    if [[ -e "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

write_wrapper() {
  local name="$1"
  shift
  local wrapper_path="$TOOLS_DIR/$name"
  ensure_dir "$TOOLS_DIR"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    printf 'exec'
    local arg
    for arg in "$@"; do
      printf ' %q' "$arg"
    done
    echo ' "$@"'
  } >"$wrapper_path"
  chmod +x "$wrapper_path"
}

write_wrapper_with_path() {
  local name="$1"
  local prepend_path="$2"
  shift 2
  local wrapper_path="$TOOLS_DIR/$name"
  ensure_dir "$TOOLS_DIR"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    printf 'export PATH=%q:$PATH\n' "$prepend_path"
    printf 'exec'
    local arg
    for arg in "$@"; do
      printf ' %q' "$arg"
    done
    echo ' "$@"'
  } >"$wrapper_path"
  chmod +x "$wrapper_path"
}

copy_executable() {
  local source="$1"
  local destination="$2"
  ensure_dir "$(dirname "$destination")"
  cp "$source" "$destination"
  chmod +x "$destination"
}

download_to() {
  local url="$1"
  local destination="$2"
  local curl_bin
  curl_bin="$(require_cmd curl)"
  "$curl_bin" -fsSL "$url" -o "$destination"
}

install_python_tool() {
  local package="$1"
  local version="$2"
  local command_name="$3"
  local module="${4:-$package}"
  local python user_base scripts_dir script_path

  python="$(resolve_python)"
  "$python" -m pip install --user --disable-pip-version-check --upgrade "setuptools<81"
  "$python" -m pip install --user --disable-pip-version-check --upgrade "${package}==${version}"
  user_base="$(resolve_python_user_base "$python")"
  scripts_dir="$user_base/bin"
  script_path="$(find_first_existing "$scripts_dir/$command_name" "$scripts_dir/${command_name}-script.py" || true)"

  if [[ -n "$script_path" ]]; then
    if [[ "$script_path" == *.py ]]; then
      write_wrapper_with_path "$command_name" "$scripts_dir" "$python" "$script_path"
      return
    fi
    write_wrapper_with_path "$command_name" "$scripts_dir" "$script_path"
    return
  fi

  write_wrapper_with_path "$command_name" "$scripts_dir" "$python" "-m" "$module"
}

install_go_tool() {
  local module="$1"
  local version="$2"
  local output_name="${3:-$(basename "$module")}"
  local go_bin

  go_bin="$(require_cmd go)"
  ensure_dir "$TOOLS_DIR"
  GOBIN="$TOOLS_DIR" "$go_bin" install "${module}@${version}"
  if [[ "$output_name" != "$(basename "$module")" && -f "$TOOLS_DIR/$(basename "$module")" ]]; then
    mv "$TOOLS_DIR/$(basename "$module")" "$TOOLS_DIR/$output_name"
  fi
}

install_tar_binary() {
  local url="$1"
  local binary_name="$2"
  local output_name="$3"
  local work_dir archive_path binary_path

  work_dir="$(new_temp_dir)"
  (
    trap 'rm -rf "$work_dir"' EXIT
    archive_path="$work_dir/archive.tar.gz"
    download_to "$url" "$archive_path"
    tar -xzf "$archive_path" -C "$work_dir"
    binary_path="$(find "$work_dir" -type f -name "$binary_name" | head -n 1)"
    if [[ -z "$binary_path" ]]; then
      echo "Binary $binary_name not found in archive: $url" >&2
      exit 1
    fi
    copy_executable "$binary_path" "$TOOLS_DIR/$output_name"
  )
}

install_zip_binary() {
  local url="$1"
  local binary_name="$2"
  local output_name="$3"
  local work_dir archive_path binary_path

  require_cmd unzip >/dev/null
  work_dir="$(new_temp_dir)"
  (
    trap 'rm -rf "$work_dir"' EXIT
    archive_path="$work_dir/archive.zip"
    download_to "$url" "$archive_path"
    unzip -q "$archive_path" -d "$work_dir"
    binary_path="$(find "$work_dir" -type f -name "$binary_name" | head -n 1)"
    if [[ -z "$binary_path" ]]; then
      echo "Binary $binary_name not found in archive: $url" >&2
      exit 1
    fi
    copy_executable "$binary_path" "$TOOLS_DIR/$output_name"
  )
}

install_direct_binary() {
  local url="$1"
  local output_name="$2"
  ensure_dir "$TOOLS_DIR"
  download_to "$url" "$TOOLS_DIR/$output_name"
  chmod +x "$TOOLS_DIR/$output_name"
}

resolve_brew_binary() {
  local formula="$1"
  local binary_name="$2"
  local prefix

  if have_cmd "$binary_name"; then
    command -v "$binary_name"
    return 0
  fi

  prefix="$(brew --prefix "$formula" 2>/dev/null || true)"
  if [[ -n "$prefix" ]]; then
    find_first_existing "$prefix/bin/$binary_name" "$prefix/sbin/$binary_name" || true
  fi
}

install_brew_wrapper() {
  local formula="$1"
  local binary_name="$2"
  local path

  require_cmd brew >/dev/null
  brew install "$formula"
  path="$(resolve_brew_binary "$formula" "$binary_name")"
  if [[ -z "$path" ]]; then
    echo "Installed $formula but could not resolve $binary_name" >&2
    exit 1
  fi
  write_wrapper "$binary_name" "$path"
}

install_brew_cask_wrapper() {
  local cask="$1"
  local binary_name="$2"
  local path

  require_cmd brew >/dev/null
  brew install --cask "$cask"
  path="$(command -v "$binary_name" || true)"
  if [[ -z "$path" ]]; then
    echo "Installed cask $cask but could not resolve $binary_name" >&2
    exit 1
  fi
  write_wrapper "$binary_name" "$path"
}

gitleaks_release_suffix() {
  case "$OS/$ARCH" in
    darwin/arm64) echo "darwin_arm64" ;;
    darwin/x86_64|darwin/amd64) echo "darwin_x64" ;;
    linux/x86_64|linux/amd64) echo "linux_x64" ;;
    linux/arm64|linux/aarch64) echo "linux_arm64" ;;
    linux/armv6l|linux/armv6) echo "linux_armv6" ;;
    linux/armv7l|linux/armv7) echo "linux_armv7" ;;
    *) return 1 ;;
  esac
}

syft_release_suffix() {
  case "$OS/$ARCH" in
    darwin/arm64) echo "darwin_arm64" ;;
    darwin/x86_64|darwin/amd64) echo "darwin_amd64" ;;
    linux/x86_64|linux/amd64) echo "linux_amd64" ;;
    linux/arm64|linux/aarch64) echo "linux_arm64" ;;
    *) return 1 ;;
  esac
}

staticcheck_release_suffix() {
  case "$OS/$ARCH" in
    darwin/arm64) echo "darwin_arm64" ;;
    darwin/x86_64|darwin/amd64) echo "darwin_amd64" ;;
    linux/x86_64|linux/amd64) echo "linux_amd64" ;;
    linux/386|linux/i386) echo "linux_386" ;;
    linux/arm64|linux/aarch64) echo "linux_arm64" ;;
    linux/armv5l) echo "linux_armv5l" ;;
    linux/armv6l) echo "linux_armv6l" ;;
    linux/armv7l) echo "linux_armv7l" ;;
    *) return 1 ;;
  esac
}

osv_scanner_release_suffix() {
  case "$OS/$ARCH" in
    darwin/arm64) echo "darwin_arm64" ;;
    darwin/x86_64|darwin/amd64) echo "darwin_amd64" ;;
    linux/x86_64|linux/amd64) echo "linux_amd64" ;;
    linux/arm64|linux/aarch64) echo "linux_arm64" ;;
    *) return 1 ;;
  esac
}

install_gitleaks_release() {
  local suffix
  suffix="$(gitleaks_release_suffix)"
  install_tar_binary "https://github.com/gitleaks/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_${suffix}.tar.gz" "gitleaks" "gitleaks"
}

install_syft_release() {
  local suffix
  suffix="$(syft_release_suffix)"
  install_tar_binary "https://github.com/anchore/syft/releases/download/v1.22.0/syft_1.22.0_${suffix}.tar.gz" "syft" "syft"
}

grype_release_suffix() {
  case "$OS/$ARCH" in
    darwin/arm64) echo "darwin_arm64" ;;
    darwin/x86_64|darwin/amd64) echo "darwin_amd64" ;;
    linux/x86_64|linux/amd64) echo "linux_amd64" ;;
    linux/arm64|linux/aarch64) echo "linux_arm64" ;;
    *) return 1 ;;
  esac
}

install_grype_release() {
  local suffix
  suffix="$(grype_release_suffix)"
  install_tar_binary "https://github.com/anchore/grype/releases/download/v0.94.0/grype_0.94.0_${suffix}.tar.gz" "grype" "grype"
}

install_staticcheck_release() {
  local suffix
  suffix="$(staticcheck_release_suffix)"
  install_tar_binary "https://github.com/dominikh/go-tools/releases/download/2025.1.1/staticcheck_${suffix}.tar.gz" "staticcheck" "staticcheck"
}

install_osv_scanner_release() {
  local suffix
  suffix="$(osv_scanner_release_suffix)"
  install_direct_binary "https://github.com/google/osv-scanner/releases/download/v2.2.2/osv-scanner_${suffix}" "osv-scanner"
}

install_trivy_managed() {
  if [[ "$OS" == "darwin" ]]; then
    install_brew_wrapper "trivy" "trivy"
    return
  fi
  install_go_tool "github.com/aquasecurity/trivy/cmd/trivy" "v0.69.1" "trivy"
}

install_codeql_bundle() {
  if [[ "$OS" != "darwin" && "$OS" != "linux" ]]; then
    echo "Unsupported OS for local CodeQL install. Use container setup instead." >&2
    exit 1
  fi

  local work_dir archive_path bundle_dir target_root
  work_dir="$(new_temp_dir)"
  (
    trap 'rm -rf "$work_dir"' EXIT
    if [[ "$OS" == "darwin" ]]; then
      archive_path="$work_dir/codeql-bundle-osx64.tar.gz"
      download_to "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.23.3/codeql-bundle-osx64.tar.gz" "$archive_path"
    else
      archive_path="$work_dir/codeql-bundle-linux64.tar.gz"
      download_to "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.23.3/codeql-bundle-linux64.tar.gz" "$archive_path"
    fi
    tar -xzf "$archive_path" -C "$work_dir"
    bundle_dir="$(find "$work_dir" -maxdepth 1 -type d -name 'codeql*' | head -n 1)"
    if [[ -z "$bundle_dir" ]]; then
      echo "CodeQL bundle directory not found after extraction." >&2
      exit 1
    fi
    target_root="$TOOLS_ROOT/codeql"
    rm -rf "$target_root"
    mkdir -p "$target_root"
    cp -R "$bundle_dir"/. "$target_root"/
    write_wrapper "codeql" "$target_root/codeql"
  )
}

install_zap_bundle_linux() {
  local work_dir archive_path bundle_dir target_root
  work_dir="$(new_temp_dir)"
  (
    trap 'rm -rf "$work_dir"' EXIT
    archive_path="$work_dir/zap-linux.tar.gz"
    download_to "https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_Linux.tar.gz" "$archive_path"
    tar -xzf "$archive_path" -C "$work_dir"
    bundle_dir="$(find "$work_dir" -maxdepth 1 -type d -name 'ZAP_*' | head -n 1)"
    if [[ -z "$bundle_dir" ]]; then
      echo "OWASP ZAP bundle directory not found after extraction." >&2
      exit 1
    fi
    target_root="$TOOLS_ROOT/zap"
    rm -rf "$target_root"
    mkdir -p "$target_root"
    cp -R "$bundle_dir"/. "$target_root"/
    write_wrapper "zaproxy" "$target_root/zap.sh"
  )
}

install_zap_bundle_darwin() {
  local work_dir dmg_path mount_dir app_path target_root target_app executable_path attached

  require_cmd hdiutil >/dev/null
  work_dir="$(new_temp_dir)"
  dmg_path="$work_dir/zap-macos.dmg"
  mount_dir="$work_dir/mount"
  attached=0
  trap 'if [[ "${attached:-0}" -eq 1 ]]; then hdiutil detach "$mount_dir" -quiet || true; fi; rm -rf "$work_dir"' RETURN
  mkdir -p "$mount_dir"
  download_to "https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_aarch64.dmg" "$dmg_path"
  hdiutil attach "$dmg_path" -mountpoint "$mount_dir" -nobrowse -quiet
  attached=1
  app_path="$(find "$mount_dir" -maxdepth 1 -type d -name '*.app' | head -n 1)"
  if [[ -z "$app_path" ]]; then
    echo "OWASP ZAP app bundle not found in dmg." >&2
    exit 1
  fi

  target_root="$TOOLS_ROOT/zap"
  target_app="$target_root/$(basename "$app_path")"
  rm -rf "$target_root"
  mkdir -p "$target_root"
  ditto "$app_path" "$target_app"
  hdiutil detach "$mount_dir" -quiet || true
  attached=0
  executable_path="$(find "$target_app/Contents/MacOS" -type f | head -n 1)"
  if [[ -z "$executable_path" ]]; then
    executable_path="$(find "$target_app" -type f -name 'zap.sh' | head -n 1)"
  fi
  if [[ -z "$executable_path" ]]; then
    echo "OWASP ZAP executable not found in app bundle." >&2
    exit 1
  fi
  write_wrapper "zaproxy" "$executable_path"
}

install_knip() {
  local npm npm_root
  npm="$(resolve_npm)"
  npm_root="$TOOLS_ROOT/npm"
  ensure_dir "$npm_root"
  "$npm" install --prefix "$npm_root" "knip@5.70.1"
  write_wrapper "knip" "$npm" "exec" "--prefix" "$npm_root" "knip" "--"
}

nuclei_release_suffix() {
  case "$OS/$ARCH" in
    darwin/arm64) echo "macOS_arm64" ;;
    darwin/x86_64|darwin/amd64) echo "macOS_amd64" ;;
    linux/x86_64|linux/amd64) echo "linux_amd64" ;;
    linux/arm64|linux/aarch64) echo "linux_arm64" ;;
    *) return 1 ;;
  esac
}

install_nuclei_release() {
  local suffix
  suffix="$(nuclei_release_suffix)"
  install_zip_binary "https://github.com/projectdiscovery/nuclei/releases/download/v3.4.10/nuclei_3.4.10_${suffix}.zip" "nuclei" "nuclei"
}

install_clamav_wrapper() {
  local path=""
  if [[ "$OS" == "darwin" ]]; then
    install_brew_wrapper "clamav" "clamscan"
    return
  fi
  if [[ "$OS" == "linux" ]]; then
    require_cmd sudo >/dev/null
    sudo apt-get update
    sudo apt-get install -y clamav
    path="$(command -v clamscan || true)"
    if [[ -z "$path" ]]; then
      echo "ClamAV installed but clamscan was not found on PATH" >&2
      exit 1
    fi
    write_wrapper "clamscan" "$path"
    return
  fi
  echo "Unsupported OS for ClamAV install. Use container setup instead." >&2
  exit 1
}

run_or_print() {
  local description="$1"
  shift
  if [[ "$APPLY" == "true" ]]; then
    echo "  -> $description"
    "$@"
  else
    echo "  $description"
  fi
}

apply_safe_steps() {
  run_or_print "Install semgrep 1.119.0 into the managed tools directory" install_python_tool "semgrep" "1.119.0" "semgrep" "semgrep"
  run_or_print "Install checkov 3.2.489 into the managed tools directory" install_python_tool "checkov" "3.2.489" "checkov" "checkov.main"
  run_or_print "Install staticcheck 2025.1.1 into the managed tools directory" install_staticcheck_release
  run_or_print "Install govulncheck 1.1.4 into the managed tools directory" install_go_tool "golang.org/x/vuln/cmd/govulncheck" "v1.1.4"
  run_or_print "Install gitleaks 8.24.2 into the managed tools directory" install_gitleaks_release
  run_or_print "Install trivy into the managed tools directory" install_trivy_managed
  run_or_print "Install syft 1.22.0 into the managed tools directory" install_syft_release
  run_or_print "Install grype 0.94.0 into the managed tools directory" install_grype_release
  run_or_print "Install osv-scanner 2.2.2 into the managed tools directory" install_osv_scanner_release
  run_or_print "Install ClamAV 1.4.3 and write a managed wrapper" install_clamav_wrapper
}

apply_deep_steps() {
  run_or_print "Install CodeQL 2.23.3 into the managed tools directory" install_codeql_bundle
  run_or_print "Install knip 5.70.1 into the managed tools directory" install_knip
  run_or_print "Install vulture 2.14 into the managed tools directory" install_python_tool "vulture" "2.14" "vulture" "vulture"
}

apply_active_steps() {
  if [[ "$OS" == "darwin" ]]; then
    run_or_print "Install nuclei 3.4.10 into the managed tools directory" install_nuclei_release
    run_or_print "Install OWASP ZAP 2.16.1 into the managed tools directory" install_zap_bundle_darwin
    return
  fi

  if [[ "$OS" == "linux" ]]; then
    local arch
    arch="$(linux_arch)"
    run_or_print "Install nuclei 3.4.10 into the managed tools directory" install_zip_binary "https://github.com/projectdiscovery/nuclei/releases/download/v3.4.10/nuclei_3.4.10_linux_${arch}.zip" "nuclei" "nuclei"
    run_or_print "Install OWASP ZAP 2.16.1 into the managed tools directory" install_zap_bundle_linux
    return
  fi

  echo "Unsupported OS for active local scanner installation. Use container setup instead." >&2
  exit 1
}

ensure_dir "$TOOLS_DIR"
ensure_dir "$TOOLS_ROOT"

echo "Pinned scanner install plan for mode: $MODE on $OS/$ARCH"
case "$MODE" in
  safe)
    apply_safe_steps
    ;;
  deep)
    apply_safe_steps
    apply_deep_steps
    ;;
  active)
    apply_active_steps
    ;;
  full)
    apply_safe_steps
    apply_deep_steps
    apply_active_steps
    ;;
  *)
    echo "Unsupported mode: $MODE" >&2
    exit 1
    ;;
esac

echo
echo "Managed tools directory: $TOOLS_DIR"
if [[ "$APPLY" == "true" ]]; then
  echo "Installation attempt finished."
else
  echo "Run again with --apply to execute the commands."
fi
