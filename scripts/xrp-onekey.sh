#!/usr/bin/env bash
# One-click installer for XRPS/XRPC on Linux
# - Installs or uninstalls binaries from the latest GitHub release
# - Optionally creates/removes simple systemd services

set -euo pipefail

REPO_OWNER="kilvil"
REPO_NAME="xrp"
INSTALL_DIR="/usr/local/bin"
GH_API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"
GH_DOWNLOAD_BASE="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need_linux() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This installer supports Linux only." >&2
    exit 1
  fi
}

detect_arch() {
  local m
  m=$(uname -m)
  case "$m" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *)
      echo "Unsupported architecture: $m" >&2
      exit 1
      ;;
  esac
}

sudo_prefix() {
  if [[ -w "$INSTALL_DIR" ]]; then
    echo ""
  else
    if command -v sudo >/dev/null 2>&1; then
      echo "sudo"
    else
      echo "Cannot write to $INSTALL_DIR and sudo not available" >&2
      exit 1
    fi
  fi
}

latest_tag() {
  local token_hdr=()
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    token_hdr=("-H" "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  # Extract tag_name with minimal deps
  curl -fsSL -H "Accept: application/vnd.github+json" "${token_hdr[@]}" \
    "${GH_API}/releases/latest" |
    sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1
}

download_and_install() {
  local name="$1"
  local arch tag asset url tmpdir tmpfile
  arch=$(detect_arch)
  tag=$(latest_tag)
  if [[ -z "$tag" ]]; then
    echo "Failed to resolve latest release tag from GitHub API" >&2
    exit 1
  fi
  asset="${name}_${tag}_linux_${arch}.tar.gz"
  url="${GH_DOWNLOAD_BASE}/${tag}/${asset}"

  echo "Downloading ${asset} (tag ${tag})..."
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  tmpfile="$tmpdir/$asset"

  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --retry-delay 1 -o "$tmpfile" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$tmpfile" "$url"
  else
    echo "Need curl or wget to download artifacts" >&2
    exit 1
  fi

  echo "Extracting ${asset}..."
  tar -C "$tmpdir" -xzf "$tmpfile"
  if [[ ! -f "$tmpdir/${name}" ]]; then
    echo "Archive did not contain ${name}" >&2
    exit 1
  fi

  local sp
  sp=$(sudo_prefix)
  echo "Installing ${name} to ${INSTALL_DIR}/${name} ..."
  $sp install -m 0755 "$tmpdir/${name}" "${INSTALL_DIR}/${name}"
  echo "Installed: ${INSTALL_DIR}/${name}"

  maybe_setup_systemd "$name"
}

maybe_setup_systemd() {
  local name="$1"
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi
  read -r -p "Create and start systemd service for ${name}? [y/N] " yn || yn="n"
  case "$yn" in
    [Yy]*) create_systemd_unit "$name" ;;
    *) echo "Skipped systemd setup for ${name}." ;;
  esac
}

create_systemd_unit() {
  local name="$1"
  local svc_port
  case "$name" in
    xrps) svc_port=8080 ;;
    xrpc) svc_port=8081 ;;
    *) svc_port=0 ;;
  esac
  local unit_dir="/etc/systemd/system"
  local unit_file="$unit_dir/${name}.service"
  local sp
  sp=$(sudo_prefix)

  echo "Creating systemd unit ${unit_file}..."
  $sp mkdir -p "$unit_dir"
  $sp tee "$unit_file" >/dev/null <<UNIT
[Unit]
Description=${name^^} Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${INSTALL_DIR}/${name} ${svc_port:+-addr :$svc_port}
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

  echo "Enabling and starting ${name}..."
  $sp systemctl daemon-reload
  $sp systemctl enable --now "$name" || true
  $sp systemctl status --no-pager -l "$name" || true
}

uninstall_binary() {
  local name="$1"
  local sp
  sp=$(sudo_prefix)

  if command -v systemctl >/dev/null 2>&1; then
    echo "Stopping and disabling ${name} (if present)..."
    $sp systemctl stop "$name" 2>/dev/null || true
    $sp systemctl disable "$name" 2>/dev/null || true
    $sp rm -f "/etc/systemd/system/${name}.service" 2>/dev/null || true
    $sp systemctl daemon-reload || true
  fi

  echo "Removing ${INSTALL_DIR}/${name} (if present)..."
  $sp rm -f "${INSTALL_DIR}/${name}" 2>/dev/null || true
  echo "${name} uninstalled."
}

menu() {
  cat <<'EOF'
================ XRP One-key ================
1) 安装 XRPS (Linux)
2) 卸载 XRPS
3) 安装 XRPC (Linux)
4) 卸载 XRPC
5) 退出
============================================
EOF
}

main() {
  need_linux
  need_cmd tar
  # curl or wget checked later

  while true; do
    menu
    read -r -p "请选择 [1-5]: " choice || exit 0
    case "$choice" in
      1) download_and_install xrps ;;
      2) uninstall_binary xrps ;;
      3) download_and_install xrpc ;;
      4) uninstall_binary xrpc ;;
      5) echo "Bye."; exit 0 ;;
      *) echo "无效选择，请重试。" ;;
    esac
  done
}

main "$@"

