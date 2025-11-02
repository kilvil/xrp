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

# internal state
_SYSTEMD_SETUP=0

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

default_port_for() {
  case "$1" in
    xrps) echo 8080 ;;
    xrpc) echo 8081 ;;
    *) echo 0 ;;
  esac
}

detect_server_ip() {
  if command -v ip >/dev/null 2>&1; then
    local src
    src=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){ if($i=="src"){print $(i+1); exit} }}') || true
    if [[ -n "$src" ]]; then echo "$src"; return; fi
  fi
  if command -v hostname >/dev/null 2>&1; then
    local ips
    ips=$(hostname -I 2>/dev/null | awk '{print $1}') || true
    if [[ -n "$ips" ]]; then echo "$ips"; return; fi
  fi
  echo "127.0.0.1"
}

print_panel_urls() {
  local name="$1" port="$2" ip
  ip=$(detect_server_ip)
  echo "面板地址："
  echo "  http://$ip:$port/ui/"
  echo "  http://127.0.0.1:$port/ui/"
}

parse_pass_from_lines() {
  sed -n 's/.*初始密码:[[:space:]]*\([^[:space:]]\+\).*/\1/p' | tail -n1
}

try_grab_pass_from_journal() {
  local svc="$1"
  if ! command -v journalctl >/dev/null 2>&1; then return 1; fi
  journalctl -u "$svc" --since "-10 minutes" -o cat 2>/dev/null | parse_pass_from_lines || return 1
}

temp_start_and_grab_pass() {
  local name="$1" port="$2"
  local tmpfile
  tmpfile=$(mktemp)
  trap "rm -f '$tmpfile'" EXIT
  echo "临时启动 $name 以生成并捕获初始密码…"
  set +e
  "${INSTALL_DIR}/${name}" -addr ":${port}" >"$tmpfile" 2>&1 &
  local pid=$!
  sleep 3
  local pass
  pass=$(parse_pass_from_lines < "$tmpfile")
  kill "$pid" >/dev/null 2>&1; sleep 1; kill -9 "$pid" >/dev/null 2>&1
  set -e
  if [[ -n "$pass" ]]; then
    echo "$pass"
    rm -f "$tmpfile" || true
    trap - EXIT
    return 0
  fi
  rm -f "$tmpfile" || true
  trap - EXIT
  return 1
}

post_install_info() {
  local name="$1" method="$2" # systemd|manual
  local port
  port=$(default_port_for "$name")
  print_panel_urls "$name" "$port"

  echo "尝试获取管理员账号密码（首次启动会输出）："
  local pass=""
  if [[ "$method" == "systemd" ]]; then
    sleep 2
    pass=$(try_grab_pass_from_journal "$name" || true)
  fi
  if [[ -z "$pass" && "$method" == "manual" ]]; then
    read -r -p "是否现在临时启动 ${name} 并显示初始密码？[y/N] " yn || yn="n"
    case "$yn" in
      [Yy]*) pass=$(temp_start_and_grab_pass "$name" "$port" || true) ;;
    esac
  fi
  if [[ -n "$pass" ]]; then
    echo "- 账号：admin"
    echo "- 初始密码：$pass"
  else
    echo "未捕获到初始密码。可能不是首次启动，或日志不可用。"
    echo "如为首次启动，可在 'journalctl -u ${name} -o cat' 中查找包含‘初始密码’的日志行。"
  fi
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
  _SYSTEMD_SETUP=0
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
  trap "rm -rf '$tmpdir'" EXIT
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
  if [[ "${_SYSTEMD_SETUP}" != "1" ]]; then
    post_install_info "$name" manual
  fi
  # cleanup tmpdir and clear trap to avoid leaking to script exit
  rm -rf "$tmpdir" || true
  trap - EXIT
}

maybe_setup_systemd() {
  local name="$1"
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi
  read -r -p "Create and start systemd service for ${name}? [y/N] " yn || yn="n"
  case "$yn" in
    [Yy]*) create_systemd_unit "$name" ; _SYSTEMD_SETUP=1; post_install_info "$name" systemd ;;
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
Environment=${name^^}_STATE_DIR=/var/lib/${name}
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
