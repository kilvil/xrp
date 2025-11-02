#!/usr/bin/env bash
set -euo pipefail

BIN_SRC="${1:-./xrpc}"
BIN_DST="/usr/local/bin/xrpc"
UNIT_DIR="/etc/systemd/system"
UNIT_FILE="$UNIT_DIR/xrpc.service"

if [[ ! -x "$BIN_SRC" ]]; then
  echo "Binary not found or not executable: $BIN_SRC" >&2
  exit 1
fi

install -m 0755 "$BIN_SRC" "$BIN_DST"
mkdir -p "$UNIT_DIR"
cat > "$UNIT_FILE" <<'UNIT'
[Unit]
Description=XRPC Client (Xray Reverse Bridge)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/xrpc -addr :8081
Environment=XRPC_STATE_DIR=/var/lib/xrpc
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now xrpc
systemctl status --no-pager -l xrpc || true

echo "XRPC installed. Listening on :8081"
