#!/usr/bin/env bash
set -euo pipefail

BIN_SRC="${1:-./xrps}"
BIN_DST="/usr/local/bin/xrps"
UNIT_DIR="/etc/systemd/system"
UNIT_FILE="$UNIT_DIR/xrps.service"

if [[ ! -x "$BIN_SRC" ]]; then
  echo "Binary not found or not executable: $BIN_SRC" >&2
  exit 1
fi

install -m 0755 "$BIN_SRC" "$BIN_DST"
mkdir -p "$UNIT_DIR"
cat > "$UNIT_FILE" <<'UNIT'
[Unit]
Description=XRPS Server (Xray Reverse Portal)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/xrps -addr :8080
Environment=XRPS_STATE_DIR=/var/lib/xrps
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now xrps
systemctl status --no-pager -l xrps || true

echo "XRPS installed. Listening on :8080"
