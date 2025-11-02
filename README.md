# XRP Monorepo (XRPS + XRPC)

This repo contains two services to manage Xray reverse proxying:

- `xrps` (server/portal): create and manage reverse tunnels; generate Base64 connection params for clients. XRPS only defines how to connect to the server (portal addr, REALITY handshake, entry ports). It does not decide the forwarding destination.
- `xrpc` (client/bridge): paste Base64 params to connect; shows status, logs and reconnection events. XRPC decides each tunnel’s forwarding target `ip:port` (default `127.0.0.1:80`, or `127.0.0.1:mapPort` when a hint is provided) and can change it at runtime.

Note: xray-core is now embedded in-process by default. Services build an Xray JSON config (REALITY + Reverse v4) and start a core instance internally, writing `./logs/*.log` for access/error and exposing restart endpoints. You can still point to an external config via `XRAY_CFG_PORTAL`/`XRAY_CFG_BRIDGE` for debugging.

## Quick start

- Run XRPS (server):
  - `go run ./xrps -addr :8080`
  - Health: `GET /healthz`
  - REALITY helpers (keys use base64url without padding):
    - `GET /api/reality/x25519` → `{ privateKey, publicKey }` (base64)
  - Create tunnel: `POST /api/tunnels` (see payload below)
  - Generate params: `POST /api/tunnels/{id}/connection-params`
  - System events (SSE): `GET /logs/stream`
  - Xray file logs:
    - Tail: `GET /api/logs?type=access|error&tail=200` (tail<=0 returns full file)
    - Streams: `GET /logs/access/stream`, `GET /logs/error/stream` (stream starts from file head, then follows)
    - Configure log dir via env `XRPS_LOG_DIR` (default `./logs`)

- Run XRPC (client):
  - `go run ./xrpc -addr :8081`
  - Health: `GET /healthz`
  - REALITY helpers (mirror, base64url): `GET /api/reality/x25519`, `GET /api/reality/mldsa65`
  - Apply profile: `POST /api/profile/apply` with `{ "base64": "..." }` or raw Base64 body
  - List tunnels: `GET /api/tunnels` (with target field)
  - Update per-tunnel: `PATCH /api/tunnels/{id}` with `{ map_port?, active?, target? }`
  - Status: `GET /status`
  - System events (SSE): `GET /logs/stream`
  - Xray file logs:
    - Tail: `GET /api/logs?type=access|error&tail=200` (tail<=0 returns full file)
    - Streams: `GET /logs/access/stream`, `GET /logs/error/stream` (stream starts from file head, then follows)
    - Configure log dir via env `XRPC_LOG_DIR` (default `./logs`)

Core control (placeholder until xray-core embed is wired):
- Restart: `POST /api/core/restart` (both XRPS and XRPC)

Xray integration
- Embedded core: requires Go to fetch `github.com/xtls/xray-core`. Set `XRAY_LOCATION_ASSET` (or per-service `XRPS_XRAY_ASSET`/`XRPC_XRAY_ASSET`) if you need custom geo files. REALITY keys must be base64url (no padding).

Encryption policy
- XRPS API 不接受 `encryption: "pq"`。请使用 `"none"`（Vision）或完整 PQ 串（以 `mlkem768x25519plus.` 开头）。
- Optional config overrides:
  - XRPS reads `XRAY_CFG_PORTAL` (path to JSON). If set, XRPS uses this file instead of generated config and writes a copy to `xray.portal.json` in run dir.
  - XRPC reads `XRAY_CFG_BRIDGE` (path to JSON). If set, XRPC uses this file and writes a copy to `xray.bridge.json` in run dir.
  

Run directories and ports
- XRPS writes its effective config to `~/xrp/xray.portal.json`. On startup, if there are no tunnels loaded and this file exists, XRPS will reuse it instead of generating a minimal config. You can still override with `XRAY_CFG_PORTAL`.
- XRPC writes its effective config to `~/xrp/xray.bridge.json`. On startup, if no profile is applied and this file exists, XRPC will reuse it instead of generating a minimal config. You can still override with `XRAY_CFG_BRIDGE`.

Tips
- In dev, you can simulate log streaming by appending lines to `./logs/access.log` or `./logs/error.log`; the SSE endpoints will push new lines.

### Create tunnel (XRPS)

POST `/api/tunnels`

```
{
  "name": "demo",
  "portal_addr": "portal.example.com",
  "handshake_port": 9443,
  "server_name": "www.fandom.com",
  "encryption": "none",
  "entry_ports": [31234, 31235]
}
```

Then `POST /api/tunnels/{id}/connection-params` returns:

```
{
  "json": "{...}",
  "base64": "<base64url>"
}
```

Paste that Base64 into XRPC via `POST /api/profile/apply`.

## Build

- Root module: `go 1.21`. External runtime dep: xray binary (provided via `XRAY_BIN`).
- Build binaries:
  - `go build -o bin/xrps ./xrps`
  - `go build -o bin/xrpc ./xrpc`

## Install (systemd, optional)

See scripts:
- `scripts/install_xrps.sh`
- `scripts/install_xrpc.sh`

These copy binaries to `/usr/local/bin` and create simple systemd units.

## 一键脚本（Linux）

- 在线运行（从 GitHub 拉取并用 bash 执行）：
  - `bash <(curl -fsSL https://raw.githubusercontent.com/kilvil/xrp/master/scripts/xrp-onekey.sh)`
  - 或 `curl -fsSL https://raw.githubusercontent.com/kilvil/xrp/master/scripts/xrp-onekey.sh | bash`

- 功能菜单（数字选择）：
  - 1 安装 XRPS
  - 2 卸载 XRPS
  - 3 安装 XRPC
  - 4 卸载 XRPC

- 说明：
  - 仅支持 Linux；需要 `curl`/`wget` 与 `tar`。
  - 默认安装目录为 `/usr/local/bin`，需要写入权限（自动使用 `sudo`）。
  - 脚本会自动解析 GitHub 最新 Release，下载匹配架构的二进制（amd64/arm64）。
  - 安装后可选择是否创建并启动 systemd 服务（可选）。
  - 卸载会尝试停止/禁用并移除同名 systemd 服务，然后删除二进制。

## Next steps

- Integrate xray-core: construct `core.Config` inside the process; add reverse v4, REALITY and tunnel routing per PRD.
- Replace in-memory store with SQLite; implement auth and RBAC.
- Attach real logs and stats from xray instead of simulated SSE events.
### Web UI (React + Vite)

- Dev servers are under `web/xrps` and `web/xrpc`. See `web/README.md`.
- Optional: after building (`pnpm build`) you can serve the static UI from the Go services:
  - XRPS: set env `XRPS_UI_DIR=web/xrps/dist` then run `go run ./xrps`; UI at `http://localhost:8080/ui/`.
  - XRPC: set env `XRPC_UI_DIR=web/xrpc/dist` then run `go run ./xrpc`; UI at `http://localhost:8081/ui/`.
