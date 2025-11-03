# XRP（统一版：Inbound + Outbound）

XRP 将原 XRPS（Portal/Server）与 XRPC（Bridge/Client）合并为一个进程 + 一个前端。

- Inbound（原 XRPS 功能）：创建握手/入口（REALITY + Entry Ports），生成给客户端使用的 Base64 参数。
- Outbound（原 XRPC 功能）：粘贴 Base64 参数后建立反连，按隧道设置本地转发表达式（target / map_port / active）。

内置 xray-core：后端会在进程内构建 Xray JSON（REALITY + Reverse v4 + stats/policy）并启动核心，默认写入 `./logs/access.log`、`./logs/error.log`。也可以通过环境变量使用外部配置。

## 快速开始

- 后端（统一版）
  - 开发运行：`make run`（等价 `go run ./src -addr :8080`）
  - 健康检查：`GET /healthz`
  - 状态：`GET /status`
  - 管理员凭据：首次启动自动生成（日志打印），或执行 `go run ./src -reset-admin`

- 前端（Vite + React）
  - `cd web && npm install && npm run dev`（http://localhost:5173，已代理到 :8080）
  - 在 UI 右上角输入 admin/密码（Basic Auth）
  - 也可构建静态资源：`npm run build`，然后设置 `XRP_UI_DIR=web/dist` 后端会在 `/ui/` 提供静态页面

## API 概览（统一版）

- Inbound（隧道入口，原 XRPS）
  - `GET/POST /api/inbound/tunnels`
  - `GET/PATCH/DELETE /api/inbound/tunnels/:id`
  - `POST /api/inbound/tunnels/:id/connection-params`
  - 统计：`GET /api/inbound/stats/snapshot`、`GET /api/inbound/stats/range?since=...&entry=...`

- Outbound（反向连接，原 XRPC）
  - `POST /api/outbound/profile/apply`（Content-Type: text/plain 或 application/json {"base64": "..."}）
  - `GET /api/outbound/tunnels`
  - `GET/PATCH/DELETE /api/outbound/tunnels/:id`
  - 统计：`GET /api/outbound/stats/snapshot`、`GET /api/outbound/stats/range?since=...&tunnel=...`

- 日志与 WS
  - SSE：`GET /logs/stream`、`/logs/access/stream`、`/logs/error/stream`
  - Tail：`GET /api/logs?type=access|error&tail=200`
  - WS 实时速率：`/ws/stats`（消息包含 role=portal|bridge）

- REALITY/VLESS 辅助
  - `GET /api/reality/x25519` → `{ publicKey, privateKey }`（base64url）
  - `GET /api/vlessenc?algo=pq|x25519&seconds=600` → 生成 decryption/encryption 串

加密策略
- Inbound 接口不接受 `encryption: "pq"` 的简写。请使用 `"none"`（Vision）或完整 PQ 串（以 `mlkem768x25519plus.` 开头）。
  
可选配置覆盖（调试）
- 统一调试配置输出：`$HOME/xrp/xray.unified.json`（或 `XRP_XRAY_CFG_PATH` 指定路径）
- 若设置 `XRP_XRAY_CFG_PATH` 指向一个 JSON 文件，后端将优先使用该文件内容启动核心，并把有效配置写回该路径便于检查。
  

运行目录与持久化
- 有效配置（调试副本）：`$HOME/xrp/xray.unified.json`（或 `XRP_XRAY_CFG_PATH`）
- 日志目录：`XRP_LOG_DIR`（默认 `./logs`），文件 `access.log`、`error.log`
- 面板数据（持久化）：
  - Inbound 隧道列表：`$XRP_STATE_DIR/portal/tunnels.json`（默认 `./state/xrps/tunnels.json`）
  - Outbound Profile：`$XRP_STATE_DIR/bridge/profile.json`（默认 `./state/xrpc/profile.json`）
  - Outbound 隧道状态：`$XRP_STATE_DIR/bridge/tunnel_states.json`
- 管理员凭据：`$XRP_STATE_DIR/admin.auth.json`（首次启动会生成 admin/随机密码并打印到日志）

## 管理员密码

- 重置管理员密码：
  - 开发：`go run ./src -reset-admin`
  - 二进制：`bin/xrp -reset-admin`
- 凭据写入 `$XRP_STATE_DIR/admin.auth.json`，并在标准输出打印新密码。
Tips
- In dev, you can simulate log streaming by appending lines to `./logs/access.log` or `./logs/error.log`; the SSE endpoints will push new lines.

### 创建 Inbound 隧道

POST `/api/inbound/tunnels`

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

随后 `POST /api/inbound/tunnels/{id}/connection-params` 返回：

```
{
  "json": "{...}",
  "base64": "<base64url>"
}
```

将 Base64 粘贴到 Outbound：`POST /api/outbound/profile/apply`。

## 构建

- 后端：`make build`（输出 `bin/xrp`）或 `go build -o bin/xrp ./src`
- 前端：`cd web && npm run build`（生成 `web/dist`，后端通过 `XRP_UI_DIR=web/dist` 提供 `/ui/`）

## 部署（可选 systemd/Docker）

- systemd：暂未更新一键脚本到统一版，可参考二进制启动参数与环境变量自定义单元。

## Docker

- 统一镜像与 compose 尚未更新到合并版；你可以参考 `make build` 产物将 `bin/xrp` 和 `web/dist` 放入镜像，并通过以下环境变量控制：
  - `XRP_UI_DIR`：静态 UI 目录（如 `/ui`）
  - `XRP_STATE_DIR`：状态存储（profile/tunnels/admin）
  - `XRP_LOG_DIR`：日志落盘目录
  - `XRP_XRAY_CFG_PATH`：调试时写入/读取的统一配置路径

## 一键脚本（暂未更新）

历史脚本仍指向分离版 XRPS/XRPC。合并版发布后会提供新的安装脚本与 compose 示例。

## Next steps

- Integrate xray-core: construct `core.Config` inside the process; add reverse v4, REALITY and tunnel routing per PRD.
- Replace in-memory store with SQLite; implement auth and RBAC.
- Attach real logs and stats from xray instead of simulated SSE events.
### Web UI (React + Vite)

- Dev servers are under `web/xrps` and `web/xrpc`. See `web/README.md`.
- Optional: after building (`pnpm build`) you can serve the static UI from the Go services:
  - XRPS: set env `XRPS_UI_DIR=web/xrps/dist` then run `go run ./xrps`; UI at `http://localhost:8080/ui/`.
  - XRPC: set env `XRPC_UI_DIR=web/xrpc/dist` then run `go run ./xrpc`; UI at `http://localhost:8081/ui/`.
