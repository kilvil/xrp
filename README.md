# XRP（统一版：Inbound + Outbound）

XRP 将原 XRPS（Portal/Server）与 XRPC（Bridge/Client）合并为一个进程 + 一个前端。

- Inbound（原 XRPS 功能）：创建握手/入口（REALITY + Entry Ports），生成给客户端使用的 Base64 参数。
- Outbound（原 XRPC 功能）：粘贴 Base64 参数后建立反连，按隧道设置本地转发表达式（target / map_port / active）。

内置 xray-core：后端会在进程内构建 Xray JSON（REALITY + Reverse v4 + stats/policy）并启动核心，默认写入 `/var/lib/xrp/access.log`、`/var/lib/xrp/error.log`。也可以通过环境变量使用外部配置。

## 快速开始

- 后端（统一版）
  - 开发运行：`make run`（等价 `go run ./src -addr :8080`）
  - 健康检查：`GET /healthz`
  - 状态：`GET /status`
  - 管理员凭据：首次启动自动生成（日志打印），或执行 `go run ./src -reset-admin`

- 前端（Vite + React）
  - 开发：`cd web && npm install && npm run dev`（http://localhost:5173，已代理到 :8080）
  - 生产：先构建前端 `npm run build`，再将 `web/dist` 复制到 `src/ui` 并使用 `-tags ui_embed` 构建后端以将 UI 打包进二进制：
    - `cd web && npm run build`
    - `rm -rf ../src/ui && mkdir -p ../src/ui && cp -a dist/* ../src/ui/`
    - `GOCACHE="$PWD/../.gocache" go build -tags ui_embed -o ../bin/xrp ../src`

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
- 无（路径固定）。
  

- 运行目录与持久化（固定路径）
- 有效配置：`/var/lib/xrp/xray.unified.json`
- 日志目录：`/var/lib/xrp`，文件 `access.log`、`error.log`
- 面板数据：
  - Inbound 隧道列表：`/var/lib/xrp/portal/tunnels.json`
  - Outbound Profile：`/var/lib/xrp/bridge/profile.json`
  - Outbound 隧道状态：`/var/lib/xrp/bridge/tunnel_states.json`
- 管理员凭据：固定写入 `/etc/lib/xrp/admin.auth.json`（首次启动会生成 admin/随机密码并打印到日志）

## 管理员密码

- 重置管理员密码：
  - 开发：`go run ./src -reset-admin`
  - 二进制：`bin/xrp -reset-admin`
- 凭据写入固定路径：`/etc/lib/xrp/admin.auth.json`，并在标准输出打印新密码。
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
- 前端：`cd web && npm run build`（生成 `web/dist`，用于内嵌到二进制）

## 一键安装脚本（XRP 合并版）

Linux 一键安装、卸载与重置（交互式菜单）。推荐使用最新发布页的脚本：

```
curl -fsSL https://github.com/kilvil/xrp/releases/latest/download/xrp-onekey.sh -o xrp-onekey.sh
chmod +x xrp-onekey.sh
./xrp-onekey.sh
```

或直接使用仓库脚本（可能不是发布版，请自行判断）：

```
bash <(curl -fsSL https://raw.githubusercontent.com/kilvil/xrp/master/scripts/xrp-onekey.sh)
```

菜单项：
- 1) 安装 XRP（下载 `xrp_<tag>_linux_<arch>.*`，安装到 `/usr/local/bin/xrp`，可选创建 systemd 服务）
- 2) 卸载 XRP（停止并移除 systemd，删除二进制）
- 3) 重置 XRP 管理员密码（更新 `/etc/lib/xrp/admin.auth.json` 并打印新密码）
- 4) 退出

systemd 单元关键设置（由脚本创建）：
- ExecStart: `/usr/local/bin/xrp -addr :8080`

安装后面板地址：
- `http://<服务器IP>:8080/`（仅根路径，已移除历史兼容 `/ui` 路由）

## Docker

- 统一镜像与 compose 尚未更新到合并版；建议将 `/var/lib/xrp` 和 `/etc/lib/xrp` 作为卷挂载以持久化配置、日志与凭据。前端建议内置到二进制（`-tags ui_embed`）。

## 手动运行（不使用脚本）

```
bin/xrp -addr :8080
```

## Next steps

- Integrate xray-core: construct `core.Config` inside the process; add reverse v4, REALITY and tunnel routing per PRD.
- Replace in-memory store with SQLite; implement auth and RBAC.
- Attach real logs and stats from xray instead of simulated SSE events.
### Web UI (React + Vite)

- Dev servers are under `web/xrps` and `web/xrpc`. See `web/README.md`.
- Optional: legacy split UIs are documented under `legacy/` for reference only.
