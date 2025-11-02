# XRP（Xray Reverse Proxy）PRD

版本：v1.0 草案（可迭代）

## 1. 概述

XRP 是一个基于 Xray 的反向代理管理工具，包含：
- XRPS（Server/Portal）：部署在公网服务器，用于创建并管理反向隧道入口（Handshake/传输端口），生成连接参数；带 Web 面板与 API。
- XRPC（Client/Bridge）：部署在业务侧（内网或需要被反向访问的主机），粘贴连接参数（Base64 编码的 JSON + 验证密钥）即可建立到 XRPS 的反向隧道；支持查看 Xray 日志/状态、重连信息与流量统计。

两端统一技术栈：Go 后端（内嵌 xray-core）、React 前端。产物采用单文件部署（前端静态资源 embed 到 Go 可执行），提供一键安装脚本并注册为系统服务（systemd）。

## 2. 目标与非目标

目标
- 一键部署 XRPS/XRPC，默认即用；
- XRPS 上可创建“隧道”（Handshake 端口 + 一个或多个传输端口）；
- 自动生成连接参数（VLESS + REALITY + Reverse v4），编码为 Base64，XRPC 直接粘贴使用；
- XRPS/XRPC 均支持：查看 Xray 运行状态、实时/历史日志、基础流量统计；
- 良好的稳定性与重连体验（断线告警、自动重连、状态提示）；
- 面板/接口具备权限控制与审计日志。

非目标（v1 不包含，后续规划）
- 跨平台 GUI 客户端（v1 仅 Web + CLI + systemd）。
- 复杂 ACL/审计策略（v1 做到基础黑名单/广告域名/私有网段拦截即可）。
- 自动申请证书（REALITY 不依赖证书；面板 HTTPS 可放置到 v1.1，或交由外部反代）。

## 3. 术语与反向模型

- Handshake 端口：Portal 暴露的 VLESS+REALITY 监听端口（默认 9443），Bridge 的反向连接先通过此端口建立“反向链路”。
- 传输端口（Tunnel Entry）：Portal 暴露的隧道对外入口端口（可多个，例如 31234/31235…）。外部对这些端口的访问，会经“反向链路”转发至 Bridge 的本地服务端口。
- Reverse v4：Xray 原生反向特性，通过双方 tag 对应，将 Portal 的“tunnel inbound”与 Bridge 的“reverse inbound”建立绑定通道。

对齐参考：参考 reference/xray-rp 的 Portal/Bridge 架构与 reference/XrayR 的“内嵌 xray-core + 动态增删入/出站 + 统计”模式。特别注意：XRPS 仅提供“连接到服务端”的定义（Portal 地址、REALITY Handshake 参数、传输入口端口等），不决定客户端实际转发到的目标 IP:Port；XRPC 才决定每条隧道映射到本机或任意内网目标的 IP:Port（默认 127.0.0.1:mapPort，可自定义）。

## 4. 总体架构

统一组件（两端复用）：
- Core Orchestrator：内嵌 xray-core，按需构建 `core.Config`，并通过 `inbound.Manager`/`outbound.Manager`/`stats.Manager` 动态增删入站/出站与读写统计。
- API Server（Go/REST + WS）：对外提供配置、运维、统计、日志流接口；
- Web UI（React）：单页应用，打包内嵌；
- Storage：SQLite（采用 `modernc.org/sqlite` 无 CGO），保存隧道、密钥、审计、统计快照。

部署形态：
- XRPS：在公网主机上以 systemd 服务运行（监听面板端口与 xray 监听端口）。
- XRPC：在内网主机上以 systemd 服务运行（正向代理功能已移除）。

## 5. 功能清单

XRPS（服务器/Portal）
- 面板：仪表盘（运行状态、CPU/内存/连接数/速率）、隧道列表/详情、日志查看（实时/历史）、统计图表、系统设置。
- 隧道管理：
  - 创建/修改/删除隧道：指定 Handshake 端口、REALITY 参数（serverName、公钥/私钥、shortId、PQ 模式）、传输端口（一个或多个）。
  - 每个传输端口自动创建一对反向通道标识（`t-inbound-*` ↔ `r-outbound-*`）。
  - 一键生成连接参数（见 §8），并提供 Base64 文本与二维码（可选）。
- 运行控制：启动/停止/重启 Core、配置校验（Dry-Run）、端口冲突检测。
- 监控运维：
  - Xray 日志（access/error），支持筛选/下载；
  - 实时状态（WS 推送）：活动连接/丢包/重连次数；
  - 流量统计：按入站/出站/用户（如启用 user 维度）累计与速率。
- 安全：管理员账户、Token、二次校验（可选）；审计日志（配置变更与运维操作）。

XRPC（客户端/Bridge）
- 首次引导：粘贴 Base64 连接参数（或扫码），解析后展示摘要，确认后应用；应用后需在前端为每条隧道手动输入/确认出口地址（默认 127.0.0.1:80）。
- 连接管理：连接/断开/重连、自动重连（指数退避 + 抖动）、当前状态；
- 目标映射：为每条隧道设置“目标地址 target（ip:port）”，可随时调整并热更新（XRPS 不再提供默认映射端口提示）。
- 日志/状态：实时查看 xray 日志、最近重连原因、当前速率与累计流量；
- 多配置档：保存多组连接参数，手动启停；
- 运行控制：启动/停止/重启 Core、配置校验、端口冲突检测。

## 6. 反向隧道配置（核心设计）

XRPS（Portal 侧，按隧道集合动态生成/变更）
- Inbounds：
  - `external-vless`（VLESS+REALITY，监听 Handshake 端口，认证：多客户端，每个隧道一条 `id(UUID)`，并写入 `reverse.tag=r-outbound-{i}`）。
  - `t-inbound-{i}`（protocol=tunnel，监听“传输端口”）。
- Routing：
  - 规则：`inboundTag=["t-inbound-{i}"] -> outboundTag="r-outbound-{i}"`。
  - 基础阻断：BT、私有网段、广告域名等。
- Outbounds：`direct` / `blackhole`，以及每个 `r-outbound-{i}` 对应 reverse 链路出口（由 external-vless 的 client.reverses 建立）。

XRPC（Bridge 侧，粘贴参数后生成）
- Inbounds：
  - `r-inbound-{i}`（由 reverse 链路在 Bridge 端生成的入口 tag）。
  - （已移除）`socks-in`/正向代理相关能力。
- Outbounds：
  - `rev-link-{i}`（VLESS+REALITY，直连 XRPS 的 Handshake 端口，`reverse.tag="r-inbound-{i}"`）。
  - `local-web-{i}`（freedom，`redirect=127.0.0.1:<映射端口>`）。
  - （已移除）`proxy`（正向上网出站）。
- Routing：
  - `inboundTag=["r-inbound-{i}"] -> outboundTag="local-web-{i}"`。
  - （已移除）本地 SOCKS → proxy 出站路由。

说明：REALITY 采用 `flow=xtls-rprx-vision`，`decryption=none`（服务端 inbound），客户端 outbound “encryption” 支持 PQ 与 X25519 两档；`fingerprint=chrome`。

## 7. 连接参数（JSON Schema + Base64）

编码：`base64url(JSON)`（无换行，无前缀），UI 提供复制/二维码。建议在 UI/文档中统一称“验证密钥”。

示例（v1，无正向代理）：
```json
{
  "version": 1,
  "portal_addr": "portal.example.com",
  "handshake": {
    "port": 9443,
    "serverName": "www.fandom.com",
    "publicKey": "<reality_public_key>",
    "shortId": "<short_id>",
    "encryption": "none|pq",          
    "flow": "xtls-rprx-vision"
  },
  "tunnels": [
    { "entry_port": 31234, "id": "<uuid-1>", "tag": "t1", "map_port_hint": 0 },
    { "entry_port": 31235, "id": "<uuid-2>", "tag": "t2", "map_port_hint": 0 }
  ]
  "meta": { "comment": "demo", "createdAt": "2025-01-01T00:00:00Z" }
}
```

XRPC 解析流程：Base64 解码 → JSON schema 校验 → 显示摘要（入口端口/映射端口建议/REALITY SNI 等）→ 应用生成 xray-core 运行图。

## 8. 后端设计（Go）

内嵌 xray-core：
- 按 XrayR 方式在进程内构建 `core.Config` 并启动，避免依赖外部 xray 可执行；
- 动态变更：使用 `inbound.Manager`/`outbound.Manager` 热增删（无需进程重启）；
- 统计：`stats.Manager` 读取计数器（入/出站级别为主，必要时可引入“用户”维度，以隧道 uuid 为 user）；
- 日志：启用 access/error 双日志；WS/HTTP 提供 tail 与过滤；
- 配置校验：先做 JSON 校验，再调用 xray `-test` 等价的内部构建校验（失败给出详细错误）。

模块划分：
- core: xray 编排与运行时（实例、入出站、路由、统计、日志）
- api: REST + WS（认证、RBAC、中间件、错误码）
- store: SQLite（隧道、密钥、统计快照、审计日志）
- svc: 系统服务适配（systemd 单元模板渲染、healthcheck）
- ui: 内嵌静态资源（embed.FS）

关键 API（XRPS）：
- 隧道管理
  - POST /api/tunnels（创建；输入：handshake 端口、SNI、PQ 模式、entry 端口数组等）
  - GET /api/tunnels，GET /api/tunnels/:id
  - PATCH /api/tunnels/:id，DELETE /api/tunnels/:id
  - POST /api/tunnels/:id/connection-params → { json, base64 }
- 运行控制
  - POST /api/core/start|stop|restart|reload
  - GET /api/core/status（进程状态/监听端口/连接数）
  - POST /api/core/validate（配置校验）
- 观测
  - GET /api/logs?type=access|error&tail=N
  - SSE /logs/access/stream 与 /logs/error/stream（持续推送文件日志新增行）
  - GET /api/stats?since=ts&by=inbound|outbound
  - WS /ws/status（重连/在线连接数/速率推送）

关键 API（XRPC）：
- 连接管理
  - POST /api/profile/apply（body: base64 字符串）
  - GET /api/profile/active，GET /api/profile/list
- 运行控制/观测：与 XRPS 同型（status/logs/stats），但统计以本地为主。

认证与安全
- XRPS：管理员登录（本地用户/密码）、API Token；可开启只读角色；
- XRPC：本地控制台需要本机访问或 token；
- 连接参数中的敏感字段（私钥不外发，公钥+shortId+uuid 外发即可）。

## 9. 前端设计（React）

XRPS UI
- Dashboard：核心状态、最近重连次数、总连接数、速率、CPU/内存；
- Tunnels：列表（端口、SNI、PQ、启停、在线状态、流量）、详情（多传输端口的路由与 tag 关系）、生成 Base64/二维码；
- Logs：access/error 实时流（滚动）、搜索/过滤、级别筛选；
- Stats：按时间窗口（5m/1h/1d），折线/柱状图；
- Settings：面板端口、鉴权、数据目录、备份/导出。

XRPC UI
- Connect：粘贴 Base64 → 摘要预览 → 应用；
- Status：在线/离线、最近重连（时间/原因）、当前速率、累计流量；
- Tunnels：每条隧道的“本地映射端口”设置与即时生效；
- Logs/Stats：同上简化版。

技术
- 构建：Vite + React + TypeScript；样式库（MUI/AntD 任一）；
- 与后端通信：REST + WebSocket；
- 打包：静态产物 embed 到 Go 二进制（`embed.FS`）。

## 10. 存储模型（SQLite）

主要表（简化）：
- tunnels(id, name, created_at, updated_at, enabled)
- handshake(id, tunnel_id, port, server_name, public_key, private_key, short_id, encryption, flow)
- entries(id, tunnel_id, entry_port, tag)
- profiles(id, name, base64, active, created_at)  // XRPC 侧
- stats_snap(id, scope, scope_id, in_bytes, out_bytes, ts)
- audits(id, actor, action, payload, ts)

备注：私钥仅存 XRPS。导出连接参数时不包含私钥。

## 11. 运行与重连策略

- Xray 由进程内托管，崩溃自动拉起（主进程守护），重连使用指数退避（上限 60s，含抖动）。
- WS 推送重连事件（type=reconnect, reason, at）。
- 端口冲突检测：创建/修改之前探测端口是否被占用；失败给出清晰提示。

## 12. 一键脚本与服务

安装脚本（XRPS/XRPC 各一）：
- 检测包管理器（apt/dnf/yum/apk）；
- 下载指定版本单文件二进制到 `/usr/local/bin/xrps|xrpc`；
- 创建工作目录 `/etc/xrp`、`/var/lib/xrp`、`/var/log/xrp`；
- 生成 systemd unit（`/etc/systemd/system/xrps.service`/`xrpc.service`），包含：
  - `ExecStart=/usr/local/bin/xrps serve`（或 `xrpc serve`）
  - `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`（允许 <1024 端口）
  - `Restart=on-failure`，`LimitNOFILE=1048576`
- `systemctl enable --now xrps|xrpc`。

升级/卸载：
- `xrps|xrpc upgrade --version vX.Y.Z`（或脚本参数）；
- 保留数据目录与日志；卸载可带 `--purge` 全清理。

## 13. 统计与日志

- 统计：使用 `stats.Manager` 读取入站/出站计数器，按隧道聚合（以 tag 对应），存储快照用于图表；
- 日志：xray 的 access/error 输出到文件并同时通过管道转发到 WS；支持级别与关键字过滤；
- 报表：近 5 分钟速率曲线、24 小时累计、Top N 隧道活动。

## 14. 安全与权限

- 首次启动要求设置管理密码；
- 所有 API 需 Token 鉴权（Bearer/JWT），支持只读 Token；
- CSRF 防护（Cookie + SameSite/Lax）或所有写接口仅 Bearer；
- 审计：记录隧道 CRUD、启动停止、导出参数等操作。

## 15. 失败与边界场景

- REALITY 配置错误（publicKey/shortId/SNI 不匹配）→ 连接失败与自诊断建议；
- 端口冲突 → 阻止创建并提示占用进程；
- Base64/JSON 非法 → 给出示例与字段含义；
- 长时间离线 → UI 告警与邮件/Telegram（可选 webhook）。

## 16. 里程碑

M0（原型）：
- 单隧道打通（9443 + 31234），命令行/最小 UI，可用 Base64 参数；

M1（可用）：
- 多隧道、面板、日志流、统计、自动重连、一键脚本、systemd 服务；

## 17. 附：生成配置要点（落地对照）

Portal（XRPS）
- REALITY VLESS inbound（handshakePort）：`decryption=none`，clients 为每隧道一条 id(uuid)，每条带 `reverse.tag=r-outbound-{i}`；
- N 个 `t-inbound-{i}`（protocol=tunnel，entryPort）→ 路由到 `r-outbound-{i}`；
- 阻断规则：BT/私网/广告域名；
- outbounds：`direct`、`blackhole`；

Bridge（XRPC）
- N 个 `rev-link-{i}`（VLESS+REALITY，连接 Portal handshakePort，`reverse.tag=r-inbound-{i}`）；
- N 条路由：`inboundTag=[r-inbound-{i}] -> outboundTag=local-web-{i}`（freedom 重定向为 `target`，默认 127.0.0.1:mapPort，可改为任意内网 IP:Port）；
- 可选 socks-in 与 proxy 出站（走 Portal 正向 443）。

## 18. 开放问题

- PQ（ML-KEM）支持的具体加密参数稳定性与最低 xray-core 版本约束；
- 是否引入自定义 Dispatcher 以支持更精细的限速/设备数限制（参考 XrayR），或先用原生 stats；
- Windows/macOS 安装脚本与服务（v1 可不做，标注不支持）。

## 19. 参考分析（XrayR 与 xray-rp）

XrayR 如何接管 xray（内嵌 + 热更新）
- 进程内嵌入：使用 `github.com/xtls/xray-core/core` 创建 `*core.Instance`，不依赖外部二进制。
- 管理入口：通过 `inbound.Manager`/`outbound.Manager`/`stats.Manager` 动态增删入/出站与查询流量计数，避免重启；见 `reference/XrayR/service/controller/controller.go`。
- 入站构建器：按面板返回的节点类型（VLESS/VMess/Trojan/SS 等）拼装 `conf.InboundDetourConfig`，包括 `streamSettings`、REALITY 或 TLS 等；见 `inboundbuilder.go`。
- REALITY 支持：当启用 REALITY 时为入站配置 `security=reality`，填充 `serverNames/privateKey/shortIds` 等，禁用 decryption；支持 ProxyProtocol。
- 用户同步与限速：周期任务从面板拉取节点和用户列表，比较增删差集后调用 add/remove 接口动态调整；集成 `stats.Manager` 与自定义 Dispatcher 做限速与设备数（可选）。
- 日志与状态：xray access/error 输出到文件；控制器周期上报系统状态（CPU/Mem/Disk/Uptime）。

xray-rp 如何实现反向代理（Portal/Bridge 一键脚本）
- Portal 侧：
  - 一个 VLESS+REALITY inbound 作为握手入口（正向 443、反向 9443 可分开配置），`decryption=none`，`flow=xtls-rprx-vision`；反向用途的 clients 带 `reverse.tag=r-outbound-{i}`。
  - 每个“传输端口”创建一条 `t-inbound-{i}`（protocol=tunnel）。
  - 路由将 `inboundTag=t-inbound-{i}` 指向 `outboundTag=r-outbound-{i}`，从而把公网传入的 tunnel 流量经“反向链路”送回 Bridge。
- Bridge 侧：
  - 为每条隧道配置一个 VLESS+REALITY 出站（连接 Portal 握手端口），写 `reverse.tag=r-inbound-{i}` 建立反向通道。
  - freedom 出站 `local-web-{i}` 配置 `redirect=127.0.0.1:<映射端口>`，路由把 `inboundTag=r-inbound-{i}` 指到该 freedom，从而把 Portal 收到的请求转发到本地/内网服务。
  - 可选开启本地 SOCKS（走 Portal 正向 443 出站）。
- 关键点：完全依赖 Xray 原生 Reverse v4（通过 reverse tag 对齐）；REALITY 提供抗审计的握手信道；所有映射（目标 IP:Port）由 Bridge 侧决定，Portal 只暴露入口端口并负责反代回传。
