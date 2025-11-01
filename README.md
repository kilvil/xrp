# XRP Monorepo (XRPS + XRPC)

This repo contains two services to manage Xray reverse proxying:

- `xrps` (server/portal): create and manage reverse tunnels; generate Base64 connection params for clients. XRPS only defines how to connect to the server (portal addr, REALITY handshake, entry ports). It does not decide the forwarding destination.
- `xrpc` (client/bridge): paste Base64 params to connect; shows status, logs and reconnection events. XRPC decides each tunnel’s forwarding target `ip:port` (default `127.0.0.1:mapPort`) and can change it at runtime.

Note: current implementation is a functional scaffold without xray-core integration. It provides the API/flow, SSE logs, and in-memory management so we can iterate quickly and later plug in xray orchestration.

## Quick start

- Run XRPS (server):
  - `go run ./xrps -addr :8080`
  - Health: `GET /healthz`
  - REALITY helpers:
    - `GET /api/reality/x25519` → `{ privateKey, publicKey }` (base64)
    - `GET /api/reality/mldsa65` → `{ seed (base64), seedHex, verifyHex }`
  - Create tunnel: `POST /api/tunnels` (see payload below)
  - Generate params: `POST /api/tunnels/{id}/connection-params`
  - System events (SSE): `GET /logs/stream`
  - Xray file logs:
    - Tail: `GET /api/logs?type=access|error&tail=200`
    - Streams: `GET /logs/access/stream`, `GET /logs/error/stream`
    - Configure log dir via env `XRPS_LOG_DIR` (default `./logs`)

- Run XRPC (client):
  - `go run ./xrpc -addr :8081`
  - Health: `GET /healthz`
  - REALITY helpers (mirror): `GET /api/reality/x25519`, `GET /api/reality/mldsa65`
  - Apply profile: `POST /api/profile/apply` with `{ "base64": "..." }` or raw Base64 body
  - List tunnels: `GET /api/tunnels` (with target field)
  - Update per-tunnel: `PATCH /api/tunnels/{id}` with `{ map_port?, active?, target? }`
  - Status: `GET /status`
  - System events (SSE): `GET /logs/stream`
  - Xray file logs:
    - Tail: `GET /api/logs?type=access|error&tail=200`
    - Streams: `GET /logs/access/stream`, `GET /logs/error/stream`
    - Configure log dir via env `XRPC_LOG_DIR` (default `./logs`)

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
  "encryption": "pq",
  "entry_ports": [31234, 31235],
  "enable_forward": false,
  "forward_port": 443
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

- Root module: `go 1.21`, no external deps for the scaffold.
- Build binaries:
  - `go build -o bin/xrps ./xrps`
  - `go build -o bin/xrpc ./xrpc`

## Install (systemd, optional)

See scripts:
- `scripts/install_xrps.sh`
- `scripts/install_xrpc.sh`

These copy binaries to `/usr/local/bin` and create simple systemd units.

## Next steps

- Integrate xray-core: construct `core.Config` inside the process; add reverse v4, REALITY and tunnel routing per PRD.
- Replace in-memory store with SQLite; implement auth and RBAC.
- Attach real logs and stats from xray instead of simulated SSE events.
### Web UI (React + Vite)

- Dev servers are under `web/xrps` and `web/xrpc`. See `web/README.md`.
- Optional: after building (`pnpm build`) you can serve the static UI from the Go services:
  - XRPS: set env `XRPS_UI_DIR=web/xrps/dist` then run `go run ./xrps`; UI at `http://localhost:8080/ui/`.
  - XRPC: set env `XRPC_UI_DIR=web/xrpc/dist` then run `go run ./xrpc`; UI at `http://localhost:8081/ui/`.
