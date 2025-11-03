# XRP Web UIs (XRPS + XRPC)

Two Vite + React + TypeScript single-page apps for the XRP scaffold:

- `web/xrps`: Admin panel for XRPS (server/portal).
- `web/xrpc`: Control panel for XRPC (client/bridge).

Highlights
- Uses shadcn/ui style structure (components under `components/ui`) with a pixelated Neubrutalism look built purely with Tailwind utilities.
- Light/Dark theme with a toggle (persists to `localStorage`, prefers OS on first load).
- Connects to backends via REST and SSE (Server-Sent Events) per PRD.
- Vite dev server proxies avoid CORS changes in Go services.

Prereqs
- Node 18+, pnpm or npm.

Dev (XRPS)
```
cd web/xrps
pnpm install   # or npm install
pnpm dev       # or npm run dev
# Backend: go run ./xrps -addr :8080
```

Dev (XRPC)
```
cd web/xrpc
pnpm install   # or npm install
pnpm dev       # or npm run dev
# Backend: go run ./xrpc -addr :8081
```

Build
```
pnpm build     # inside each app
```

Notes
- The UI uses Tailwind classnames and shadcn-like components. You can `pnpm dlx shadcn@latest init` later to swap components with the official generator if desired.
- No custom CSS files are used beyond Tailwind's entry (`src/index.css` with `@tailwind` directives). All styling is expressed as Tailwind utilities.
