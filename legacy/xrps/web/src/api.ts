export type Tunnel = {
  id: string
  name: string
  portal_addr: string
  handshake: {
    port: number
    serverName: string
    publicKey: string
    shortId: string
    encryption: string
    flow: string
  }
  entries: Array<{
    entry_port: number
    id: string
    tag: string
    map_port_hint: number
  }>
  createdAt: string
  updatedAt: string
}

export type CreateTunnelReq = {
  name: string
  portal_addr: string
  handshake_port: number
  server_name: string
  encryption: string
  decryption?: string
  entry_ports: number[]
  public_key?: string
  short_id?: string
  private_key?: string
}

export type StatsTunnelSnapshot = {
  id: string
  tag: string
  entry_port: number
  uplink: number
  downlink: number
  total: number
}

export type StatsSnapshot = {
  ts: number
  tunnels: StatsTunnelSnapshot[]
  total: { uplink: number; downlink: number; total: number }
}

const API = {
  async status() {
    const res = await fetch('/status')
    return res.json()
  },
  async newX25519(): Promise<{ publicKey: string; privateKey: string }> {
    const res = await fetch('/api/reality/x25519')
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async listTunnels(): Promise<Tunnel[]> {
    const res = await fetch('/api/tunnels')
    return res.json()
  },
  async createTunnel(payload: CreateTunnelReq): Promise<Tunnel> {
    const res = await fetch('/api/tunnels', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async getTunnel(id: string): Promise<Tunnel> {
    const res = await fetch(`/api/tunnels/${id}`)
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async coreRestart(): Promise<{ ok: boolean; message?: string }> {
    const res = await fetch('/api/core/restart', { method: 'POST' })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async deleteTunnel(id: string): Promise<void> {
    const res = await fetch(`/api/tunnels/${id}`, { method: 'DELETE' })
    if (!res.ok && res.status !== 204) throw new Error(await res.text())
  },
  async tailLogs(type: 'access' | 'error', tail: number = 200): Promise<{ type: string; path: string; lines: string[] }> {
    const q = new URLSearchParams({ type, tail: String(tail) })
    const res = await fetch(`/api/logs?${q.toString()}`)
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async genParams(id: string): Promise<{ json: string; base64: string }> {
    const res = await fetch(`/api/tunnels/${id}/connection-params`, { method: 'POST' })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async genVlessEnc(algo: 'pq' | 'x25519' = 'pq'): Promise<{ algorithm: string; mode: string; decryption: string; encryption: string; note?: string }> {
    const q = new URLSearchParams({ algo })
    const res = await fetch(`/api/vlessenc?${q.toString()}`)
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async statsSnapshot(): Promise<StatsSnapshot> {
    const res = await fetch('/api/stats/snapshot')
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async statsRange(sinceMs: number, entryId?: string): Promise<{ series: Array<{ ts: number; uplink: number; downlink: number }>; interval: number }> {
    const q = new URLSearchParams({ since: String(sinceMs) })
    if (entryId) q.set('entry', entryId)
    const res = await fetch(`/api/stats/range?${q.toString()}`)
    if (!res.ok) throw new Error(await res.text())
    const data = await res.json()
    const series = (data.series || []).map((p: any) => ({ ts: p.ts, uplink: p.uplink ?? p.Up ?? p.up, downlink: p.downlink ?? p.Down ?? p.down }))
    return { series, interval: data.interval || 0 }
  },
  // Logs SSE streams (aligned with XRPS/XRPC backends)
  makeAccessLogStream(): EventSource {
    return new EventSource('/logs/access/stream')
  },
  makeErrorLogStream(): EventSource {
    return new EventSource('/logs/error/stream')
  },
  // Backward-compat alias (defaults to access logs)
  makeLogStream(): EventSource {
    return this.makeAccessLogStream()
  }
}

export default API
