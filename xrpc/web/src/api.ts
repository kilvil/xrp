export type TunnelState = {
  id: string
  tag: string
  entry_port: number
  map_port: number
  target: string
  active: boolean
  status: string
  last_change: string
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
  async activeProfile() {
    const res = await fetch('/api/profile/active')
    return res.json()
  },
  async applyBase64(base64: string) {
    const res = await fetch('/api/profile/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ base64 })
    })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async statsSnapshot(): Promise<StatsSnapshot> {
    const res = await fetch('/api/stats/snapshot')
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async statsRange(sinceMs: number, tunnelId?: string): Promise<{ series: Array<{ ts: number; uplink: number; downlink: number }>; interval: number }> {
    const q = new URLSearchParams({ since: String(sinceMs) })
    if (tunnelId) q.set('tunnel', tunnelId)
    const res = await fetch(`/api/stats/range?${q.toString()}`)
    if (!res.ok) throw new Error(await res.text())
    const data = await res.json()
    // normalize key names
    const series = (data.series || []).map((p: any) => ({ ts: p.ts, uplink: p.uplink ?? p.Up ?? p.up, downlink: p.downlink ?? p.Down ?? p.down }))
    return { series, interval: data.interval || 0 }
  },
  async coreRestart(): Promise<{ ok: boolean; message?: string }> {
    const res = await fetch('/api/core/restart', { method: 'POST' })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async listTunnels(): Promise<TunnelState[]> {
    const res = await fetch('/api/tunnels')
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async tailLogs(type: 'access' | 'error', tail: number = 200): Promise<{ type: string; path: string; lines: string[] }> {
    const q = new URLSearchParams({ type, tail: String(tail) })
    const res = await fetch(`/api/logs?${q.toString()}`)
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async deleteTunnel(id: string): Promise<void> {
    const res = await fetch(`/api/tunnels/${id}`, { method: 'DELETE' })
    if (!res.ok && res.status !== 204) throw new Error(await res.text())
  },
  async patchTunnel(id: string, payload: Partial<{ map_port: number; active: boolean; target: string }>): Promise<TunnelState> {
    const res = await fetch(`/api/tunnels/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
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
