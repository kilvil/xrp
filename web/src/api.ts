// Unified API for inbound (portal) and outbound (bridge)

export type InboundTunnel = {
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
  entries: Array<{ entry_port: number; id: string; tag: string; map_port_hint?: number }>
  createdAt: string
  updatedAt: string
}

export type CreateInboundReq = {
  name: string
  portal_addr: string
  handshake_port: number
  server_name: string
  encryption: string
  decryption?: string
  entry_ports: number[]
  public_key?: string
  short_id?: string
  private_key: string
}

export type OutboundTunnelState = {
  id: string
  tag: string
  entry_port: number
  map_port: number
  target: string
  active: boolean
  status?: string
  last_change?: string
}

const API = {
  async status() {
    const res = await fetch('/status')
    return res.json()
  },
  core: {
    async restart(): Promise<{ ok: boolean; ts: number }> {
      const res = await fetch('/api/core/restart', { method: 'POST' })
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
  },
  async newX25519(): Promise<{ publicKey: string; privateKey: string }> {
    const res = await fetch('/api/reality/x25519')
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  async genVlessEnc(algo: 'pq' | 'x25519' = 'pq'): Promise<{ algorithm: string; mode: string; decryption: string; encryption: string; note?: string }> {
    const q = new URLSearchParams({ algo })
    const res = await fetch(`/api/vlessenc?${q.toString()}`)
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  inbound: {
    async listTunnels(): Promise<InboundTunnel[]> {
      const res = await fetch('/api/inbound/tunnels')
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    async getTunnel(id: string): Promise<InboundTunnel> {
      const res = await fetch(`/api/inbound/tunnels/${id}`)
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    async createTunnel(payload: CreateInboundReq): Promise<InboundTunnel> {
      const res = await fetch('/api/inbound/tunnels', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    async deleteTunnel(id: string): Promise<void> {
      const res = await fetch(`/api/inbound/tunnels/${id}`, { method: 'DELETE' })
      if (!res.ok && res.status !== 204) throw new Error(await res.text())
    },
    async genParams(id: string): Promise<{ json: string; base64: string }> {
      const res = await fetch(`/api/inbound/tunnels/${id}/connection-params`, { method: 'POST' })
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    async statsSnapshot() {
      const res = await fetch('/api/inbound/stats/snapshot')
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    async statsRange(sinceMs: number, entryId?: string) {
      const q = new URLSearchParams({ since: String(sinceMs) }); if (entryId) q.set('entry', entryId)
      const res = await fetch(`/api/inbound/stats/range?${q.toString()}`)
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
  },
  outbound: {
    async applyBase64(base64: string) {
      const res = await fetch('/api/outbound/profile/apply', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ base64 }) })
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    async listTunnels(): Promise<OutboundTunnelState[]> {
      const res = await fetch('/api/outbound/tunnels')
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    async getTunnel(id: string): Promise<OutboundTunnelState> {
      const res = await fetch(`/api/outbound/tunnels/${id}`)
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    async patchTunnel(id: string, payload: Partial<{ map_port: number; active: boolean; target: string }>): Promise<OutboundTunnelState> {
      const res = await fetch(`/api/outbound/tunnels/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    async deleteTunnel(id: string): Promise<void> {
      const res = await fetch(`/api/outbound/tunnels/${id}`, { method: 'DELETE' })
      if (!res.ok && res.status !== 204) throw new Error(await res.text())
    },
    async statsSnapshot() {
      const res = await fetch('/api/outbound/stats/snapshot')
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    async statsRange(sinceMs: number, tunnelId?: string) {
      const q = new URLSearchParams({ since: String(sinceMs) }); if (tunnelId) q.set('tunnel', tunnelId)
      const res = await fetch(`/api/outbound/stats/range?${q.toString()}`)
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
  },
  logs: {
    async tail(type: 'access'|'error', tail: number = 200) {
      const q = new URLSearchParams({ type, tail: String(tail) })
      const res = await fetch(`/api/logs?${q.toString()}`)
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    makeAccessLogStream(): EventSource { return new EventSource('/logs/access/stream') },
    makeErrorLogStream(): EventSource { return new EventSource('/logs/error/stream') },
  }
  ,
  config: {
    async get(): Promise<{ path: string; content: string }> {
      const res = await fetch('/api/config')
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    }
  }
}

export default API
