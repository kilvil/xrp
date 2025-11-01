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
  async listTunnels(): Promise<TunnelState[]> {
    const res = await fetch('/api/tunnels')
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
  makeLogStream(): EventSource {
    return new EventSource('/logs/stream')
  }
}

export default API
