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
  forward: {
    enabled: boolean
    port: number
    id: string
    serverName: string
    publicKey: string
    shortId: string
    flow: string
  }
  createdAt: string
  updatedAt: string
}

export type CreateTunnelReq = {
  name: string
  portal_addr: string
  handshake_port: number
  server_name: string
  encryption: string
  entry_ports: number[]
  enable_forward: boolean
  forward_port: number
  public_key?: string
  short_id?: string
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
  async newMLDSA65(): Promise<{ seed: string; verify: string }> {
    const res = await fetch('/api/reality/mldsa65')
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
  async deleteTunnel(id: string): Promise<void> {
    const res = await fetch(`/api/tunnels/${id}`, { method: 'DELETE' })
    if (!res.ok && res.status !== 204) throw new Error(await res.text())
  },
  async genParams(id: string): Promise<{ json: string; base64: string }> {
    const res = await fetch(`/api/tunnels/${id}/connection-params`, { method: 'POST' })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  },
  makeLogStream(): EventSource {
    return new EventSource('/logs/stream')
  }
}

export default API
