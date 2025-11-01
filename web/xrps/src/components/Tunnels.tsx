import React from 'react'
import API, { CreateTunnelReq, Tunnel } from '../api'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Textarea } from './ui/textarea'
import { Label } from './ui/label'
import { Card, CardTitle } from './ui/card'
import { Checkbox } from './ui/checkbox'

export default function Tunnels() {
  const [list, setList] = React.useState<Tunnel[]>([])
  const [loading, setLoading] = React.useState(false)
  const [selected, setSelected] = React.useState<Tunnel | null>(null)
  const [params, setParams] = React.useState<{ json: string; base64: string } | null>(null)

  const load = React.useCallback(async () => {
    setLoading(true)
    try { setList(await API.listTunnels()) } finally { setLoading(false) }
  }, [])
  React.useEffect(() => { load() }, [load])

  const onSelect = async (id: string) => {
    const t = await API.getTunnel(id)
    setSelected(t)
    setParams(null)
  }

  const onDelete = async (id: string) => {
    await API.deleteTunnel(id)
    setSelected(null)
    setParams(null)
    await load()
  }

  const onGen = async () => {
    if (!selected) return
    setParams(await API.genParams(selected.id))
  }

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div className="space-y-4">
        <Card>
          <CardTitle>创建隧道</CardTitle>
          <TunnelForm onCreated={t => { setSelected(t); load() }} />
        </Card>

        <Card>
          <CardTitle>隧道列表 {loading && '…'}</CardTitle>
          <div className="space-y-2">
            {list.map(t => (
              <div key={t.id} className="flex items-center justify-between bg-white text-black border-4 border-black shadow-[8px_8px_0_rgba(0,0,0,0.9)] p-2 dark:bg-zinc-900 dark:text-white dark:border-white dark:shadow-[8px_8px_0_rgba(255,255,255,0.2)]">
                <div>
                  <div className="font-semibold">{t.name || t.id}</div>
                  <div className="text-xs opacity-70">{t.portal_addr} · HS {t.handshake.port} · {t.entries.length} entries</div>
                </div>
                <div className="flex gap-2">
                  <Button variant="accent" onClick={() => onSelect(t.id)}>详情</Button>
                  <Button variant="ghost" onClick={() => onDelete(t.id)}>删除</Button>
                </div>
              </div>
            ))}
            {list.length === 0 && <div className="text-sm opacity-70">暂无隧道，先在左侧创建一个。</div>}
          </div>
        </Card>
      </div>

      <div className="space-y-4">
        <Card>
          <CardTitle>隧道详情</CardTitle>
          {!selected && <div className="text-sm opacity-70">选择左侧列表中的一条隧道。</div>}
          {selected && (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div><b>ID</b>：{selected.id}</div>
                <div><b>名称</b>：{selected.name}</div>
                <div><b>Portal</b>：{selected.portal_addr}</div>
                <div><b>HS 端口</b>：{selected.handshake.port}</div>
                <div><b>SNI</b>：{selected.handshake.serverName}</div>
                <div><b>加密</b>：{selected.handshake.encryption}</div>
              </div>
              <div className="space-y-2">
                <div className="font-semibold">传输入口端口</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {selected.entries.map(e => (
                    <div key={e.id} className="bg-white text-black border-4 border-black shadow-[8px_8px_0_rgba(0,0,0,0.9)] p-2 dark:bg-zinc-900 dark:text-white dark:border-white dark:shadow-[8px_8px_0_rgba(255,255,255,0.2)]">
                      <div className="text-sm"><b>{e.tag}</b> → 入口 {e.entry_port}</div>
                      <div className="text-xs opacity-70">UUID {e.id}</div>
                      <div className="text-xs opacity-70">默认出口端口 {e.map_port_hint}（XRPC 可修改）</div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="flex gap-2">
                <Button onClick={onGen}>生成连接参数</Button>
              </div>
            </div>
          )}
        </Card>

        <Card>
          <CardTitle>连接参数</CardTitle>
          {!params && <div className="text-sm opacity-70">点击“生成连接参数”获取 Base64 与 JSON。</div>}
          {params && (
            <div className="space-y-3">
              <div>
                <div className="font-semibold mb-1">Base64</div>
                <Textarea className="h-24" value={params.base64} readOnly />
                <div className="mt-2 flex gap-2">
                  <Button onClick={() => navigator.clipboard.writeText(params.base64)}>复制</Button>
                </div>
              </div>
              <div>
                <div className="font-semibold mb-1">JSON</div>
                <Textarea className="h-40 font-mono" value={params.json} readOnly />
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}

function TunnelForm({ onCreated }: { onCreated: (t: Tunnel) => void }) {
  const [form, setForm] = React.useState<CreateTunnelReq>({
    name: 'demo',
    portal_addr: 'portal.example.com',
    handshake_port: 9443,
    server_name: 'www.fandom.com',
    encryption: 'pq',
    entry_ports: [31234, 31235],
    enable_forward: false,
    forward_port: 443,
  })
  const [submitting, setSubmitting] = React.useState(false)
  const [privKey, setPrivKey] = React.useState('')
  const [pqSeed, setPqSeed] = React.useState('')

  const set = (k: keyof CreateTunnelReq, v: any) => setForm(s => ({ ...s, [k]: v }))
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    try {
      const t = await API.createTunnel(form)
      onCreated(t)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>名称</Label>
          <Input value={form.name} onChange={e => set('name', e.target.value)} />
        </div>
        <div>
          <Label>Portal 地址</Label>
          <Input value={form.portal_addr} onChange={e => set('portal_addr', e.target.value)} />
        </div>
        <div>
          <Label>Handshake 端口</Label>
          <Input type="number" value={form.handshake_port} onChange={e => set('handshake_port', Number(e.target.value))} />
        </div>
        <div>
          <div className="flex items-center justify-between">
            <Label>SNI</Label>
            <button type="button" className="text-xs underline" onClick={() => set('server_name', randomSNI())}>随机</button>
          </div>
          <Input value={form.server_name} onChange={e => set('server_name', e.target.value)} />
        </div>
        <div>
          <Label>加密</Label>
          <select className="w-full border-4 border-black dark:border-white px-3 py-2 bg-white dark:bg-zinc-800 text-black dark:text-white" value={form.encryption} onChange={e => set('encryption', e.target.value)}>
            <option value="x25519">x25519</option>
            <option value="pq">pq</option>
            <option value="none">none</option>
          </select>
        </div>
        <div>
          <Label>传输端口（逗号分隔）</Label>
          <Input value={form.entry_ports.join(',')} onChange={e => set('entry_ports', e.target.value.split(',').map(s => Number(s.trim())).filter(Boolean))} />
        </div>
        <div className="flex items-center gap-3">
          <Label className="m-0">启用正向代理</Label>
          <Checkbox checked={form.enable_forward} onCheckedChange={(v) => set('enable_forward', v)} aria-label="启用正向代理" />
        </div>
        <div>
          <Label>正向端口</Label>
          <Input type="number" value={form.forward_port} onChange={e => set('forward_port', Number(e.target.value))} />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2 font-semibold">REALITY 设置</div>
        <div>
          <div className="flex items-center justify-between">
            <Label>Public Key</Label>
            <button type="button" className="text-xs underline" onClick={async () => {
              const { publicKey, privateKey } = await API.newX25519()
              set('public_key', publicKey)
              setPrivKey(privateKey)
            }}>生成证书</button>
          </div>
          <Input value={form.public_key || ''} onChange={e => set('public_key', e.target.value)} placeholder="base64" />
        </div>
        <div>
          <Label>Private Key（仅服务器保存）</Label>
          <Input value={privKey} onChange={e => setPrivKey(e.target.value)} placeholder="base64" />
        </div>
        <div>
          <div className="flex items-center justify-between">
            <Label>Short ID</Label>
            <button type="button" className="text-xs underline" onClick={() => set('short_id', randHex(8))}>随机</button>
          </div>
          <Input value={form.short_id || ''} onChange={e => set('short_id', e.target.value)} placeholder="8~16 hex" />
        </div>
        <div>
          <div className="flex items-center justify-between">
            <Label>PQ Seed</Label>
            <button type="button" className="text-xs underline" onClick={async () => {
              const { seed, verify } = await API.newMLDSA65()
              setPqSeed(seed)
            }}>生成 Seed</button>
          </div>
          <Input value={pqSeed} onChange={e => setPqSeed(e.target.value)} placeholder="mldsa65 seed (hex)" />
        </div>
      </div>
      <Button disabled={submitting} type="submit">{submitting ? '创建中…' : '创建'}</Button>
    </form>
  )
}

function randHex(n: number) {
  const arr = new Uint8Array(n)
  crypto.getRandomValues(arr)
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')
}

function randomSNI() {
  const list = [
    'www.apple.com', 'www.microsoft.com', 'www.cloudflare.com', 'www.amazon.com', 'www.wikipedia.org', 'www.bing.com', 'www.yahoo.com', 'www.stackoverflow.com', 'www.youtube.com', 'www.spotify.com'
  ]
  return list[Math.floor(Math.random() * list.length)]
}
