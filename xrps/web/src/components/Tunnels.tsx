import React from 'react'
import API, { CreateTunnelReq, Tunnel } from '../api'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Textarea } from './ui/textarea'
import { Label } from './ui/label'
import { Card, CardTitle } from './ui/card'
import { Dialog, DialogBody, DialogClose, DialogContent, DialogHeader, DialogTitle } from './ui/dialog'
// Checkbox removed as forward proxy feature is removed

export default function Tunnels() {
  const [list, setList] = React.useState<Tunnel[]>([])
  const [loading, setLoading] = React.useState(false)
  const [selected, setSelected] = React.useState<Tunnel | null>(null)
  // Cache connection params per tunnel ID; control per-entry collapsibles
  const [paramsByTunnel, setParamsByTunnel] = React.useState<Record<string, { json: string; base64: string }>>({})
  const [entryOpen, setEntryOpen] = React.useState<Record<string, boolean>>({})
  const [entryJsonOpen, setEntryJsonOpen] = React.useState<Record<string, boolean>>({})
  const [showCreate, setShowCreate] = React.useState(false)

  const load = React.useCallback(async () => {
    setLoading(true)
    try { setList(await API.listTunnels()) } finally { setLoading(false) }
  }, [])
  React.useEffect(() => { load() }, [load])

  const onSelect = async (id: string) => {
    const t = await API.getTunnel(id)
    setSelected(t)
    // keep cache; collapse entry sections when switching
    setEntryOpen({})
    setEntryJsonOpen({})
  }

  const onDelete = async (id: string) => {
    await API.deleteTunnel(id)
    setSelected(null)
    setEntryOpen({})
    setEntryJsonOpen({})
    await load()
  }

  const ensureParams = async (tid: string) => {
    if (paramsByTunnel[tid]) return paramsByTunnel[tid]
    const p = await API.genParams(tid)
    setParamsByTunnel(prev => ({ ...prev, [tid]: p }))
    return p
  }

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div className="space-y-4">
        <Card>
          <div className="flex items-center justify-between">
            <CardTitle className="m-0">隧道列表 {loading && '…'}</CardTitle>
            <Button onClick={() => setShowCreate(true)}>新建隧道</Button>
          </div>
          <div className="space-y-2">
            {list.map(t => (
              <div key={t.id} className="flex items-center justify-between rounded-lg border border-slate-200 bg-white p-3 shadow-sm text-slate-900 dark:bg-slate-900 dark:text-slate-100 dark:border-slate-800">
                <div>
                  <div className="font-medium">{t.name || t.id}</div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">{t.portal_addr} · HS {t.handshake.port} · {t.entries.length} entries</div>
                </div>
                <div className="flex gap-2">
                  <Button variant="secondary" onClick={() => onSelect(t.id)}>详情</Button>
                  <Button variant="ghost" onClick={() => onDelete(t.id)}>删除</Button>
                </div>
              </div>
            ))}
            {list.length === 0 && <div className="text-sm opacity-70">暂无隧道，点击右上角“新建隧道”。</div>}
          </div>
        </Card>
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>创建隧道</DialogTitle>
              <DialogClose />
            </DialogHeader>
            <DialogBody>
              <TunnelForm onCreated={t => { setSelected(t); setShowCreate(false); load() }} />
            </DialogBody>
          </DialogContent>
        </Dialog>
      </div>

      <div className="space-y-4">
        <Card>
          <CardTitle>隧道详情</CardTitle>
          {!selected && <div className="text-sm opacity-70">选择左侧列表中的一条隧道。</div>}
          {selected && (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div><span className="whitespace-nowrap"><b>ID</b>：</span>{selected.id}</div>
                <div><span className="whitespace-nowrap"><b>名称</b>：</span>{selected.name}</div>
                <div><span className="whitespace-nowrap"><b>Portal</b>：</span>{selected.portal_addr}</div>
                <div><span className="whitespace-nowrap"><b>HS 端口</b>：</span>{selected.handshake.port}</div>
                <div><span className="whitespace-nowrap"><b>SNI</b>：</span>{selected.handshake.serverName}</div>
                <div className="flex items-center gap-2">
                  <span className="whitespace-nowrap"><b>加密</b>：</span>
                  {selected.handshake.encryption && selected.handshake.encryption.startsWith('mlkem768x25519plus.') ? (
                    <span className="inline-flex items-center rounded border border-emerald-300 bg-emerald-50 px-2 py-0.5 text-xs text-emerald-700 dark:border-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300">PQ: ML-KEM-768 已设置</span>
                  ) : (
                    <span className="inline-flex items-center rounded border border-slate-300 bg-slate-50 px-2 py-0.5 text-xs text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">none</span>
                  )}
                  {selected.handshake.encryption && (
                    <Button variant="ghost" onClick={() => navigator.clipboard.writeText(selected.handshake.encryption)}>复制</Button>
                  )}
                </div>
              </div>
              <div className="space-y-2">
                <div className="font-semibold">传输入口端口</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {selected.entries.map(e => (
                    <div key={e.id} className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm dark:bg-slate-900 dark:border-slate-800">
                      <div className="text-sm"><b>{e.tag}</b> → 入口 {e.entry_port}</div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">UUID {e.id}</div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">出口需在 XRPC 手动设置（默认 127.0.0.1:80）</div>
                      <div className="mt-2 border-t border-slate-200 pt-2 dark:border-slate-800">
                        <div className="flex items-center gap-2">
                          <Button
                            variant="secondary"
                            onClick={async () => {
                              if (!selected) return
                              await ensureParams(selected.id)
                              setEntryOpen(prev => ({ ...prev, [e.id]: !prev[e.id] }))
                            }}
                          >连接参数</Button>
                          {entryOpen[e.id] && (
                            <Button
                              variant="ghost"
                              onClick={() => setEntryJsonOpen(prev => ({ ...prev, [e.id]: !prev[e.id] }))}
                            >{entryJsonOpen[e.id] ? '收起 JSON' : '展开 JSON'}</Button>
                          )}
                        </div>
                        {entryOpen[e.id] && selected && paramsByTunnel[selected.id] && (
                          <div className="mt-2 space-y-2">
                            <div className="flex items-center gap-2">
                              <div className="text-xs font-medium">Base64</div>
                              <div className="flex-1 truncate font-mono text-xs text-slate-600 dark:text-slate-300">{paramsByTunnel[selected.id].base64}</div>
                              <Button variant="ghost" onClick={() => navigator.clipboard.writeText(paramsByTunnel[selected.id].base64)}>复制</Button>
                            </div>
                            {entryJsonOpen[e.id] && (
                              <Textarea className="h-28 font-mono" value={paramsByTunnel[selected.id].json} readOnly />
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
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
    name: 'tunnel' + randHex(6),
    portal_addr: (typeof window !== 'undefined' ? window.location.hostname : 'localhost'),
    handshake_port: 9443,
    server_name: 'www.fandom.com',
    // Align with backend: default to none; advanced PQ must start with mlkem768x25519plus.
    encryption: 'none',
    entry_ports: [31234, 31235],
  })
  const [submitting, setSubmitting] = React.useState(false)
  const [privKey, setPrivKey] = React.useState('')
  // Support PQ per backend policy: none or mlkem768x25519plus.*
  const [encryptionMode, setEncryptionMode] = React.useState<'none' | 'custom'>('none')
  const [customEnc, setCustomEnc] = React.useState<string>('')
  const [pqAlgo, setPqAlgo] = React.useState<'pq' | 'x25519'>('pq')
  const [genPair, setGenPair] = React.useState<{ decryption: string; encryption: string } | null>(null)
  const [showEncAdv, setShowEncAdv] = React.useState(false)

  const set = (k: keyof CreateTunnelReq, v: any) => setForm(s => ({ ...s, [k]: v }))
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    try {
      // attach server-side decryption only when we have a generated pair for PQ
      const dec = (encryptionMode === 'custom' && customEnc.startsWith('mlkem768x25519plus.') && genPair?.decryption) ? genPair.decryption : undefined
      const payload: CreateTunnelReq = { ...form, private_key: privKey || undefined, decryption: dec }
      const t = await API.createTunnel(payload)
      onCreated(t)
      // Clear sensitive key from UI state after successful submit
      setPrivKey('')
    } finally {
      setSubmitting(false)
    }
  }

  // client-side basic validation and port conflict checks
  const errors = React.useMemo(() => {
    const errs: string[] = []
    const inRange = (p: number) => p > 0 && p <= 65535
    if (!inRange(form.handshake_port)) errs.push('Handshake 端口必须在 1-65535')
    if (!form.server_name.trim()) errs.push('SNI 不能为空')
    if (!privKey.trim()) errs.push('需要 Private Key（可点击上方“生成密钥对”）')
    if (!form.entry_ports.length) errs.push('至少需要一个传输端口')
    const seen = new Set<number>()
    for (const p of form.entry_ports) {
      if (!inRange(p)) errs.push(`传输端口 ${p} 必须在 1-65535`)
      if (seen.has(p)) errs.push(`传输端口重复：${p}`)
      seen.add(p)
    }
    if (form.entry_ports.includes(form.handshake_port)) errs.push('Handshake 端口不能与传输端口相同')
    return errs
  }, [form])

  return (
    <form onSubmit={submit} className="space-y-3">
      <div className="flex flex-col gap-3">
        <div>
          <Label className="whitespace-nowrap">名称</Label>
          <Input value={form.name} onChange={e => set('name', e.target.value)} />
        </div>
        <div>
          <Label className="whitespace-nowrap">Portal 地址</Label>
          <Input value={form.portal_addr} onChange={e => set('portal_addr', e.target.value)} />
        </div>
        <div>
          <Label className="whitespace-nowrap">Handshake 端口</Label>
          <Input type="number" min={1} max={65535} value={form.handshake_port} onChange={e => set('handshake_port', Number(e.target.value))} />
        </div>
        <div>
          <div className="flex items-center justify-between">
            <Label className="whitespace-nowrap">SNI</Label>
            <button type="button" className="text-xs underline whitespace-nowrap" onClick={() => set('server_name', randomSNI())}>随机</button>
          </div>
          <Input value={form.server_name} onChange={e => set('server_name', e.target.value)} />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <Label className="m-0 whitespace-nowrap">加密</Label>
            <select
              className="flex-1 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-600 focus-visible:border-indigo-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
              value={encryptionMode}
              onChange={e => {
                const mode = e.target.value as 'none' | 'custom'
                setEncryptionMode(mode)
                if (mode === 'none') {
                  set('encryption', 'none')
                  setGenPair(null)
                } else {
                  const next = customEnc || 'mlkem768x25519plus.'
                  setCustomEnc(next)
                  set('encryption', next)
                }
              }}
            >
              <option value="none">none</option>
              <option value="custom">自定义/生成（X25519 或 后量子 ML-KEM-768）</option>
            </select>
          </div>
          {encryptionMode === 'custom' && (
            <div className="mt-2 space-y-2">
              <div className="flex items-center gap-2">
                <Label className="m-0 whitespace-nowrap">算法</Label>
                <select
                  className="flex-1 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-600 focus-visible:border-indigo-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                  value={pqAlgo}
                  onChange={e => setPqAlgo(e.target.value as 'pq' | 'x25519')}
                >
                  <option value="pq">ML-KEM-768（后量子）</option>
                  <option value="x25519">X25519（非PQ）</option>
                </select>
                <Button className="whitespace-nowrap" type="button" variant="secondary" onClick={async () => {
                  try {
                    const pair = await API.genVlessEnc(pqAlgo)
                    setGenPair({ decryption: pair.decryption, encryption: pair.encryption })
                    setCustomEnc(pair.encryption)
                    set('encryption', pair.encryption)
                  } catch (e) { console.error(e) }
                }}>生成 enc/dec</Button>
              </div>
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center rounded border border-indigo-300 bg-indigo-50 px-2 py-0.5 text-xs text-indigo-700 dark:border-indigo-800 dark:bg-indigo-900/40 dark:text-indigo-300">
                  {genPair?.encryption ? (pqAlgo === 'pq' ? '已生成 · ML-KEM-768' : '已生成 · X25519') : (customEnc ? '已设置自定义值' : '未生成')}
                </span>
                {genPair?.decryption && <Button className="whitespace-nowrap" type="button" variant="ghost" onClick={() => navigator.clipboard.writeText(genPair.decryption)}>复制 decryption</Button>}
                {(genPair?.encryption || customEnc) && <Button className="whitespace-nowrap" type="button" variant="ghost" onClick={() => navigator.clipboard.writeText(genPair?.encryption || customEnc)}>复制 encryption</Button>}
                <Button className="whitespace-nowrap" type="button" variant="ghost" onClick={() => setShowEncAdv(v => !v)}>{showEncAdv ? '收起详情' : '展开详情'}</Button>
              </div>
              {showEncAdv && (
                <>
                  <Input
                    value={customEnc}
                    onChange={e => {
                      const v = e.target.value
                      setCustomEnc(v)
                      set('encryption', v)
                    }}
                    placeholder="mlkem768x25519plus.your-params"
                  />
                  {!customEnc.startsWith('mlkem768x25519plus.') && (
                    <div className="text-xs text-red-600 dark:text-red-400">
                      需要以 mlkem768x25519plus. 开头，示例：mlkem768x25519plus.xyz
                    </div>
                  )}
                  {genPair && (
                    <div className="mt-2 grid gap-2">
                      <div>
                        <div className="text-xs font-medium mb-1">decryption（服务端入站）</div>
                        <Textarea className="h-16 font-mono" value={genPair.decryption} readOnly />
                        <div className="mt-1"><Button type="button" variant="ghost" onClick={() => navigator.clipboard.writeText(genPair.decryption)}>复制</Button></div>
                      </div>
                      <div>
                        <div className="text-xs font-medium mb-1">encryption（客户端出站/XRPC）</div>
                        <Textarea className="h-16 font-mono" value={genPair.encryption} readOnly />
                        <div className="mt-1"><Button type="button" variant="ghost" onClick={() => navigator.clipboard.writeText(genPair.encryption)}>复制</Button></div>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
        <div>
          <Label className="whitespace-nowrap">传输端口</Label>
          <div className="mt-1 space-y-2">
            {form.entry_ports.map((p, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <Input
                  type="number"
                  min={1}
                  max={65535}
                  placeholder="1-65535"
                  value={p === 0 ? '' as any : p}
                  onChange={e => {
                    const v = e.target.value
                    const n = v === '' ? 0 : Number(v)
                    set('entry_ports', form.entry_ports.map((pp, i) => i === idx ? n : pp))
                  }}
                />
                <Button className="whitespace-nowrap" type="button" variant="secondary" onClick={() => set('entry_ports', [...form.entry_ports, 0])}>＋</Button>
                <Button className="whitespace-nowrap" type="button" variant="ghost" onClick={() => set('entry_ports', form.entry_ports.filter((_, i) => i !== idx))} disabled={form.entry_ports.length <= 1}>－</Button>
              </div>
            ))}
          </div>
        </div>
        {/* 正向代理功能已移除 */}
      </div>
      <div className="flex flex-col gap-3">
        <div className="font-semibold whitespace-nowrap">REALITY 设置</div>
        <div>
          <div className="flex items-center justify-between">
            <Label className="whitespace-nowrap">Public Key</Label>
            <button type="button" className="text-xs underline whitespace-nowrap" onClick={async () => {
              const { publicKey, privateKey } = await API.newX25519()
              set('public_key', publicKey)
              setPrivKey(privateKey)
            }}>生成密钥对</button>
          </div>
          <Input value={form.public_key || ''} onChange={e => set('public_key', e.target.value)} placeholder="base64url(32 bytes)" />
        </div>
        <div>
          <Label className="whitespace-nowrap">Private Key（仅服务器保存）</Label>
          <Input value={privKey} onChange={e => setPrivKey(e.target.value)} placeholder="base64url(32 bytes)" />
          </div>
        <div>
          <div className="flex items-center justify-between">
            <Label className="whitespace-nowrap">Short ID</Label>
            <button type="button" className="text-xs underline whitespace-nowrap" onClick={() => set('short_id', randHex(8))}>随机</button>
          </div>
          <Input value={form.short_id || ''} onChange={e => set('short_id', e.target.value)} placeholder="8~16 hex" />
        </div>
      </div>
      {(() => {
        const encValid = encryptionMode === 'none' || (customEnc && customEnc.startsWith('mlkem768x25519plus.'))
        return (
          <div className="space-y-2">
            {errors.length > 0 && (
              <div className="text-sm text-red-600 dark:text-red-400">
                {errors.map((e, i) => (<div key={i}>• {e}</div>))}
              </div>
            )}
            <Button className="whitespace-nowrap" disabled={submitting || !encValid || errors.length > 0} type="submit">{submitting ? '创建中…' : '创建'}</Button>
          </div>
        )
      })()}
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
