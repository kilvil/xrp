import React from 'react'
import API, { CreateInboundReq, InboundTunnel } from '../api'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Textarea } from './ui/textarea'
import { Label } from './ui/label'
import { Card, CardTitle } from './ui/card'
import { Dialog, DialogBody, DialogClose, DialogContent, DialogHeader, DialogTitle } from './ui/dialog'
import { copyText } from '../lib/utils'

export default function InboundTunnels() {
  const [list, setList] = React.useState<InboundTunnel[]>([])
  const [loading, setLoading] = React.useState(false)
  const [selected, setSelected] = React.useState<InboundTunnel | null>(null)
  const [paramsByTunnel, setParamsByTunnel] = React.useState<Record<string, { json: string; base64: string }>>({})
  const [entryOpen, setEntryOpen] = React.useState<Record<string, boolean>>({})
  const [entryJsonOpen, setEntryJsonOpen] = React.useState<Record<string, boolean>>({})
  const [showCreate, setShowCreate] = React.useState(false)

  const load = React.useCallback(async () => {
    setLoading(true)
    try { setList(await API.inbound.listTunnels()) } finally { setLoading(false) }
  }, [])
  React.useEffect(() => { load() }, [load])

  const onSelect = async (id: string) => {
    const t = await API.inbound.getTunnel(id)
    setSelected(t)
    setEntryOpen({}); setEntryJsonOpen({})
  }

  const onDelete = async (id: string) => {
    await API.inbound.deleteTunnel(id)
    setSelected(null); setEntryOpen({}); setEntryJsonOpen({})
    await load()
  }

  const ensureParams = async (tid: string) => {
    if (paramsByTunnel[tid]) return paramsByTunnel[tid]
    const p = await API.inbound.genParams(tid)
    setParamsByTunnel(prev => ({ ...prev, [tid]: p }))
    return p
  }

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div className="space-y-4">
        <Card>
          <div className="flex items-center justify-between pb-2">
            <CardTitle className="m-0">入口隧道列表 {loading && '…'}</CardTitle>
            <Button onClick={() => setShowCreate(true)}>新建入口隧道</Button>
          </div>
          <div className="space-y-2">
            {list.map(t => (
              <div key={t.id} className="flex items-center justify-between rounded-lg border border-slate-200 bg-white p-3 shadow-sm text-slate-900 dark:bg-slate-900 dark:text-slate-100 dark:border-slate-800">
                <div>
                  <div className="font-medium">{t.name || t.id}</div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">{t.portal_addr || '—'} · HS {t.handshake.port} · {t.entries.length} entries</div>
                </div>
                <div className="flex gap-2">
                  <Button variant="secondary" onClick={() => onSelect(t.id)}>详情</Button>
                  <Button variant="ghost" onClick={() => onDelete(t.id)}>删除</Button>
                </div>
              </div>
            ))}
            {list.length === 0 && <div className="text-sm opacity-70">暂无入口隧道，点击右上角“新建入口隧道”。</div>}
          </div>
        </Card>
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>创建入口隧道</DialogTitle>
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
          <CardTitle>入口隧道详情</CardTitle>
          {!selected && <div className="text-sm opacity-70">选择左侧列表中的一条隧道。</div>}
          {selected && (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div><span className="whitespace-nowrap"><b>ID</b>：</span>{selected.id}</div>
                <div><span className="whitespace-nowrap"><b>名称</b>：</span>{selected.name}</div>
                <div><span className="whitespace-nowrap"><b>Portal</b>：</span>{selected.portal_addr || '—'}</div>
                <div><span className="whitespace-nowrap"><b>HS 端口</b>：</span>{selected.handshake.port}</div>
                <div><span className="whitespace-nowrap"><b>SNI</b>：</span>{selected.handshake.serverName}</div>
                <div className="flex items-center gap-2">
                  <span className="whitespace-nowrap"><b>加密</b>：</span>
                  {selected.handshake.encryption && selected.handshake.encryption.startsWith('mlkem768x25519plus.') ? (
                    <span className="inline-flex items-center rounded border border-emerald-300 bg-emerald-50 px-2 py-0.5 text-xs text-emerald-700 ring-1 ring-emerald-600/20">PQ</span>
                  ) : (
                    <span className="inline-flex items-center rounded border border-slate-300 bg-slate-50 px-2 py-0.5 text-xs text-slate-700 ring-1 ring-slate-600/20">none</span>
                  )}
                </div>
                <div><span className="whitespace-nowrap"><b>PublicKey</b>：</span><span className="font-mono break-all">{selected.handshake.publicKey || '—'}</span></div>
                <div><span className="whitespace-nowrap"><b>ShortID</b>：</span><span className="font-mono break-all">{selected.handshake.shortId || '—'}</span></div>
              </div>
              <div>
                <div className="text-sm font-medium mb-1">入口列表</div>
                <div className="space-y-2">
                  {selected.entries.map(e => (
                    <div key={e.id} className="rounded border border-slate-200 dark:border-slate-800 p-2">
                      <div className="flex items-center justify-between text-sm">
                        <div className="font-medium">{e.tag} · 端口 {e.entry_port}</div>
                        <div className="flex gap-2">
                          <Button variant="secondary" onClick={async () => {
                            const p = await ensureParams(selected.id)
                            await copyText(p.base64)
                            alert('已复制 Base64 连接参数')
                          }}>复制 Base64</Button>
                          <Button variant="secondary" onClick={async () => {
                            const p = await ensureParams(selected.id)
                            await copyText(p.json)
                            alert('已复制 JSON 连接参数')
                          }}>复制 JSON</Button>
                          <Button variant="ghost" onClick={() => setEntryJsonOpen(v => ({ ...v, [e.id]: !v[e.id] }))}>{entryJsonOpen[e.id] ? '收起' : '展开'}</Button>
                        </div>
                      </div>
                      {entryJsonOpen[e.id] && (
                        <div className="mt-2">
                          <Textarea className="h-40 font-mono" value={(paramsByTunnel[selected.id]?.json)||''} readOnly />
                        </div>
                      )}
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

function TunnelForm({ onCreated }: { onCreated: (t: InboundTunnel) => void }) {
  // defaults per legacy: name = tunnel+randHex(6), portal = window.hostname, SNI prefilled
  const [name, setName] = React.useState('tunnel' + randHex(6))
  const [portal, setPortal] = React.useState(typeof window !== 'undefined' ? window.location.hostname : '')
  const [hsPort, setHsPort] = React.useState(9443)
  const [sni, setSni] = React.useState('www.fandom.com')
  const [entryPorts, setEntryPorts] = React.useState<number[]>([31234, 31235])
  const [pub, setPub] = React.useState('')
  const [sid, setSid] = React.useState('')
  const [priv, setPriv] = React.useState('')
  const [busy, setBusy] = React.useState(false)
  const [msg, setMsg] = React.useState('')

  // encryption selector (none / PQ), with backend generator
  const [encMode, setEncMode] = React.useState<'none' | 'pq'>('none')
  const [customEnc, setCustomEnc] = React.useState('')
  const [genPair, setGenPair] = React.useState<{ decryption: string; encryption: string } | null>(null)
  const [showEncAdv, setShowEncAdv] = React.useState(false)

  const onGenKey = async () => {
    try {
      const kp = await API.newX25519()
      setPub(kp.publicKey); setPriv(kp.privateKey)
    } catch (e: any) { setMsg(e.message || '生成密钥失败') }
  }

  const onGenPQ = async () => {
    try {
      const pair = await API.genVlessEnc('pq')
      setGenPair({ decryption: pair.decryption, encryption: pair.encryption })
      setCustomEnc(pair.encryption)
    } catch (e: any) { setMsg(e.message || '生成加密参数失败') }
  }

  const onCreate = async () => {
    const encValue = encMode === 'none' ? 'none' : (customEnc || genPair?.encryption || '')
    const decValue = encMode === 'none' ? undefined : (genPair?.decryption || undefined)
    const payload: CreateInboundReq = {
      name: name.trim(), portal_addr: portal.trim(), handshake_port: Number(hsPort), server_name: sni.trim(), encryption: encValue,
      decryption: decValue,
      entry_ports: entryPorts.filter(p => Number(p) > 0), public_key: pub.trim() || undefined, short_id: sid.trim() || undefined, private_key: priv.trim(),
    }
    setBusy(true); setMsg('')
    try { const t = await API.inbound.createTunnel(payload); onCreated(t) } catch (e: any) { setMsg(e.message || '创建失败') } finally { setBusy(false) }
  }

  // validation similar to legacy
  const errors = React.useMemo(() => {
    const errs: string[] = []
    const inRange = (p: number) => p > 0 && p <= 65535
    if (!inRange(hsPort)) errs.push('Handshake 端口必须在 1-65535')
    if (!sni.trim()) errs.push('SNI 不能为空')
    if (!priv.trim()) errs.push('需要 Private Key（点击“生成密钥对”）')
    const ports = entryPorts.filter(p => Number(p) > 0)
    if (ports.length === 0) errs.push('至少需要一个传输端口')
    const seen = new Set<number>()
    for (const p of ports) {
      if (!inRange(p)) errs.push(`传输端口 ${p} 必须在 1-65535`)
      if (seen.has(p)) errs.push(`传输端口重复：${p}`)
      seen.add(p)
    }
    if (ports.includes(hsPort)) errs.push('Handshake 端口不能与传输端口相同')
    if (encMode === 'pq' && !(customEnc || genPair?.encryption)) errs.push('请选择或生成后量子加密参数')
    return errs
  }, [hsPort, sni, priv, entryPorts, encMode, customEnc, genPair])

  const encValid = encMode === 'none' || (customEnc || genPair?.encryption)

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <Label className="whitespace-nowrap">名称</Label>
            <button type="button" className="text-xs underline whitespace-nowrap" onClick={() => setName('tunnel' + randHex(6))}>随机</button>
          </div>
          <Input value={name} onChange={e=>setName(e.target.value)} placeholder="可选" />
        </div>
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <Label className="whitespace-nowrap">Portal</Label>
            <button type="button" className="text-xs underline whitespace-nowrap" onClick={() => setPortal(typeof window !== 'undefined' ? window.location.hostname : portal)}>自动</button>
          </div>
          <Input value={portal} onChange={e=>setPortal(e.target.value)} placeholder="IP 或域名" />
        </div>
        <div className="space-y-1">
          <Label>HS 端口</Label>
          <Input type="number" min={1} max={65535} value={hsPort} onChange={e=>setHsPort(Number(e.target.value))} placeholder="9443" />
        </div>
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <Label>SNI</Label>
            <button type="button" className="text-xs underline whitespace-nowrap" onClick={() => setSni(randomSNI())}>随机</button>
          </div>
          <Input value={sni} onChange={e=>setSni(e.target.value)} placeholder="server name" />
        </div>
        <div className="space-y-1 col-span-2">
          <div className="flex items-center gap-2">
            <Label className="m-0 whitespace-nowrap">加密</Label>
            <select
              className="flex-1 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-600 focus-visible:border-indigo-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
              value={encMode}
              onChange={e => { const v = e.target.value as 'none'|'pq'; setEncMode(v) }}
            >
              <option value="none">none（无加密）</option>
              <option value="pq">后量子（ML-KEM-768）</option>
            </select>
            {encMode === 'pq' && (
              <Button className="whitespace-nowrap" type="button" variant="secondary" onClick={onGenPQ}>生成 enc/dec</Button>
            )}
          </div>
          {encMode === 'pq' && (
            <div className="mt-2 space-y-2">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center rounded border border-indigo-300 bg-indigo-50 px-2 py-0.5 text-xs text-indigo-700 dark:border-indigo-800 dark:bg-indigo-900/40 dark:text-indigo-300">
                  {genPair?.encryption ? '已生成 · ML-KEM-768' : (customEnc ? '已设置自定义值' : '未生成')}
                </span>
                {genPair?.decryption && <Button className="whitespace-nowrap" type="button" variant="ghost" onClick={() => copyText(genPair.decryption)}>复制 decryption</Button>}
                {(genPair?.encryption || customEnc) && <Button className="whitespace-nowrap" type="button" variant="ghost" onClick={() => copyText(genPair?.encryption || customEnc)}>复制 encryption</Button>}
                <Button className="whitespace-nowrap" type="button" variant="ghost" onClick={() => setShowEncAdv(v => !v)}>{showEncAdv ? '收起详情' : '展开详情'}</Button>
              </div>
              {showEncAdv && (
                <>
                  <Input
                    value={customEnc}
                    onChange={e => setCustomEnc(e.target.value)}
                    placeholder="mlkem768x25519plus.…"
                  />
                  {!customEnc.startsWith('mlkem768x25519plus.') && !genPair?.encryption && (
                    <div className="text-xs text-red-600 dark:text-red-400">需要以 mlkem768x25519plus. 开头，或点击上方生成</div>
                  )}
                  {genPair && (
                    <div className="mt-2 grid gap-2">
                      <div>
                        <div className="text-xs font-medium mb-1">decryption（服务端入站）</div>
                        <Textarea className="h-16 font-mono" value={genPair.decryption} readOnly />
                        <div className="mt-1"><Button type="button" variant="ghost" onClick={() => copyText(genPair.decryption)}>复制</Button></div>
                      </div>
                      <div>
                        <div className="text-xs font-medium mb-1">encryption（客户端出站/XRPC）</div>
                        <Textarea className="h-16 font-mono" value={genPair.encryption} readOnly />
                        <div className="mt-1"><Button type="button" variant="ghost" onClick={() => copyText(genPair.encryption)}>复制</Button></div>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
        <div className="space-y-1 col-span-2">
          <Label className="whitespace-nowrap">传输端口</Label>
          <div className="mt-1 space-y-2">
            {entryPorts.map((p, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <Input
                  type="number"
                  min={1}
                  max={65535}
                  placeholder="1-65535"
                  value={p === 0 ? ('' as any) : p}
                  onChange={e => {
                    const v = e.target.value
                    const n = v === '' ? 0 : Number(v)
                    setEntryPorts(entryPorts.map((pp, i) => (i === idx ? n : pp)))
                  }}
                />
                <Button className="whitespace-nowrap" type="button" variant="secondary" onClick={() => setEntryPorts([...entryPorts, 0])}>＋</Button>
                <Button className="whitespace-nowrap" type="button" variant="ghost" onClick={() => setEntryPorts(entryPorts.filter((_, i) => i !== idx))} disabled={entryPorts.length <= 1}>－</Button>
              </div>
            ))}
          </div>
        </div>
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <Label>Public Key</Label>
            <button type="button" className="text-xs underline whitespace-nowrap" onClick={onGenKey}>生成密钥对</button>
          </div>
          <Input value={pub} onChange={e=>setPub(e.target.value)} placeholder="可选，留空将根据私钥推导" />
        </div>
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <Label>Short ID</Label>
            <button type="button" className="text-xs underline whitespace-nowrap" onClick={() => setSid(randHex(8))}>随机</button>
          </div>
          <Input value={sid} onChange={e=>setSid(e.target.value)} placeholder="8~16 hex" />
        </div>
        <div className="space-y-1 col-span-2">
          <Label>Private Key（base64url 32B）</Label>
          <Input value={priv} onChange={e=>setPriv(e.target.value)} placeholder="必填" />
        </div>
      </div>
      <div className="space-y-2">
        {errors.length > 0 && (
          <div className="text-sm text-red-600 dark:text-red-400">
            {errors.map((e, i) => (<div key={i}>• {e}</div>))}
          </div>
        )}
        <div className="flex gap-2">
          <Button onClick={onCreate} disabled={busy || !encValid || errors.length > 0}>{busy ? '创建中…' : '创建'}</Button>
          <Button variant="secondary" onClick={() => { setName('tunnel' + randHex(6)); setPortal(typeof window !== 'undefined' ? window.location.hostname : ''); setHsPort(9443); setSni('www.fandom.com'); setEncMode('none'); setCustomEnc(''); setGenPair(null); setShowEncAdv(false); setEntryPorts([31234,31235]); setPub(''); setSid(''); setPriv('') }}>重置</Button>
        </div>
      </div>
      {msg && <div className="text-sm opacity-80">{msg}</div>}
    </div>
  )
}

function randHex(n: number) {
  const arr = new Uint8Array(n)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(arr)
  } else {
    for (let i = 0; i < n; i++) arr[i] = Math.floor(Math.random() * 256)
  }
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')
}

function randomSNI() {
  const list = [
    'www.apple.com', 'www.microsoft.com', 'www.cloudflare.com', 'www.amazon.com', 'www.wikipedia.org', 'www.bing.com', 'www.yahoo.com', 'www.stackoverflow.com', 'www.youtube.com', 'www.spotify.com'
  ]
  return list[Math.floor(Math.random() * list.length)]
}
