import React from 'react'
import API, { OutboundTunnelState } from '../api'
import { Button } from './ui/button'
import { Textarea } from './ui/textarea'
import { Plus } from 'lucide-react'

export default function OutboundTunnels() {
  const [list, setList] = React.useState<OutboundTunnelState[]>([])
  const [loading, setLoading] = React.useState(false)
  const [showAdd, setShowAdd] = React.useState(false)
  const [base64, setBase64] = React.useState('')
  const [msg, setMsg] = React.useState('')
  const [portalAddr, setPortalAddr] = React.useState<string>(typeof window !== 'undefined' ? window.location.hostname : '')

  const load = React.useCallback(async () => {
    setLoading(true)
    try {
      const data = await API.outbound.listTunnels()
      const sorted = [...data].sort((a, b) => {
        const an = (a.tag || a.id || '').toString()
        const bn = (b.tag || b.id || '').toString()
        return an.localeCompare(bn, undefined, { sensitivity: 'base', numeric: true })
      })
      setList(sorted)
    } finally {
      setLoading(false)
    }
  }, [])
  React.useEffect(() => { load() }, [load])
  // auto-refresh list periodically to reflect live connection status
  React.useEffect(() => {
    const id = setInterval(() => { load().catch(() => {}) }, 5000)
    return () => clearInterval(id)
  }, [load])

  const onDelete = async (id: string) => { await API.outbound.deleteTunnel(id); await load() }
  const onEditTarget = async (it: OutboundTunnelState) => {
    const cur = it.target || (it.map_port ? String(it.map_port) : '')
    const v = window.prompt('设置出口目标（host:port 或 端口号）', cur)
    if (!v) return
    await API.outbound.patchTunnel(it.id, { target: v.trim() })
    await load()
  }
  const onToggleActive = async (it: OutboundTunnelState) => { await API.outbound.patchTunnel(it.id, { active: !it.active }); await load() }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">出口隧道列表 {loading && '…'}</h2>
        <div className="flex gap-2">
          <Button variant="secondary" onClick={load}>刷新</Button>
          <Button onClick={() => { setShowAdd(true); setMsg(''); }}>
            <Plus className="w-4 h-4 inline mr-1" /> 新建
          </Button>
        </div>
      </div>
      {list.length === 0 && (
        <div className="opacity-70 text-sm">暂无隧道，点击右上角 “新建” 粘贴 Base64 配置。</div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {list.map(it => (
          <div key={it.id} className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm text-slate-900 dark:bg-slate-900 dark:text-slate-100 dark:border-slate-800">
            <div className="flex items-center justify-between">
              <div className="font-medium">{it.tag}</div>
              {(() => {
                const st = it.status || 'unknown'
                const cls = st === 'connected'
                  ? 'bg-green-50 text-green-700 ring-green-600/20'
                  : 'bg-slate-100 text-slate-700 ring-slate-600/20'
                return <span className={'text-xs px-2 py-0.5 rounded-full ring-1 ring-inset ' + cls}>{st}</span>
              })()}
            </div>
            <div className="mt-2 grid grid-cols-2 gap-1 text-sm">
              <div>
                入口：
                {it.entry_port > 0 ? (
                  <a
                    href={`//${portalAddr}:${it.entry_port}`}
                    target="_blank"
                    rel="noreferrer"
                    className="underline font-mono text-indigo-600 hover:text-indigo-500 inline-block"
                    title="打开隧道入口"
                  >
                    {portalAddr}:{it.entry_port}
                  </a>
                ) : (
                  <span>-</span>
                )}
              </div>
              <div className="col-span-2">出口（目标）：{it.target || '-'}</div>
              <div>启用：{String(it.active)}</div>
              <div className="col-span-2 opacity-70 text-xs">ID：{it.id}</div>
            </div>
            <div className="mt-3 flex gap-2">
              <Button variant="secondary" onClick={() => onEditTarget(it)}>编辑出口</Button>
              <Button variant="secondary" onClick={() => onToggleActive(it)}>{it.active ? '禁用' : '启用'}</Button>
              <Button variant="danger" onClick={() => onDelete(it.id)}>删除</Button>
            </div>
          </div>
        ))}
      </div>

      {showAdd && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/40" onClick={() => setShowAdd(false)} />
          <div className="relative w-full max-w-xl rounded-lg border border-slate-200 bg-white p-4 shadow-lg text-slate-900 dark:bg-slate-900 dark:text-slate-100 dark:border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <div className="text-lg font-semibold">新建隧道</div>
              <button onClick={() => setShowAdd(false)} className="inline-flex items-center justify-center h-8 w-8 rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-800">×</button>
            </div>
            <div className="text-sm mb-2">粘贴来自入口端的 Base64 连接参数：</div>
            <Textarea className="h-40" value={base64} onChange={e => setBase64(e.target.value)} />
            <div className="mt-3 flex gap-2">
              <Button onClick={async () => {
                try {
                  const prev = new Set(list.map(it => it.id))
                  setMsg('应用中…')
                  await API.outbound.applyBase64(base64.trim())
                  setMsg('已应用，正在加载隧道…')
                  const data = await API.outbound.listTunnels()
                  const sorted = [...data].sort((a, b) => {
                    const an = (a.tag || a.id || '').toString()
                    const bn = (b.tag || b.id || '').toString()
                    return an.localeCompare(bn, undefined, { sensitivity: 'base', numeric: true })
                  })
                  setList(sorted)
                  for (const it of sorted) {
                    if (!prev.has(it.id)) {
                      const def = '127.0.0.1:80'
                      const v = window.prompt(`为隧道 ${it.tag || it.id} 设置出口目标（host:port）`, def)
                      if (v && v.trim()) { try { await API.outbound.patchTunnel(it.id, { target: v.trim() }) } catch {} }
                    }
                  }
                  setShowAdd(false); setBase64('')
                } catch (e: any) { setMsg('失败：' + e.message) }
              }}>应用</Button>
              <Button variant="secondary" onClick={() => setBase64('')}>清空</Button>
            </div>
            {msg && <div className="mt-2 text-sm">{msg}</div>}
          </div>
        </div>
      )}
    </div>
  )
}
