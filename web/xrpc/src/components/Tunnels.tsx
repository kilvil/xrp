import React from 'react'
import API, { TunnelState } from '../api'
import { Button } from './ui/button'
import { Textarea } from './ui/textarea'
import { Plus } from 'lucide-react'

export default function Tunnels() {
  const [list, setList] = React.useState<TunnelState[]>([])
  const [loading, setLoading] = React.useState(false)
  const [showAdd, setShowAdd] = React.useState(false)
  const [base64, setBase64] = React.useState('')
  const [msg, setMsg] = React.useState('')
  const load = React.useCallback(async () => {
    setLoading(true)
    try {
      setList(await API.listTunnels())
    } finally {
      setLoading(false)
    }
  }, [])
  React.useEffect(() => { load() }, [load])

  const onDelete = async (id: string) => {
    await API.deleteTunnel(id)
    await load()
  }
  const onEditTarget = async (it: TunnelState) => {
    const cur = it.target || (it.map_port ? String(it.map_port) : '')
    const v = window.prompt('设置出口目标（host:port 或 端口号）', cur)
    if (!v) return
    await API.patchTunnel(it.id, { target: v.trim() })
    await load()
  }
  const onToggleActive = async (it: TunnelState) => {
    await API.patchTunnel(it.id, { active: !it.active })
    await load()
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="font-extrabold tracking-wide text-xl uppercase">隧道列表 {loading && '…'}</h2>
        <div className="flex gap-2">
          <Button onClick={load}>刷新</Button>
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
          <div key={it.id} className="bg-white text-black border-4 border-black shadow-[8px_8px_0_rgba(0,0,0,0.9)] p-3 dark:bg-zinc-900 dark:text-white dark:border-white dark:shadow-[8px_8px_0_rgba(255,255,255,0.2)]">
            <div className="flex items-center justify-between">
              <div className="font-semibold">{it.tag}</div>
              <span className={
                'text-xs px-2 py-0.5 border-2 rounded-none ' +
                (it.status === 'connected' ? 'border-green-700 text-green-700' : 'border-zinc-700 text-zinc-700')
              }>{it.status}</span>
            </div>
            <div className="mt-2 grid grid-cols-2 gap-1 text-sm">
              <div>
                入口：
                {it.entry_port > 0 ? (
                  <a
                    href={`//${window.location.hostname}:${it.entry_port}`}
                    target="_blank"
                    rel="noreferrer"
                    className="underline font-mono hover:-translate-y-0.5 inline-block"
                    title="打开隧道入口"
                  >
                    {window.location.hostname}:{it.entry_port}
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
              <Button onClick={() => onEditTarget(it)}>编辑出口</Button>
              <Button onClick={() => onToggleActive(it)}>{it.active ? '禁用' : '启用'}</Button>
              <Button className="bg-red-300 hover:-translate-y-0.5" onClick={() => onDelete(it.id)}>删除</Button>
            </div>
          </div>
        ))}
      </div>

      {showAdd && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/40" onClick={() => setShowAdd(false)} />
          <div className="relative w-full max-w-xl bg-white text-black border-4 border-black shadow-[8px_8px_0_rgba(0,0,0,0.9)] p-4 rounded-none dark:bg-zinc-900 dark:text-white dark:border-white dark:shadow-[8px_8px_0_rgba(255,255,255,0.2)]">
            <div className="flex items-center justify-between mb-2">
              <div className="font-extrabold tracking-wide text-lg uppercase">新建隧道</div>
              <button onClick={() => setShowAdd(false)} className="px-2 py-1 border-2 border-black dark:border-white">×</button>
            </div>
            <div className="text-sm mb-2">粘贴来自 XRPS 的 Base64 连接参数：</div>
            <Textarea className="h-40" value={base64} onChange={e => setBase64(e.target.value)} />
            <div className="mt-3 flex gap-2">
              <Button onClick={async () => {
                try {
                  setMsg('应用中…')
                  await API.applyBase64(base64.trim())
                  setMsg('已应用，正在加载隧道…')
                  await load()
                  setShowAdd(false)
                  setBase64('')
                } catch (e: any) {
                  setMsg('失败：' + e.message)
                }
              }}>应用</Button>
              <Button onClick={() => setBase64('')}>清空</Button>
            </div>
            {msg && <div className="mt-2 text-sm">{msg}</div>}
          </div>
        </div>
      )}
    </div>
  )
}
