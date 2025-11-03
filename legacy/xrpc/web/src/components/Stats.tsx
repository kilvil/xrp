import React from 'react'
import API from '@/api'
import { Card, CardTitle } from './ui/card'

type Point = { t: number; up: number; down: number }

function formatBps(bps: number) {
  if (bps < 1000) return `${bps.toFixed(0)} B/s`
  const kb = bps / 1024
  if (kb < 1000) return `${kb.toFixed(1)} KiB/s`
  const mb = kb / 1024
  return `${mb.toFixed(2)} MiB/s`
}

function formatBytes(n: number) {
  const abs = Math.abs(n)
  if (abs < 1024) return `${n.toFixed(0)} B`
  const kb = n / 1024
  if (Math.abs(kb) < 1024) return `${kb.toFixed(1)} KiB`
  const mb = kb / 1024
  if (Math.abs(mb) < 1024) return `${mb.toFixed(2)} MiB`
  const gb = mb / 1024
  return `${gb.toFixed(2)} GiB`
}

function LineChart({ points, colorUp = '#4f46e5', colorDown = '#64748b', height = 120 }: { points: Point[]; colorUp?: string; colorDown?: string; height?: number }) {
  const width = 600
  const pad = 8
  const n = points.length
  const xs = points.map((_, i) => pad + (i * (width - pad * 2)) / Math.max(1, n - 1))
  const maxVal = Math.max(1, ...points.map(p => Math.max(p.up, p.down)))
  const y = (v: number) => height - pad - (v / maxVal) * (height - pad * 2)
  const path = (sel: (p: Point) => number) => points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${xs[i]},${y(sel(p))}`).join(' ')
  return (
    <svg width="100%" viewBox={`0 0 ${width} ${height}`}> 
      <polyline fill="none" stroke={colorDown} strokeWidth="2" points={points.map((p,i)=>`${xs[i]},${y(p.down)}`).join(' ')} />
      <polyline fill="none" stroke={colorUp} strokeWidth="2" points={points.map((p,i)=>`${xs[i]},${y(p.up)}`).join(' ')} />
    </svg>
  )
}

export default function Stats() {

  // 历史线图：基于后端 /api/stats/range
  const [win, setWin] = React.useState<number>(5 * 60 * 1000) // 5m
  const [filterId, setFilterId] = React.useState<string>('') // 空=总计
  const [series, setSeries] = React.useState<Point[]>([])
  const [cur, setCur] = React.useState<{up:number,down:number}>({up:0,down:0})
  // 初始填充历史
  React.useEffect(() => {
    let mounted = true
    API.statsRange(Date.now()-win, filterId || undefined).then(r => {
      if (!mounted) return
      const s = r.series.map(p => ({ t: p.ts, up: p.uplink, down: p.downlink }))
      setSeries(s)
      if (s.length) setCur({ up: s[s.length-1].up, down: s[s.length-1].down })
    }).catch(()=>{})
    return () => { mounted = false }
  }, [win, filterId])
  // 通过 WebSocket 追加实时点
  const [wsLast, setWsLast] = React.useState<any>(null)
  // 初始化一次快照用于展示累计
  React.useEffect(() => {
    let mounted = true
    API.statsSnapshot().then(snap => {
      if (!mounted) return
      setWsLast({ ts: snap.ts, bytes: { up: snap.total.uplink, down: snap.total.downlink }, tunnels: (snap.tunnels||[]).map(t=>({ id: t.id, tag: t.tag, entry_port: t.entry_port, up: 0, down: 0, bytesUp: t.uplink, bytesDown: t.downlink })) })
    }).catch(()=>{})
    return () => { mounted = false }
  }, [])
  React.useEffect(() => {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${location.host}/ws/stats`)
    ws.onmessage = (ev) => {
      try {
        const raw = JSON.parse(ev.data)
        const norm = {
          ts: raw.ts as number,
          total: { up: (raw.total?.up ?? raw.total?.Up ?? 0) as number, down: (raw.total?.down ?? raw.total?.Down ?? 0) as number },
          bytes: { up: (raw.bytes?.up ?? raw.bytes?.Up ?? 0) as number, down: (raw.bytes?.down ?? raw.bytes?.Down ?? 0) as number },
          tunnels: ((raw.tunnels as any[]) || []).map(t => ({
            id: t.id ?? t.ID,
            tag: t.tag ?? t.Tag,
            entry_port: t.entry_port ?? t.EntryPort,
            up: t.up ?? t.Up ?? 0,
            down: t.down ?? t.Down ?? 0,
            bytesUp: t.bytesUp ?? t.BytesUp ?? 0,
            bytesDown: t.bytesDown ?? t.BytesDown ?? 0,
          })),
        }
        setWsLast(norm)
        const ts = norm.ts
        let up = norm.total.up, down = norm.total.down
        if (filterId) {
          const it = (norm.tunnels as any[] | undefined)?.find(t => t.id === filterId)
          if (it) { up = it.up ?? 0; down = it.down ?? 0 } else { up = 0; down = 0 }
        }
        setSeries(prev => {
          const next = [...prev, { t: ts, up, down }].filter(p => p.t >= Date.now()-win)
          return next
        })
        setCur({ up, down })
      } catch {}
    }
    return () => { ws.close() }
  }, [win, filterId])

  return (
    <div className="grid gap-4">
      <Card>
        <div className="flex items-center justify-between">
          <CardTitle>速率趋势</CardTitle>
          <div className="flex gap-2 items-center">
            <select className="rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900" value={filterId} onChange={e=>setFilterId(e.target.value)}>
              <option key="all" value="">全部隧道</option>
              {(((wsLast?.tunnels as any[])||[])).map((t: any, idx: number) => (
                <option key={t.id || t.entry_port || t.tag || idx} value={t.id}>{t.tag || t.id}</option>
              ))}
            </select>
            <select className="rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900" value={win} onChange={e=>setWin(Number(e.target.value))}>
              <option key="5m" value={5*60*1000}>近5分钟</option>
              <option key="15m" value={15*60*1000}>近15分钟</option>
              <option key="1h" value={60*60*1000}>近1小时</option>
            </select>
          </div>
        </div>
        <div className="text-sm text-slate-600 dark:text-slate-300">上行：{formatBps(cur.up)} · 下行：{formatBps(cur.down)}</div>
        <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          累计：↑ {formatBytes((wsLast?.bytes?.up)||0)} · ↓ {formatBytes((wsLast?.bytes?.down)||0)} · 合计 {formatBytes(((wsLast?.bytes?.up)||0)+((wsLast?.bytes?.down)||0))}
        </div>
        <div className="mt-2">
          {series.length > 1 ? <LineChart points={series} /> : <div className="text-sm text-slate-500">暂无数据</div>}
        </div>
      </Card>
      <Card>
        <CardTitle>各隧道当前速率</CardTitle>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {(() => {
            const tunnels: any[] = (wsLast?.tunnels as any[]) || []
            return tunnels.map((t: any, idx: number) => (
              <div key={t.id || t.entry_port || t.tag || idx} className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
                <div className="flex items-center justify-between text-sm"><div className="font-medium">{t.tag || t.id}</div><div className="text-xs text-slate-500">入口 {t.entry_port}</div></div>
                <div className="mt-1 text-xs text-slate-600 dark:text-slate-300">↑ {formatBps(t.up || 0)} · ↓ {formatBps(t.down || 0)}</div>
              </div>
            ))
          })()}
        </div>
      </Card>
    </div>
  )
}
