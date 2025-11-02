import React from 'react'
import { Button } from './components/ui/button'
import API from './api'
import LogsViewer from './components/LogsViewer'
import Tunnels from './components/Tunnels'
import ThemeToggle from './components/ThemeToggle'
import { Card } from './components/ui/card'
import Stats from './components/Stats'

export default function App() {
  const [tab, setTab] = React.useState<'status' | 'logs' | 'tunnels' | 'stats'>('tunnels')
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-zinc-950 dark:text-slate-100">
      <div className="max-w-3xl mx-auto p-6 space-y-6">
        <header className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold tracking-tight">XRPC 控制台</h1>
          <nav className="flex gap-2 items-center">
            <Button variant={tab==='status' ? 'secondary' : 'ghost'} onClick={() => setTab('status')}>状态</Button>
            <Button variant={tab==='tunnels' ? 'secondary' : 'ghost'} onClick={() => setTab('tunnels')}>隧道</Button>
            <Button variant={tab==='logs' ? 'secondary' : 'ghost'} onClick={() => setTab('logs')}>日志</Button>
            <Button variant={tab==='stats' ? 'secondary' : 'ghost'} onClick={() => setTab('stats')}>统计</Button>
            <ThemeToggle />
          </nav>
        </header>
        {tab === 'status' && <Status />}
        {tab === 'tunnels' && <Tunnels />}
        {tab === 'logs' && <LogsPanel />}
        {tab === 'stats' && <Stats />}
      </div>
    </div>
  )
}

function Status() {
  const [st, setSt] = React.useState<any>(null)
  React.useEffect(() => {
    API.status().then(setSt)
    const id = setInterval(() => API.status().then(setSt), 4000)
    return () => clearInterval(id)
  }, [])
  return (
    <Card>
      {st ? (
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div><b>Uptime</b>：{st.uptime}</div>
          <div><b>Connected</b>：{String(st.status.connected)}</div>
          <div><b>Reconnects</b>：{st.status.reconnects}</div>
          <div><b>LastError</b>：{st.status.lastError || '—'}</div>
          <div><b>HasProfile</b>：{String(st.status.hasProfile)}</div>
        </div>
      ) : '加载中…'}
    </Card>
  )
}

function LogsPanel() {
  const [logType, setLogType] = React.useState<'access' | 'error'>('access')
  const [restarting, setRestarting] = React.useState(false)
  const [msg, setMsg] = React.useState('')
  const onRestart = async () => {
    try {
      setRestarting(true); setMsg('')
      const res = await API.coreRestart()
      setMsg(res.message || '已触发重启')
    } catch (e: any) {
      setMsg('重启失败：' + e.message)
    } finally {
      setRestarting(false)
    }
  }
  return (
    <Card>
      <div className="flex items-center justify-between mb-2">
        <div className="text-lg font-semibold">实时日志（{logType}）</div>
        <div className="flex gap-2">
          <Button variant={logType==='access' ? 'secondary' : 'ghost'} onClick={() => setLogType('access')}>Access</Button>
          <Button variant={logType==='error' ? 'secondary' : 'ghost'} onClick={() => setLogType('error')}>Error</Button>
          <Button onClick={onRestart} disabled={restarting}>{restarting ? '重启中…' : '重启 Core'}</Button>
        </div>
      </div>
      <LogsViewer makeStream={logType === 'access' ? API.makeAccessLogStream : API.makeErrorLogStream} />
      {msg && <div className="mt-2 text-sm opacity-80">{msg}</div>}
    </Card>
  )
}
