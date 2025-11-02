import React from 'react'
import { Button } from './components/ui/button'
import API from './api'
import LogsViewer from './components/LogsViewer'
import Tunnels from './components/Tunnels'
import ThemeToggle from './components/ThemeToggle'

export default function App() {
  const [tab, setTab] = React.useState<'status' | 'logs' | 'tunnels'>('tunnels')
  return (
    <div className="min-h-screen bg-slate-50 text-black dark:bg-zinc-950 dark:text-white">
      <div className="max-w-3xl mx-auto p-4 space-y-4">
        <header className="flex items-center justify-between">
          <h1 className="font-extrabold tracking-wide text-2xl uppercase">XRPC 控制台</h1>
          <nav className="flex gap-2 items-center">
            <Button onClick={() => setTab('status')}>状态</Button>
            <Button onClick={() => setTab('tunnels')}>隧道</Button>
            <Button onClick={() => setTab('logs')}>日志</Button>
            <ThemeToggle />
          </nav>
        </header>
        {tab === 'status' && <Status />}
        {tab === 'tunnels' && <Tunnels />}
        {tab === 'logs' && <LogsPanel />}
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
    <div className="bg-white text-black border-4 border-black shadow-[8px_8px_0_rgba(0,0,0,0.9)] p-4 dark:bg-zinc-900 dark:text-white dark:border-white dark:shadow-[8px_8px_0_rgba(255,255,255,0.2)]">
      {st ? (
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div><b>Uptime</b>：{st.uptime}</div>
          <div><b>Connected</b>：{String(st.status.connected)}</div>
          <div><b>Reconnects</b>：{st.status.reconnects}</div>
          <div><b>LastError</b>：{st.status.lastError || '—'}</div>
          <div><b>HasProfile</b>：{String(st.status.hasProfile)}</div>
        </div>
      ) : '加载中…'}
    </div>
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
    <div className="bg-white text-black border-4 border-black shadow-[8px_8px_0_rgba(0,0,0,0.9)] p-4 dark:bg-zinc-900 dark:text-white dark:border-white dark:shadow-[8px_8px_0_rgba(255,255,255,0.2)]">
      <div className="flex items-center justify-between mb-2">
        <div className="font-extrabold tracking-wide text-lg uppercase">实时日志（{logType}）</div>
        <div className="flex gap-2">
          <Button variant={logType==='access' ? 'accent' : 'ghost'} onClick={() => setLogType('access')}>Access</Button>
          <Button variant={logType==='error' ? 'accent' : 'ghost'} onClick={() => setLogType('error')}>Error</Button>
          <Button onClick={onRestart} disabled={restarting}>{restarting ? '重启中…' : '重启 Core'}</Button>
        </div>
      </div>
      <LogsViewer makeStream={logType === 'access' ? API.makeAccessLogStream : API.makeErrorLogStream} />
      {msg && <div className="mt-2 text-sm opacity-80">{msg}</div>}
    </div>
  )
}
