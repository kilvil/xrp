import React from 'react'
import { Button } from './components/ui/button'
import ThemeToggle from './components/ThemeToggle'
import InboundTunnels from './components/InboundTunnels'
import OutboundTunnels from './components/OutboundTunnels'
import LogsViewer from './components/LogsViewer'
import API from './api'
import Stats from './components/Stats'
import ConfigViewer from './components/ConfigViewer'

function TabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return <Button variant={active ? 'secondary' : 'ghost'} onClick={onClick}>{children}</Button>
}

export default function App() {
  const [tab, setTab] = React.useState<'inbound' | 'outbound' | 'logs' | 'stats' | 'config'>('inbound')
  // Trigger browser basic auth prompt by loading a protected resource in an offscreen iframe
  React.useEffect(() => {
    const id = setTimeout(() => {
      const ifr = document.createElement('iframe')
      ifr.src = '/status'
      ifr.style.position = 'absolute'
      ifr.style.width = '1px'
      ifr.style.height = '1px'
      ifr.style.opacity = '0'
      ifr.style.pointerEvents = 'none'
      document.body.appendChild(ifr)
      // cleanup later (after prompt completes)
      setTimeout(() => { try { ifr.remove() } catch {} }, 8000)
    }, 50)
    return () => clearTimeout(id)
  }, [])

  const [logType, setLogType] = React.useState<'access' | 'error'>('access')
  const [restarting, setRestarting] = React.useState(false)
  const onRestart = async () => {
    try {
      setRestarting(true)
      await API.core.restart()
    } catch (e: any) {
      window.alert(`重启失败：${e?.message || e}`)
    } finally {
      setRestarting(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-zinc-950 dark:text-slate-100">
      <div className="max-w-6xl mx-auto p-6 space-y-6">
        <header className="flex items-center gap-3 justify-between">
          <h1 className="text-2xl font-semibold tracking-tight">XRP 控制台</h1>
          <nav className="flex gap-2 items-center">
            <TabButton active={tab==='inbound'} onClick={() => setTab('inbound')}>入口</TabButton>
            <TabButton active={tab==='outbound'} onClick={() => setTab('outbound')}>出口</TabButton>
            <TabButton active={tab==='logs'} onClick={() => setTab('logs')}>日志</TabButton>
            <TabButton active={tab==='stats'} onClick={() => setTab('stats')}>统计</TabButton>
            <TabButton active={tab==='config'} onClick={() => setTab('config')}>配置</TabButton>
            <ThemeToggle />
          </nav>
        </header>
        <div className="flex items-center gap-2">
          <Button variant="secondary" onClick={onRestart} disabled={restarting}>{restarting ? '正在重启…' : '重启 Xray'}</Button>
          <a className="ml-auto underline text-sm" href="/status" target="_blank" rel="noreferrer">重新验证</a>
          <a className="underline text-sm" href="/healthz" target="_blank" rel="noreferrer">healthz</a>
        </div>
        {tab === 'inbound' && <InboundTunnels />}
        {tab === 'outbound' && <OutboundTunnels />}
        {tab === 'logs' && (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Button variant={logType==='access' ? 'secondary' : 'ghost'} onClick={() => setLogType('access')}>Access</Button>
              <Button variant={logType==='error' ? 'secondary' : 'ghost'} onClick={() => setLogType('error')}>Error</Button>
              <Button variant="secondary" onClick={() => {/* stream is live */}}>实时</Button>
            </div>
            <LogsViewer makeStream={logType === 'access' ? API.logs.makeAccessLogStream : API.logs.makeErrorLogStream} />
          </div>
        )}
        {tab === 'stats' && <Stats />}
        {tab === 'config' && <ConfigViewer />}
      </div>
    </div>
  )
}
