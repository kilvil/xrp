import React from 'react'
import { Button } from './components/ui/button'
import Dashboard from './components/Dashboard'
import Tunnels from './components/Tunnels'
import Stats from './components/Stats'
import ThemeToggle from './components/ThemeToggle'

function TabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return <Button variant={active ? 'secondary' : 'ghost'} onClick={onClick}>{children}</Button>
}

export default function App() {
  const [tab, setTab] = React.useState<'dash' | 'tunnels' | 'logs' | 'stats' | 'settings'>('dash')
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-zinc-950 dark:text-slate-100">
      <div className="max-w-6xl mx-auto p-6 space-y-6">
        <header className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold tracking-tight">XRPS 控制台</h1>
          <nav className="flex gap-2 items-center">
            <TabButton active={tab==='dash'} onClick={() => setTab('dash')}>仪表盘</TabButton>
            <TabButton active={tab==='tunnels'} onClick={() => setTab('tunnels')}>隧道</TabButton>
            <Button variant={tab==='stats' ? 'secondary' : 'ghost'} onClick={() => setTab('stats')}>统计</Button>
            <ThemeToggle />
          </nav>
        </header>
        {tab === 'dash' && <Dashboard />}
        {tab === 'tunnels' && <Tunnels />}
        {tab === 'stats' && <Stats />}
      </div>
    </div>
  )
}
