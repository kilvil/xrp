import React from 'react'
import { Button } from './components/ui/button'
import Dashboard from './components/Dashboard'
import Tunnels from './components/Tunnels'
import ThemeToggle from './components/ThemeToggle'

function TabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return <Button variant={active ? 'accent' : 'ghost'} onClick={onClick} className="rounded-none">{children}</Button>
}

export default function App() {
  const [tab, setTab] = React.useState<'dash' | 'tunnels' | 'logs' | 'stats' | 'settings'>('dash')
  return (
    <div className="min-h-screen bg-slate-50 text-black dark:bg-zinc-950 dark:text-white">
      <div className="max-w-6xl mx-auto p-4 space-y-4">
        <header className="flex items-center justify-between">
          <h1 className="font-extrabold tracking-wide text-2xl uppercase">XRPS 控制台</h1>
          <nav className="flex gap-2 items-center">
            <TabButton active={tab==='dash'} onClick={() => setTab('dash')}>仪表盘</TabButton>
            <TabButton active={tab==='tunnels'} onClick={() => setTab('tunnels')}>隧道</TabButton>
            <ThemeToggle />
          </nav>
        </header>
        {tab === 'dash' && <Dashboard />}
        {tab === 'tunnels' && <Tunnels />}
      </div>
    </div>
  )
}
