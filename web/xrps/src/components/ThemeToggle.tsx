import React from 'react'

function getInitial(): boolean {
  if (typeof localStorage !== 'undefined' && localStorage.getItem('theme') === 'dark') return true
  if (typeof localStorage !== 'undefined' && localStorage.getItem('theme') === 'light') return false
  return typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
}

export default function ThemeToggle() {
  const [dark, setDark] = React.useState(getInitial())
  React.useEffect(() => {
    const root = document.documentElement
    if (dark) {
      root.classList.add('dark')
      localStorage.setItem('theme', 'dark')
    } else {
      root.classList.remove('dark')
      localStorage.setItem('theme', 'light')
    }
  }, [dark])
  return (
    <button
      onClick={() => setDark(v => !v)}
      className="px-3 py-2 border-4 border-black dark:border-white bg-white dark:bg-zinc-900 text-black dark:text-white shadow-[6px_6px_0_rgba(0,0,0,0.9)] dark:shadow-[6px_6px_0_rgba(255,255,255,0.2)] rounded-none text-sm"
      title="切换主题"
    >
      {dark ? '🌙' : '🌞'}
    </button>
  )
}

