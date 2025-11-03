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
      className="inline-flex items-center rounded-md border border-slate-200 bg-white px-3 py-2 text-sm text-slate-600 hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-600 focus-visible:ring-offset-2 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
      title="切换主题"
    >
      {dark ? '🌙' : '🌞'}
    </button>
  )
}

