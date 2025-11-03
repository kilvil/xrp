import React from 'react'
import API from '../api'

export default function ConfigViewer() {
  const [cfg, setCfg] = React.useState<{ path: string; content: string } | null>(null)
  const [err, setErr] = React.useState<string>('')
  const [Editor, setEditor] = React.useState<React.FC<any> | null>(null)

  React.useEffect(() => {
    API.config.get().then(setCfg).catch(e => setErr(e.message || String(e)))
  }, [])

  React.useEffect(() => {
    let mounted = true
    import('@monaco-editor/react').then(mod => {
      if (mounted) setEditor(() => mod.default as any)
    }).catch(() => {})
    return () => { mounted = false }
  }, [])

  if (err) return <div className="text-sm text-rose-600">读取配置失败：{err}</div>
  if (!cfg) return <div className="text-sm opacity-70">加载配置中…</div>

  return (
    <div className="space-y-3">
      <div className="text-sm">文件路径：<span className="font-mono">{cfg.path}</span></div>
      {Editor ? (
        <Editor
          height="70vh"
          defaultLanguage="json"
          theme={document.documentElement.classList.contains('dark') ? 'vs-dark' : 'light'}
          options={{ readOnly: true, minimap: { enabled: false }, wordWrap: 'on' }}
          value={cfg.content}
        />
      ) : (
        <pre className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs overflow-auto dark:bg-slate-950 dark:border-slate-800">{cfg.content}</pre>
      )}
    </div>
  )
}

