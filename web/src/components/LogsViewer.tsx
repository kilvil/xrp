import React from 'react'

type Props = { makeStream: () => EventSource }

export default function LogsViewer({ makeStream }: Props) {
  const [lines, setLines] = React.useState<string[]>([])
  React.useEffect(() => {
    const es = makeStream()
    const onMsg = (e: MessageEvent) => setLines(prev => [...prev.slice(-199), e.data])
    es.onmessage = onMsg
    return () => { es.close() }
  }, [makeStream])

  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 h-80 overflow-auto text-sm dark:bg-slate-950 dark:border-slate-800">
      {lines.map((l, i) => (
        <div key={i} className="font-mono whitespace-pre-wrap break-words text-slate-800 dark:text-slate-200">{l}</div>
      ))}
    </div>
  )
}

