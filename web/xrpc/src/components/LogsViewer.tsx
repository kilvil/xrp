import React from 'react'

export default function LogsViewer({ makeStream }: { makeStream: () => EventSource }) {
  const [lines, setLines] = React.useState<string[]>([])
  React.useEffect(() => {
    const es = makeStream()
    es.onmessage = e => setLines(prev => [...prev.slice(-199), e.data])
    return () => { es.close() }
  }, [makeStream])

  return (
    <div className="bg-white text-black border-4 border-black shadow-[8px_8px_0_rgba(0,0,0,0.9)] p-3 h-72 overflow-auto text-sm dark:bg-zinc-900 dark:text-white dark:border-white dark:shadow-[8px_8px_0_rgba(255,255,255,0.2)]">
      {lines.map((l, i) => <div key={i} className="font-mono whitespace-pre-wrap break-words">{l}</div>)}
    </div>
  )
}
