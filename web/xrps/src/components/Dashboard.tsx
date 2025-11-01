import React from 'react'
import API from '../api'
import LogsViewer from './LogsViewer'
import { Card, CardTitle } from './ui/card'

export default function Dashboard() {
  const [status, setStatus] = React.useState<any>(null)
  React.useEffect(() => {
    API.status().then(setStatus)
    const id = setInterval(() => API.status().then(setStatus), 5000)
    return () => clearInterval(id)
  }, [])
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardTitle>运行状态</CardTitle>
        {status ? (
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div><b>Uptime</b>：{status.uptime}</div>
            <div><b>隧道数</b>：{status.tunnels}</div>
            <div><b>时间</b>：{status.now}</div>
          </div>
        ) : (
          <div className="text-sm opacity-70">加载中…</div>
        )}
      </Card>
      <Card>
        <CardTitle>实时日志</CardTitle>
        <LogsViewer makeStream={API.makeLogStream} />
      </Card>
    </div>
  )
}
