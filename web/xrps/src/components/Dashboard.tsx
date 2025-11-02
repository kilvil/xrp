import React from 'react'
import API from '../api'
import LogsViewer from './LogsViewer'
import { Card, CardTitle } from './ui/card'
import { Button } from './ui/button'

export default function Dashboard() {
  const [status, setStatus] = React.useState<any>(null)
  const [logType, setLogType] = React.useState<'access' | 'error'>('access')
  const [restarting, setRestarting] = React.useState(false)
  const [msg, setMsg] = React.useState('')
  React.useEffect(() => {
    API.status().then(setStatus)
    const id = setInterval(() => API.status().then(setStatus), 5000)
    return () => clearInterval(id)
  }, [])
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
        <div className="flex items-center justify-between">
          <CardTitle>实时日志（{logType === 'access' ? 'access' : 'error'}）</CardTitle>
          <div className="flex gap-2">
            <Button variant={logType==='access' ? 'accent' : 'ghost'} onClick={() => setLogType('access')}>Access</Button>
            <Button variant={logType==='error' ? 'accent' : 'ghost'} onClick={() => setLogType('error')}>Error</Button>
            <Button onClick={onRestart} disabled={restarting}>{restarting ? '重启中…' : '重启 Core'}</Button>
          </div>
        </div>
        <LogsViewer makeStream={logType === 'access' ? API.makeAccessLogStream : API.makeErrorLogStream} />
        {msg && <div className="mt-2 text-sm opacity-80">{msg}</div>}
      </Card>
    </div>
  )
}
