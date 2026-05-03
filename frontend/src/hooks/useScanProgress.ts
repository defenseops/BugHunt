import { useEffect, useRef, useState, useCallback } from 'react'

export interface LogEntry {
  ts: string
  level: 'info' | 'success' | 'warning' | 'error'
  module: string | null
  message: string
}

type WsStatus = 'connecting' | 'connected' | 'disconnected' | 'error'

interface UseScanProgressReturn {
  logs: LogEntry[]
  status: WsStatus
  clear: () => void
}

const WS_BASE = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`
const MAX_LOGS = 500
const RECONNECT_DELAY_MS = 3000

export function useScanProgress(
  scanId: string | null,
  enabled: boolean = true,
): UseScanProgressReturn {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [status, setStatus] = useState<WsStatus>('disconnected')
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const enabledRef = useRef(enabled)
  enabledRef.current = enabled

  const clear = useCallback(() => setLogs([]), [])

  const connect = useCallback(() => {
    if (!scanId || !enabledRef.current) return

    // Clean up existing connection
    if (wsRef.current) {
      wsRef.current.onclose = null
      wsRef.current.close()
    }

    const url = `${WS_BASE}/ws/scans/${scanId}/progress`
    setStatus('connecting')
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => setStatus('connected')

    ws.onmessage = (event) => {
      try {
        const entry: LogEntry = JSON.parse(event.data)
        setLogs((prev) => {
          const next = [...prev, entry]
          return next.length > MAX_LOGS ? next.slice(-MAX_LOGS) : next
        })
      } catch {
        // plain text fallback
        setLogs((prev) => [
          ...prev,
          { ts: new Date().toISOString(), level: 'info', module: null, message: event.data },
        ])
      }
    }

    ws.onerror = () => setStatus('error')

    ws.onclose = () => {
      setStatus('disconnected')
      if (enabledRef.current) {
        reconnectRef.current = setTimeout(connect, RECONNECT_DELAY_MS)
      }
    }
  }, [scanId])

  useEffect(() => {
    if (!enabled || !scanId) {
      wsRef.current?.close()
      setStatus('disconnected')
      return
    }
    connect()
    return () => {
      enabledRef.current = false
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
      wsRef.current?.onclose && (wsRef.current.onclose = null)
      wsRef.current?.close()
    }
  }, [scanId, enabled, connect])

  return { logs, status, clear }
}
