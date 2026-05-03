import { useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Terminal, Wifi, WifiOff, Loader, Trash2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { LogEntry } from '@/hooks/useScanProgress'

const LEVEL_STYLES: Record<string, { text: string; prefix: string }> = {
  info:    { text: 'text-cyber-muted',  prefix: '[*]' },
  success: { text: 'text-cyber-green',  prefix: '[+]' },
  warning: { text: 'text-yellow-400',   prefix: '[!]' },
  error:   { text: 'text-cyber-red',    prefix: '[-]' },
}

function StatusDot({ status }: { status: string }) {
  if (status === 'connected')
    return (
      <span className="flex items-center gap-1.5 text-cyber-green text-[10px] font-mono">
        <Wifi className="w-3 h-3" />
        LIVE
        <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
      </span>
    )
  if (status === 'connecting')
    return (
      <span className="flex items-center gap-1.5 text-yellow-400 text-[10px] font-mono">
        <Loader className="w-3 h-3 animate-spin" />
        CONNECTING
      </span>
    )
  return (
    <span className="flex items-center gap-1.5 text-cyber-muted text-[10px] font-mono">
      <WifiOff className="w-3 h-3" />
      {status.toUpperCase()}
    </span>
  )
}

function LogLine({ entry }: { entry: LogEntry & { _id?: number } }) {
  const style = LEVEL_STYLES[entry.level] ?? LEVEL_STYLES.info
  const time  = new Date(entry.ts).toLocaleTimeString('en-GB', { hour12: false })

  return (
    <motion.div
      className="flex gap-2 text-xs font-mono leading-5 group"
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.15 }}
    >
      <span className="text-cyber-muted/40 shrink-0 select-none w-16">{time}</span>
      {entry.module && (
        <span className="text-cyber-blue/70 shrink-0 w-16 truncate">[{entry.module}]</span>
      )}
      <span className={cn('shrink-0 select-none', style.text)}>{style.prefix}</span>
      <span className={cn('break-all', style.text)}>{entry.message}</span>
    </motion.div>
  )
}

interface ScanProgressLogProps {
  logs: LogEntry[]
  status: string
  scanStatus: string
  onClear: () => void
  className?: string
}

export function ScanProgressLog({
  logs,
  status,
  scanStatus,
  onClear,
  className,
}: ScanProgressLogProps) {
  const bottomRef = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const autoScrollRef = useRef(true)

  // Auto-scroll only if user hasn't scrolled up
  useEffect(() => {
    if (autoScrollRef.current) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs])

  function handleScroll() {
    const el = containerRef.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
    autoScrollRef.current = atBottom
  }

  const isActive = scanStatus === 'running' || scanStatus === 'pending'

  return (
    <div className={cn('cyber-card flex flex-col', className)}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-cyber-border shrink-0">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-cyber-green" />
          <span className="text-xs font-mono text-cyber-text tracking-widest">SCAN LOG</span>
          {logs.length > 0 && (
            <span className="text-[10px] font-mono text-cyber-muted/50">({logs.length})</span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <StatusDot status={isActive ? status : 'disconnected'} />
          {logs.length > 0 && (
            <button
              onClick={onClear}
              className="p-1 rounded text-cyber-muted hover:text-cyber-red transition-colors cursor-pointer"
              title="Clear logs"
            >
              <Trash2 className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Log body */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto p-4 space-y-0.5 min-h-[200px] max-h-[420px]"
        style={{ fontVariantLigatures: 'none' }}
      >
        {logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-2">
            {isActive ? (
              <>
                <Loader className="w-5 h-5 text-cyber-muted/30 animate-spin" />
                <p className="text-xs font-mono text-cyber-muted/40">Waiting for scan output...</p>
              </>
            ) : (
              <p className="text-xs font-mono text-cyber-muted/40">No logs available</p>
            )}
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {logs.map((entry, i) => (
              <LogLine key={i} entry={entry} />
            ))}
          </AnimatePresence>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Typing cursor when active */}
      {isActive && status === 'connected' && (
        <div className="px-4 py-1.5 border-t border-cyber-border/50">
          <span className="text-xs font-mono text-cyber-green/50">
            {'> '}
            <motion.span
              className="inline-block w-2 h-3 bg-cyber-green/60 align-middle ml-0.5"
              animate={{ opacity: [1, 0] }}
              transition={{ duration: 0.7, repeat: Infinity, repeatType: 'reverse' }}
            />
          </span>
        </div>
      )}
    </div>
  )
}
