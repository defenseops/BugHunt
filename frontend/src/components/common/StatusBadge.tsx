import { cn } from '@/lib/utils'

const map: Record<string, { label: string; cls: string; dot: string }> = {
  pending:   { label: 'PENDING',   cls: 'text-cyber-muted border-cyber-muted/30',  dot: 'bg-cyber-muted' },
  running:   { label: 'RUNNING',   cls: 'text-cyber-blue border-cyber-blue/30',    dot: 'bg-cyber-blue animate-pulse' },
  completed: { label: 'COMPLETED', cls: 'text-cyber-green border-cyber-green/30',  dot: 'bg-cyber-green' },
  failed:    { label: 'FAILED',    cls: 'text-cyber-red border-cyber-red/30',      dot: 'bg-cyber-red' },
  critical:  { label: 'CRITICAL',  cls: 'text-red-400 border-red-400/30',          dot: 'bg-red-400' },
  high:      { label: 'HIGH',      cls: 'text-orange-400 border-orange-400/30',    dot: 'bg-orange-400' },
  medium:    { label: 'MEDIUM',    cls: 'text-yellow-400 border-yellow-400/30',    dot: 'bg-yellow-400' },
  low:       { label: 'LOW',       cls: 'text-blue-400 border-blue-400/30',        dot: 'bg-blue-400' },
  info:      { label: 'INFO',      cls: 'text-cyber-muted border-cyber-muted/30',  dot: 'bg-cyber-muted' },
}

interface StatusBadgeProps {
  status: string
  className?: string
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const s = map[status.toLowerCase()] ?? { label: status.toUpperCase(), cls: 'text-cyber-muted border-cyber-muted/30', dot: 'bg-cyber-muted' }
  return (
    <span className={cn('inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-mono rounded border', s.cls, className)}>
      <span className={cn('w-1.5 h-1.5 rounded-full', s.dot)} />
      {s.label}
    </span>
  )
}
