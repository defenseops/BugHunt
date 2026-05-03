import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(iso: string) {
  return new Intl.DateTimeFormat('ru-RU', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  }).format(new Date(iso))
}

export function severityColor(severity: string) {
  const map: Record<string, string> = {
    critical: 'text-red-400',
    high:     'text-orange-400',
    medium:   'text-yellow-400',
    low:      'text-blue-400',
    info:     'text-cyber-muted',
  }
  return map[severity.toLowerCase()] ?? 'text-cyber-muted'
}

export function statusColor(status: string) {
  const map: Record<string, string> = {
    pending:   'text-cyber-muted',
    running:   'text-cyber-blue',
    completed: 'text-cyber-green',
    failed:    'text-cyber-red',
  }
  return map[status.toLowerCase()] ?? 'text-cyber-muted'
}
