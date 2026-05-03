import { useParams, useNavigate, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowLeft, Shield, FileText, Trash2,
  AlertTriangle, ChevronRight, RefreshCw,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { StatusBadge } from '@/components/common/StatusBadge'
import { ScanProgressLog } from '@/components/common/ScanProgressLog'
import { useScanProgress } from '@/hooks/useScanProgress'
import { scansApi, reportsApi } from '@/lib/api'
import { formatDate, severityColor } from '@/lib/utils'
import { useState } from 'react'

interface Finding {
  id: string
  type: string
  severity: string | null
  title: string
  description: string | null
  cvss_score: string | null
  cve_id: string | null
  port: number | null
  protocol: string | null
  service: string | null
  remediation: string | null
}

interface ScanDetail {
  id: string
  target: string
  scan_type: string
  status: string
  current_phase: string | null
  error_message: string | null
  started_at: string | null
  finished_at: string | null
  created_at: string
  findings_count: number
  findings: Finding[]
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const [generatingReport, setGeneratingReport] = useState(false)
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId!),
    refetchInterval: (query) => {
      const status = query.state.data?.data?.status
      return status === 'running' || status === 'pending' ? 3000 : false
    },
    enabled: !!scanId,
  })

  const scan: ScanDetail | undefined = data?.data

  const isActive = scan?.status === 'running' || scan?.status === 'pending'
  const { logs, status: wsStatus, clear } = useScanProgress(
    scanId ?? null,
    isActive,
  )

  const findings = (scan?.findings ?? []).sort((a, b) => {
    const ai = SEVERITY_ORDER.indexOf(a.severity ?? 'info')
    const bi = SEVERITY_ORDER.indexOf(b.severity ?? 'info')
    return ai - bi
  })

  const severityCounts = findings.reduce<Record<string, number>>((acc, f) => {
    const s = f.severity ?? 'info'
    acc[s] = (acc[s] ?? 0) + 1
    return acc
  }, {})

  async function handleGenerateReport(_lang: 'ru' | 'en' = 'ru') {
    if (!scanId) return
    setGeneratingReport(true)
    try {
      await reportsApi.generate(scanId)
    } catch { /* error shown via toast in future */ }
    finally { setGeneratingReport(false) }
  }

  async function handleDelete() {
    if (!scanId || !confirm('Delete this scan and all its findings?')) return
    await scansApi.delete(scanId)
    navigate('/dashboard/scans')
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-cyber-green border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="text-center py-16">
        <p className="font-mono text-cyber-muted">Scan not found</p>
        <Button variant="ghost" size="sm" className="mt-4" asChild>
          <Link to="/dashboard/scans">← Back</Link>
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Back + header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <button
            onClick={() => navigate(-1)}
            className="flex items-center gap-1.5 text-xs font-mono text-cyber-muted hover:text-cyber-text transition-colors cursor-pointer mb-3"
          >
            <ArrowLeft className="w-3 h-3" />
            BACK
          </button>
          <h1 className="text-lg font-mono font-bold text-cyber-text break-all">{scan.target}</h1>
          <div className="flex items-center gap-3 mt-1">
            <StatusBadge status={scan.status} />
            <span className="text-xs font-mono text-cyber-muted uppercase">{scan.scan_type}</span>
            <span className="text-xs font-mono text-cyber-muted/50">{formatDate(scan.created_at)}</span>
          </div>
          {scan.current_phase && isActive && (
            <p className="text-xs font-mono text-cyber-green mt-1 animate-pulse">
              Phase: {scan.current_phase.toUpperCase()}
            </p>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => refetch()}
            className="p-2 rounded border border-cyber-border text-cyber-muted hover:text-cyber-text hover:border-cyber-green transition-all cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          {scan.status === 'completed' && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleGenerateReport('ru')}
              loading={generatingReport}
            >
              <FileText className="w-3.5 h-3.5" />
              REPORT
            </Button>
          )}
          <Button size="sm" variant="danger" onClick={handleDelete}>
            <Trash2 className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* Error message */}
      {scan.error_message && (
        <div className="flex items-start gap-2 p-3 rounded border border-cyber-red/30 bg-cyber-red/5">
          <AlertTriangle className="w-4 h-4 text-cyber-red shrink-0 mt-0.5" />
          <p className="text-xs font-mono text-cyber-red">{scan.error_message}</p>
        </div>
      )}

      {/* Stats row */}
      {findings.length > 0 && (
        <motion.div
          className="grid grid-cols-5 gap-3"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
        >
          {SEVERITY_ORDER.map((sev) => (
            <div key={sev} className="cyber-card p-3 text-center">
              <p className={`text-2xl font-mono font-bold ${severityColor(sev)}`}>
                {severityCounts[sev] ?? 0}
              </p>
              <p className="text-[10px] font-mono text-cyber-muted uppercase tracking-widest mt-0.5">
                {sev}
              </p>
            </div>
          ))}
        </motion.div>
      )}

      {/* Live log */}
      {(isActive || logs.length > 0) && (
        <ScanProgressLog
          logs={logs}
          status={wsStatus}
          scanStatus={scan.status}
          onClear={clear}
          className="min-h-[280px]"
        />
      )}

      {/* Findings list */}
      {findings.length > 0 && (
        <motion.div
          className="cyber-card"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <div className="flex items-center justify-between p-4 border-b border-cyber-border">
            <h2 className="text-sm font-mono font-semibold text-cyber-text">
              FINDINGS <span className="text-cyber-green">({findings.length})</span>
            </h2>
          </div>

          <div className="divide-y divide-cyber-border">
            {findings.map((f) => (
              <motion.div key={f.id} layout>
                <button
                  className="w-full flex items-center justify-between px-4 py-3 hover:bg-cyber-secondary/30 transition-colors cursor-pointer text-left"
                  onClick={() => setExpandedFinding(expandedFinding === f.id ? null : f.id)}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <StatusBadge status={f.severity ?? 'info'} className="shrink-0" />
                    <div className="min-w-0">
                      <p className="text-sm font-mono text-cyber-text truncate">{f.title}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[10px] font-mono text-cyber-muted uppercase">{f.type}</span>
                        {f.port && (
                          <span className="text-[10px] font-mono text-cyber-muted/60">
                            port {f.port}/{f.protocol}
                          </span>
                        )}
                        {f.cve_id && (
                          <span className="text-[10px] font-mono text-cyber-blue/70">{f.cve_id}</span>
                        )}
                      </div>
                    </div>
                  </div>
                  <ChevronRight
                    className={`w-3.5 h-3.5 text-cyber-muted/40 shrink-0 transition-transform duration-150 ${
                      expandedFinding === f.id ? 'rotate-90' : ''
                    }`}
                  />
                </button>

                {expandedFinding === f.id && (
                  <motion.div
                    className="px-4 pb-4 space-y-3"
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.15 }}
                  >
                    {f.description && (
                      <div>
                        <p className="text-[10px] font-mono text-cyber-muted/50 uppercase tracking-widest mb-1">Description</p>
                        <p className="text-xs font-sans text-cyber-muted leading-relaxed whitespace-pre-wrap">{f.description}</p>
                      </div>
                    )}
                    {f.remediation && (
                      <div className="border-l-2 border-cyber-green/30 pl-3">
                        <p className="text-[10px] font-mono text-cyber-green/50 uppercase tracking-widest mb-1">Remediation</p>
                        <p className="text-xs font-sans text-cyber-muted leading-relaxed">{f.remediation}</p>
                      </div>
                    )}
                    {f.cvss_score && (
                      <p className="text-xs font-mono text-cyber-muted">
                        CVSS: <span className={severityColor(f.severity ?? 'info')}>{f.cvss_score}</span>
                      </p>
                    )}
                  </motion.div>
                )}
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Empty state */}
      {scan.status === 'completed' && findings.length === 0 && (
        <div className="cyber-card p-12 text-center">
          <Shield className="w-8 h-8 text-cyber-green mx-auto mb-3" />
          <p className="font-mono text-sm text-cyber-green">No vulnerabilities found</p>
          <p className="font-mono text-xs text-cyber-muted/50 mt-1">Target appears secure for tested vectors</p>
        </div>
      )}
    </div>
  )
}
