import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowLeft, Shield, FileText, Trash2, AlertTriangle,
  ChevronRight, RefreshCw, ExternalLink, Terminal,
  Globe, Network, Search, Zap,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { StatusBadge } from '@/components/common/StatusBadge'
import { ScanProgressLog } from '@/components/common/ScanProgressLog'
import { useScanProgress } from '@/hooks/useScanProgress'
import { scansApi, reportsApi } from '@/lib/api'
import { cn, formatDate, severityColor } from '@/lib/utils'

// ── Types ──────────────────────────────────────────────────────────────────

interface Finding {
  id: string
  type: string
  severity: string | null
  title: string
  description: string | null
  evidence: string | null
  cvss_score: string | null
  cvss_vector: string | null
  cve_id: string | null
  port: number | null
  protocol: string | null
  service: string | null
  version: string | null
  remediation: string | null
  msf_module: string | null
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

// ── Constants ──────────────────────────────────────────────────────────────

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_BG: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info:     'bg-cyber-secondary text-cyber-muted border-cyber-border',
}

// ── Small helpers ──────────────────────────────────────────────────────────

function CvssBadge({ score, vector }: { score: string | null; vector?: string | null }) {
  if (!score) return null
  const n = parseFloat(score)
  const sev = n >= 9 ? 'critical' : n >= 7 ? 'high' : n >= 4 ? 'medium' : 'low'
  return (
    <span
      title={vector ?? undefined}
      className={cn('inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border', SEVERITY_BG[sev])}
    >
      CVSS {n.toFixed(1)}
    </span>
  )
}

function CveLink({ cveId }: { cveId: string | null }) {
  if (!cveId) return null
  return (
    <a
      href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-0.5 text-[10px] font-mono text-cyber-blue/70 hover:text-cyber-blue transition-colors"
      onClick={(e) => e.stopPropagation()}
    >
      {cveId}
      <ExternalLink className="w-2.5 h-2.5" />
    </a>
  )
}

function MsfTag({ module }: { module: string | null }) {
  if (!module) return null
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-400 border border-purple-500/25">
      <Terminal className="w-2.5 h-2.5" />
      {module.split('/').slice(-1)[0]}
    </span>
  )
}

// ── Finding card ───────────────────────────────────────────────────────────

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false)
  const isAttackPath = f.type === 'attack_path'

  return (
    <motion.div layout className={cn(isAttackPath && 'border-l-2 border-orange-500/50')}>
      <button
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-cyber-secondary/30 transition-colors cursor-pointer text-left"
        onClick={() => setOpen(!open)}
      >
        <div className="flex items-center gap-3 min-w-0 flex-1">
          <StatusBadge status={f.severity ?? 'info'} className="shrink-0" />
          <div className="min-w-0 flex-1">
            <p className="text-sm font-mono text-cyber-text truncate">{f.title}</p>
            <div className="flex flex-wrap items-center gap-2 mt-1">
              <span className="text-[10px] font-mono text-cyber-muted/50 uppercase">{f.type}</span>
              {f.port && (
                <span className="text-[10px] font-mono text-cyber-muted/60">
                  :{f.port}/{f.protocol}
                </span>
              )}
              {f.service && (
                <span className="text-[10px] font-mono text-cyber-muted/60">{f.service}</span>
              )}
              <CveLink cveId={f.cve_id} />
              <CvssBadge score={f.cvss_score} vector={f.cvss_vector} />
              <MsfTag module={f.msf_module} />
            </div>
          </div>
        </div>
        <ChevronRight
          className={cn(
            'w-3.5 h-3.5 text-cyber-muted/40 shrink-0 transition-transform duration-150',
            open && 'rotate-90',
          )}
        />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            className="px-4 pb-4 space-y-3 border-t border-cyber-border/50"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.15 }}
          >
            {f.description && (
              <div className="pt-3">
                <p className="text-[10px] font-mono text-cyber-muted/50 uppercase tracking-widest mb-1.5">
                  Description
                </p>
                <p className="text-xs font-sans text-cyber-muted leading-relaxed whitespace-pre-wrap">
                  {f.description}
                </p>
              </div>
            )}

            {f.evidence && (
              <div>
                <p className="text-[10px] font-mono text-cyber-muted/50 uppercase tracking-widest mb-1.5">Evidence</p>
                <pre className="text-[10px] font-mono text-cyber-muted/80 bg-cyber-primary/60 p-2 rounded overflow-x-auto whitespace-pre-wrap break-all">
                  {f.evidence}
                </pre>
              </div>
            )}

            {f.remediation && (
              <div className="border-l-2 border-cyber-green/30 pl-3">
                <p className="text-[10px] font-mono text-cyber-green/50 uppercase tracking-widest mb-1">
                  Remediation
                </p>
                <p className="text-xs font-sans text-cyber-muted leading-relaxed">{f.remediation}</p>
              </div>
            )}

            <div className="flex flex-wrap gap-3 pt-1">
              {f.cvss_score && (
                <div>
                  <p className="text-[10px] font-mono text-cyber-muted/50 uppercase tracking-widest mb-0.5">CVSS</p>
                  <CvssBadge score={f.cvss_score} vector={f.cvss_vector} />
                  {f.cvss_vector && (
                    <p className="text-[9px] font-mono text-cyber-muted/40 mt-0.5 break-all">{f.cvss_vector}</p>
                  )}
                </div>
              )}
              {f.msf_module && (
                <div>
                  <p className="text-[10px] font-mono text-cyber-muted/50 uppercase tracking-widest mb-0.5">MSF Module</p>
                  <span className="text-[10px] font-mono text-purple-400">{f.msf_module}</span>
                </div>
              )}
              {f.version && (
                <div>
                  <p className="text-[10px] font-mono text-cyber-muted/50 uppercase tracking-widest mb-0.5">Version</p>
                  <span className="text-[10px] font-mono text-cyber-muted">{f.version}</span>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

// ── Port table ─────────────────────────────────────────────────────────────

function PortsTable({ findings }: { findings: Finding[] }) {
  const ports = findings.filter((f) => f.type === 'port' || f.type === 'service')
  if (!ports.length) return <EmptyTab icon={<Network className="w-6 h-6" />} label="No port findings" />
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="border-b border-cyber-border text-[10px] text-cyber-muted/50 uppercase tracking-widest">
            <th className="text-left px-4 py-2">Port</th>
            <th className="text-left px-4 py-2">Protocol</th>
            <th className="text-left px-4 py-2">Service</th>
            <th className="text-left px-4 py-2">Version</th>
            <th className="text-left px-4 py-2">Severity</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-cyber-border/50">
          {ports.map((f) => (
            <tr key={f.id} className="hover:bg-cyber-secondary/20 transition-colors">
              <td className="px-4 py-2.5 text-cyber-green font-bold">{f.port ?? '—'}</td>
              <td className="px-4 py-2.5 text-cyber-muted/60 uppercase">{f.protocol ?? 'tcp'}</td>
              <td className="px-4 py-2.5 text-cyber-text">{f.service ?? '—'}</td>
              <td className="px-4 py-2.5 text-cyber-muted/60">{f.version ?? '—'}</td>
              <td className="px-4 py-2.5">
                <span className={cn('px-1.5 py-0.5 rounded text-[10px] border', SEVERITY_BG[f.severity ?? 'info'])}>
                  {f.severity ?? 'info'}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Attack paths ───────────────────────────────────────────────────────────

function AttackPathCard({ f }: { f: Finding }) {
  const steps = (f.description ?? '')
    .split('\n')
    .filter((l) => /^\s*\d+\./.test(l))
    .map((l) => l.trim())

  return (
    <div className="p-4 border border-orange-500/20 rounded bg-orange-500/5 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Zap className="w-3.5 h-3.5 text-orange-400" />
            <span className={cn('text-xs font-mono font-bold', severityColor(f.severity ?? 'info'))}>
              {f.title}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <CvssBadge score={f.cvss_score} />
            {f.msf_module && <MsfTag module={f.msf_module} />}
          </div>
        </div>
        <span className={cn('px-2 py-0.5 rounded text-[10px] font-mono font-bold border shrink-0', SEVERITY_BG[f.severity ?? 'info'])}>
          {(f.severity ?? 'info').toUpperCase()}
        </span>
      </div>

      {steps.length > 0 && (
        <ol className="space-y-1.5 pl-1">
          {steps.map((step, i) => (
            <li key={i} className="flex items-start gap-2 text-xs font-sans text-cyber-muted">
              <span className="shrink-0 w-4 h-4 rounded-full bg-orange-500/20 text-orange-400 text-[9px] font-mono flex items-center justify-center mt-0.5">
                {i + 1}
              </span>
              {step.replace(/^\d+\.\s*/, '')}
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

// ── Empty tab ──────────────────────────────────────────────────────────────

function EmptyTab({ icon, label }: { icon: React.ReactNode; label: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-cyber-muted/40">
      {icon}
      <p className="text-xs font-mono mt-2">{label}</p>
    </div>
  )
}

// ── Tabs definition ────────────────────────────────────────────────────────

type TabId = 'overview' | 'vulns' | 'ports' | 'osint' | 'paths' | 'log'

// ── Main component ─────────────────────────────────────────────────────────

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<TabId>('overview')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [generatingReport, setGeneratingReport] = useState(false)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId!),
    refetchInterval: (query) => {
      const s = query.state.data?.data?.status
      return s === 'running' || s === 'pending' ? 3000 : false
    },
    enabled: !!scanId,
  })

  const scan: ScanDetail | undefined = data?.data
  const isActive = scan?.status === 'running' || scan?.status === 'pending'
  const { logs, status: wsStatus, clear } = useScanProgress(scanId ?? null, isActive)

  const allFindings: Finding[] = (scan?.findings ?? []).sort((a, b) => {
    const ai = SEVERITY_ORDER.indexOf(a.severity ?? 'info')
    const bi = SEVERITY_ORDER.indexOf(b.severity ?? 'info')
    return ai - bi
  })

  const severityCounts = allFindings.reduce<Record<string, number>>((acc, f) => {
    const s = f.severity ?? 'info'
    acc[s] = (acc[s] ?? 0) + 1
    return acc
  }, {})

  // Tab buckets
  const vulnFindings  = allFindings.filter((f) => ['cve', 'exploit', 'vuln', 'web', 'endpoint', 'ssl', 'header'].includes(f.type))
  const portFindings  = allFindings.filter((f) => f.type === 'port' || f.type === 'service')
  const osintFindings = allFindings.filter((f) => f.type === 'osint')
  const pathFindings  = allFindings.filter((f) => f.type === 'attack_path' || f.type === 'msf_mapping')
  const topCritical   = allFindings.filter((f) => f.severity === 'critical' || f.severity === 'high').slice(0, 5)

  const tabs: { id: TabId; label: string; count?: number; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview',     icon: <Shield className="w-3 h-3" /> },
    { id: 'vulns',    label: 'Vulns',        count: vulnFindings.length,  icon: <AlertTriangle className="w-3 h-3" /> },
    { id: 'ports',    label: 'Ports',        count: portFindings.length,  icon: <Network className="w-3 h-3" /> },
    { id: 'osint',    label: 'OSINT',        count: osintFindings.length, icon: <Globe className="w-3 h-3" /> },
    { id: 'paths',    label: 'Attack Paths', count: pathFindings.length,  icon: <Zap className="w-3 h-3" /> },
    { id: 'log',      label: 'Log',          icon: <Terminal className="w-3 h-3" /> },
  ]

  // Filtered list for vulns tab
  const filteredVulns = severityFilter === 'all'
    ? vulnFindings
    : vulnFindings.filter((f) => (f.severity ?? 'info') === severityFilter)

  async function handleGenerateReport(lang: 'ru' | 'en' = 'ru') {
    if (!scanId) return
    setGeneratingReport(true)
    try {
      await reportsApi.generate(scanId, lang)

      // Poll until ready (max 60s)
      let ready = false
      for (let i = 0; i < 30; i++) {
        await new Promise((r) => setTimeout(r, 2000))
        const { data: reports } = await reportsApi.list(scanId)
        const report = reports.find((r: { lang: string; status: string }) => r.lang === lang && r.status !== 'failed')
        if (report?.status === 'ready') { ready = true; break }
        if (report?.status === 'failed') throw new Error('Report generation failed')
      }

      if (!ready) throw new Error('Report generation timed out')

      // Download
      const { data } = await reportsApi.download(scanId, lang)
      const url = URL.createObjectURL(new Blob([data], { type: 'application/pdf' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `pentrascan_${scanId}_${lang}.pdf`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Report error:', err)
    } finally {
      setGeneratingReport(false)
    }
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
    <div className="space-y-5 max-w-5xl">
      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <button
            onClick={() => navigate(-1)}
            className="flex items-center gap-1.5 text-xs font-mono text-cyber-muted hover:text-cyber-text transition-colors cursor-pointer mb-3"
          >
            <ArrowLeft className="w-3 h-3" /> BACK
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
            className="p-2 rounded border border-cyber-border text-cyber-muted hover:text-cyber-green hover:border-cyber-green transition-all cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          {scan.status === 'completed' && (
            <Button size="sm" variant="outline" onClick={() => handleGenerateReport('ru')} loading={generatingReport}>
              <FileText className="w-3.5 h-3.5" /> REPORT
            </Button>
          )}
          <Button size="sm" variant="danger" onClick={handleDelete}>
            <Trash2 className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* ── Error ── */}
      {scan.error_message && (
        <div className="flex items-start gap-2 p-3 rounded border border-cyber-red/30 bg-cyber-red/5">
          <AlertTriangle className="w-4 h-4 text-cyber-red shrink-0 mt-0.5" />
          <p className="text-xs font-mono text-cyber-red">{scan.error_message}</p>
        </div>
      )}

      {/* ── Severity stats ── */}
      {allFindings.length > 0 && (
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
              <p className="text-[10px] font-mono text-cyber-muted uppercase tracking-widest mt-0.5">{sev}</p>
            </div>
          ))}
        </motion.div>
      )}

      {/* ── Tabs + content ── */}
      {(allFindings.length > 0 || logs.length > 0 || isActive) && (
        <motion.div
          className="cyber-card"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          {/* Tab bar */}
          <div className="flex items-center gap-0 border-b border-cyber-border overflow-x-auto">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  'flex items-center gap-1.5 px-4 py-3 text-xs font-mono whitespace-nowrap transition-colors cursor-pointer border-b-2',
                  activeTab === tab.id
                    ? 'border-cyber-green text-cyber-green'
                    : 'border-transparent text-cyber-muted hover:text-cyber-text',
                )}
              >
                {tab.icon}
                {tab.label}
                {tab.count !== undefined && tab.count > 0 && (
                  <span className={cn(
                    'px-1 rounded text-[9px]',
                    activeTab === tab.id ? 'bg-cyber-green/20' : 'bg-cyber-secondary',
                  )}>
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Tab: Overview */}
          {activeTab === 'overview' && (
            <div className="p-4 space-y-5">
              {/* Duration */}
              <div className="grid grid-cols-3 gap-3 text-xs font-mono">
                <div>
                  <p className="text-cyber-muted/50 uppercase tracking-widest text-[10px] mb-1">Started</p>
                  <p className="text-cyber-text">{scan.started_at ? formatDate(scan.started_at) : '—'}</p>
                </div>
                <div>
                  <p className="text-cyber-muted/50 uppercase tracking-widest text-[10px] mb-1">Finished</p>
                  <p className="text-cyber-text">{scan.finished_at ? formatDate(scan.finished_at) : '—'}</p>
                </div>
                <div>
                  <p className="text-cyber-muted/50 uppercase tracking-widest text-[10px] mb-1">Total Findings</p>
                  <p className="text-cyber-green font-bold">{allFindings.length}</p>
                </div>
              </div>

              {/* Attack paths summary */}
              {pathFindings.filter((f) => f.type === 'attack_path').length > 0 && (
                <div>
                  <p className="text-[10px] font-mono text-orange-400/70 uppercase tracking-widest mb-2 flex items-center gap-1">
                    <Zap className="w-3 h-3" /> Attack Chains Identified
                  </p>
                  <div className="space-y-2">
                    {pathFindings.filter((f) => f.type === 'attack_path').map((f) => (
                      <div key={f.id} className="flex items-center justify-between gap-3 px-3 py-2 rounded bg-orange-500/5 border border-orange-500/15">
                        <span className="text-xs font-mono text-cyber-text truncate">{f.title}</span>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <CvssBadge score={f.cvss_score} />
                          <MsfTag module={f.msf_module} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Top critical/high */}
              {topCritical.length > 0 && (
                <div>
                  <p className="text-[10px] font-mono text-cyber-muted/50 uppercase tracking-widest mb-2 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> Top Critical / High
                  </p>
                  <div className="space-y-0 divide-y divide-cyber-border/50 rounded border border-cyber-border overflow-hidden">
                    {topCritical.map((f) => (
                      <div key={f.id} className="flex items-center justify-between gap-3 px-3 py-2.5 hover:bg-cyber-secondary/20">
                        <div className="flex items-center gap-2 min-w-0">
                          <StatusBadge status={f.severity ?? 'info'} className="shrink-0" />
                          <span className="text-xs font-mono text-cyber-text truncate">{f.title}</span>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <CveLink cveId={f.cve_id} />
                          <CvssBadge score={f.cvss_score} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {allFindings.length === 0 && scan.status === 'completed' && (
                <div className="flex flex-col items-center py-8 text-cyber-green">
                  <Shield className="w-8 h-8 mb-2" />
                  <p className="text-sm font-mono">No vulnerabilities found</p>
                  <p className="text-xs font-mono text-cyber-muted/50 mt-1">Target appears secure</p>
                </div>
              )}
            </div>
          )}

          {/* Tab: Vulnerabilities */}
          {activeTab === 'vulns' && (
            <div>
              {/* Severity filter */}
              <div className="flex items-center gap-1.5 p-3 border-b border-cyber-border overflow-x-auto">
                <Search className="w-3 h-3 text-cyber-muted/50 shrink-0" />
                {['all', ...SEVERITY_ORDER].map((s) => (
                  <button
                    key={s}
                    onClick={() => setSeverityFilter(s)}
                    className={cn(
                      'px-2 py-0.5 rounded text-[10px] font-mono transition-colors cursor-pointer border',
                      severityFilter === s
                        ? (SEVERITY_BG[s] ?? 'bg-cyber-green/20 text-cyber-green border-cyber-green/40')
                        : 'border-cyber-border text-cyber-muted/60 hover:border-cyber-border/80',
                    )}
                  >
                    {s.toUpperCase()}
                  </button>
                ))}
              </div>
              {filteredVulns.length > 0
                ? <div className="divide-y divide-cyber-border">{filteredVulns.map((f) => <FindingRow key={f.id} f={f} />)}</div>
                : <EmptyTab icon={<AlertTriangle className="w-6 h-6" />} label="No vulnerability findings" />
              }
            </div>
          )}

          {/* Tab: Ports */}
          {activeTab === 'ports' && <PortsTable findings={portFindings} />}

          {/* Tab: OSINT */}
          {activeTab === 'osint' && (
            osintFindings.length > 0
              ? <div className="divide-y divide-cyber-border">{osintFindings.map((f) => <FindingRow key={f.id} f={f} />)}</div>
              : <EmptyTab icon={<Globe className="w-6 h-6" />} label="No OSINT findings" />
          )}

          {/* Tab: Attack Paths */}
          {activeTab === 'paths' && (
            <div className="p-4 space-y-3">
              {pathFindings.filter((f) => f.type === 'attack_path').length > 0
                ? pathFindings.filter((f) => f.type === 'attack_path').map((f) => <AttackPathCard key={f.id} f={f} />)
                : <EmptyTab icon={<Zap className="w-6 h-6" />} label="No attack paths identified" />
              }
            </div>
          )}

          {/* Tab: Log */}
          {activeTab === 'log' && (
            <div className="p-4">
              {logs.length > 0 || isActive
                ? <ScanProgressLog logs={logs} status={wsStatus} scanStatus={scan.status} onClear={clear} className="min-h-[300px]" />
                : <EmptyTab icon={<Terminal className="w-6 h-6" />} label="No log available" />
              }
            </div>
          )}
        </motion.div>
      )}

      {/* Empty state when scan just created */}
      {scan.status === 'completed' && allFindings.length === 0 && (
        <div className="cyber-card p-12 text-center">
          <Shield className="w-8 h-8 text-cyber-green mx-auto mb-3" />
          <p className="font-mono text-sm text-cyber-green">No vulnerabilities found</p>
          <p className="font-mono text-xs text-cyber-muted/50 mt-1">Target appears secure for tested vectors</p>
        </div>
      )}
    </div>
  )
}
