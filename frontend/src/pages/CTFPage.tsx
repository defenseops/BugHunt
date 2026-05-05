import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import { Plus, RefreshCw, ChevronRight, Flag, Copy, Check } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { StatusBadge } from '@/components/common/StatusBadge'
import { scansApi } from '@/lib/api'
import { formatDate } from '@/lib/utils'

interface Scan {
  id: string
  target: string
  scan_type: string
  status: string
  created_at: string
  findings_count?: number
  ctf_flag_format?: string
}

interface Finding {
  id: string
  type: string
  title: string
  evidence: string | null
  description: string | null
  severity: string | null
}

// ── Flag copy button ───────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000) }}
      className="flex items-center gap-1 text-[10px] font-mono px-2 py-1 rounded border border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10 transition-colors cursor-pointer"
    >
      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
      {copied ? 'COPIED' : 'COPY'}
    </button>
  )
}

// ── Flag card ──────────────────────────────────────────────────────────────

function FlagCard({ finding }: { finding: Finding }) {
  const raw = finding.title
    .replace('FLAG CAPTURED: ', '')
    .replace(/FLAG CAPTURED via .+?: /, '')
  const flag = raw.includes('{') ? raw : finding.description?.match(/Flag: (.+)/)?.[1] ?? raw
  const technique = finding.evidence?.match(/technique=([^\s]+)/)?.[1] ?? 'automated'

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      className="rounded-lg border border-green-500/50 bg-green-500/5 p-4"
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-green-400 text-base">⚑</span>
          <span className="text-[10px] font-mono text-green-500 uppercase tracking-widest">Flag captured</span>
        </div>
        <CopyButton text={flag} />
      </div>
      <p className="font-mono text-green-300 text-sm break-all mb-2">{flag}</p>
      <p className="text-[10px] font-mono text-green-600">via {technique}</p>
    </motion.div>
  )
}

// ── CTF scan row ───────────────────────────────────────────────────────────

function CTFScanRow({ scan }: { scan: Scan }) {
  const navigate = useNavigate()
  const { data } = useQuery({
    queryKey: ['scan', scan.id],
    queryFn: () => scansApi.get(scan.id),
    enabled: scan.status === 'completed',
  })
  const findings: Finding[] = data?.data?.findings ?? []
  const flags = findings.filter(f => f.type === 'flag')

  return (
    <motion.div
      className="border border-cyber-border rounded-lg overflow-hidden mb-3"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
    >
      {/* Header row */}
      <div
        className="flex items-center justify-between px-4 py-3 bg-cyber-secondary/30 hover:bg-cyber-secondary/50 cursor-pointer transition-colors"
        onClick={() => navigate(`/dashboard/scans/${scan.id}`)}
      >
        <div className="flex items-center gap-3 min-w-0">
          <Flag className="w-4 h-4 text-yellow-500 shrink-0" />
          <div className="min-w-0">
            <p className="text-sm font-mono text-cyber-text truncate">{scan.target}</p>
            <p className="text-[10px] font-mono text-yellow-500/70">
              {scan.ctf_flag_format ? `format: ${scan.ctf_flag_format}` : 'auto-detect format'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {flags.length > 0 && (
            <span className="text-xs font-mono text-green-400 flex items-center gap-1">
              ⚑ {flags.length} flag{flags.length !== 1 ? 's' : ''}
            </span>
          )}
          <StatusBadge status={scan.status} />
          <span className="text-[10px] font-mono text-cyber-muted/50 hidden md:block">{formatDate(scan.created_at)}</span>
          <ChevronRight className="w-3.5 h-3.5 text-cyber-muted/40" />
        </div>
      </div>

      {/* Flags inline */}
      {flags.length > 0 && (
        <div className="px-4 py-3 space-y-2 border-t border-cyber-border">
          {flags.map(f => <FlagCard key={f.id} finding={f} />)}
        </div>
      )}

      {scan.status === 'completed' && flags.length === 0 && (
        <div className="px-4 py-2 border-t border-cyber-border">
          <p className="text-[10px] font-mono text-cyber-muted/50">No flags captured — check Vulns tab for attack vectors</p>
        </div>
      )}
    </motion.div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function CTFPage() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [flagFormat, setFlagFormat] = useState('')
  const [launching, setLaunching] = useState(false)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['ctf-scans'],
    queryFn: () => scansApi.list({ limit: 50 }),
    refetchInterval: 5000,
  })

  const allScans: Scan[] = data?.data?.items ?? []
  const ctfScans = allScans.filter(s => s.scan_type === 'ctf')

  async function handleLaunch(e: React.FormEvent) {
    e.preventDefault()
    if (!target.trim()) return
    setLaunching(true)
    try {
      await scansApi.create({
        target: target.trim(),
        scan_type: 'ctf',
        ...(flagFormat.trim() ? { ctf_flag_format: flagFormat.trim() } : {}),
      })
      setTarget('')
      setFlagFormat('')
      refetch()
    } catch { /* handled globally */ }
    finally { setLaunching(false) }
  }

  const totalFlags = ctfScans.reduce((sum, s) => sum + (s.findings_count ?? 0), 0)
  const solved = ctfScans.filter(s => s.status === 'completed').length

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-mono font-bold text-yellow-400 flex items-center gap-2">
            <span>⚑</span> CTF MODE
          </h1>
          <p className="text-xs font-mono text-cyber-muted mt-1">
            {ctfScans.length} challenges &nbsp;·&nbsp; {solved} completed &nbsp;·&nbsp;
            <span className="text-green-400">{totalFlags} findings total</span>
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="p-2 rounded border border-cyber-border text-cyber-muted hover:text-cyber-text transition-colors cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Launch form */}
      <motion.div
        className="cyber-card p-5 border border-yellow-500/40 rounded-lg"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <p className="text-xs font-mono text-yellow-500/70 tracking-widest mb-4">// NEW CTF CHALLENGE</p>
        <form onSubmit={handleLaunch} className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-3">
            <Input
              placeholder="target — IP, domain, or http://host:port"
              value={target}
              onChange={e => setTarget(e.target.value)}
              className="flex-1"
            />
            <Button
              type="submit"
              loading={launching}
              className="shrink-0 bg-yellow-500 text-black hover:bg-yellow-400 border-yellow-500 font-mono"
            >
              <Plus className="w-3.5 h-3.5" />
              HUNT FLAGS
            </Button>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-yellow-500/60 whitespace-nowrap">Flag format:</span>
            <Input
              placeholder="e.g. aues{...} or FLAG{...}  (leave empty = auto-detect all formats)"
              value={flagFormat}
              onChange={e => setFlagFormat(e.target.value)}
              className="flex-1 border-yellow-500/30 text-yellow-300 placeholder:text-yellow-500/25"
            />
          </div>
        </form>

        {/* Techniques hint */}
        <div className="mt-4 pt-4 border-t border-yellow-500/20">
          <p className="text-[10px] font-mono text-yellow-500/50 mb-2 uppercase tracking-widest">Techniques included</p>
          <div className="flex flex-wrap gap-1.5">
            {[
              'Common paths', '.git recon', 'JWT attack', 'IDOR enum', 'SSTI probe',
              'XXE', 'SSRF', 'CMDi', 'NoSQL', 'GraphQL', 'File upload RCE',
              'Mass assignment', 'Path bypass', 'Debug console', 'Type juggling',
              'Cookie manip', 'JS analysis', 'Page crawler', 'API fuzz',
              'Blind SQLi', 'Blind XXE', 'RCE chain', 'Source grep',
              'Math captcha', 'Crypto solver',
            ].map(t => (
              <span key={t} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-500/60 border border-yellow-500/20">
                {t}
              </span>
            ))}
          </div>
        </div>
      </motion.div>

      {/* CTF scans list */}
      <div>
        <p className="text-xs font-mono text-cyber-muted mb-3 uppercase tracking-widest">// CTF HISTORY</p>
        {isLoading ? (
          <div className="p-8 text-center">
            <div className="inline-block w-6 h-6 border-2 border-yellow-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : ctfScans.length === 0 ? (
          <div className="cyber-card p-12 text-center border border-yellow-500/20">
            <span className="text-4xl block mb-3 text-yellow-500/20">⚑</span>
            <p className="text-sm font-mono text-cyber-muted">No CTF challenges yet</p>
            <p className="text-xs font-mono text-cyber-muted/50 mt-1">Launch your first scan above</p>
          </div>
        ) : (
          <div>
            {ctfScans.map(scan => (
              <CTFScanRow key={scan.id} scan={scan} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
