import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Zap, Square, Activity, Wifi, WifiOff,
  AlertTriangle, ChevronDown, Shield, Target,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ddosApi } from '@/lib/api'

// ── Types ──────────────────────────────────────────────────────────────────

type AttackType = 'http_flood' | 'slowloris' | 'slow_post' | 'syn_flood' | 'udp_flood' | 'icmp_flood'
type Intensity  = 'low' | 'medium' | 'high'
type JobStatus  = 'idle' | 'running' | 'completed' | 'stopped' | 'error'

interface JobStats {
  job_id:        string
  status:        JobStatus
  attack_type:   string
  target:        string
  elapsed:       number
  duration:      number
  sent:          number
  success:       number
  errors:        number
  timeouts:      number
  avg_latency:   number | null
  service_up:    boolean | null
  findings_count: number
}

// ── Config options ────────────────────────────────────────────────────────────

const ATTACK_TYPES: { value: AttackType; label: string; layer: string; desc: string }[] = [
  { value: 'http_flood', label: 'HTTP Flood',    layer: 'L7', desc: 'GET/POST flood with randomized headers' },
  { value: 'slowloris',  label: 'Slowloris',     layer: 'L7', desc: 'Slow headers — holds connections open' },
  { value: 'slow_post',  label: 'Slow POST',     layer: 'L7', desc: 'RUDY — drip body 1 byte/sec' },
  { value: 'syn_flood',  label: 'SYN Flood',     layer: 'L4', desc: 'hping3 TCP SYN flood' },
  { value: 'udp_flood',  label: 'UDP Flood',     layer: 'L4', desc: 'hping3 UDP packet flood' },
  { value: 'icmp_flood', label: 'ICMP Flood',    layer: 'L3', desc: 'hping3 ICMP echo flood' },
]

const INTENSITIES: { value: Intensity; label: string; mult: string; color: string }[] = [
  { value: 'low',    label: 'Low',    mult: '30%',  color: 'text-cyber-green' },
  { value: 'medium', label: 'Medium', mult: '100%', color: 'text-yellow-400' },
  { value: 'high',   label: 'High',   mult: '200%', color: 'text-cyber-red' },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

function progressPct(elapsed: number, duration: number): number {
  return duration > 0 ? Math.min((elapsed / duration) * 100, 100) : 0
}

// ── Metric card ───────────────────────────────────────────────────────────────

function MetricCard({ label, value, color = 'text-cyber-text', sub }: {
  label: string; value: string | number; color?: string; sub?: string
}) {
  return (
    <div className="bg-cyber-surface border border-cyber-border rounded-lg p-4 text-center">
      <div className={`text-2xl font-mono font-bold ${color}`}>{value}</div>
      <div className="text-[10px] font-mono text-cyber-muted uppercase tracking-widest mt-1">{label}</div>
      {sub && <div className="text-[9px] font-mono text-cyber-muted/50 mt-0.5">{sub}</div>}
    </div>
  )
}

// ── Attack type selector ──────────────────────────────────────────────────────

function AttackTypeSelect({ value, onChange }: {
  value: AttackType; onChange: (v: AttackType) => void
}) {
  const [open, setOpen] = useState(false)
  const current = ATTACK_TYPES.find(a => a.value === value)!

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between bg-cyber-surface border border-cyber-border
                   rounded-lg px-4 py-3 text-cyber-text font-mono text-sm hover:border-cyber-green/50
                   transition-colors"
      >
        <span className="flex items-center gap-3">
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-cyber-green/40
                           text-cyber-green/80 bg-cyber-green/5">
            {current.layer}
          </span>
          {current.label}
        </span>
        <ChevronDown className={`w-4 h-4 text-cyber-muted transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.15 }}
            className="absolute z-50 top-full left-0 right-0 mt-1 bg-cyber-bg border border-cyber-border
                       rounded-lg overflow-hidden shadow-xl"
          >
            {ATTACK_TYPES.map(a => (
              <button
                key={a.value}
                onClick={() => { onChange(a.value); setOpen(false) }}
                className={`w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-cyber-surface
                            transition-colors ${a.value === value ? 'bg-cyber-surface/50' : ''}`}
              >
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-cyber-green/40
                                 text-cyber-green/80 bg-cyber-green/5 mt-0.5 shrink-0">
                  {a.layer}
                </span>
                <div>
                  <div className="text-sm font-mono text-cyber-text">{a.label}</div>
                  <div className="text-[10px] font-mono text-cyber-muted mt-0.5">{a.desc}</div>
                </div>
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ── Live gauge bar ────────────────────────────────────────────────────────────

function GaugeBar({ pct, color = '#22C55E' }: { pct: number; color?: string }) {
  return (
    <div className="h-1.5 w-full bg-cyber-border rounded-full overflow-hidden">
      <motion.div
        className="h-full rounded-full"
        style={{ background: color }}
        animate={{ width: `${pct}%` }}
        transition={{ duration: 0.5 }}
      />
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function DDoSPanel() {
  const [target,      setTarget]      = useState('')
  const [attackType,  setAttackType]  = useState<AttackType>('http_flood')
  const [intensity,   setIntensity]   = useState<Intensity>('medium')
  const [concurrency, setConcurrency] = useState(50)
  const [duration,    setDuration]    = useState(30)
  const [method,      setMethod]      = useState<'GET' | 'POST'>('GET')

  const [jobId,  setJobId]  = useState<string | null>(null)
  const [stats,  setStats]  = useState<JobStats | null>(null)
  const [uiStatus, setUiStatus] = useState<JobStatus>('idle')
  const [error,  setError]  = useState<string | null>(null)

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Poll status while running
  useEffect(() => {
    if (!jobId || uiStatus !== 'running') {
      if (pollRef.current) clearInterval(pollRef.current)
      return
    }

    pollRef.current = setInterval(async () => {
      try {
        const res = await ddosApi.status(jobId)
        const data: JobStats = res.data
        setStats(data)
        if (data.status !== 'running') {
          setUiStatus(data.status)
          clearInterval(pollRef.current!)
        }
      } catch {
        clearInterval(pollRef.current!)
        setUiStatus('error')
      }
    }, 1000)

    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [jobId, uiStatus])

  async function handleStart() {
    if (!target.trim()) return
    setError(null)
    setStats(null)
    try {
      const res = await ddosApi.start({
        target: target.trim(),
        attack_type: attackType,
        method,
        concurrency,
        duration,
        intensity,
      })
      setJobId(res.data.job_id)
      setUiStatus('running')
      setStats(res.data)
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Failed to start attack'
      setError(msg)
    }
  }

  async function handleStop() {
    if (!jobId) return
    try {
      await ddosApi.stop(jobId)
      setUiStatus('stopped')
    } catch {
      // ignore
    }
  }

  function handleReset() {
    setJobId(null)
    setStats(null)
    setUiStatus('idle')
    setError(null)
  }

  const isRunning = uiStatus === 'running'
  const isDone    = ['completed', 'stopped', 'error'].includes(uiStatus)
  const pct       = stats ? progressPct(stats.elapsed, stats.duration) : 0
  const timeoutPct = stats && stats.sent > 0
    ? Math.round((stats.timeouts / stats.sent) * 100)
    : 0

  return (
    <div className="space-y-6 max-w-4xl">

      {/* Header */}
      <div>
        <h1 className="text-xl font-mono font-bold text-cyber-text flex items-center gap-2">
          <Zap className="w-5 h-5 text-cyber-red" />
          DDoS STRESS TEST
        </h1>
        <p className="text-xs font-mono text-cyber-muted mt-1">
          Authorized penetration testing only. Results saved as scan findings.
        </p>
      </div>

      {/* Warning banner */}
      <div className="flex items-start gap-3 bg-yellow-500/5 border border-yellow-500/20 rounded-lg p-4">
        <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
        <p className="text-xs font-mono text-yellow-400/80">
          Only test targets you own or have explicit written authorization to test.
          Unauthorized DDoS attacks are illegal and may result in criminal prosecution.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* ── Config panel ── */}
        <div className="space-y-4">
          <div className="cyber-card p-5 space-y-4">
            <h2 className="text-xs font-mono text-cyber-muted uppercase tracking-widest">Configuration</h2>

            {/* Target */}
            <div className="space-y-1.5">
              <label className="text-xs font-mono text-cyber-muted uppercase tracking-widest">Target</label>
              <div className="relative">
                <Target className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
                <Input
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  placeholder="192.168.1.1 or https://target.com"
                  className="pl-9 font-mono text-sm"
                  disabled={isRunning}
                />
              </div>
            </div>

            {/* Attack type */}
            <div className="space-y-1.5">
              <label className="text-xs font-mono text-cyber-muted uppercase tracking-widest">Attack Type</label>
              <AttackTypeSelect value={attackType} onChange={setAttackType} />
            </div>

            {/* Intensity */}
            <div className="space-y-1.5">
              <label className="text-xs font-mono text-cyber-muted uppercase tracking-widest">Intensity</label>
              <div className="grid grid-cols-3 gap-2">
                {INTENSITIES.map(i => (
                  <button
                    key={i.value}
                    onClick={() => setIntensity(i.value)}
                    disabled={isRunning}
                    className={`py-2 rounded-lg border font-mono text-xs transition-all
                      ${intensity === i.value
                        ? `border-current ${i.color} bg-current/5`
                        : 'border-cyber-border text-cyber-muted hover:border-cyber-muted/50'
                      }`}
                  >
                    {i.label}
                    <span className="block text-[10px] opacity-60">{i.mult}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* HTTP method (only for http_flood) */}
            {attackType === 'http_flood' && (
              <div className="space-y-1.5">
                <label className="text-xs font-mono text-cyber-muted uppercase tracking-widest">Method</label>
                <div className="grid grid-cols-2 gap-2">
                  {(['GET', 'POST'] as const).map(m => (
                    <button
                      key={m}
                      onClick={() => setMethod(m)}
                      disabled={isRunning}
                      className={`py-2 rounded-lg border font-mono text-xs transition-all
                        ${method === m
                          ? 'border-cyber-green text-cyber-green bg-cyber-green/5'
                          : 'border-cyber-border text-cyber-muted hover:border-cyber-muted/50'
                        }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Concurrency + Duration */}
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-xs font-mono text-cyber-muted uppercase tracking-widest">
                  Concurrency
                </label>
                <Input
                  type="number" min={1} max={500}
                  value={concurrency}
                  onChange={e => setConcurrency(Number(e.target.value))}
                  className="font-mono text-sm"
                  disabled={isRunning}
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-mono text-cyber-muted uppercase tracking-widest">
                  Duration (s)
                </label>
                <Input
                  type="number" min={5} max={300}
                  value={duration}
                  onChange={e => setDuration(Number(e.target.value))}
                  className="font-mono text-sm"
                  disabled={isRunning}
                />
              </div>
            </div>

            {/* Error */}
            {error && (
              <p className="text-xs font-mono text-cyber-red border border-cyber-red/20 bg-cyber-red/5 rounded px-3 py-2">
                {error}
              </p>
            )}

            {/* Action buttons */}
            <div className="flex gap-3 pt-1">
              {!isRunning && !isDone && (
                <Button
                  onClick={handleStart}
                  disabled={!target.trim()}
                  className="flex-1 bg-cyber-red hover:bg-cyber-red/80 text-white font-mono text-sm"
                >
                  <Zap className="w-4 h-4 mr-2" />
                  LAUNCH ATTACK
                </Button>
              )}
              {isRunning && (
                <Button
                  onClick={handleStop}
                  variant="outline"
                  className="flex-1 border-cyber-red text-cyber-red hover:bg-cyber-red/10 font-mono text-sm"
                >
                  <Square className="w-4 h-4 mr-2" />
                  STOP
                </Button>
              )}
              {isDone && (
                <Button
                  onClick={handleReset}
                  variant="outline"
                  className="flex-1 font-mono text-sm"
                >
                  NEW TEST
                </Button>
              )}
            </div>
          </div>
        </div>

        {/* ── Live metrics panel ── */}
        <div className="space-y-4">

          {/* Status + progress */}
          <div className="cyber-card p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-mono text-cyber-muted uppercase tracking-widest">Live Metrics</h2>
              <div className="flex items-center gap-2">
                {isRunning && (
                  <span className="flex items-center gap-1.5 text-[10px] font-mono text-cyber-green">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
                    LIVE
                  </span>
                )}
                {isDone && (
                  <span className={`text-[10px] font-mono uppercase ${
                    uiStatus === 'completed' ? 'text-cyber-green'
                    : uiStatus === 'stopped'   ? 'text-yellow-400'
                    : 'text-cyber-red'
                  }`}>
                    {uiStatus}
                  </span>
                )}
              </div>
            </div>

            {/* Progress bar */}
            {(isRunning || isDone) && stats && (
              <div className="space-y-1">
                <div className="flex justify-between text-[10px] font-mono text-cyber-muted">
                  <span>{stats.elapsed}s elapsed</span>
                  <span>{stats.duration}s total</span>
                </div>
                <GaugeBar
                  pct={pct}
                  color={isRunning ? '#22C55E' : uiStatus === 'stopped' ? '#EAB308' : '#22C55E'}
                />
              </div>
            )}

            {/* Service status */}
            {stats?.service_up !== null && stats?.service_up !== undefined && (
              <div className={`flex items-center gap-2 text-sm font-mono rounded-lg px-4 py-2.5 border
                ${stats.service_up
                  ? 'border-cyber-green/20 bg-cyber-green/5 text-cyber-green'
                  : 'border-cyber-red/20 bg-cyber-red/5 text-cyber-red'
                }`}
              >
                {stats.service_up
                  ? <><Wifi className="w-4 h-4" /> Target is UP</>
                  : <><WifiOff className="w-4 h-4" /> Target is DOWN / Unresponsive</>
                }
              </div>
            )}

            {/* Metric grid */}
            {stats ? (
              <div className="grid grid-cols-2 gap-3">
                <MetricCard label="Packets Sent" value={fmt(stats.sent)} color="text-cyber-text" />
                <MetricCard
                  label="Timeouts"
                  value={`${timeoutPct}%`}
                  color={timeoutPct >= 50 ? 'text-cyber-red' : timeoutPct >= 20 ? 'text-yellow-400' : 'text-cyber-muted'}
                  sub={`${fmt(stats.timeouts)} reqs`}
                />
                <MetricCard
                  label="Avg Latency"
                  value={stats.avg_latency != null ? `${stats.avg_latency}ms` : '—'}
                  color={
                    stats.avg_latency == null ? 'text-cyber-muted'
                    : stats.avg_latency > 5000 ? 'text-cyber-red'
                    : stats.avg_latency > 1000 ? 'text-yellow-400'
                    : 'text-cyber-green'
                  }
                />
                <MetricCard
                  label="Findings"
                  value={stats.findings_count}
                  color={stats.findings_count > 0 ? 'text-cyber-red' : 'text-cyber-muted'}
                  sub="vulnerabilities"
                />
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Activity className="w-8 h-8 text-cyber-muted/30" />
                <p className="text-xs font-mono text-cyber-muted/50">
                  Configure and launch an attack to see live metrics
                </p>
              </div>
            )}
          </div>

          {/* Impact summary (post-attack) */}
          <AnimatePresence>
            {isDone && stats && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="cyber-card p-5 space-y-3"
              >
                <h2 className="text-xs font-mono text-cyber-muted uppercase tracking-widest flex items-center gap-2">
                  <Shield className="w-3.5 h-3.5" />
                  Attack Summary
                </h2>
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between border-b border-cyber-border pb-2">
                    <span className="text-cyber-muted">Target</span>
                    <span className="text-cyber-text">{stats.target}</span>
                  </div>
                  <div className="flex justify-between border-b border-cyber-border pb-2">
                    <span className="text-cyber-muted">Attack type</span>
                    <span className="text-cyber-text">{stats.attack_type.replace('_', ' ').toUpperCase()}</span>
                  </div>
                  <div className="flex justify-between border-b border-cyber-border pb-2">
                    <span className="text-cyber-muted">Duration</span>
                    <span className="text-cyber-text">{stats.elapsed}s / {stats.duration}s</span>
                  </div>
                  <div className="flex justify-between border-b border-cyber-border pb-2">
                    <span className="text-cyber-muted">Total requests</span>
                    <span className="text-cyber-text">{fmt(stats.sent)}</span>
                  </div>
                  <div className="flex justify-between border-b border-cyber-border pb-2">
                    <span className="text-cyber-muted">Timeout rate</span>
                    <span className={timeoutPct >= 50 ? 'text-cyber-red' : timeoutPct >= 20 ? 'text-yellow-400' : 'text-cyber-green'}>
                      {timeoutPct}%
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-cyber-muted">Service after attack</span>
                    <span className={stats.service_up ? 'text-cyber-green' : 'text-cyber-red'}>
                      {stats.service_up === null ? '—' : stats.service_up ? 'ONLINE' : 'OFFLINE'}
                    </span>
                  </div>
                </div>
                {stats.findings_count > 0 && (
                  <p className="text-[10px] font-mono text-cyber-green border border-cyber-green/20 bg-cyber-green/5 rounded px-3 py-2">
                    {stats.findings_count} finding(s) saved to scan report
                  </p>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  )
}
