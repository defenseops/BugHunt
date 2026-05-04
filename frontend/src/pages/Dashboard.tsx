import { useState } from 'react'
import { Routes, Route, Link, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Shield, FileText, Clock, AlertTriangle,
  Plus, RefreshCw, ChevronRight, Target,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { Navbar } from '@/components/layout/Navbar'
import { Sidebar } from '@/components/layout/Sidebar'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { StatusBadge } from '@/components/common/StatusBadge'
import { PageTransition } from '@/components/common/PageTransition'
import ScanDetail from '@/pages/ScanDetail'
import DDoSPanel   from '@/pages/DDoSPanel'
import BillingPage  from '@/pages/Billing'
import AdminPanel   from '@/pages/AdminPanel'
import { scansApi } from '@/lib/api'
import { formatDate } from '@/lib/utils'
import { useAuthStore } from '@/stores/authStore'

// ── Stat card ──────────────────────────────────────────────────────────────
function StatCard({ label, value, icon: Icon, color, sub }: {
  label: string; value: string | number; icon: React.FC<{ className?: string }>
  color: string; sub?: string
}) {
  return (
    <motion.div
      className="cyber-card p-5 flex items-start gap-4"
      whileHover={{ scale: 1.01, boxShadow: '0 0 0 1px #22C55E44' }}
      transition={{ duration: 0.15 }}
    >
      <div className={`p-2.5 rounded-lg border ${color} bg-current/5`}>
        <Icon className={`w-4 h-4 ${color.replace('border-', 'text-')}`} />
      </div>
      <div>
        <p className="text-2xl font-mono font-bold text-cyber-text">{value}</p>
        <p className="text-xs font-mono text-cyber-muted tracking-widest uppercase">{label}</p>
        {sub && <p className="text-[10px] font-mono text-cyber-muted/50 mt-0.5">{sub}</p>}
      </div>
    </motion.div>
  )
}

// ── Overview ───────────────────────────────────────────────────────────────
function Overview() {
  const navigate = useNavigate()
  const user = useAuthStore((s) => s.user)
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list({ limit: 5 }),
  })

  const scans: Scan[] = data?.data?.items ?? []
  const total: number = data?.data?.total ?? 0

  const stats = [
    { label: 'Total Scans',   value: total,        icon: Shield,       color: 'border-cyber-green',   sub: 'all time' },
    { label: 'Reports',       value: scans.filter((s) => s.status === 'completed').length, icon: FileText, color: 'border-cyber-blue', sub: 'ready to download' },
    { label: 'Running',       value: scans.filter((s) => s.status === 'running').length,   icon: Clock,    color: 'border-yellow-500', sub: 'in progress' },
    { label: 'Findings',      value: '—',          icon: AlertTriangle, color: 'border-cyber-red',    sub: 'critical CVEs' },
  ]

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-mono font-bold text-cyber-text">
            WELCOME, <span className="text-cyber-green">{user?.full_name?.toUpperCase() ?? 'OPERATOR'}</span>
          </h1>
          <p className="text-xs font-mono text-cyber-muted mt-1">
            Tier: <span className="text-cyber-green uppercase">{user?.subscription_tier}</span>
          </p>
        </div>
        <Button size="sm" onClick={() => navigate('/dashboard/scans')} className="flex items-center gap-2">
          <Plus className="w-3.5 h-3.5" />
          NEW SCAN
        </Button>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.07 }}
          >
            <StatCard {...s} />
          </motion.div>
        ))}
      </div>

      {/* Recent scans */}
      <motion.div
        className="cyber-card"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <div className="flex items-center justify-between p-5 border-b border-cyber-border">
          <h2 className="text-sm font-mono font-semibold text-cyber-text">RECENT SCANS</h2>
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetch()}
              className="p-1.5 rounded hover:bg-cyber-secondary text-cyber-muted hover:text-cyber-text transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
            <Link to="/dashboard/scans" className="text-xs font-mono text-cyber-green hover:neon-text flex items-center gap-1 cursor-pointer">
              ALL SCANS <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
        </div>

        {isLoading ? (
          <div className="p-8 text-center">
            <div className="inline-block w-6 h-6 border-2 border-cyber-green border-t-transparent rounded-full animate-spin" />
          </div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center">
            <Target className="w-8 h-8 text-cyber-muted/30 mx-auto mb-3" />
            <p className="text-sm font-mono text-cyber-muted">No scans yet</p>
            <p className="text-xs font-mono text-cyber-muted/50 mt-1">Start your first scan to see results here</p>
            <Button size="sm" className="mt-4" onClick={() => navigate('/dashboard/scans')}>
              START SCAN
            </Button>
          </div>
        ) : (
          <div className="divide-y divide-cyber-border">
            {scans.map((scan) => (
              <ScanRow key={scan.id} scan={scan} />
            ))}
          </div>
        )}
      </motion.div>
    </div>
  )
}

// ── Scans page ─────────────────────────────────────────────────────────────
interface Scan {
  id: string
  target: string
  scan_type: string
  status: string
  created_at: string
  findings_count?: number
}

function ScanRow({ scan }: { scan: Scan }) {
  const navigate = useNavigate()
  return (
    <motion.div
      className="flex items-center justify-between px-5 py-3.5 hover:bg-cyber-secondary/30 transition-colors duration-150 cursor-pointer"
      whileHover={{ x: 2 }}
      onClick={() => navigate(`/dashboard/scans/${scan.id}`)}
    >
      <div className="flex items-center gap-3 min-w-0">
        <Shield className="w-4 h-4 text-cyber-muted shrink-0" />
        <div className="min-w-0">
          <p className="text-sm font-mono text-cyber-text truncate">{scan.target}</p>
          <p className="text-[10px] font-mono text-cyber-muted uppercase">{scan.scan_type}</p>
        </div>
      </div>
      <div className="flex items-center gap-4 shrink-0">
        {scan.findings_count !== undefined && (
          <span className="text-xs font-mono text-cyber-muted">{scan.findings_count} findings</span>
        )}
        <StatusBadge status={scan.status} />
        <span className="text-[10px] font-mono text-cyber-muted/50 hidden md:block">{formatDate(scan.created_at)}</span>
        <ChevronRight className="w-3.5 h-3.5 text-cyber-muted/30" />
      </div>
    </motion.div>
  )
}

function ScansPage() {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('full')
  const [launching, setLaunching] = useState(false)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['scans', 'all'],
    queryFn: () => scansApi.list({ limit: 50 }),
  })
  const scans: Scan[] = data?.data?.items ?? []

  async function handleLaunch(e: React.FormEvent) {
    e.preventDefault()
    if (!target.trim()) return
    setLaunching(true)
    try {
      await scansApi.create({ target: target.trim(), scan_type: scanType })
      setTarget('')
      refetch()
    } catch { /* handled via global interceptor */ }
    finally { setLaunching(false) }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-mono font-bold text-cyber-text">SCANS</h1>

      {/* New scan form */}
      <motion.div
        className="cyber-card p-5 border border-cyber-border rounded-lg"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <p className="text-xs font-mono text-cyber-muted tracking-widest mb-4">// NEW SCAN</p>
        <form onSubmit={handleLaunch} className="flex flex-col sm:flex-row gap-3">
          <Input
            placeholder="target IP or domain (e.g. 192.168.1.1)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="flex-1"
          />
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            className="h-10 rounded-md border border-cyber-border bg-cyber-primary px-3 font-mono text-sm text-cyber-text focus:outline-none focus:border-cyber-green cursor-pointer"
          >
            <option value="full">Full Scan</option>
            <option value="port">Port Only</option>
            <option value="vuln">Vulnerability</option>
            <option value="web">Web App</option>
          </select>
          <Button type="submit" loading={launching} className="shrink-0">
            <Plus className="w-3.5 h-3.5" />
            LAUNCH
          </Button>
        </form>
      </motion.div>

      {/* Scans list */}
      <motion.div
        className="cyber-card"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <div className="flex items-center justify-between p-5 border-b border-cyber-border">
          <h2 className="text-sm font-mono font-semibold text-cyber-text">ALL SCANS</h2>
          <button onClick={() => refetch()} className="p-1.5 rounded hover:bg-cyber-secondary text-cyber-muted hover:text-cyber-text transition-colors cursor-pointer">
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
        {isLoading ? (
          <div className="p-8 text-center">
            <div className="inline-block w-6 h-6 border-2 border-cyber-green border-t-transparent rounded-full animate-spin" />
          </div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center">
            <p className="text-sm font-mono text-cyber-muted">No scans yet. Launch your first scan above.</p>
          </div>
        ) : (
          <div className="divide-y divide-cyber-border">
            {scans.map((scan) => <ScanRow key={scan.id} scan={scan} />)}
          </div>
        )}
      </motion.div>
    </div>
  )
}

// ── Placeholder pages ──────────────────────────────────────────────────────
function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-64 gap-3">
      <p className="text-xs font-mono text-cyber-muted tracking-widest">// {title}</p>
      <p className="text-sm font-mono text-cyber-muted/50">Coming in next sprint</p>
    </div>
  )
}

// ── Dashboard shell ────────────────────────────────────────────────────────
export default function Dashboard() {
  return (
    <PageTransition>
      <div className="min-h-screen bg-cyber-bg scanline-overlay">
        <Navbar />
        <Sidebar />
        <main className="pl-56 pt-14">
          <div className="p-6 max-w-6xl">
            <Routes>
              <Route index                      element={<Overview />} />
              <Route path="scans"               element={<ScansPage />} />
              <Route path="scans/:scanId"        element={<ScanDetail />} />
              <Route path="ddos"                element={<DDoSPanel />} />
              <Route path="reports"             element={<PlaceholderPage title="REPORTS" />} />
              <Route path="billing"             element={<BillingPage />} />
              <Route path="settings"            element={<PlaceholderPage title="SETTINGS" />} />
              <Route path="admin/*"              element={<AdminPanel />} />
            </Routes>
          </div>
        </main>
      </div>
    </PageTransition>
  )
}
