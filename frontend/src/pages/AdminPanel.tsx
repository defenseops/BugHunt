import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Users, Shield, Activity, Search, RefreshCw,
  ChevronLeft, ChevronRight, ToggleLeft, ToggleRight,
  Crown, UserX, TrendingUp, Clock, CheckCircle, XCircle,
} from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { adminApi } from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface AdminUser {
  id: string; email: string; full_name: string | null
  role: string; is_active: boolean; created_at: string; subscription_tier: string
}
interface AdminScan {
  id: string; user_id: string; user_email: string
  target: string; scan_type: string; status: string; created_at: string
}
interface Stats {
  total_users: number; active_users: number; pro_users: number
  total_scans: number; running_scans: number; completed_scans: number
  failed_scans: number; total_reports: number
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
}

function PlanBadge({ plan }: { plan: string }) {
  return (
    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase
      ${plan === 'pro'
        ? 'border-cyber-green/40 text-cyber-green bg-cyber-green/5'
        : 'border-cyber-border text-cyber-muted'
      }`}>
      {plan}
    </span>
  )
}

function StatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    completed: 'bg-cyber-green', running: 'bg-yellow-400 animate-pulse',
    failed: 'bg-cyber-red', pending: 'bg-cyber-muted',
  }
  return <span className={`inline-block w-1.5 h-1.5 rounded-full mr-2 ${colors[status] ?? 'bg-cyber-muted'}`} />
}

function Pagination({ page, total, limit, onPage }: {
  page: number; total: number; limit: number; onPage: (p: number) => void
}) {
  const pages = Math.ceil(total / limit)
  if (pages <= 1) return null
  return (
    <div className="flex items-center justify-between pt-3 border-t border-cyber-border">
      <span className="text-[10px] font-mono text-cyber-muted">
        {(page - 1) * limit + 1}–{Math.min(page * limit, total)} of {total}
      </span>
      <div className="flex gap-1">
        <button disabled={page === 1} onClick={() => onPage(page - 1)}
          className="p-1 rounded hover:bg-cyber-surface disabled:opacity-30 transition-colors">
          <ChevronLeft className="w-4 h-4 text-cyber-muted" />
        </button>
        {Array.from({ length: Math.min(pages, 5) }, (_, i) => {
          const p = i + 1
          return (
            <button key={p} onClick={() => onPage(p)}
              className={`w-7 h-7 rounded text-xs font-mono transition-colors
                ${p === page ? 'bg-cyber-green/10 text-cyber-green border border-cyber-green/30' : 'text-cyber-muted hover:bg-cyber-surface'}`}>
              {p}
            </button>
          )
        })}
        <button disabled={page === pages} onClick={() => onPage(page + 1)}
          className="p-1 rounded hover:bg-cyber-surface disabled:opacity-30 transition-colors">
          <ChevronRight className="w-4 h-4 text-cyber-muted" />
        </button>
      </div>
    </div>
  )
}

// ── Users tab ─────────────────────────────────────────────────────────────────

function UsersTab() {
  const qc = useQueryClient()
  const [page, setPage]     = useState(1)
  const [search, setSearch] = useState('')
  const [plan, setPlan]     = useState('')
  const [_editId, setEditId] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['admin-users', page, search, plan],
    queryFn: () => adminApi.users({ page, limit: 20, search: search || undefined, plan: plan || undefined })
      .then(r => r.data),
  })

  const mutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      adminApi.updateUser(id, payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-users'] })
      setEditId(null)
    },
  })

  const users: AdminUser[] = data?.items ?? []
  const total: number      = data?.total ?? 0

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
          <Input value={search} onChange={e => { setSearch(e.target.value); setPage(1) }}
            placeholder="Search by email…" className="pl-9 font-mono text-sm" />
        </div>
        <div className="flex gap-1">
          {['', 'free', 'pro'].map(p => (
            <button key={p} onClick={() => { setPlan(p); setPage(1) }}
              className={`px-3 py-1.5 rounded text-xs font-mono border transition-all
                ${plan === p ? 'border-cyber-green text-cyber-green bg-cyber-green/5' : 'border-cyber-border text-cyber-muted hover:border-cyber-muted/50'}`}>
              {p === '' ? 'All' : p.toUpperCase()}
            </button>
          ))}
        </div>
        <Button variant="outline" size="sm" className="font-mono text-xs"
          onClick={() => qc.invalidateQueries({ queryKey: ['admin-users'] })}>
          <RefreshCw className="w-3.5 h-3.5" />
        </Button>
      </div>

      {/* Table */}
      <div className="cyber-card overflow-hidden">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="border-b border-cyber-border bg-cyber-surface/50">
              {['Email', 'Name', 'Plan', 'Role', 'Status', 'Joined', 'Actions'].map(h => (
                <th key={h} className="text-left py-2.5 px-4 text-[10px] text-cyber-muted uppercase tracking-widest">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} className="border-b border-cyber-border/40">
                  {Array.from({ length: 7 }).map((_, j) => (
                    <td key={j} className="py-3 px-4">
                      <div className="h-3 bg-cyber-surface rounded animate-pulse" />
                    </td>
                  ))}
                </tr>
              ))
            ) : users.map(user => (
              <tr key={user.id}
                className="border-b border-cyber-border/40 hover:bg-cyber-surface/30 transition-colors">
                <td className="py-3 px-4 text-cyber-text">{user.email}</td>
                <td className="py-3 px-4 text-cyber-muted">{user.full_name ?? '—'}</td>
                <td className="py-3 px-4"><PlanBadge plan={user.subscription_tier} /></td>
                <td className="py-3 px-4">
                  <span className={`text-[10px] uppercase ${user.role === 'admin' ? 'text-cyber-red' : 'text-cyber-muted'}`}>
                    {user.role}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <span className={`flex items-center gap-1.5 ${user.is_active ? 'text-cyber-green' : 'text-cyber-red'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${user.is_active ? 'bg-cyber-green' : 'bg-cyber-red'}`} />
                    {user.is_active ? 'Active' : 'Disabled'}
                  </span>
                </td>
                <td className="py-3 px-4 text-cyber-muted">{fmtDate(user.created_at)}</td>
                <td className="py-3 px-4">
                  <div className="flex items-center gap-1">
                    {/* Toggle active */}
                    <button
                      title={user.is_active ? 'Disable' : 'Enable'}
                      onClick={() => mutation.mutate({ id: user.id, payload: { is_active: !user.is_active } })}
                      className="p-1 rounded hover:bg-cyber-surface transition-colors"
                    >
                      {user.is_active
                        ? <ToggleRight className="w-4 h-4 text-cyber-green" />
                        : <ToggleLeft  className="w-4 h-4 text-cyber-muted" />}
                    </button>
                    {/* Toggle plan */}
                    <button
                      title={user.subscription_tier === 'pro' ? 'Downgrade to Free' : 'Grant Pro'}
                      onClick={() => mutation.mutate({
                        id: user.id,
                        payload: { plan: user.subscription_tier === 'pro' ? 'free' : 'pro' }
                      })}
                      className="p-1 rounded hover:bg-cyber-surface transition-colors"
                    >
                      <Crown className={`w-4 h-4 ${user.subscription_tier === 'pro' ? 'text-yellow-400' : 'text-cyber-muted'}`} />
                    </button>
                    {/* Toggle admin */}
                    <button
                      title={user.role === 'admin' ? 'Remove admin' : 'Make admin'}
                      onClick={() => mutation.mutate({
                        id: user.id,
                        payload: { role: user.role === 'admin' ? 'user' : 'admin' }
                      })}
                      className="p-1 rounded hover:bg-cyber-surface transition-colors"
                    >
                      <UserX className={`w-4 h-4 ${user.role === 'admin' ? 'text-cyber-red' : 'text-cyber-muted'}`} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {!isLoading && users.length === 0 && (
          <div className="text-center py-10 text-xs font-mono text-cyber-muted/50">No users found</div>
        )}

        <div className="px-4 pb-4">
          <Pagination page={page} total={total} limit={20} onPage={setPage} />
        </div>
      </div>
    </div>
  )
}

// ── Scans tab ─────────────────────────────────────────────────────────────────

function ScansTab() {
  const qc = useQueryClient()
  const [page, setPage]         = useState(1)
  const [statusFilter, setStatus] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['admin-scans', page, statusFilter],
    queryFn:  () => adminApi.scans({ page, limit: 20, status: statusFilter || undefined }).then(r => r.data),
  })

  const scans: AdminScan[] = data?.items ?? []
  const total: number      = data?.total ?? 0

  const STATUSES = ['', 'pending', 'running', 'completed', 'failed']

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex gap-1 flex-wrap">
          {STATUSES.map(s => (
            <button key={s} onClick={() => { setStatus(s); setPage(1) }}
              className={`px-3 py-1.5 rounded text-xs font-mono border transition-all
                ${statusFilter === s ? 'border-cyber-green text-cyber-green bg-cyber-green/5' : 'border-cyber-border text-cyber-muted hover:border-cyber-muted/50'}`}>
              {s === '' ? 'All' : s}
            </button>
          ))}
        </div>
        <Button variant="outline" size="sm" className="font-mono text-xs ml-auto"
          onClick={() => qc.invalidateQueries({ queryKey: ['admin-scans'] })}>
          <RefreshCw className="w-3.5 h-3.5" />
        </Button>
      </div>

      <div className="cyber-card overflow-hidden">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="border-b border-cyber-border bg-cyber-surface/50">
              {['Target', 'Type', 'Status', 'User', 'Created'].map(h => (
                <th key={h} className="text-left py-2.5 px-4 text-[10px] text-cyber-muted uppercase tracking-widest">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} className="border-b border-cyber-border/40">
                  {Array.from({ length: 5 }).map((_, j) => (
                    <td key={j} className="py-3 px-4">
                      <div className="h-3 bg-cyber-surface rounded animate-pulse" />
                    </td>
                  ))}
                </tr>
              ))
            ) : scans.map(scan => (
              <tr key={scan.id} className="border-b border-cyber-border/40 hover:bg-cyber-surface/30 transition-colors">
                <td className="py-3 px-4 text-cyber-text font-mono">{scan.target}</td>
                <td className="py-3 px-4">
                  <span className="text-[10px] uppercase border border-cyber-border px-1.5 py-0.5 rounded text-cyber-muted">
                    {scan.scan_type}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <span className="flex items-center text-cyber-muted">
                    <StatusDot status={scan.status} />{scan.status}
                  </span>
                </td>
                <td className="py-3 px-4 text-cyber-muted">{scan.user_email}</td>
                <td className="py-3 px-4 text-cyber-muted">{fmtDate(scan.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {!isLoading && scans.length === 0 && (
          <div className="text-center py-10 text-xs font-mono text-cyber-muted/50">No scans found</div>
        )}

        <div className="px-4 pb-4">
          <Pagination page={page} total={total} limit={20} onPage={setPage} />
        </div>
      </div>
    </div>
  )
}

// ── Stats tab ─────────────────────────────────────────────────────────────────

function StatsTab() {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery<Stats>({
    queryKey: ['admin-stats'],
    queryFn:  () => adminApi.stats().then(r => r.data),
    refetchInterval: 30_000,
  })

  const statCards = data ? [
    { label: 'Total Users',    value: data.total_users,     icon: Users,       color: 'text-cyber-blue',   border: 'border-cyber-blue' },
    { label: 'Active Users',   value: data.active_users,    icon: Activity,    color: 'text-cyber-green',  border: 'border-cyber-green' },
    { label: 'Pro Users',      value: data.pro_users,       icon: Crown,       color: 'text-yellow-400',   border: 'border-yellow-400' },
    { label: 'Total Scans',    value: data.total_scans,     icon: Shield,      color: 'text-cyber-text',   border: 'border-cyber-border' },
    { label: 'Running',        value: data.running_scans,   icon: TrendingUp,  color: 'text-yellow-400',   border: 'border-yellow-400' },
    { label: 'Completed',      value: data.completed_scans, icon: CheckCircle, color: 'text-cyber-green',  border: 'border-cyber-green' },
    { label: 'Failed',         value: data.failed_scans,    icon: XCircle,     color: 'text-cyber-red',    border: 'border-cyber-red' },
    { label: 'Reports',        value: data.total_reports,   icon: Clock,       color: 'text-cyber-muted',  border: 'border-cyber-border' },
  ] : []

  const conversion = data && data.total_users > 0
    ? ((data.pro_users / data.total_users) * 100).toFixed(1)
    : '0.0'

  return (
    <div className="space-y-5">
      <div className="flex justify-end">
        <Button variant="outline" size="sm" className="font-mono text-xs"
          onClick={() => qc.invalidateQueries({ queryKey: ['admin-stats'] })}>
          <RefreshCw className="w-3.5 h-3.5 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Metric grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {isLoading
          ? Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="cyber-card p-5 h-20 animate-pulse" />
            ))
          : statCards.map(({ label, value, icon: Icon, color, border }) => (
              <motion.div
                key={label}
                className="cyber-card p-5 flex items-start gap-3"
                whileHover={{ scale: 1.02 }}
                transition={{ duration: 0.15 }}
              >
                <div className={`p-2 rounded-lg border ${border} bg-current/5`}>
                  <Icon className={`w-4 h-4 ${color}`} />
                </div>
                <div>
                  <p className={`text-2xl font-mono font-bold ${color}`}>{value}</p>
                  <p className="text-[9px] font-mono text-cyber-muted uppercase tracking-widest mt-0.5">{label}</p>
                </div>
              </motion.div>
            ))
        }
      </div>

      {/* Conversion + scan health */}
      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Free → Pro conversion */}
          <div className="cyber-card p-5 space-y-3">
            <h3 className="text-xs font-mono text-cyber-muted uppercase tracking-widest">
              Free → Pro Conversion
            </h3>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-mono font-bold text-cyber-green">{conversion}%</span>
              <span className="text-xs font-mono text-cyber-muted">
                ({data.pro_users} / {data.total_users} users)
              </span>
            </div>
            <div className="h-2 bg-cyber-border rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-cyber-green rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${conversion}%` }}
                transition={{ duration: 0.8 }}
              />
            </div>
          </div>

          {/* Scan health */}
          <div className="cyber-card p-5 space-y-3">
            <h3 className="text-xs font-mono text-cyber-muted uppercase tracking-widest">
              Scan Health
            </h3>
            {data.total_scans > 0 && (() => {
              const bars = [
                { label: 'Completed', count: data.completed_scans, color: 'bg-cyber-green' },
                { label: 'Running',   count: data.running_scans,   color: 'bg-yellow-400' },
                { label: 'Failed',    count: data.failed_scans,    color: 'bg-cyber-red' },
              ]
              return bars.map(({ label, count, color }) => (
                <div key={label} className="space-y-1">
                  <div className="flex justify-between text-[10px] font-mono text-cyber-muted">
                    <span>{label}</span>
                    <span>{count} ({((count / data.total_scans) * 100).toFixed(0)}%)</span>
                  </div>
                  <div className="h-1.5 bg-cyber-border rounded-full overflow-hidden">
                    <motion.div
                      className={`h-full rounded-full ${color}`}
                      initial={{ width: 0 }}
                      animate={{ width: `${(count / data.total_scans) * 100}%` }}
                      transition={{ duration: 0.6 }}
                    />
                  </div>
                </div>
              ))
            })()}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main Admin Panel ──────────────────────────────────────────────────────────

type Tab = 'users' | 'scans' | 'stats'

const TABS: { id: Tab; label: string; icon: React.FC<{ className?: string }> }[] = [
  { id: 'users', label: 'Users',      icon: Users    },
  { id: 'scans', label: 'Scans',      icon: Shield   },
  { id: 'stats', label: 'Statistics', icon: Activity },
]

export default function AdminPanel() {
  const [tab, setTab] = useState<Tab>('users')

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-xl font-mono font-bold text-cyber-text flex items-center gap-2">
          <Shield className="w-5 h-5 text-cyber-red" />
          ADMIN PANEL
        </h1>
        <p className="text-xs font-mono text-cyber-muted mt-1">System administration</p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-cyber-border pb-0">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono transition-all
              border-b-2 -mb-px ${tab === id
                ? 'border-cyber-green text-cyber-green'
                : 'border-transparent text-cyber-muted hover:text-cyber-text'
              }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={tab}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -6 }}
          transition={{ duration: 0.15 }}
        >
          {tab === 'users' && <UsersTab />}
          {tab === 'scans' && <ScansTab />}
          {tab === 'stats' && <StatsTab />}
        </motion.div>
      </AnimatePresence>
    </div>
  )
}
