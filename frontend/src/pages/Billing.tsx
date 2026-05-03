import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  CreditCard, Check, Zap, Shield, FileText,
  Clock, AlertCircle, ExternalLink, RefreshCw,
} from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { billingApi } from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface BillingStatus {
  plan: string
  status: string
  expires_at: string | null
  payment_provider: string | null
}

interface HistoryItem {
  id: string
  plan: string
  status: string
  payment_provider: string | null
  payment_id: string | null
  created_at: string
  expires_at: string | null
}

// ── Plan features ─────────────────────────────────────────────────────────────

const FREE_FEATURES = [
  { text: '3 scan targets total',        ok: true  },
  { text: 'DNS + OSINT + Port scan',     ok: true  },
  { text: 'CVE mapping (NVD)',           ok: true  },
  { text: 'PDF report (RU/EN)',          ok: true  },
  { text: 'Web vulnerabilities (SQLi, XSS, LFI…)', ok: false },
  { text: 'Brute force (Hydra, SMB/AD)', ok: false },
  { text: 'Post-exploitation & PrivEsc', ok: false },
  { text: 'DDoS stress testing',         ok: false },
  { text: 'Metasploit integration',      ok: false },
  { text: 'Unlimited targets',           ok: false },
]

const PRO_FEATURES = [
  { text: 'Unlimited scan targets',      ok: true },
  { text: 'Full scanner pipeline',       ok: true },
  { text: 'Web vulns (SQLi, XSS, LFI…)', ok: true },
  { text: 'Brute force (Hydra, SMB/AD)', ok: true },
  { text: 'Post-exploitation & PrivEsc', ok: true },
  { text: 'DDoS stress testing',         ok: true },
  { text: 'Metasploit integration',      ok: true },
  { text: 'Hash cracking',               ok: true },
  { text: 'Priority support',            ok: true },
  { text: '30-day subscription',         ok: true },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
  })
}

function daysLeft(iso: string | null): number | null {
  if (!iso) return null
  const diff = new Date(iso).getTime() - Date.now()
  return Math.max(0, Math.ceil(diff / 86_400_000))
}

function statusColor(s: string): string {
  switch (s) {
    case 'active':    return 'text-cyber-green border-cyber-green/30 bg-cyber-green/5'
    case 'expired':   return 'text-cyber-red border-cyber-red/30 bg-cyber-red/5'
    case 'cancelled': return 'text-cyber-muted border-cyber-border bg-transparent'
    default:          return 'text-cyber-muted border-cyber-border bg-transparent'
  }
}

// ── Current plan card ─────────────────────────────────────────────────────────

function CurrentPlan({ data }: { data: BillingStatus }) {
  const isPro    = data.plan === 'pro' && data.status === 'active'
  const days     = daysLeft(data.expires_at)

  return (
    <div className="cyber-card p-6">
      <div className="flex items-start justify-between mb-4">
        <div>
          <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest mb-1">Current Plan</p>
          <h2 className="text-2xl font-mono font-bold text-cyber-text">
            {isPro ? 'PRO' : 'FREE'}
          </h2>
        </div>
        <span className={`text-xs font-mono px-2.5 py-1 rounded border uppercase ${statusColor(data.status)}`}>
          {data.status}
        </span>
      </div>

      {isPro && data.expires_at && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs font-mono text-cyber-muted">
            <Clock className="w-3.5 h-3.5" />
            Expires {fmtDate(data.expires_at)}
            {days !== null && (
              <span className={`ml-1 ${days <= 5 ? 'text-cyber-red' : 'text-cyber-green'}`}>
                ({days}d left)
              </span>
            )}
          </div>
          {days !== null && days <= 30 && (
            <div className="h-1.5 bg-cyber-border rounded-full overflow-hidden">
              <motion.div
                className={`h-full rounded-full ${days <= 5 ? 'bg-cyber-red' : 'bg-cyber-green'}`}
                initial={{ width: 0 }}
                animate={{ width: `${(days / 30) * 100}%` }}
                transition={{ duration: 0.6 }}
              />
            </div>
          )}
        </div>
      )}

      {data.payment_provider && (
        <p className="text-xs font-mono text-cyber-muted mt-3">
          Paid via{' '}
          <span className="text-cyber-text capitalize">{data.payment_provider}</span>
        </p>
      )}
    </div>
  )
}

// ── Plan card ─────────────────────────────────────────────────────────────────

function PlanCard({
  title, price, currency, period, features, current, onSelect, loading,
}: {
  title: string
  price: string
  currency: string
  period: string
  features: { text: string; ok: boolean }[]
  current: boolean
  onSelect: () => void
  loading: boolean
}) {
  const isPro = title === 'PRO'

  return (
    <motion.div
      className={`cyber-card p-6 flex flex-col gap-5 relative overflow-hidden
        ${isPro ? 'border-cyber-green/40' : ''}`}
      whileHover={{ scale: 1.01 }}
      transition={{ duration: 0.15 }}
    >
      {isPro && (
        <div className="absolute top-0 right-0 bg-cyber-green text-cyber-bg text-[10px] font-mono
                        font-bold px-3 py-1 rounded-bl">
          RECOMMENDED
        </div>
      )}

      <div>
        <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest mb-1">{title}</p>
        <div className="flex items-baseline gap-1.5">
          <span className="text-3xl font-mono font-bold text-cyber-text">{price}</span>
          <span className="text-sm font-mono text-cyber-muted">{currency}/{period}</span>
        </div>
      </div>

      <ul className="space-y-2 flex-1">
        {features.map((f, i) => (
          <li key={i} className="flex items-start gap-2.5 text-xs font-mono">
            <Check className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${f.ok ? 'text-cyber-green' : 'text-cyber-border'}`} />
            <span className={f.ok ? 'text-cyber-text' : 'text-cyber-muted/40 line-through'}>{f.text}</span>
          </li>
        ))}
      </ul>

      <Button
        onClick={onSelect}
        disabled={current || loading}
        className={`w-full font-mono text-sm ${
          current
            ? 'opacity-40 cursor-not-allowed'
            : isPro
              ? 'bg-cyber-green hover:bg-cyber-green/80 text-cyber-bg'
              : 'variant-outline'
        }`}
        variant={isPro ? 'default' : 'outline'}
      >
        {current ? 'CURRENT PLAN' : isPro ? 'UPGRADE TO PRO' : 'DOWNGRADE TO FREE'}
      </Button>
    </motion.div>
  )
}

// ── Payment method selector ───────────────────────────────────────────────────

function PaymentModal({ onClose, onKaspi, onStripe, loading }: {
  onClose: () => void
  onKaspi: () => void
  onStripe: () => void
  loading: boolean
}) {
  return (
    <motion.div
      className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.div
        className="cyber-card p-6 w-full max-w-sm space-y-5"
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        onClick={e => e.stopPropagation()}
      >
        <div>
          <h3 className="text-sm font-mono font-bold text-cyber-text">Choose Payment Method</h3>
          <p className="text-xs font-mono text-cyber-muted mt-1">Pro plan — 4,990 ₸ / month</p>
        </div>

        <div className="space-y-3">
          {/* Kaspi Pay */}
          <button
            onClick={onKaspi}
            disabled={loading}
            className="w-full flex items-center gap-4 p-4 rounded-lg border border-cyber-border
                       hover:border-yellow-400/50 hover:bg-yellow-400/5 transition-all text-left"
          >
            <div className="w-10 h-10 rounded-lg bg-yellow-400/10 border border-yellow-400/20
                            flex items-center justify-center shrink-0">
              <span className="text-yellow-400 font-bold text-sm">K</span>
            </div>
            <div>
              <p className="text-sm font-mono text-cyber-text">Kaspi Pay</p>
              <p className="text-[10px] font-mono text-cyber-muted">Kazakhstan cards · instant</p>
            </div>
            <ExternalLink className="w-3.5 h-3.5 text-cyber-muted ml-auto shrink-0" />
          </button>

          {/* Stripe */}
          <button
            onClick={onStripe}
            disabled={loading}
            className="w-full flex items-center gap-4 p-4 rounded-lg border border-cyber-border
                       hover:border-cyber-blue/50 hover:bg-cyber-blue/5 transition-all text-left"
          >
            <div className="w-10 h-10 rounded-lg bg-cyber-blue/10 border border-cyber-blue/20
                            flex items-center justify-center shrink-0">
              <CreditCard className="w-5 h-5 text-cyber-blue" />
            </div>
            <div>
              <p className="text-sm font-mono text-cyber-text">Stripe</p>
              <p className="text-[10px] font-mono text-cyber-muted">Visa / Mastercard · worldwide</p>
            </div>
            <ExternalLink className="w-3.5 h-3.5 text-cyber-muted ml-auto shrink-0" />
          </button>
        </div>

        <Button variant="outline" className="w-full font-mono text-xs" onClick={onClose}>
          Cancel
        </Button>
      </motion.div>
    </motion.div>
  )
}

// ── History table ─────────────────────────────────────────────────────────────

function HistoryTable({ items }: { items: HistoryItem[] }) {
  if (items.length === 0) {
    return (
      <div className="text-center py-8 text-xs font-mono text-cyber-muted/50">
        No payment history yet
      </div>
    )
  }

  return (
    <table className="w-full text-xs font-mono">
      <thead>
        <tr className="border-b border-cyber-border">
          {['Plan', 'Provider', 'Status', 'Created', 'Expires'].map(h => (
            <th key={h} className="text-left py-2 px-3 text-[10px] text-cyber-muted uppercase tracking-widest">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {items.map(item => (
          <tr key={item.id} className="border-b border-cyber-border/40 hover:bg-cyber-surface/30 transition-colors">
            <td className="py-2.5 px-3 text-cyber-text capitalize">{item.plan}</td>
            <td className="py-2.5 px-3 text-cyber-muted capitalize">{item.payment_provider ?? '—'}</td>
            <td className="py-2.5 px-3">
              <span className={`px-2 py-0.5 rounded border text-[10px] uppercase ${statusColor(item.status)}`}>
                {item.status}
              </span>
            </td>
            <td className="py-2.5 px-3 text-cyber-muted">{fmtDate(item.created_at)}</td>
            <td className="py-2.5 px-3 text-cyber-muted">{fmtDate(item.expires_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function BillingPage() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [payError, setPayError]   = useState<string | null>(null)
  const [successMsg, setSuccess]  = useState<string | null>(null)

  const { data: statusData, isLoading: statusLoading } = useQuery({
    queryKey: ['billing-status'],
    queryFn:  () => billingApi.status().then(r => r.data as BillingStatus),
    refetchInterval: 30_000,
  })

  const { data: historyData, isLoading: histLoading } = useQuery({
    queryKey: ['billing-history'],
    queryFn:  () => (billingApi as any).history().then((r: any) => r.data),
  })

  const kaspiMutation = useMutation({
    mutationFn: () => billingApi.createKaspi(),
    onSuccess: (res) => {
      window.open(res.data.payment_url, '_blank')
      setShowModal(false)
      setSuccess('Kaspi Pay window opened. Complete payment to activate Pro.')
      qc.invalidateQueries({ queryKey: ['billing-status'] })
    },
    onError: (e: any) => {
      setPayError(e?.response?.data?.detail ?? 'Kaspi Pay not available')
      setShowModal(false)
    },
  })

  const stripeMutation = useMutation({
    mutationFn: () => billingApi.createStripe(),
    onSuccess: (res) => {
      window.location.href = res.data.checkout_url
    },
    onError: (e: any) => {
      setPayError(e?.response?.data?.detail ?? 'Stripe not available')
      setShowModal(false)
    },
  })

  const isLoading  = kaspiMutation.isPending || stripeMutation.isPending
  const isPro      = statusData?.plan === 'pro' && statusData?.status === 'active'
  const history: HistoryItem[] = historyData?.items ?? []

  // Check URL params for success/cancelled
  const params = new URLSearchParams(window.location.search)
  const urlSuccess   = params.get('success')   === '1'
  const urlCancelled = params.get('cancelled') === '1'

  return (
    <div className="space-y-6 max-w-4xl">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-mono font-bold text-cyber-text flex items-center gap-2">
            <CreditCard className="w-5 h-5 text-cyber-green" />
            BILLING
          </h1>
          <p className="text-xs font-mono text-cyber-muted mt-1">Manage your subscription</p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="font-mono text-xs"
          onClick={() => qc.invalidateQueries({ queryKey: ['billing-status', 'billing-history'] })}
        >
          <RefreshCw className="w-3.5 h-3.5 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Alerts */}
      <AnimatePresence>
        {(urlSuccess || successMsg) && (
          <motion.div
            initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="flex items-center gap-3 bg-cyber-green/5 border border-cyber-green/20 rounded-lg p-4"
          >
            <Check className="w-4 h-4 text-cyber-green shrink-0" />
            <p className="text-xs font-mono text-cyber-green">
              {successMsg ?? 'Payment successful! Your Pro subscription is now active.'}
            </p>
          </motion.div>
        )}
        {(urlCancelled || payError) && (
          <motion.div
            initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="flex items-center gap-3 bg-cyber-red/5 border border-cyber-red/20 rounded-lg p-4"
          >
            <AlertCircle className="w-4 h-4 text-cyber-red shrink-0" />
            <p className="text-xs font-mono text-cyber-red">
              {payError ?? 'Payment cancelled. Your plan was not changed.'}
            </p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Current plan */}
      {statusLoading ? (
        <div className="cyber-card p-6 animate-pulse h-28" />
      ) : statusData ? (
        <CurrentPlan data={statusData} />
      ) : null}

      {/* Plan cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <PlanCard
          title="FREE"
          price="0"
          currency="₸"
          period="forever"
          features={FREE_FEATURES}
          current={!isPro}
          onSelect={() => {}}
          loading={false}
        />
        <PlanCard
          title="PRO"
          price="4,990"
          currency="₸"
          period="month"
          features={PRO_FEATURES}
          current={isPro}
          onSelect={() => { setPayError(null); setSuccess(null); setShowModal(true) }}
          loading={isLoading}
        />
      </div>

      {/* Feature highlights */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { icon: Shield,   title: 'Full Pipeline',  desc: '15+ scanner modules' },
          { icon: Zap,      title: 'DDoS Testing',   desc: 'L3/L4/L7 stress tests' },
          { icon: FileText, title: 'PDF Reports',     desc: 'RU + EN professional reports' },
        ].map(({ icon: Icon, title, desc }) => (
          <div key={title} className="cyber-card p-4 text-center space-y-2">
            <Icon className="w-5 h-5 text-cyber-green mx-auto" />
            <p className="text-xs font-mono font-bold text-cyber-text">{title}</p>
            <p className="text-[10px] font-mono text-cyber-muted">{desc}</p>
          </div>
        ))}
      </div>

      {/* Payment history */}
      <div className="cyber-card p-5 space-y-4">
        <h2 className="text-xs font-mono text-cyber-muted uppercase tracking-widest">
          Payment History
        </h2>
        {histLoading ? (
          <div className="animate-pulse h-16 bg-cyber-surface rounded" />
        ) : (
          <HistoryTable items={history} />
        )}
      </div>

      {/* Payment modal */}
      <AnimatePresence>
        {showModal && (
          <PaymentModal
            onClose={() => setShowModal(false)}
            onKaspi={() => kaspiMutation.mutate()}
            onStripe={() => stripeMutation.mutate()}
            loading={isLoading}
          />
        )}
      </AnimatePresence>
    </div>
  )
}
