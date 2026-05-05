import { NavLink } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  LayoutDashboard, Shield, FileText, CreditCard,
  Settings, ChevronRight, Zap, Flag,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/stores/authStore'

const navItems = [
  { to: '/dashboard',          label: 'OVERVIEW',  icon: LayoutDashboard },
  { to: '/dashboard/scans',    label: 'SCANS',     icon: Shield },
  { to: '/dashboard/ctf',      label: 'CTF MODE',  icon: Flag, ctf: true },
  { to: '/dashboard/reports',  label: 'REPORTS',   icon: FileText },
  { to: '/dashboard/billing',  label: 'BILLING',   icon: CreditCard },
  { to: '/dashboard/ddos',     label: 'DDOS TEST', icon: Zap },
  { to: '/dashboard/settings', label: 'SETTINGS',  icon: Settings },
]

const adminItems = [
  { to: '/dashboard/admin', label: 'ADMIN', icon: Shield },
]

const itemVariants = {
  hidden:  { opacity: 0, x: -12 },
  visible: (i: number) => ({ opacity: 1, x: 0, transition: { delay: i * 0.05, duration: 0.2 } }),
}

export function Sidebar() {
  const role = useAuthStore((s) => s.user?.role)

  return (
    <motion.aside
      className="fixed left-0 top-14 bottom-0 w-56 border-r border-cyber-border bg-cyber-bg/95 backdrop-blur-sm flex flex-col z-40"
      initial={{ x: -224, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ duration: 0.3, ease: 'easeOut' }}
    >
      <div className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
        <p className="px-3 pb-2 text-[10px] font-mono text-cyber-muted/50 uppercase tracking-[0.2em]">Navigation</p>
        {navItems.map((item, i) => (
          <motion.div key={item.to} variants={itemVariants} initial="hidden" animate="visible" custom={i}>
            <SidebarLink {...item} ctf={item.ctf} />
          </motion.div>
        ))}

        {role === 'admin' && (
          <>
            <div className="pt-4">
              <p className="px-3 pb-2 text-[10px] font-mono text-cyber-red/50 uppercase tracking-[0.2em]">Admin</p>
              {adminItems.map((item, i) => (
                <motion.div key={item.to} variants={itemVariants} initial="hidden" animate="visible" custom={navItems.length + i}>
                  <SidebarLink {...item} danger />
                </motion.div>
              ))}
            </div>
          </>
        )}
      </div>

      <div className="p-3 border-t border-cyber-border">
        <div className="flex items-center gap-2 px-2 py-1.5 rounded text-[10px] font-mono text-cyber-muted">
          <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
          SYSTEM ONLINE
        </div>
      </div>
    </motion.aside>
  )
}

interface SidebarLinkProps {
  to: string
  label: string
  icon: React.FC<{ className?: string }>
  danger?: boolean
  ctf?: boolean
}

function SidebarLink({ to, label, icon: Icon, danger, ctf }: SidebarLinkProps) {
  return (
    <NavLink
      to={to}
      end={to === '/dashboard'}
      className={({ isActive }) =>
        cn(
          'group flex items-center justify-between px-3 py-2 rounded text-xs font-mono transition-all duration-150 cursor-pointer',
          isActive
            ? danger
              ? 'bg-cyber-red/10 text-cyber-red border border-cyber-red/30'
              : ctf
              ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/40'
              : 'bg-cyber-green/10 text-cyber-green border border-cyber-green/30'
            : ctf
            ? 'text-yellow-500/70 hover:text-yellow-400 hover:bg-yellow-500/5'
            : 'text-cyber-muted hover:text-cyber-text hover:bg-cyber-secondary/50',
        )
      }
    >
      <span className="flex items-center gap-2.5">
        <Icon className="w-3.5 h-3.5 shrink-0" />
        {label}
        {ctf && <span className="text-[9px] text-yellow-500/60 ml-0.5">⚑</span>}
      </span>
      <ChevronRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity duration-150" />
    </NavLink>
  )
}
