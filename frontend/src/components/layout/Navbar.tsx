import { Link, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ShieldCheck, LogOut, User, ChevronDown } from 'lucide-react'
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { useAuthStore } from '@/stores/authStore'
import { authApi } from '@/lib/api'
import { cn } from '@/lib/utils'

export function Navbar() {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)

  async function handleLogout() {
    try { await authApi.logout() } catch { /* ignore */ }
    logout()
    navigate('/login')
  }

  return (
    <motion.header
      className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-6 h-14 border-b border-cyber-border bg-cyber-bg/80 backdrop-blur-sm"
      initial={{ y: -60, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <Link to="/" className="flex items-center gap-2 group cursor-pointer">
        <ShieldCheck className="w-5 h-5 text-cyber-green group-hover:drop-shadow-[0_0_6px_#22C55E] transition-all duration-200" />
        <span className="font-mono font-bold text-sm tracking-wider neon-text">
          PENTRA<span className="text-cyber-green">SCAN</span>
        </span>
      </Link>

      {user && (
        <div className="relative">
          <button
            onClick={() => setMenuOpen(!menuOpen)}
            className="flex items-center gap-2 text-sm font-mono text-cyber-muted hover:text-cyber-text transition-colors duration-200 cursor-pointer"
          >
            <User className="w-4 h-4" />
            <span className="hidden sm:block">{user.email}</span>
            <ChevronDown className={cn('w-3 h-3 transition-transform duration-200', menuOpen && 'rotate-180')} />
          </button>

          {menuOpen && (
            <motion.div
              className="absolute right-0 top-full mt-2 w-48 cyber-card border border-cyber-border rounded-lg py-1 shadow-lg"
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.15 }}
            >
              <div className="px-3 py-2 border-b border-cyber-border">
                <p className="text-xs font-mono text-cyber-muted">TIER</p>
                <p className="text-xs font-mono text-cyber-green uppercase">{user.subscription_tier}</p>
              </div>
              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-2 px-3 py-2 text-sm font-mono text-cyber-muted hover:text-cyber-red hover:bg-cyber-red/5 transition-colors duration-150 cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
                LOGOUT
              </button>
            </motion.div>
          )}
        </div>
      )}
    </motion.header>
  )
}

export function PublicNavbar() {
  return (
    <motion.header
      className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-6 h-14 border-b border-cyber-border/50 bg-cyber-bg/60 backdrop-blur-sm"
      initial={{ y: -60, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <Link to="/" className="flex items-center gap-2 group cursor-pointer">
        <ShieldCheck className="w-5 h-5 text-cyber-green group-hover:drop-shadow-[0_0_6px_#22C55E] transition-all duration-200" />
        <span className="font-mono font-bold text-sm tracking-wider">
          PENTRA<span className="text-cyber-green neon-text">SCAN</span>
        </span>
      </Link>

      <nav className="hidden md:flex items-center gap-6">
        {['FEATURES', 'PRICING', 'DOCS'].map((item) => (
          <a
            key={item}
            href={`#${item.toLowerCase()}`}
            className="text-xs font-mono text-cyber-muted hover:text-cyber-green transition-colors duration-200 cursor-pointer tracking-widest"
          >
            {item}
          </a>
        ))}
      </nav>

      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" asChild>
          <Link to="/login">LOGIN</Link>
        </Button>
        <Button size="sm" asChild>
          <Link to="/register">GET STARTED</Link>
        </Button>
      </div>
    </motion.header>
  )
}
