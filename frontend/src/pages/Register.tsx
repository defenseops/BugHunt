import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ShieldCheck, Mail, Lock, User, AlertCircle, CheckCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { PageTransition } from '@/components/common/PageTransition'
import { authApi } from '@/lib/api'
import { useAuthStore } from '@/stores/authStore'

const requirements = [
  { label: 'At least 8 characters',   test: (p: string) => p.length >= 8 },
  { label: 'Contains uppercase',       test: (p: string) => /[A-Z]/.test(p) },
  { label: 'Contains number',          test: (p: string) => /[0-9]/.test(p) },
]

export default function Register() {
  const navigate = useNavigate()
  const setAuth = useAuthStore((s) => s.setAuth)
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const passOk = requirements.every((r) => r.test(password))

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!passOk) return
    setError('')
    setLoading(true)
    try {
      const res = await authApi.register({ email, password, full_name: fullName })
      const { access_token, user } = res.data
      setAuth(access_token, user)
      navigate('/dashboard')
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg ?? 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageTransition>
      <div className="min-h-screen bg-cyber-bg grid-bg flex items-center justify-center px-4 py-12 scanline-overlay">
        <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyber-green/5 rounded-full blur-3xl pointer-events-none" />

        <motion.div
          className="relative z-10 w-full max-w-sm"
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <div className="text-center mb-8">
            <motion.div
              className="inline-flex items-center justify-center w-12 h-12 rounded-lg border border-cyber-green/30 bg-cyber-green/5 mb-4"
              animate={{ boxShadow: ['0 0 8px #22C55E33', '0 0 20px #22C55E44', '0 0 8px #22C55E33'] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              <ShieldCheck className="w-6 h-6 text-cyber-green" />
            </motion.div>
            <h1 className="text-xl font-mono font-bold text-cyber-text">
              PENTRA<span className="text-cyber-green neon-text">SCAN</span>
            </h1>
            <p className="text-xs font-mono text-cyber-muted mt-1 tracking-widest">CREATE ACCOUNT</p>
          </div>

          <div className="cyber-card border border-cyber-border rounded-xl p-6 shadow-card">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="name">FULL NAME</Label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted pointer-events-none" />
                  <Input
                    id="name"
                    type="text"
                    placeholder="John Operator"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="pl-9"
                    required
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="email">EMAIL</Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted pointer-events-none" />
                  <Input
                    id="email"
                    type="email"
                    placeholder="operator@target.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="pl-9"
                    required
                    autoComplete="email"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="password">PASSWORD</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted pointer-events-none" />
                  <Input
                    id="password"
                    type="password"
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="pl-9"
                    required
                    autoComplete="new-password"
                  />
                </div>
                {password.length > 0 && (
                  <motion.ul
                    className="space-y-1 pt-1"
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                  >
                    {requirements.map((r) => {
                      const ok = r.test(password)
                      return (
                        <li key={r.label} className="flex items-center gap-1.5">
                          <CheckCircle className={`w-3 h-3 ${ok ? 'text-cyber-green' : 'text-cyber-muted/30'}`} />
                          <span className={`text-[10px] font-mono ${ok ? 'text-cyber-green' : 'text-cyber-muted/50'}`}>
                            {r.label}
                          </span>
                        </li>
                      )
                    })}
                  </motion.ul>
                )}
              </div>

              {error && (
                <motion.div
                  className="flex items-center gap-2 p-3 rounded border border-cyber-red/30 bg-cyber-red/5"
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                >
                  <AlertCircle className="w-3.5 h-3.5 text-cyber-red shrink-0" />
                  <p className="text-xs font-mono text-cyber-red">{error}</p>
                </motion.div>
              )}

              <Button type="submit" className="w-full mt-2" loading={loading} disabled={!passOk}>
                {loading ? 'CREATING ACCOUNT...' : 'CREATE ACCOUNT'}
              </Button>
            </form>

            <div className="mt-4 pt-4 border-t border-cyber-border text-center">
              <p className="text-xs font-mono text-cyber-muted">
                Already have an account?{' '}
                <Link to="/login" className="text-cyber-green hover:neon-text transition-all duration-200 cursor-pointer">
                  LOGIN
                </Link>
              </p>
            </div>
          </div>

          <p className="text-center text-[10px] font-mono text-cyber-muted/40 mt-6 tracking-widest">
            FREE — 3 SCANS INCLUDED
          </p>
        </motion.div>
      </div>
    </PageTransition>
  )
}
