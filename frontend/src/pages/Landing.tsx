import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Shield, Zap, FileText, Eye, Lock, Globe,
  Terminal, ChevronRight, ArrowRight,
} from 'lucide-react'
import { PublicNavbar } from '@/components/layout/Navbar'
import { Button } from '@/components/ui/button'
import { TypingText } from '@/components/common/GlitchText'
import { PageTransition } from '@/components/common/PageTransition'

const features = [
  { icon: Shield,   title: 'Port & Service Scan',    desc: 'Nmap-powered detection of open ports, services, and OS fingerprinting.',     cls: 'col-span-2' },
  { icon: Eye,      title: 'Vulnerability Analysis', desc: 'CVE matching via OpenVAS and custom scanner modules.',                        cls: 'col-span-1' },
  { icon: Zap,      title: 'Exploit Simulation',     desc: 'Metasploit integration for safe, controlled exploit verification.',           cls: 'col-span-1' },
  { icon: Lock,     title: 'Web App Testing',        desc: 'OWASP Top 10 checks, SQLi, XSS, CSRF and more via nikto + custom rules.',    cls: 'col-span-1' },
  { icon: Globe,    title: 'Network Mapping',        desc: 'Traceroute, DNS enum, subdomain discovery and topology visualization.',      cls: 'col-span-1' },
  { icon: FileText, title: 'PDF Reports',            desc: 'Professional RU/EN reports with CVSS scores, remediation steps, charts.',    cls: 'col-span-2' },
]

const stats = [
  { value: '50+',   label: 'Scanner Modules' },
  { value: '10K+',  label: 'CVEs Detected' },
  { value: '99.9%', label: 'Uptime SLA' },
  { value: '<5min', label: 'First Scan' },
]

const stagger = {
  animate: { transition: { staggerChildren: 0.1 } },
}
const fadeUp = {
  initial: { opacity: 0, y: 24 },
  animate: { opacity: 1, y: 0, transition: { duration: 0.4 } },
}

export default function Landing() {
  return (
    <PageTransition>
      <div className="min-h-screen bg-cyber-bg scanline-overlay">
        <PublicNavbar />

        {/* Hero */}
        <section className="relative flex flex-col items-center justify-center min-h-screen pt-14 px-4 text-center grid-bg overflow-hidden">
          {/* ambient glow */}
          <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[400px] bg-cyber-green/5 rounded-full blur-3xl pointer-events-none" />

          <motion.div
            className="relative z-10 max-w-4xl mx-auto space-y-6"
            variants={stagger}
            initial="initial"
            animate="animate"
          >
            <motion.div variants={fadeUp}>
              <span className="inline-flex items-center gap-2 px-3 py-1 border border-cyber-green/30 rounded-full text-xs font-mono text-cyber-green mb-6">
                <span className="w-1.5 h-1.5 bg-cyber-green rounded-full animate-pulse" />
                v1.0 — AUTOMATED PENETRATION TESTING PLATFORM
              </span>
            </motion.div>

            <motion.h1
              variants={fadeUp}
              className="text-4xl sm:text-6xl lg:text-7xl font-mono font-bold leading-tight"
            >
              <span className="text-cyber-text">FIND YOUR</span>
              <br />
              <span className="text-cyber-green neon-text">VULNERABILITIES</span>
              <br />
              <span className="text-cyber-text">BEFORE THEY DO</span>
            </motion.h1>

            <motion.p variants={fadeUp} className="text-cyber-muted font-sans text-lg max-w-xl mx-auto leading-relaxed">
              Professional-grade automated pentesting. Scan targets, discover CVEs, verify exploits,
              generate PDF reports — all in one platform.
            </motion.p>

            <motion.div variants={fadeUp} className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
              <Button size="lg" asChild>
                <Link to="/register" className="flex items-center gap-2">
                  START FREE SCAN
                  <ArrowRight className="w-4 h-4" />
                </Link>
              </Button>
              <Button variant="outline" size="lg" asChild>
                <Link to="#features" className="flex items-center gap-2">
                  <Terminal className="w-4 h-4" />
                  SEE HOW IT WORKS
                </Link>
              </Button>
            </motion.div>

            <motion.div variants={fadeUp} className="pt-6">
              <p className="text-xs font-mono text-cyber-muted/50 mb-3">LIVE SCAN OUTPUT</p>
              <div className="inline-block bg-cyber-primary border border-cyber-border rounded-lg px-4 py-3 text-left max-w-lg w-full">
                <div className="flex items-center gap-1.5 mb-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-cyber-red/70" />
                  <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/70" />
                  <span className="w-2.5 h-2.5 rounded-full bg-cyber-green/70" />
                </div>
                <p className="font-mono text-xs text-cyber-muted">$ pentrascan --target 192.168.1.1 --full</p>
                <p className="font-mono text-xs text-cyber-green mt-1">
                  <TypingText text="[*] Scanning 1000 ports... 3 critical CVEs found" delay={0.8} />
                </p>
              </div>
            </motion.div>
          </motion.div>

          {/* scroll hint */}
          <motion.div
            className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-1"
            animate={{ y: [0, 8, 0] }}
            transition={{ duration: 2, repeat: Infinity }}
          >
            <p className="text-[10px] font-mono text-cyber-muted/40 tracking-widest">SCROLL</p>
            <ChevronRight className="w-4 h-4 text-cyber-muted/40 rotate-90" />
          </motion.div>
        </section>

        {/* Stats */}
        <section className="py-16 border-y border-cyber-border bg-cyber-primary/30">
          <div className="max-w-5xl mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((s, i) => (
              <motion.div
                key={s.label}
                className="text-center"
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08, duration: 0.3 }}
              >
                <p className="text-3xl font-mono font-bold text-cyber-green neon-text">{s.value}</p>
                <p className="text-xs font-mono text-cyber-muted mt-1 tracking-widest uppercase">{s.label}</p>
              </motion.div>
            ))}
          </div>
        </section>

        {/* Features Bento */}
        <section id="features" className="py-24 px-6 max-w-6xl mx-auto">
          <motion.div
            className="text-center mb-16"
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
          >
            <p className="text-xs font-mono text-cyber-green tracking-[0.3em] mb-3">// CAPABILITIES</p>
            <h2 className="text-3xl font-mono font-bold text-cyber-text">
              Everything you need to <br /><span className="text-cyber-green">test your security</span>
            </h2>
          </motion.div>

          <div className="grid grid-cols-3 gap-4">
            {features.map((f, i) => (
              <motion.div
                key={f.title}
                className={`cyber-card-hover p-6 ${f.cls}`}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.07, duration: 0.3 }}
                whileHover={{ scale: 1.01 }}
              >
                <f.icon className="w-6 h-6 text-cyber-green mb-4" />
                <h3 className="font-mono font-semibold text-cyber-text mb-2 text-sm">{f.title}</h3>
                <p className="text-xs font-sans text-cyber-muted leading-relaxed">{f.desc}</p>
              </motion.div>
            ))}
          </div>
        </section>

        {/* Pricing teaser */}
        <section id="pricing" className="py-24 px-6 bg-cyber-primary/20 border-y border-cyber-border">
          <div className="max-w-3xl mx-auto text-center">
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
            >
              <p className="text-xs font-mono text-cyber-green tracking-[0.3em] mb-3">// PRICING</p>
              <h2 className="text-3xl font-mono font-bold text-cyber-text mb-6">
                Simple, transparent pricing
              </h2>
            </motion.div>

            <div className="grid md:grid-cols-2 gap-6 mt-10">
              {[
                { tier: 'FREE',       price: '0',   unit: '/ month', targets: '3 targets',   features: ['Port scan', 'Basic vuln scan', 'PDF report'] },
                { tier: 'PRO',        price: '4990', unit: '₸ / month', targets: 'Unlimited', features: ['All free features', 'Exploit simulation', 'Web app testing', 'Priority support'], highlight: true },
              ].map((plan) => (
                <motion.div
                  key={plan.tier}
                  className={`cyber-card p-6 text-left ${plan.highlight ? 'border-cyber-green shadow-neon-green' : ''}`}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  whileHover={{ scale: 1.01 }}
                >
                  {plan.highlight && (
                    <p className="text-[10px] font-mono text-cyber-green tracking-widest mb-3">★ MOST POPULAR</p>
                  )}
                  <p className="text-xs font-mono text-cyber-muted tracking-[0.2em]">{plan.tier}</p>
                  <p className="text-4xl font-mono font-bold text-cyber-text mt-1">
                    {plan.price}
                    <span className="text-sm text-cyber-muted font-normal"> {plan.unit}</span>
                  </p>
                  <p className="text-xs font-mono text-cyber-green mt-1">{plan.targets}</p>
                  <ul className="mt-4 space-y-2">
                    {plan.features.map((f) => (
                      <li key={f} className="flex items-center gap-2 text-xs font-sans text-cyber-muted">
                        <span className="text-cyber-green">✓</span> {f}
                      </li>
                    ))}
                  </ul>
                  <Button variant={plan.highlight ? 'default' : 'outline'} size="sm" className="mt-6 w-full" asChild>
                    <Link to="/register">GET STARTED</Link>
                  </Button>
                </motion.div>
              ))}
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="py-24 px-6 text-center">
          <motion.div
            className="max-w-2xl mx-auto space-y-6"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
          >
            <h2 className="text-3xl font-mono font-bold text-cyber-text">
              Ready to find your <span className="text-cyber-green neon-text">vulnerabilities?</span>
            </h2>
            <p className="text-cyber-muted font-sans">Start with 3 free scans. No credit card required.</p>
            <Button size="lg" asChild>
              <Link to="/register" className="flex items-center gap-2 mx-auto w-fit">
                CREATE FREE ACCOUNT
                <ArrowRight className="w-4 h-4" />
              </Link>
            </Button>
          </motion.div>
        </section>

        {/* Footer */}
        <footer className="border-t border-cyber-border py-8 px-6">
          <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyber-green" />
              <span className="font-mono text-xs text-cyber-muted">PENTRASCAN © 2026</span>
            </div>
            <p className="text-xs font-mono text-cyber-muted/50">
              For authorized security testing only. Use responsibly.
            </p>
          </div>
        </footer>
      </div>
    </PageTransition>
  )
}
