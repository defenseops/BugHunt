import type { Config } from 'tailwindcss'

const config: Config = {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:        '#020617',
          primary:   '#0F172A',
          secondary: '#1E293B',
          green:     '#22C55E',
          'green-dim':'#16A34A',
          text:      '#F8FAFC',
          muted:     '#94A3B8',
          border:    '#1E293B',
          red:       '#EF4444',
          blue:      '#3B82F6',
          yellow:    '#EAB308',
        },
      },
      fontFamily: {
        mono:  ['Fira Code', 'monospace'],
        sans:  ['Fira Sans', 'sans-serif'],
      },
      boxShadow: {
        'neon-green': '0 0 8px #22C55E, 0 0 24px #22C55E44',
        'neon-blue':  '0 0 8px #3B82F6, 0 0 24px #3B82F644',
        'neon-red':   '0 0 8px #EF4444, 0 0 24px #EF444444',
        'card':       '0 0 0 1px #1E293B',
      },
      animation: {
        'glitch':    'glitch 3s infinite',
        'scanline':  'scanline 8s linear infinite',
        'pulse-slow':'pulse 4s cubic-bezier(0.4,0,0.6,1) infinite',
        'typing':    'typing 2s steps(20, end)',
        'blink':     'blink 1s step-end infinite',
      },
      keyframes: {
        glitch: {
          '0%, 90%, 100%': { transform: 'translate(0)' },
          '91%': { transform: 'translate(-2px, 1px)', filter: 'hue-rotate(90deg)' },
          '93%': { transform: 'translate(2px, -1px)', filter: 'hue-rotate(-90deg)' },
          '95%': { transform: 'translate(-1px, 2px)' },
          '97%': { transform: 'translate(1px, -2px)', filter: 'hue-rotate(180deg)' },
        },
        scanline: {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        typing: {
          from: { width: '0' },
          to:   { width: '100%' },
        },
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%':      { opacity: '0' },
        },
      },
      backgroundImage: {
        'grid-pattern': `linear-gradient(#1E293B44 1px, transparent 1px), linear-gradient(90deg, #1E293B44 1px, transparent 1px)`,
        'hex-pattern':  `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%2322C55E' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
      },
    },
  },
  plugins: [],
}

export default config
