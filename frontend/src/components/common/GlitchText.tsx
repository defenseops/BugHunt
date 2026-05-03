import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

interface GlitchTextProps {
  text: string
  className?: string
  as?: 'h1' | 'h2' | 'h3' | 'span' | 'p'
}

export function GlitchText({ text, className, as: Tag = 'span' }: GlitchTextProps) {
  return (
    <Tag
      className={cn('relative inline-block font-mono animate-glitch', className)}
      data-text={text}
    >
      {text}
    </Tag>
  )
}

interface TypingTextProps {
  text: string
  className?: string
  delay?: number
}

export function TypingText({ text, className, delay = 0 }: TypingTextProps) {
  return (
    <motion.span
      className={cn('font-mono', className)}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay }}
    >
      {text.split('').map((char, i) => (
        <motion.span
          key={i}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: delay + i * 0.04, duration: 0 }}
        >
          {char}
        </motion.span>
      ))}
      <motion.span
        className="inline-block w-0.5 h-5 bg-cyber-green ml-0.5 align-middle"
        animate={{ opacity: [1, 0] }}
        transition={{ duration: 0.8, repeat: Infinity, repeatType: 'reverse' }}
      />
    </motion.span>
  )
}
