import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap text-sm font-mono font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-green disabled:pointer-events-none disabled:opacity-50 cursor-pointer',
  {
    variants: {
      variant: {
        default:   'bg-cyber-green text-cyber-bg hover:bg-cyber-green-dim shadow-neon-green',
        outline:   'border border-cyber-green text-cyber-green hover:bg-cyber-green/10 hover:shadow-neon-green',
        ghost:     'text-cyber-muted hover:text-cyber-text hover:bg-cyber-secondary',
        danger:    'border border-cyber-red text-cyber-red hover:bg-cyber-red/10 hover:shadow-neon-red',
        secondary: 'bg-cyber-secondary text-cyber-text hover:bg-cyber-secondary/80 border border-cyber-border',
      },
      size: {
        sm:      'h-8 rounded px-3 text-xs',
        default: 'h-10 rounded-md px-5',
        lg:      'h-12 rounded-md px-8 text-base',
        icon:    'h-10 w-10 rounded-md',
      },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  },
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
  loading?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, loading, children, disabled, ...props }, ref) => {
    if (asChild) {
      return (
        <Slot
          className={cn(buttonVariants({ variant, size, className }))}
          ref={ref}
          {...props}
        >
          {children}
        </Slot>
      )
    }
    return (
      <button
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        disabled={disabled || loading}
        {...props}
      >
        {loading && (
          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
          </svg>
        )}
        {children}
      </button>
    )
  },
)
Button.displayName = 'Button'

export { Button, buttonVariants }
