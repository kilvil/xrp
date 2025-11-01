import * as React from 'react'
import { clsx } from 'clsx'

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'accent' | 'ghost'
}

export function Button({ className, variant = 'primary', ...props }: ButtonProps) {
  const base = 'px-4 py-2 border-4 border-black dark:border-white shadow-[6px_6px_0_rgba(0,0,0,0.9)] dark:shadow-[6px_6px_0_rgba(255,255,255,0.2)] rounded-none active:translate-x-0 active:translate-y-0 transition-transform'
  const styles = {
    primary: 'bg-yellow-300 text-black dark:bg-yellow-400',
    accent: 'bg-cyan-300 text-black dark:bg-cyan-400',
    ghost: 'bg-white text-black dark:bg-zinc-900 dark:text-white hover:-translate-x-0.5 hover:-translate-y-0.5'
  } as const
  return <button className={clsx(base, styles[variant], className)} {...props} />
}
