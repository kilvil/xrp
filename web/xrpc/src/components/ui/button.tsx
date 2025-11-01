import * as React from 'react'
import { clsx } from 'clsx'

export function Button({ className, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={clsx('px-4 py-2 border-4 border-black dark:border-white bg-yellow-300 dark:bg-yellow-400 text-black shadow-[6px_6px_0_rgba(0,0,0,0.9)] dark:shadow-[6px_6px_0_rgba(255,255,255,0.2)] rounded-none active:translate-x-0 active:translate-y-0 transition-transform hover:-translate-x-0.5 hover:-translate-y-0.5', className)}
      {...props}
    />
  )
}
