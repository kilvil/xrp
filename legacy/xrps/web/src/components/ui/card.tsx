import * as React from 'react'
import { clsx } from 'clsx'

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={clsx(
        'bg-white text-slate-900 border border-slate-200 shadow-sm p-4 rounded-lg',
        'dark:bg-slate-900 dark:text-slate-100 dark:border-slate-800',
        className,
      )}
      {...props}
    />
  )
}

export function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={clsx('text-lg font-semibold mb-2', className)} {...props} />
}
