import * as React from 'react'
import { clsx } from 'clsx'

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={clsx(
        'bg-white text-black border-4 border-black shadow-[8px_8px_0_rgba(0,0,0,0.9)] p-4 rounded-none',
        'dark:bg-zinc-900 dark:text-white dark:border-white dark:shadow-[8px_8px_0_rgba(255,255,255,0.2)]',
        className,
      )}
      {...props}
    />
  )
}

export function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={clsx('font-extrabold tracking-wide text-xl mb-2 uppercase', className)} {...props} />
}
