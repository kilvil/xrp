import * as React from 'react'
import { clsx } from 'clsx'

export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={clsx('text-sm font-medium text-slate-700 dark:text-slate-300 whitespace-nowrap', className)} {...props} />
}

