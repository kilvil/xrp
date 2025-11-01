import * as React from 'react'
import { cn } from '@/lib/utils'

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {}

export const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(({ className, ...props }, ref) => (
  <textarea
    ref={ref}
    className={cn(
      'flex w-full rounded-none border-4 border-black dark:border-white bg-white dark:bg-zinc-800 text-black dark:text-white px-3 py-2 text-sm',
      'placeholder:text-neutral-400 dark:placeholder:text-neutral-500',
      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-black dark:focus-visible:ring-white',
      'transition-transform hover:-translate-x-0.5 hover:-translate-y-0.5',
      'disabled:cursor-not-allowed disabled:opacity-50',
      className,
    )}
    {...props}
  />
))
Textarea.displayName = 'Textarea'
