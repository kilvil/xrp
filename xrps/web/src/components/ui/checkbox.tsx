import * as React from 'react'
import { cn } from '@/lib/utils'

export interface CheckboxProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  checked?: boolean
  onCheckedChange?: (checked: boolean) => void
  disabled?: boolean
}

export function Checkbox({ checked = false, onCheckedChange, className, disabled, ...props }: CheckboxProps) {
  const toggle = React.useCallback(() => {
    if (disabled) return
    onCheckedChange?.(!checked)
  }, [checked, disabled, onCheckedChange])

  const onKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === ' ' || e.key === 'Enter') {
      e.preventDefault()
      toggle()
    }
  }

  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      aria-disabled={disabled}
      onClick={toggle}
      onKeyDown={onKeyDown}
      className={cn(
        'inline-flex items-center justify-center h-4 w-4 rounded border',
        'border-slate-300 bg-white text-white shadow-sm',
        'focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-600 focus-visible:ring-offset-2',
        'dark:border-slate-700 dark:bg-slate-900',
        disabled && 'opacity-50 cursor-not-allowed',
        className,
      )}
      {...props}
    >
      {checked && (
        <svg
          viewBox="0 0 24 24"
          width={16}
          height={16}
          aria-hidden="true"
          className="fill-indigo-600 dark:fill-indigo-400"
        >
          <path d="M20.285 6.709a1 1 0 0 1 0 1.414l-9.9 9.9a1 1 0 0 1-1.414 0l-5.257-5.257a1 1 0 0 1 1.414-1.414l4.55 4.55 9.193-9.193a1 1 0 0 1 1.414 0z"/>
        </svg>
      )}
    </button>
  )
}
