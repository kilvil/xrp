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
        'inline-flex items-center justify-center h-5 w-5 rounded-none border-4',
        'border-black dark:border-white bg-white dark:bg-zinc-800 text-black dark:text-white',
        'shadow-[3px_3px_0_rgba(0,0,0,0.9)] dark:shadow-[3px_3px_0_rgba(255,255,255,0.2)]',
        'transition-transform hover:-translate-x-0.5 hover:-translate-y-0.5 focus:outline-none focus:ring-2 focus:ring-black dark:focus:ring-white',
        disabled && 'opacity-50 cursor-not-allowed',
        className,
      )}
      {...props}
    >
      {checked && (
        <svg
          viewBox="0 0 24 24"
          width={18}
          height={18}
          aria-hidden="true"
          className="fill-current"
        >
          <path d="M20.285 6.709a1 1 0 0 1 0 1.414l-9.9 9.9a1 1 0 0 1-1.414 0l-5.257-5.257a1 1 0 0 1 1.414-1.414l4.55 4.55 9.193-9.193a1 1 0 0 1 1.414 0z"/>
        </svg>
      )}
    </button>
  )
}

