import * as React from 'react'
import { clsx } from 'clsx'

type DialogContextType = {
  onOpenChange?: (open: boolean) => void
}

const DialogCtx = React.createContext<DialogContextType>({})

export function Dialog({ open, onOpenChange, children }: { open: boolean; onOpenChange?: (open: boolean) => void; children: React.ReactNode }) {
  return (
    <DialogCtx.Provider value={{ onOpenChange }}>
      {open ? children : null}
    </DialogCtx.Provider>
  )
}

export function DialogContent({ className, children }: { className?: string; children: React.ReactNode }) {
  const ctx = React.useContext(DialogCtx)
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') ctx.onOpenChange?.(false) }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [ctx])
  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/40" onClick={() => ctx.onOpenChange?.(false)} />
      <div className="relative h-full w-full p-4 flex items-center justify-center">
        <div
          role="dialog"
          aria-modal="true"
          className={clsx(
            'relative w-full max-w-3xl rounded-lg border border-slate-200 bg-white shadow-lg text-slate-900',
            'dark:bg-slate-900 dark:text-slate-100 dark:border-slate-800',
            'flex flex-col max-h-[85vh]',
            className,
          )}
        >
          {children}
        </div>
      </div>
    </div>
  )
}

export function DialogHeader({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <div className={clsx('flex items-center justify-between px-4 py-2 border-b border-slate-200 dark:border-slate-800', className)}>
      {children}
    </div>
  )
}

export function DialogTitle({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={clsx('text-lg font-semibold', className)}>{children}</div>
}

export function DialogBody({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={clsx('overflow-y-auto p-4 flex-1', className)}>{children}</div>
}

export function DialogFooter({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <div className={clsx('px-4 py-2 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-2', className)}>
      {children}
    </div>
  )
}

export function DialogClose({ className, children = '×' }: { className?: string; children?: React.ReactNode }) {
  const ctx = React.useContext(DialogCtx)
  return (
    <button
      type="button"
      aria-label="Close"
      onClick={() => ctx.onOpenChange?.(false)}
      className={clsx('inline-flex items-center justify-center h-8 w-8 rounded-md border border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-800', className)}
    >
      {children}
    </button>
  )
}

