import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// copyText copies given text to clipboard with fallbacks.
// Uses navigator.clipboard when available; falls back to a hidden textarea.
export async function copyText(text: string): Promise<boolean> {
  // Prefer modern API when available (usually requires secure context)
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch (_) {
    // ignore and try fallback
  }

  // Fallback for HTTP or older browsers
  try {
    if (typeof document !== 'undefined') {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.setAttribute('readonly', '')
      ta.style.position = 'fixed'
      ta.style.left = '-9999px'
      ta.style.top = '0'
      document.body.appendChild(ta)
      ta.select()
      ta.setSelectionRange(0, ta.value.length)
      const ok = typeof document.execCommand === 'function' ? document.execCommand('copy') : false
      document.body.removeChild(ta)
      return ok
    }
  } catch (_) {
    // ignore
  }
  return false
}
