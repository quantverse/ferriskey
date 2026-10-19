import { useEffect, useRef } from 'react'

type CapCaptchaProps = {
  onSolve: (token: string) => void
}

/**
 * Renders the Cap proof-of-work widget when a Cap endpoint is configured,
 * either at build time (VITE_CAP_API_ENDPOINT) or at runtime via
 * `/config.json` (resolved into `window.capApiEndpoint` by App on start-up).
 * Calls `onSolve` with the verification token once the user solves the PoW.
 * Renders nothing when Cap is not configured (backend captcha disabled).
 */
export function CapCaptcha({ onSolve }: CapCaptchaProps) {
  const ref = useRef<HTMLElement | null>(null)
  const endpoint = window.capApiEndpoint

  useEffect(() => {
    if (!endpoint) return
    // The Cap widget is a custom element registered by importing the package.
    // Dynamic import so the bundle/custom-element only loads when configured.
    import('@cap.js/widget')

    const el = ref.current
    if (!el) return

    const handler = (e: Event) => {
      const detail = (e as CustomEvent<{ token: string }>).detail
      if (detail?.token) onSolve(detail.token)
    }
    el.addEventListener('solve', handler as EventListener)
    return () => el.removeEventListener('solve', handler as EventListener)
  }, [endpoint, onSolve])

  if (!endpoint) return null

  // @ts-expect-error - cap-widget is a custom element not in JSX intrinsics
  return <cap-widget ref={ref} data-cap-api-endpoint={endpoint} />
}
