import { useEffect, useRef } from 'react'

// The Cap widget is a custom element registered by importing the package.
// It is only imported when an endpoint is configured.
const CAP_ENDPOINT = import.meta.env.VITE_CAP_API_ENDPOINT as string | undefined

type CapCaptchaProps = {
  onSolve: (token: string) => void
}

/**
 * Renders the Cap proof-of-work widget when VITE_CAP_API_ENDPOINT is set.
 * Calls `onSolve` with the verification token once the user solves the PoW.
 * Renders nothing when Cap is not configured (backend captcha disabled).
 */
export function CapCaptcha({ onSolve }: CapCaptchaProps) {
  const ref = useRef<HTMLElement | null>(null)

  useEffect(() => {
    if (!CAP_ENDPOINT) return
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
  }, [onSolve])

  if (!CAP_ENDPOINT) return null

  // @ts-expect-error - cap-widget is a custom element not in JSX intrinsics
  return <cap-widget ref={ref} data-cap-api-endpoint={CAP_ENDPOINT} />
}
