/**
 * Resolves the Cap widget endpoint. Kept framework-free so it's unit-testable
 * with node:test.
 *
 * The endpoint can come from two places:
 * - `VITE_CAP_API_ENDPOINT`, baked into the bundle at build time;
 * - `cap_api_endpoint` in `/config.json`, filled in by the container
 *   entrypoint at start-up (from `CAP_API_ENDPOINT`, or derived from
 *   `CAP_VERIFY_URL` + `CAP_SITE_KEY` when `CAP_ENABLED=true`).
 *
 * The build-time value wins when set. Blank values and unsubstituted
 * `${...}` placeholders count as unset. Returns `undefined` when neither
 * source yields an endpoint (captcha disabled on the front).
 */
export function resolveCapEndpoint(buildTime: unknown, runtime: unknown): string | undefined {
  return usableEndpoint(buildTime) ?? usableEndpoint(runtime)
}

function usableEndpoint(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  const trimmed = value.trim()
  if (trimmed.length === 0 || trimmed.includes('${')) return undefined
  return trimmed
}
