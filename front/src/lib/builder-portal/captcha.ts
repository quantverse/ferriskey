/**
 * Pure helpers shared by the portal captcha block (renderer) and the portal
 * submit hook. Kept framework-free so they're unit-testable with node:test.
 */

/**
 * Reads the `captcha_token` field a `captcha` block writes into the page
 * form. Returns the trimmed token, or `undefined` when the field is absent
 * or blank (no captcha block on the page, or the user hasn't solved it).
 */
export function captchaTokenFromForm(form: FormData): string | undefined {
  const raw = form.get('captcha_token')
  if (typeof raw !== 'string') return undefined
  const trimmed = raw.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

/**
 * Maps the captcha block's `align` prop to a flex `justify-content` value so
 * the widget can be left/centre/right aligned in its row. Defaults to centre.
 */
export function captchaAlignToJustify(
  align: string | undefined,
): 'flex-start' | 'center' | 'flex-end' {
  if (align === 'left') return 'flex-start'
  if (align === 'right') return 'flex-end'
  return 'center'
}
