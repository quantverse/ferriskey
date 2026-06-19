# Portal Builder Captcha Block Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a draggable **Captcha** block to the FerrisKey Portal layout builder so admin-authored custom login/register templates render the Cap proof-of-work widget and submit its token.

**Architecture:** A new `captcha` block type renders the existing `CapCaptcha` widget plus a hidden `<input name="captcha_token">`. The token solved by the widget is written into that hidden input, so the existing `new FormData(form)` path in `portal-layout-wrapper.tsx` carries it to the submit hook unchanged — no wrapper changes. The submit hook reads `captcha_token` from FormData and injects it into the login (`authenticate`) and register (`registration`) payloads. Pure logic (token extraction, alignment mapping) is factored into a tested helper module; React wiring is verified via TypeScript build + lint + a manual runtime checklist (the frontend has no React component-test infrastructure — see Global Constraints).

**Tech Stack:** React 19 + TypeScript, Vite, the in-repo `builder-portal` renderer, `@cap.js/widget`, Node's built-in `node:test` runner via `tsx`.

**Design spec:** [docs/superpowers/specs/2026-06-19-portal-builder-captcha-block-design.md](../specs/2026-06-19-portal-builder-captcha-block-design.md)

## Global Constraints

- **Work in `front/`.** All paths below are relative to repo root; run commands from `front/`.
- **Test runner = `node:test` via tsx.** The repo has NO React Testing Library / jsdom. Existing tests (`src/hooks/auth-refresh-controller.test.ts`, `src/pages/authentication/feature/callback-helpers.test.ts`) import `test from 'node:test'` and `assert from 'node:assert/strict'` and test PURE functions only. Follow this exactly: unit-test extracted pure helpers; do NOT introduce a component-testing framework. Run a test file with: `npx tsx --test <path>`.
- **Lint gate:** `pnpm run lint` (eslint). Must pass with zero errors per task that changes `.ts`/`.tsx`.
- **Type/build gate:** `pnpm run build` runs `tsc -b && vite build` — this is the type-check gate, run in the final integration task. Per-task, rely on `pnpm run lint`.
- **Captcha is global & backend-gated** by `CAP_ENABLED` (no per-realm/frontend signal). The block only RENDERS the widget when `VITE_CAP_API_ENDPOINT` is set (the existing `CapCaptcha` returns `null` otherwise).
- **Accepted footgun (per design):** a `CAP_ENABLED=true` backend + a template missing the Captcha block ⇒ `400 captcha token required`. Mitigations are doc/UI notes only; do NOT add an auto-render fallback or a builder warning.
- **Scope:** login + register pages only. Do not touch backend code.

---

### Task 1: Pure captcha helpers (`captcha.ts`) — TDD

The only genuinely pure, unit-testable logic: extract the token from FormData, and map the block's `align` prop to a CSS `justify-content` value. Both are reused by later tasks.

**Files:**
- Create: `front/src/lib/builder-portal/captcha.ts`
- Test: `front/src/lib/builder-portal/captcha.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `captchaTokenFromForm(form: FormData): string | undefined` — returns the trimmed `captcha_token` value, or `undefined` when absent/blank.
  - `captchaAlignToJustify(align: string | undefined): 'flex-start' | 'center' | 'flex-end'` — maps `'left' | 'center' | 'right'` (default/unknown ⇒ `'center'`).

- [ ] **Step 1: Write the failing test**

Create `front/src/lib/builder-portal/captcha.test.ts`:

```ts
import test from 'node:test'
import assert from 'node:assert/strict'

import { captchaAlignToJustify, captchaTokenFromForm } from './captcha'

test('captchaTokenFromForm returns the trimmed token when present', () => {
  const form = new FormData()
  form.append('captcha_token', '  tok-123  ')
  assert.equal(captchaTokenFromForm(form), 'tok-123')
})

test('captchaTokenFromForm returns undefined when the field is absent', () => {
  const form = new FormData()
  assert.equal(captchaTokenFromForm(form), undefined)
})

test('captchaTokenFromForm returns undefined when the field is blank', () => {
  const form = new FormData()
  form.append('captcha_token', '   ')
  assert.equal(captchaTokenFromForm(form), undefined)
})

test('captchaAlignToJustify maps known alignments', () => {
  assert.equal(captchaAlignToJustify('left'), 'flex-start')
  assert.equal(captchaAlignToJustify('center'), 'center')
  assert.equal(captchaAlignToJustify('right'), 'flex-end')
})

test('captchaAlignToJustify defaults to center for unknown/undefined', () => {
  assert.equal(captchaAlignToJustify(undefined), 'center')
  assert.equal(captchaAlignToJustify('weird'), 'center')
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd front && npx tsx --test src/lib/builder-portal/captcha.test.ts`
Expected: FAIL — cannot find module `./captcha` (or export missing).

- [ ] **Step 3: Write the minimal implementation**

Create `front/src/lib/builder-portal/captcha.ts`:

```ts
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd front && npx tsx --test src/lib/builder-portal/captcha.test.ts`
Expected: PASS — `tests 5 / pass 5 / fail 0`.

- [ ] **Step 5: Lint**

Run: `cd front && pnpm run lint`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add front/src/lib/builder-portal/captcha.ts front/src/lib/builder-portal/captcha.test.ts
git commit -m "feat(portal): add pure captcha helpers (token extraction + align)"
```

---

### Task 2: Captcha block type + renderer

Add the `captcha` type to the union and render it. New exported `PortalCaptchaBlock` component renders the live widget + hidden token field at runtime, and a static placeholder in the builder canvas/preview. Reuses `CapCaptcha` (no widget re-implementation).

**Files:**
- Modify: `front/src/lib/builder-portal/types.ts` (union + props interface)
- Modify: `front/src/lib/builder-portal/renderer.tsx` (imports, `PortalCaptchaBlock`, `case 'captcha'`)

**Interfaces:**
- Consumes: `captchaAlignToJustify` from `./captcha` (Task 1); `CapCaptcha` from `@/components/cap-captcha` (signature: `CapCaptcha({ onSolve }: { onSolve: (token: string) => void })`); `orderStyle(node)` and the `RenderOptions` type already in `renderer.tsx`.
- Produces: exported `PortalCaptchaBlock({ node, options }: { node: BuilderNode; options: RenderOptions })` — reused by Task 5.

- [ ] **Step 1: Add the block type to the union**

In `front/src/lib/builder-portal/types.ts`, add `PortalCaptchaProps` after `PortalInputProps` (line 57) and extend `PortalNodeType` (lines 59-70). Replace:

```ts
export interface PortalInputProps {
  label?: string
  placeholder?: string
  type?: 'text' | 'email' | 'password'
  helperText?: string
}

export type PortalNodeType =
  | 'container'
  | 'heading'
  | 'text'
  | 'image'
  | 'spacer'
  | 'divider'
  | 'button'
  | 'input'
  | 'magic_link_button'
  | 'passkey_button'
  | 'page-content'
```

with:

```ts
export interface PortalInputProps {
  label?: string
  placeholder?: string
  type?: 'text' | 'email' | 'password'
  helperText?: string
}

export interface PortalCaptchaProps {
  align?: 'left' | 'center' | 'right'
}

export type PortalNodeType =
  | 'container'
  | 'heading'
  | 'text'
  | 'image'
  | 'spacer'
  | 'divider'
  | 'button'
  | 'input'
  | 'magic_link_button'
  | 'passkey_button'
  | 'captcha'
  | 'page-content'
```

- [ ] **Step 2: Import `CapCaptcha`, `ShieldCheck`, and the align helper in the renderer**

In `front/src/lib/builder-portal/renderer.tsx`, the lucide import block is lines 3-10 and the local imports are lines 12-17. Replace:

```tsx
import {
  AlertCircle,
  Copy,
  KeyRound,
  Loader2,
  Mail,
  QrCode as QrCodeIcon,
} from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import type { Schemas } from '@/api/api.client'
import ProviderIcon, {
  isProviderIconKey,
} from '@/pages/identity-providers/components/provider-icon'
import type { BuilderNode } from '../builder-core'
import { PortalInput } from './components/portal-input'
```

with:

```tsx
import {
  AlertCircle,
  Copy,
  KeyRound,
  Loader2,
  Mail,
  QrCode as QrCodeIcon,
  ShieldCheck,
} from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import type { Schemas } from '@/api/api.client'
import { CapCaptcha } from '@/components/cap-captcha'
import ProviderIcon, {
  isProviderIconKey,
} from '@/pages/identity-providers/components/provider-icon'
import type { BuilderNode } from '../builder-core'
import { PortalInput } from './components/portal-input'
import { captchaAlignToJustify } from './captcha'
```

Also ensure `useRef` and `useCallback` are imported. Line 1 is currently:

```tsx
import { useState, type CSSProperties, type ReactNode } from 'react'
```

Replace it with:

```tsx
import { useCallback, useRef, useState, type CSSProperties, type ReactNode } from 'react'
```

- [ ] **Step 3: Add the `case 'captcha'` branch in `renderNode`**

In `renderer.tsx`, the `case 'form_error_banner'` branch is lines 369-372. Immediately AFTER it (before `case 'input':` at line 374), add:

```tsx
    case 'captcha':
      return (
        <PortalCaptchaBlock key={node.id} node={node} options={options} />
      )
```

- [ ] **Step 4: Define the `PortalCaptchaBlock` component**

In `renderer.tsx`, add this exported component next to the other exported block components (e.g. immediately after the `FormErrorBannerBlock` definition, which ends at line 687):

```tsx
/**
 * Captcha block. At runtime renders the Cap proof-of-work widget and a hidden
 * `captcha_token` input; when the user solves the challenge the token is
 * written into the hidden input, so the surrounding <form>'s FormData carries
 * it to the submit handler exactly like any other field — no wrapper plumbing.
 *
 * The widget itself only appears when `VITE_CAP_API_ENDPOINT` is configured
 * (CapCaptcha returns null otherwise); the hidden input is always present so
 * the field exists in FormData regardless.
 *
 * In the builder canvas / preview (`options.runtime` falsy) we render a static
 * placeholder — no network call, no live widget — so the admin can position
 * the block without solving a challenge.
 */
export function PortalCaptchaBlock({
  node,
  options,
}: {
  node: BuilderNode
  options: RenderOptions
}) {
  const hiddenRef = useRef<HTMLInputElement | null>(null)
  const handleSolve = useCallback((token: string) => {
    if (hiddenRef.current) hiddenRef.current.value = token
  }, [])
  const justifyContent = captchaAlignToJustify(node.props.align as string | undefined)

  if (!options.runtime) {
    return (
      <div
        data-fk-id={node.id}
        style={{ display: 'flex', justifyContent, ...orderStyle(node) }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '12px 16px',
            borderRadius: 'var(--fk-radius-input, 6px)',
            border: '1px dashed var(--border, #d4d4d8)',
            color: 'var(--muted-foreground, #71717a)',
            fontSize: 12,
          }}
        >
          <ShieldCheck size={16} aria-hidden />
          <span>Captcha — shown to end-users when enabled</span>
        </div>
      </div>
    )
  }

  return (
    <div
      data-fk-id={node.id}
      style={{ display: 'flex', justifyContent, ...orderStyle(node) }}
    >
      <CapCaptcha onSolve={handleSolve} />
      <input type='hidden' name='captcha_token' ref={hiddenRef} />
    </div>
  )
}
```

- [ ] **Step 5: Lint**

Run: `cd front && pnpm run lint`
Expected: no errors. (If lint flags `ShieldCheck`/`useRef`/`useCallback` as unused, the case/component wasn't added — recheck Steps 3-4.)

- [ ] **Step 6: Commit**

```bash
git add front/src/lib/builder-portal/types.ts front/src/lib/builder-portal/renderer.tsx
git commit -m "feat(portal): render captcha block with hidden token field"
```

---

### Task 3: Register the block in the palette + restrict to login/register

Make the block draggable and confine it to the two pages where backend captcha is enforced.

**Files:**
- Modify: `front/src/lib/builder-portal/components.tsx` (palette entry + `RESTRICTED_TO_PAGE_TYPE`)

**Interfaces:**
- Consumes: the `'captcha'` type (Task 2); `ComponentDefinition` shape (already used throughout `portalComponents`).
- Produces: a `portalComponents` entry `{ type: 'captcha', label: 'Captcha', icon, defaultProps: { align: 'center' }, defaultStyles: {} }`, available only on `login` + `register` pages.

- [ ] **Step 1: Add the palette entry**

In `front/src/lib/builder-portal/components.tsx`, the `portalComponents` array closes with the `form_error_banner` entry (lines 485-493) then `]` at line 494. Insert the captcha entry between the `form_error_banner` entry's closing `},` (line 493) and the `]` (line 494):

```tsx
  {
    type: 'captcha',
    label: 'Captcha',
    icon: <ShieldCheck size={14} />,
    defaultProps: {
      align: 'center',
    },
    defaultStyles: {},
  },
```

(`ShieldCheck` is already imported in this file — see line 25 — and is reused intentionally; no new import needed.)

- [ ] **Step 2: Restrict the block to login + register pages**

In `components.tsx`, `RESTRICTED_TO_PAGE_TYPE` is defined at lines 670-673:

```tsx
export const RESTRICTED_TO_PAGE_TYPE: Record<string, ReadonlySet<string>> = {
  totp_qr_code: new Set(['totp_setup']),
  totp_secret: new Set(['totp_setup']),
}
```

Replace it with:

```tsx
export const RESTRICTED_TO_PAGE_TYPE: Record<string, ReadonlySet<string>> = {
  totp_qr_code: new Set(['totp_setup']),
  totp_secret: new Set(['totp_setup']),
  // Captcha enforcement (backend) only covers login + self-service register,
  // so only offer the block where it can do something.
  captcha: new Set(['login', 'register']),
}
```

- [ ] **Step 3: Lint**

Run: `cd front && pnpm run lint`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add front/src/lib/builder-portal/components.tsx
git commit -m "feat(portal): add captcha to builder palette (login + register only)"
```

---

### Task 4: Config panel for the captcha block

Give the selected block an editor: a locked-behaviour note + an alignment select.

**Files:**
- Modify: `front/src/lib/builder-portal/config-panels/config-panel-renderer.tsx` (new `case 'captcha'`)

**Interfaces:**
- Consumes: `SelectField`, `ConfigSection`, the `IdentitySection` local (`identity`), and `updateProp` — all already in this file.
- Produces: a config-panel branch for `'captcha'`.

- [ ] **Step 1: Add the `case 'captcha'` branch**

In `front/src/lib/builder-portal/config-panels/config-panel-renderer.tsx`, inside `renderPortalConfigPanelInner`'s `switch (node.type)`, add a `case 'captcha':` immediately before `case 'page-content':` (line 1024):

```tsx
    case 'captcha':
      return (
        <div className='flex flex-col'>
          {identity}
          <div className='border-b border-border bg-muted/40 px-3 py-2 text-[11px] text-muted-foreground'>
            Renders the Cap proof-of-work widget only when the Cap endpoint is
            configured (VITE_CAP_API_ENDPOINT). On submit it sends the solved
            token. Add this block to login &amp; register pages when captcha is
            enforced — otherwise those submissions are rejected.
          </div>
          <ConfigSection title='Layout'>
            <SelectField
              label='Alignment'
              value={(node.props.align as string) || 'center'}
              options={[
                { label: 'Left', value: 'left' },
                { label: 'Center', value: 'center' },
                { label: 'Right', value: 'right' },
              ]}
              onChange={(v) => updateProp('align', v)}
              allowEmpty={false}
            />
          </ConfigSection>
        </div>
      )
```

- [ ] **Step 2: Lint**

Run: `cd front && pnpm run lint`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add front/src/lib/builder-portal/config-panels/config-panel-renderer.tsx
git commit -m "feat(portal): config panel for captcha block (alignment + note)"
```

---

### Task 5: Builder-canvas placeholder

Render the block on the editing canvas by reusing `PortalCaptchaBlock` in preview mode (mirrors how `form_error_banner` / `totp_*` are previewed).

**Files:**
- Modify: `front/src/lib/builder-portal/visual-blocks/visual-block-registry.tsx` (import + `case 'captcha'`)

**Interfaces:**
- Consumes: `PortalCaptchaBlock` from `../renderer` (Task 2); `chromeStyle(isSelected)` already in this file.
- Produces: a canvas rendering for `'captcha'`.

- [ ] **Step 1: Import `PortalCaptchaBlock`**

In `front/src/lib/builder-portal/visual-blocks/visual-block-registry.tsx`, the import from `../renderer` spans lines 6-32 and currently ends with `FormErrorBannerBlock,`. Add `PortalCaptchaBlock,` to that import list, e.g. replace:

```tsx
  TotpSecretBlock,
  FormErrorBannerBlock,
} from '../renderer'
```

with:

```tsx
  TotpSecretBlock,
  FormErrorBannerBlock,
  PortalCaptchaBlock,
} from '../renderer'
```

- [ ] **Step 2: Add the `case 'captcha'` branch**

In `renderVisualBlock`'s `switch (node.type)`, add a `case 'captcha':` immediately before `case 'page-content':` (line 204):

```tsx
    case 'captcha':
      // Canvas preview: reuse the runtime block with no `runtime` option so it
      // renders the static placeholder (no live widget / network).
      return (
        <div style={chromeStyle(isSelected)}>
          <PortalCaptchaBlock node={node} options={{}} />
        </div>
      )
```

- [ ] **Step 3: Lint**

Run: `cd front && pnpm run lint`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add front/src/lib/builder-portal/visual-blocks/visual-block-registry.tsx
git commit -m "feat(portal): captcha block placeholder on builder canvas"
```

---

### Task 6: Inject the captcha token into login + register submits

Read `captcha_token` from the page FormData and add it to both payloads.

**Files:**
- Modify: `front/src/pages/authentication/hooks/use-portal-page-submit.ts` (import + `loginSubmit` + `registerSubmit`)

**Interfaces:**
- Consumes: `captchaTokenFromForm` from `@/lib/builder-portal/captcha` (Task 1). The `authenticate` mutation's `data` already accepts `captcha_token?: string` (see `auth.api.ts:56`); the `registration` mutation's `body` does NOT type it, so cast the body with `as never` (the same pattern used in `page-register-feature.tsx:60`).
- Produces: login + register requests carrying `captcha_token`.

- [ ] **Step 1: Import the helper**

In `front/src/pages/authentication/hooks/use-portal-page-submit.ts`, the imports end at line 14 (`import { useOAuthParams } from './use-oauth-params'`). Add after it:

```ts
import { captchaTokenFromForm } from '@/lib/builder-portal/captcha'
```

- [ ] **Step 2: Inject into `loginSubmit`**

The `authenticate(...)` call is at lines 95-100:

```ts
      authenticate(
        {
          data: { username, password },
          realm: realm_name ?? 'master',
          clientId,
        },
```

Replace the `data` line so it becomes:

```ts
      authenticate(
        {
          data: { username, password, captcha_token: captchaTokenFromForm(data) },
          realm: realm_name ?? 'master',
          clientId,
        },
```

- [ ] **Step 3: Inject into `registerSubmit`**

The `registration(...)` call is at lines 186-198:

```ts
      registration({
        path: { realm_name: realm_name ?? 'master' },
        body: {
          email,
          password,
          // Username defaults to the local-part of the email so a tree that
          // omits the field still produces a valid record — admins who want
          // explicit usernames just add a `username_input` block.
          username: String(data.get('username') ?? '').trim() || email.split('@')[0],
          first_name: String(data.get('first_name') ?? '').trim() || null,
          last_name: String(data.get('last_name') ?? '').trim() || null,
        },
      })
```

Replace it with (adds `captcha_token` and casts the body `as never`, mirroring `page-register-feature.tsx`, because the generated `RegistrationRequest` type does not include the field):

```ts
      registration({
        path: { realm_name: realm_name ?? 'master' },
        body: {
          email,
          password,
          // Username defaults to the local-part of the email so a tree that
          // omits the field still produces a valid record — admins who want
          // explicit usernames just add a `username_input` block.
          username: String(data.get('username') ?? '').trim() || email.split('@')[0],
          first_name: String(data.get('first_name') ?? '').trim() || null,
          last_name: String(data.get('last_name') ?? '').trim() || null,
          // The generated RegistrationRequest type doesn't model captcha_token,
          // so cast the body — same approach as page-register-feature.tsx.
          captcha_token: captchaTokenFromForm(data),
        } as never,
      })
```

- [ ] **Step 4: Lint**

Run: `cd front && pnpm run lint`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add front/src/pages/authentication/hooks/use-portal-page-submit.ts
git commit -m "feat(portal): submit captcha token on portal login + register"
```

---

### Task 7: Update README note + final build gate

Replace the now-stale README note ("templates do not yet render a captcha block") and run the full type/build gate over all changes.

**Files:**
- Modify: `README.md` (Captcha section closing note)

**Interfaces:**
- Consumes: all prior tasks.
- Produces: accurate docs + a green `pnpm run build`.

- [ ] **Step 1: Update the README note**

In `README.md`, find the closing note of the **🛡️ Captcha (Cap)** section:

```markdown
> **Note:** the captcha widget is rendered only by the built-in login/register pages. Custom Portal-builder templates do not yet render a captcha block.
```

Replace it with:

```markdown
> **Note:** on custom Portal-builder templates the captcha is a block — drag the **Captcha** block onto the login and register pages for the widget to appear (it is not inserted automatically). When `CAP_ENABLED=true` and a template omits it, those submissions are rejected with `400 captcha token required`.
```

- [ ] **Step 2: Run the unit tests**

Run: `cd front && npx tsx --test src/lib/builder-portal/captcha.test.ts`
Expected: PASS — `pass 5 / fail 0`.

- [ ] **Step 3: Run lint**

Run: `cd front && pnpm run lint`
Expected: no errors.

- [ ] **Step 4: Run the full type/build gate**

Run: `cd front && pnpm run build`
Expected: `tsc -b` reports no type errors and `vite build` completes. (This is the authoritative type-check for the React wiring in Tasks 2-6.)

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: portal captcha is a builder block, not auto-rendered"
```

---

## Manual Verification Checklist (after Task 7)

The frontend has no React component tests, so verify the wiring by running the app (see README "Captcha (Cap)" section for full setup):

1. In the Portal layout builder, open a **login** page layout: the **Captcha** block appears in the palette; on a **totp_setup**/**forgot_password** layout it does NOT.
2. Drag the Captcha block in → canvas shows the dashed "Captcha" placeholder; selecting it shows the Alignment select + note in the config panel; changing alignment moves the placeholder.
3. With `VITE_CAP_API_ENDPOINT` set (frontend rebuilt) and `CAP_ENABLED=true` (backend): load the realm's custom login page → the Cap widget renders; solve it and submit → login succeeds (token accepted).
4. Remove the block from the template, keep `CAP_ENABLED=true`: submit → `400 captcha token required` (confirms the documented footgun).
5. With `CAP_ENABLED=false` / `VITE_CAP_API_ENDPOINT` unset: the block renders nothing at runtime and login/register still work.

---

## Self-Review (completed by plan author)

- **Spec coverage:** All 6 files in spec §4 are covered — types.ts/renderer (Task 2), components.tsx (Task 3), config-panel (Task 4), visual-block-registry (Task 5), use-portal-page-submit (Task 6). Footgun mitigations (§5): palette restriction (Task 3), config-panel note (Task 4), README note (Task 7). Testing (§6): pure helpers TDD'd (Task 1); React wiring covered by build/lint + manual checklist — an explicit, documented adaptation to the repo's no-component-test convention (Global Constraints), not a gap.
- **Type consistency:** `captchaTokenFromForm` / `captchaAlignToJustify` signatures are defined in Task 1 and consumed unchanged in Tasks 2 & 6. `PortalCaptchaBlock({ node, options })` defined in Task 2, consumed in Task 5. `'captcha'` type added in Task 2 before any task switches on it.
- **No placeholders:** every code step contains the actual code; commands include expected output.
