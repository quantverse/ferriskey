# Portal Builder: Captcha Block

**Date:** 2026-06-19
**Status:** Approved (design) — pending implementation plan
**Scope:** Add a draggable **Captcha** block to the Portal layout builder so admin-authored custom login/sign-up templates can render the Cap proof-of-work widget and submit its token. Today only the built-in React login/register pages render `<CapCaptcha>`; custom Portal templates render no captcha, so with `CAP_ENABLED=true` they break at submit.

**Related:** [2026-06-18-portal-auth-rate-limiting-captcha-design.md](./2026-06-18-portal-auth-rate-limiting-captcha-design.md) (backend enforcement + non-portal frontend). This spec extends that frontend work to the Portal builder.

---

## 1. Background

The branch `feat/portal-auth-rate-limit-captcha` added Cap captcha enforcement on three backend endpoints (login `authenticate`, self-service `registrations`, public password grant) gated globally by `CAP_ENABLED`, and a `CapCaptcha` widget on the built-in React login/register pages gated by the build-time `VITE_CAP_API_ENDPOINT`.

The Portal builder is a separate rendering path. A realm admin composes a login/register page as a tree of `BuilderNode`s; at runtime `treeToReactNode` (`front/src/lib/builder-portal/renderer.tsx`) renders that tree inside a `<form>` (`front/src/pages/authentication/components/portal-layout-wrapper.tsx`). **No captcha block exists**, so an admin using a custom template cannot present a captcha — and when backend captcha is enforced, every login/register from that template returns `400 captcha token required`.

### Key architectural facts (confirmed by reading the code)

- **Inputs are uncontrolled.** Each input block renders a native `<input name=...>`; values are collected via `new FormData(form)` in `portal-layout-wrapper.tsx:218-222`. There is no form context, controlled state, or refs.
- **The wrapper submits raw FormData.** `handleSubmit` calls `onSubmit(new FormData(event.currentTarget))`; `usePortalPageSubmit` reads named fields (`data.get('username')`, etc.).
- **The Cap widget emits its token via a JS `solve` event**, not as a form field — see `front/src/components/cap-captcha.tsx`. `CapCaptcha` renders `<cap-widget>` only when `VITE_CAP_API_ENDPOINT` is set, otherwise `null`.
- **Two builder render paths:** `renderer.tsx` (`treeToReactNode`) for the live runtime page, and `visual-blocks/visual-block-registry.tsx` for the builder editing canvas. A new block type must be handled in both.

---

## 2. Decisions (locked)

| Decision | Choice | Rationale |
|---|---|---|
| Mechanism | **Draggable builder block** (not auto-render, not auto+block hybrid) | User choice: admins control placement. Footgun accepted & mitigated (§5). |
| Token transport | **Hidden `<input name="captcha_token">` inside the block**, value set on `solve` | Rides the existing FormData path. **Zero changes to the wrapper.** No refs threaded through. |
| Block availability | **Login + register pages only** (`RESTRICTED_TO_PAGE_TYPE`) | These are the only self-service flows the backend enforces captcha on. |
| Required-block wiring | **Not** added to `REQUIRED_BLOCK_TYPES` | That set is backend/requirements-driven and would force captcha even when `CAP_ENABLED=false`. The builder cannot know the backend flag. |
| Config props | `align` only | Captcha has no meaningful styling knobs; the widget is self-contained. |

---

## 3. Data Flow

```
Captcha block (type: 'captcha')
  ├─ runtime (treeToReactNode, runtime:true):
  │     <div align>
  │       <CapCaptcha onSolve={t => hiddenInput.value = t} />   // <cap-widget>, or null if VITE_CAP_API_ENDPOINT unset
  │       <input type="hidden" name="captcha_token" ref={hiddenInput} />
  │     </div>
  │
  └─ builder canvas (visual-block-registry) & preview (runtime:false):
        static "🛡 Captcha" placeholder box — no network, no widget

Submit:
  wrapper handleSubmit → new FormData(form)        // picks up captcha_token automatically
    → usePortalPageSubmit reads data.get('captcha_token')
      → login:    authenticate({ data: { username, password, captcha_token } })
      → register: registration({ body: { ..., captcha_token } })
```

The hidden input lives inside the page `<form>`, so the existing `new FormData(form)` collects `captcha_token` with no wrapper change. When `VITE_CAP_API_ENDPOINT` is unset, `CapCaptcha` renders nothing and the hidden input stays empty — consistent with the non-portal pages and harmless when backend captcha is disabled.

---

## 4. Files to Touch (6)

| # | File | Change |
|---|---|---|
| 1 | `front/src/lib/builder-portal/types.ts` | Add `'captcha'` to `PortalNodeType` union; add `PortalCaptchaProps { align?: 'left'\|'center'\|'right' }`. |
| 2 | `front/src/lib/builder-portal/renderer.tsx` | Add `case 'captcha':`. New local component `PortalCaptchaField` that wraps `CapCaptcha` + a hidden `<input name="captcha_token">` via a ref, honouring `align`. In preview (`runtime` falsy) render a static placeholder. |
| 3 | `front/src/lib/builder-portal/components.tsx` | Add palette entry `{ type:'captcha', label:'Captcha', icon:<ShieldCheck size={14}/>, defaultProps:{ align:'center' } }`. Add `'captcha'` to `RESTRICTED_TO_PAGE_TYPE` mapped to login + register page types. |
| 4 | `front/src/lib/builder-portal/config-panels/config-panel-renderer.tsx` | Add `case 'captcha':` — locked-hint note ("Renders the Cap widget only when the Cap endpoint is configured; emits the captcha token on submit.") + an alignment `SelectField`. |
| 5 | `front/src/lib/builder-portal/visual-blocks/visual-block-registry.tsx` | Add a captcha placeholder rendering for the editing canvas (mirrors other non-interactive blocks like `identity_providers`). |
| 6 | `front/src/pages/authentication/hooks/use-portal-page-submit.ts` | In the **login** and **register** branches read `data.get('captcha_token')`; inject `captcha_token` into the `authenticate()` and `registration()` payloads (omit/empty when absent). |

**Not touched:** `portal-layout-wrapper.tsx` (FormData bridge makes it unnecessary).

### Reuse note
`PortalCaptchaField` reuses the existing `CapCaptcha` component (`front/src/components/cap-captcha.tsx`) rather than re-implementing the widget. The only new behaviour is mirroring the solved token into a hidden form field.

---

## 5. The Footgun (accepted, mitigated)

A pure builder block means: if `CAP_ENABLED=true` on the backend but the admin's template omits the Captcha block, every portal login/register returns `400 captcha token required`.

Mitigations included in this work (none change the chosen block-based mechanism):
- The block is **discoverable in the right place** — restricted to the login + register palettes.
- A **config-panel note** explains the block only renders when the Cap endpoint is configured.
- A **README line** (Captcha section): custom Portal templates must include the Captcha block on login/register pages when captcha is enforced.

Explicitly **out of scope:** auto-render fallback, and any builder-side "captcha enforced but block missing" warning (the frontend has no signal for the backend `CAP_ENABLED` flag).

---

## 6. Testing

**Unit (frontend):**
- Renderer: a `captcha` node with `runtime:true` emits a hidden `input[name="captcha_token"]` and (when endpoint configured) the widget; with `runtime` falsy it emits the placeholder, no widget.
- `solve` event handler writes the token into the hidden input's value.
- `usePortalPageSubmit`: login and register branches inject `captcha_token` from FormData into their payloads; absent token → field omitted or empty, no crash.

**Manual / integration:**
1. Build a custom login template containing the Captcha block; set `VITE_CAP_API_ENDPOINT` + `CAP_ENABLED=true`. Confirm the widget renders, the token submits, and login succeeds.
2. Remove the block from the template; confirm the documented `400 captcha token required` (verifies the footgun behaves as documented).
3. With `CAP_ENABLED=false` / endpoint unset: block renders nothing at runtime, login/register still work.

---

## 7. Out of Scope

- Backend changes (enforcement already exists and is unchanged).
- Auto-render fallback or hybrid placement.
- Per-realm captcha toggle / surfacing the backend `CAP_ENABLED` flag to the frontend.
- Captcha on flows other than login + register (totp, forgot/reset password, magic link).
