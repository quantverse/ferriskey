# Portal Auth: Rate Limiting + Cap Proof-of-Work CAPTCHA

**Date:** 2026-06-18
**Status:** Approved (design) — pending implementation plan
**Scope:** Add abuse controls to the public portal authentication endpoints (login, sign-up, and the brute-forceable token grant) of the FerrisKey IAM. Two mechanisms: per-IP/per-account rate limiting and a Cap (trycap.dev) SHA-256 proof-of-work CAPTCHA.

---

## 1. Background & Audit Findings

A security audit of the portal auth surface found **no abuse controls of any kind**.

### Attacker-reachable, unthrottled endpoints

| Purpose | Method / Path | Handler | Risk |
|---|---|---|---|
| Login | `POST /realms/{realm}/login-actions/authenticate` | `api/.../authentication/handlers/authentificate.rs:112` | Unlimited password brute-force / credential stuffing |
| Registration (self-service) | `POST /realms/{realm}/protocol/openid-connect/registrations` | `api/.../authentication/handlers/registration.rs:91` | Mass automated account creation / spam (when `user_registration_enabled`) |
| Token — password grant | `POST /realms/{realm}/protocol/openid-connect/token` | `api/.../authentication/handlers/token.rs:51` | **Second brute-force path**: ROPC `grant_type=password` bypasses the login flow |
| Email verify / resend | `POST /login-actions/verify-email`, `.../resend-verification-email` | `verify_email.rs:41`, `resend_verification_email.rs:39` | Token guessing; email-bomb amplification |
| Authorize | `GET /protocol/openid-connect/auth` | `auth.rs:87` | Session/cookie spray |

### Current state (confirmed)
- **Middleware stack** (`api/src/application/http/server/http_server.rs`): `TraceLayer → CorsLayer → CookieLayer → PrometheusMetricLayer`. No rate-limit layer.
- **No** `governor` / `tower-governor`, no account lockout, no failed-attempt counter. `api/Cargo.toml` has `tower-http` with `["cors","trace"]` only.
- **No** CAPTCHA / PoW anywhere (backend or `front/`).
- **No** shared cache/state store — Postgres only. (KeyDB will be introduced by this work for Cap.)
- Only pre-existing throttle is the device-flow polling `interval` check (`core/.../device_flow/services.rs:255`) — unrelated and narrow.

### Two brute-force surfaces, not one
Any protection must cover **both** `/login-actions/authenticate` and the token endpoint's `password` grant, or it is trivially bypassed.

---

## 2. Decisions (locked)

| Decision | Choice | Rationale |
|---|---|---|
| Deployment topology | Single instance | In-process rate limiter (`tower-governor`) and in-memory brute-force counter are correct. |
| CAPTCHA technology | **Cap** (trycap.dev), SHA-256 PoW | User-specified. Self-hosted, privacy-friendly, no third party. |
| Cap integration | **Standalone sidecar** + `/siteverify` | Cap's server is JS-only; reimplementing its wire protocol in Rust carries correctness risk. Rust backend validates with one HTTP call. |
| Cap state store | **KeyDB** (not Valkey) | Redis-protocol compatible; project will run a KeyDB cluster anyway. |
| PoW enforcement | Sign-up **and** login, always | Strongest; no failure-tracking needed to decide when to show it. |
| Login defense | Per-IP rate limit **+** per-account failure counter | Per-IP stops fast single-source loops; per-account stops slow distributed guessing of one user. |
| Account lockout | **No hard lockout** | Per-account counter escalates to a *temporary throttle* only — avoids account-DoS. |
| Client IP source | Trust `X-Forwarded-For` from nginx | API sits behind nginx reverse proxy. |

---

## 3. Architecture

```
                         ┌──────────────────────────────────────────────┐
  browser                │  ferriskey api (Axum, Rust, single instance)  │
  ───────                │                                               │
  <cap-widget> ──────────┼──► (talks directly to Cap Standalone)         │
       │                 │                                               │
       │ solves PoW       │   request path on protected auth routes:     │
       ▼                 │     1. rate-limit layer      → 429            │
  POST auth request ─────┼──► 2. captcha verify         → 400            │
   (X-Captcha-Token)     │     3. brute-force throttle  → 429            │
                         │     4. credential check (existing)            │
                         │            │                                  │
                         │            └─► POST /siteverify ──┐           │
                         └───────────────────────────────────┼──────────┘
                                                             ▼
                              ┌─────────────────┐     ┌─────────────┐
   <cap-widget> ─────────────►│ Cap Standalone  │────►│   KeyDB     │
   (/challenge, /redeem)      │ (Bun container) │     │ (challenge/ │
                              │  /siteverify    │     │  token state)│
                              └─────────────────┘     └─────────────┘
```

**Why captcha before credential check:** PoW absorbs attacker cost before any DB/credential work happens.

---

## 4. Component 1 — Rate Limiting (in-process)

**Dependency:** add `tower-governor` to `api/Cargo.toml`.

**Scope:** a dedicated limiter layer applied **only** to the sensitive routes — `authenticate`, `token`, `registrations`, `verify-email`, `resend-verification-email`, `auth` — composed onto those routers (or via a route-allowlist predicate). Global traffic (JWKS, discovery, introspection, userinfo, metrics) is unaffected.

**Key extraction (client IP):** a custom `KeyExtractor`:
1. If `TRUSTED_PROXY_COUNT > 0` and `X-Forwarded-For` is present: take the IP that is `TRUSTED_PROXY_COUNT` hops from the right (the address nginx itself observed).
2. Otherwise fall back to the socket peer address (`ConnectInfo<SocketAddr>`).

**Response:** `429 Too Many Requests` with a `Retry-After` header.

**Config (`Args` / env):**
- `RATE_LIMIT_ENABLED` (default `true`)
- `AUTH_RATE_LIMIT_PER_MIN` (default `20`)
- `AUTH_RATE_LIMIT_BURST` (default `5`)
- `TRUSTED_PROXY_COUNT` (default `1`)

**Hardening (must be in the implementation):**
- XFF trust is sound **only** if the API port is not directly internet-exposed. Document this as a deployment requirement.
- `front/nginx.conf` must **set/overwrite** `X-Forwarded-For` with the real client address (`proxy_set_header X-Forwarded-For $remote_addr;` or `X-Real-IP`) rather than appending to a client-supplied value, so a client cannot pre-seed spoofed hops.

---

## 5. Component 2 — Per-IP + Per-Account Brute-Force Counter

**Port:** new trait `BruteForceGuard` in `core` (domain) so the storage backend is swappable.

**Default impl:** in-memory `DashMap` keyed by `(realm_id, username)`:
- `failure_count`, sliding `window_start`, `throttled_until: Option<Instant>`.

**Behavior:**
- On a **failed** `authenticate` or password-grant: increment within the window.
- After `LOGIN_MAX_FAILURES` failures in `LOGIN_FAILURE_WINDOW_SECS`: set `throttled_until = now + LOGIN_THROTTLE_SECS`; subsequent attempts for that account return `429` (slow-down) until the cooldown elapses.
- On **success**: reset the entry.

**Config:**
- `LOGIN_MAX_FAILURES` (default `5`)
- `LOGIN_FAILURE_WINDOW_SECS` (default `300`)
- `LOGIN_THROTTLE_SECS` (default `300`)

**Future:** a KeyDB-backed `BruteForceGuard` impl replaces the in-memory one for multi-instance correctness — drop-in via the trait. Out of scope now.

---

## 6. Component 3 — Cap PoW CAPTCHA (sidecar)

### Infrastructure (docker-compose, Helm later)
Two new services:
- **`cap`** — official Cap Standalone (Bun). Env: `ADMIN_KEY` (32+ chars), `REDIS_URL=redis://keydb:6379`. Exposes the widget API (`/<site_key>/challenge`, `/<site_key>/redeem`) and `/<site_key>/siteverify`.
- **`keydb`** — Redis-protocol-compatible store for Cap's challenge/token state.

A **site key** (public) and **secret key** (backend) are provisioned via the Cap dashboard / config.

### Frontend (`front/`)
- Add the Cap widget (`@cap.js/widget`) to the **login** and **registration** pages.
- Mount `<cap-widget data-cap-api-endpoint="<cap_url>/<site_key>/">`; on solve, capture the token.
- Send the token to the FerrisKey API as header **`X-Captcha-Token`** on the authenticate / registration / password-grant requests.
- Prefer wiring through the existing generated API client where possible (per CLAUDE.md frontend guidance).

### Backend (`core` + `api`)
- **Port:** `CaptchaVerifier` trait in `core` — `async fn verify(&self, token: Option<&str>, client_ip: ...) -> Result<(), CaptchaError>`.
- **Adapter:** `CapCaptchaVerifier` — `POST <CAP_VERIFY_URL>/<CAP_SITE_KEY>/siteverify` with body `{ "secret": CAP_SECRET, "response": <token> }`; success requires `{ "success": true }`.
- **No-op adapter** when `CAP_ENABLED=false` (returns Ok) — keeps dev/CI and non-browser clients working.
- Verification runs **before** credential checks in the handler/service.

### Enforcement points
- **Registration** — always.
- **`authenticate`** — always.
- **Token endpoint** — **only** for `grant_type=password` from **public** clients. Other grant types (`client_credentials`, `refresh_token`, `authorization_code`, `device_code`) are non-interactive and must not be forced through a browser puzzle; rate limiting covers them.

### Availability behavior
- **Fail-closed** on login/registration when Cap is unreachable: reject the request (so an attacker cannot disable the CAPTCHA by DoSing the sidecar). Behavior controlled by `CAP_FAIL_OPEN` (default `false`).

### Config
- `CAP_ENABLED` (default `false` — must be explicitly enabled in prod)
- `CAP_VERIFY_URL` (e.g. `http://cap:3000`)
- `CAP_SITE_KEY`
- `CAP_SECRET`
- `CAP_FAIL_OPEN` (default `false`)

---

## 7. Request Ordering & Error Handling

**Order on a protected route:** `rate-limit (429)` → `captcha verify (400)` → `brute-force throttle (429)` → existing credential check.

**Error types:** new `CoreError` variants mapped via the existing `From<CoreError> for ApiError`:
- `CaptchaRequired` / `CaptchaInvalid` → `400` (distinct error code from auth failure — never reveal credential validity here).
- `TooManyRequests` → `429` with `Retry-After`.

Rate-limit `429`s are emitted by the `tower-governor` layer directly; brute-force `429`s flow through `CoreError`.

---

## 8. Testing Strategy

**Unit:**
- IP extractor: XFF hop selection at `TRUSTED_PROXY_COUNT`, missing-header fallback to peer IP, spoof attempt (client-supplied extra hops ignored).
- `BruteForceGuard`: increment, throttle after N, reset on success, window expiry.
- `CaptchaVerifier`: mock Cap returning success / failure / missing-token / Cap-unreachable (fail-closed vs `CAP_FAIL_OPEN`).

**Integration (`api/tests/it/`):**
- `429` after exceeding the limit on each protected route.
- `400` when `CAP_ENABLED` and `X-Captcha-Token` absent/invalid on login + registration.
- Password-grant captcha gating (public client requires token; confidential/other grants do not).
- Per-account throttle after N failed logins; reset after success.
- Cap-down ⇒ login rejected when fail-closed.

---

## 9. Out of Scope (flagged, not built now)

- Public self-service **password-reset** flow (does not exist today; reset is admin-only).
- Moving rate-limit / brute-force state to **KeyDB** for multi-instance (trait makes it a later drop-in).
- **Per-realm** captcha / rate-limit toggles (global config flags for v1).
- Hard account **lockout** (deliberately excluded to avoid account-DoS).

---

## 10. Affected Files (anticipated)

- `api/Cargo.toml` — add `tower-governor` (and HTTP client for siteverify if not already present).
- `api/src/application/http/server/http_server.rs` — wire the rate-limit layer onto protected routers; add IP extractor.
- `api/src/application/http/server/app_state.rs` — hold `BruteForceGuard` + `CaptchaVerifier`.
- `api/src/<Args>` — new config fields/env.
- `api/src/application/http/authentication/handlers/{authentificate,registration,token}.rs` — captcha + brute-force hooks.
- `api/src/application/http/errors/error.rs` + `core/src/domain/common/errors.rs` — new error variants.
- `core/src/domain/.../` — `CaptchaVerifier` and `BruteForceGuard` ports + default impls (new small domain module, e.g. `abuse`/`portal_security`).
- `front/` — Cap widget on login + registration pages; send `X-Captcha-Token`.
- `front/nginx.conf` — set real-client `X-Forwarded-For`.
- `docker-compose.yaml` — `cap` + `keydb` services.
- `.env.example` / docs — new env vars and deployment notes.
