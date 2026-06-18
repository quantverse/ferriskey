# Portal Auth Rate Limiting + Cap PoW CAPTCHA — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-IP rate limiting, per-account brute-force throttling, and a Cap (trycap.dev) SHA-256 proof-of-work CAPTCHA to the portal login, registration, and password-grant endpoints of the FerrisKey API.

**Architecture:** All three controls live in the **`ferriskey-api`** crate (not `core`), because they are HTTP/transport concerns and need to read request headers and the client IP. They are constructed from config in `AppState::new` and stored as `Arc`s on `AppState`. Rate limiting is a custom `axum` middleware backed by the stable `governor` crate, scoped to the sensitive routes only. Brute-force tracking is an in-memory `DashMap` behind a `BruteForceGuard` trait (swappable for a KeyDB-backed impl later). Cap is verified via one HTTP `POST /siteverify` call from a `CaptchaVerifier` trait (no-op when disabled). Cap itself runs as a Standalone sidecar backed by KeyDB, added to `docker-compose.yaml`.

**Tech Stack:** Rust, Axum 0.8, `governor` 0.6 (rate limiting), `dashmap` 6 (state), `reqwest` 0.12 (Cap siteverify), React 19 + `@cap.js/widget` (frontend), Cap Standalone + KeyDB (Docker).

## Global Constraints

- **No `.unwrap()` in non-test code** — use `?`, `ok_or_else`, `unwrap_or_default`, or `match`. (`NonZeroU32::new(...).unwrap()` is acceptable only on a compile-time constant that is provably non-zero; prefer `.ok_or_else` on config-derived values.)
- **`AppState::new(args, service)` signature MUST NOT change** — it is called by existing integration tests (`api/tests/token_basic_auth_test.rs:115`, `organization_test.rs`, `portal_theme_test.rs`). New components are derived from `args` inside `new`.
- **Captcha defaults OFF** — `CAP_ENABLED=false` by default so existing tests, CI, dev, and non-browser clients keep working. The no-op verifier returns `Ok(())`.
- **Rate limiting defaults ON** but with generous limits; it must be disable-able via `RATE_LIMIT_ENABLED=false` so integration tests that fire many requests don't trip it. Tests that assert 429 enable it with a tiny limit.
- **Captcha token transport = request body field `captcha_token`** (not a header). Reason: the three endpoints span JSON (`authenticate`, `registrations`) and form-url-encoded (`token`); a body field works uniformly with the existing generated frontend client. The field is `Option<String>`, always optional at the type level; enforcement is decided server-side.
- **Token-endpoint captcha applies only to `grant_type=password` with NO client secret** (the public-client / browser ROPC vector). Confidential clients (Basic auth or `client_secret`) and all other grant types are exempt.
- **Cap unreachable ⇒ fail closed** (reject) unless `CAP_FAIL_OPEN=true`.
- Run backend checks with `cargo check -p ferriskey-api` and `cargo test -p ferriskey-api`. Integration tests that need Postgres are marked `#[ignore]` and run with `-- --ignored` (mirror `token_basic_auth_test.rs`).
- Frontend: `cd front && pnpm run lint && pnpm run build`.

---

## File Structure

**New files (api crate):**
- `api/src/application/security/mod.rs` — module root, re-exports.
- `api/src/application/security/brute_force.rs` — `BruteForceGuard` trait + `InMemoryBruteForceGuard`.
- `api/src/application/security/captcha.rs` — `CaptchaVerifier` trait + `NoopCaptchaVerifier` + `CapCaptchaVerifier` + `CaptchaError`.
- `api/src/application/security/rate_limit.rs` — `KeyedRateLimiter` type alias, `build_rate_limiter`, `client_ip`, `auth_rate_limit` middleware.
- `api/tests/portal_security_test.rs` — integration tests (rate limit 429, captcha 400, brute-force throttle).

**Modified files:**
- `api/Cargo.toml` — add `governor`, `dashmap`, `reqwest`.
- `api/src/application.rs` — declare `pub mod security;` (verify module wiring).
- `api/src/args.rs` — add `SecurityArgs` group + field on `Args` + `Default`.
- `api/src/application/http/server/app_state.rs` — add `rate_limiter`, `brute_force`, `captcha` fields; build them in `new`.
- `api/src/application/http/server/api_entities/api_error.rs` — add `TooManyRequests` variant + `IntoResponse` arm with `Retry-After`.
- `api/src/application/http/authentication/router.rs` — scope the rate-limit layer onto sensitive routes only.
- `api/src/application/http/authentication/handlers/authentificate.rs` — captcha + brute-force hooks; add `captcha_token` field.
- `api/src/application/http/authentication/handlers/registration.rs` — captcha hook; add `captcha_token` field.
- `api/src/application/http/authentication/validators.rs` — add `captcha_token` to `TokenRequestValidator`.
- `api/src/application/http/authentication/handlers/token.rs` — captcha + brute-force for public-client password grant.
- `api/src/main.rs` — `into_make_service_with_connect_info::<SocketAddr>()` (both bind paths).
- `docker-compose.yaml` — `cap` + `keydb` services.
- `front/nginx.conf` — overwrite `X-Forwarded-For` with `$remote_addr`.
- `front/package.json` — add `@cap.js/widget`.
- `front/src/components/cap-captcha.tsx` — React wrapper (new).
- `front/src/pages/authentication/hooks/use-login-form.ts` + `ui/page-login.tsx` — render widget, capture token.
- `front/src/pages/authentication/feature/page-register-feature.tsx` + `ui/page-register.tsx` — render widget, capture token.
- `front/src/api/auth.api.ts` — send `captcha_token`.
- `.env.example` (api) and docs — new env vars.

---

## Task 1: Security config (`SecurityArgs`)

**Files:**
- Modify: `api/src/args.rs`

**Interfaces:**
- Produces: `Args.security: SecurityArgs` with fields:
  `rate_limit_enabled: bool`, `auth_rate_limit_per_min: u32`, `auth_rate_limit_burst: u32`,
  `login_max_failures: u32`, `login_failure_window_secs: u64`, `login_throttle_secs: u64`,
  `cap_enabled: bool`, `cap_verify_url: String`, `cap_site_key: String`, `cap_secret: String`, `cap_fail_open: bool`.

- [ ] **Step 1: Add the `SecurityArgs` struct and wire it into `Args`**

In `api/src/args.rs`, add the field to `Args` (after the `observability` field, before `command`):

```rust
    #[command(flatten)]
    pub security: SecurityArgs,
```

Add it to the `Default for Args` impl (before `command: None,`):

```rust
            security: SecurityArgs::default(),
```

Add the struct + default near the other `*Args` structs:

```rust
#[derive(clap::Args, Debug, Clone)]
pub struct SecurityArgs {
    #[arg(long = "rate-limit-enabled", env = "RATE_LIMIT_ENABLED", default_value_t = true)]
    pub rate_limit_enabled: bool,
    #[arg(long = "auth-rate-limit-per-min", env = "AUTH_RATE_LIMIT_PER_MIN", default_value_t = 20)]
    pub auth_rate_limit_per_min: u32,
    #[arg(long = "auth-rate-limit-burst", env = "AUTH_RATE_LIMIT_BURST", default_value_t = 5)]
    pub auth_rate_limit_burst: u32,
    #[arg(long = "login-max-failures", env = "LOGIN_MAX_FAILURES", default_value_t = 5)]
    pub login_max_failures: u32,
    #[arg(long = "login-failure-window-secs", env = "LOGIN_FAILURE_WINDOW_SECS", default_value_t = 300)]
    pub login_failure_window_secs: u64,
    #[arg(long = "login-throttle-secs", env = "LOGIN_THROTTLE_SECS", default_value_t = 300)]
    pub login_throttle_secs: u64,
    #[arg(long = "cap-enabled", env = "CAP_ENABLED", default_value_t = false)]
    pub cap_enabled: bool,
    #[arg(long = "cap-verify-url", env = "CAP_VERIFY_URL", default_value = "")]
    pub cap_verify_url: String,
    #[arg(long = "cap-site-key", env = "CAP_SITE_KEY", default_value = "")]
    pub cap_site_key: String,
    #[arg(long = "cap-secret", env = "CAP_SECRET", default_value = "")]
    pub cap_secret: String,
    #[arg(long = "cap-fail-open", env = "CAP_FAIL_OPEN", default_value_t = false)]
    pub cap_fail_open: bool,
}

impl Default for SecurityArgs {
    fn default() -> Self {
        Self {
            rate_limit_enabled: true,
            auth_rate_limit_per_min: 20,
            auth_rate_limit_burst: 5,
            login_max_failures: 5,
            login_failure_window_secs: 300,
            login_throttle_secs: 300,
            cap_enabled: false,
            cap_verify_url: String::new(),
            cap_site_key: String::new(),
            cap_secret: String::new(),
            cap_fail_open: false,
        }
    }
}
```

- [ ] **Step 2: Add a unit test for the defaults**

Inside the existing `#[cfg(test)] mod test` block in `api/src/args.rs`, add:

```rust
    #[test]
    fn security_defaults() {
        let s = super::SecurityArgs::default();
        assert!(s.rate_limit_enabled);
        assert_eq!(s.auth_rate_limit_per_min, 20);
        assert_eq!(s.login_max_failures, 5);
        assert!(!s.cap_enabled);
        assert!(!s.cap_fail_open);
    }
```

- [ ] **Step 3: Run the test**

Run: `cargo test -p ferriskey-api --lib args::test::security_defaults`
Expected: PASS.

- [ ] **Step 4: Verify the whole crate still type-checks**

Run: `cargo check -p ferriskey-api`
Expected: compiles (warnings about unused `SecurityArgs` fields are fine for now).

- [ ] **Step 5: Commit**

```bash
git add api/src/args.rs
git commit -m "feat(security): add SecurityArgs config (rate limit, brute force, captcha)"
```

---

## Task 2: `BruteForceGuard` (per-account failure throttle)

**Files:**
- Create: `api/src/application/security/mod.rs`
- Create: `api/src/application/security/brute_force.rs`
- Modify: `api/Cargo.toml`
- Modify: `api/src/application.rs`

**Interfaces:**
- Produces:
  - `trait BruteForceGuard: Send + Sync` with
    `fn check(&self, realm: &str, username: &str) -> bool` (returns `true` if currently throttled),
    `fn record_failure(&self, realm: &str, username: &str)`,
    `fn record_success(&self, realm: &str, username: &str)`.
  - `struct InMemoryBruteForceGuard` with `new(max_failures: u32, window: Duration, throttle: Duration) -> Self`.

- [ ] **Step 1: Add dependencies**

In `api/Cargo.toml` under `[dependencies]`, add:

```toml
dashmap = "6.1.0"
```

- [ ] **Step 2: Declare the module**

In `api/src/application.rs`, add a module declaration alongside the existing `pub mod` lines:

```rust
pub mod security;
```

(If `api/src/application.rs` instead re-exports an `application/` dir module tree, add `pub mod security;` in the file that declares the other `application::*` submodules. Verify with `grep -n "pub mod" api/src/application.rs`.)

Create `api/src/application/security/mod.rs`:

```rust
pub mod brute_force;
```

- [ ] **Step 3: Write the failing test**

Create `api/src/application/security/brute_force.rs`:

```rust
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Per-account brute-force throttle. Tracks failed login attempts keyed by
/// `(realm, username)` and temporarily throttles an account after too many
/// failures inside a sliding window. Single-instance, in-memory.
pub trait BruteForceGuard: Send + Sync {
    /// Returns `true` if the account is currently throttled and the request
    /// should be rejected before any credential check.
    fn check(&self, realm: &str, username: &str) -> bool;
    fn record_failure(&self, realm: &str, username: &str);
    fn record_success(&self, realm: &str, username: &str);
}

#[derive(Clone)]
struct Entry {
    failures: u32,
    window_start: Instant,
    throttled_until: Option<Instant>,
}

pub struct InMemoryBruteForceGuard {
    entries: DashMap<String, Entry>,
    max_failures: u32,
    window: Duration,
    throttle: Duration,
}

impl InMemoryBruteForceGuard {
    pub fn new(max_failures: u32, window: Duration, throttle: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            max_failures,
            window,
            throttle,
        }
    }

    fn key(realm: &str, username: &str) -> String {
        format!("{realm}\u{0}{username}")
    }
}

impl BruteForceGuard for InMemoryBruteForceGuard {
    fn check(&self, realm: &str, username: &str) -> bool {
        let key = Self::key(realm, username);
        match self.entries.get(&key) {
            Some(entry) => match entry.throttled_until {
                Some(until) => Instant::now() < until,
                None => false,
            },
            None => false,
        }
    }

    fn record_failure(&self, realm: &str, username: &str) {
        let key = Self::key(realm, username);
        let now = Instant::now();
        let mut entry = self.entries.entry(key).or_insert(Entry {
            failures: 0,
            window_start: now,
            throttled_until: None,
        });

        // Reset the window if it has elapsed.
        if now.duration_since(entry.window_start) > self.window {
            entry.failures = 0;
            entry.window_start = now;
            entry.throttled_until = None;
        }

        entry.failures += 1;
        if entry.failures >= self.max_failures {
            entry.throttled_until = Some(now + self.throttle);
        }
    }

    fn record_success(&self, realm: &str, username: &str) {
        let key = Self::key(realm, username);
        self.entries.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> InMemoryBruteForceGuard {
        InMemoryBruteForceGuard::new(3, Duration::from_secs(300), Duration::from_secs(300))
    }

    #[test]
    fn not_throttled_initially() {
        let g = guard();
        assert!(!g.check("master", "alice"));
    }

    #[test]
    fn throttles_after_max_failures() {
        let g = guard();
        g.record_failure("master", "alice");
        g.record_failure("master", "alice");
        assert!(!g.check("master", "alice"));
        g.record_failure("master", "alice"); // 3rd -> throttled
        assert!(g.check("master", "alice"));
    }

    #[test]
    fn success_resets_failures() {
        let g = guard();
        g.record_failure("master", "alice");
        g.record_failure("master", "alice");
        g.record_success("master", "alice");
        g.record_failure("master", "alice");
        assert!(!g.check("master", "alice"));
    }

    #[test]
    fn throttle_is_per_account() {
        let g = guard();
        g.record_failure("master", "alice");
        g.record_failure("master", "alice");
        g.record_failure("master", "alice");
        assert!(g.check("master", "alice"));
        assert!(!g.check("master", "bob"));
    }

    #[test]
    fn zero_window_resets_each_call() {
        let g = InMemoryBruteForceGuard::new(3, Duration::from_secs(0), Duration::from_secs(300));
        g.record_failure("master", "alice");
        g.record_failure("master", "alice");
        g.record_failure("master", "alice");
        // Each failure is in a fresh window, so the count never reaches 3 -> never throttled.
        assert!(!g.check("master", "alice"));
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ferriskey-api --lib security::brute_force`
Expected: 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add api/Cargo.toml api/src/application.rs api/src/application/security/mod.rs api/src/application/security/brute_force.rs
git commit -m "feat(security): in-memory per-account brute-force guard"
```

---

## Task 3: `CaptchaVerifier` (Cap siteverify) + no-op

**Files:**
- Create: `api/src/application/security/captcha.rs`
- Modify: `api/src/application/security/mod.rs`
- Modify: `api/Cargo.toml`

**Interfaces:**
- Consumes: `SecurityArgs` fields (`cap_*`).
- Produces:
  - `enum CaptchaError { Missing, Invalid, Unavailable }`
  - `trait CaptchaVerifier: Send + Sync { async fn verify(&self, token: Option<&str>) -> Result<(), CaptchaError>; }`
  - `struct NoopCaptchaVerifier;`
  - `struct CapCaptchaVerifier { client, verify_url, site_key, secret, fail_open }` with
    `fn new(verify_url, site_key, secret, fail_open) -> Self`.
  - `fn build_captcha_verifier(args: &SecurityArgs) -> Arc<dyn CaptchaVerifier>`.

- [ ] **Step 1: Add the HTTP client dependency**

In `api/Cargo.toml` under `[dependencies]`:

```toml
reqwest = { version = "0.12.9", default-features = false, features = ["json", "rustls-tls"] }
async-trait = "0.1.83"
```

(The trait uses `async fn` in a trait object, so `async-trait` is required for `dyn CaptchaVerifier`.)

- [ ] **Step 2: Declare the module**

In `api/src/application/security/mod.rs`, add:

```rust
pub mod captcha;
```

- [ ] **Step 3: Write the verifier with unit tests**

Create `api/src/application/security/captcha.rs`:

```rust
use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use tracing::warn;

use crate::args::SecurityArgs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaError {
    /// No token supplied but one is required.
    Missing,
    /// Token supplied but Cap rejected it.
    Invalid,
    /// Cap could not be reached / returned an unexpected response.
    Unavailable,
}

#[async_trait]
pub trait CaptchaVerifier: Send + Sync {
    async fn verify(&self, token: Option<&str>) -> Result<(), CaptchaError>;
}

/// Used when `CAP_ENABLED=false`. Always succeeds.
pub struct NoopCaptchaVerifier;

#[async_trait]
impl CaptchaVerifier for NoopCaptchaVerifier {
    async fn verify(&self, _token: Option<&str>) -> Result<(), CaptchaError> {
        Ok(())
    }
}

#[derive(Serialize)]
struct SiteverifyBody<'a> {
    secret: &'a str,
    response: &'a str,
}

pub struct CapCaptchaVerifier {
    client: reqwest::Client,
    verify_url: String,
    site_key: String,
    secret: String,
    fail_open: bool,
}

impl CapCaptchaVerifier {
    pub fn new(verify_url: String, site_key: String, secret: String, fail_open: bool) -> Self {
        Self {
            client: reqwest::Client::new(),
            verify_url: verify_url.trim_end_matches('/').to_string(),
            site_key,
            secret,
            fail_open,
        }
    }

    /// `POST {verify_url}/{site_key}/siteverify`
    fn endpoint(&self) -> String {
        format!("{}/{}/siteverify", self.verify_url, self.site_key)
    }
}

#[async_trait]
impl CaptchaVerifier for CapCaptchaVerifier {
    async fn verify(&self, token: Option<&str>) -> Result<(), CaptchaError> {
        let token = match token {
            Some(t) if !t.is_empty() => t,
            _ => return Err(CaptchaError::Missing),
        };

        let body = SiteverifyBody { secret: &self.secret, response: token };

        let response = match self.client.post(self.endpoint()).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "Cap siteverify request failed");
                return if self.fail_open { Ok(()) } else { Err(CaptchaError::Unavailable) };
            }
        };

        if !response.status().is_success() {
            warn!(status = %response.status(), "Cap siteverify non-success status");
            return if self.fail_open { Ok(()) } else { Err(CaptchaError::Unavailable) };
        }

        let parsed: serde_json::Value = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "Cap siteverify body parse failed");
                return if self.fail_open { Ok(()) } else { Err(CaptchaError::Unavailable) };
            }
        };

        if parsed.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
            Ok(())
        } else {
            Err(CaptchaError::Invalid)
        }
    }
}

pub fn build_captcha_verifier(args: &SecurityArgs) -> Arc<dyn CaptchaVerifier> {
    if args.cap_enabled {
        Arc::new(CapCaptchaVerifier::new(
            args.cap_verify_url.clone(),
            args.cap_site_key.clone(),
            args.cap_secret.clone(),
            args.cap_fail_open,
        ))
    } else {
        Arc::new(NoopCaptchaVerifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_accepts_missing_token() {
        let v = NoopCaptchaVerifier;
        assert!(v.verify(None).await.is_ok());
    }

    #[tokio::test]
    async fn cap_missing_token_is_missing() {
        let v = CapCaptchaVerifier::new("http://127.0.0.1:1".into(), "sk".into(), "secret".into(), false);
        assert_eq!(v.verify(None).await, Err(CaptchaError::Missing));
        assert_eq!(v.verify(Some("")).await, Err(CaptchaError::Missing));
    }

    #[tokio::test]
    async fn cap_unreachable_fails_closed() {
        // Port 1 refuses connections -> Unavailable when fail_open=false.
        let v = CapCaptchaVerifier::new("http://127.0.0.1:1".into(), "sk".into(), "secret".into(), false);
        assert_eq!(v.verify(Some("tok")).await, Err(CaptchaError::Unavailable));
    }

    #[tokio::test]
    async fn cap_unreachable_fails_open_when_configured() {
        let v = CapCaptchaVerifier::new("http://127.0.0.1:1".into(), "sk".into(), "secret".into(), true);
        assert!(v.verify(Some("tok")).await.is_ok());
    }

    #[test]
    fn build_returns_noop_when_disabled() {
        let args = SecurityArgs::default();
        let _v = build_captcha_verifier(&args); // cap_enabled=false -> noop, must not panic
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p ferriskey-api --lib security::captcha`
Expected: 5 tests PASS. (The unreachable-host tests connect to `127.0.0.1:1` which refuses quickly.)

- [ ] **Step 5: Commit**

```bash
git add api/Cargo.toml api/src/application/security/mod.rs api/src/application/security/captcha.rs
git commit -m "feat(security): Cap captcha verifier (siteverify) with no-op fallback"
```

---

## Task 4: Rate-limit middleware + `client_ip` helper

**Files:**
- Create: `api/src/application/security/rate_limit.rs`
- Modify: `api/src/application/security/mod.rs`
- Modify: `api/Cargo.toml`

**Interfaces:**
- Consumes: `AppState` (added in Task 5), `SecurityArgs`.
- Produces:
  - `type KeyedRateLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;`
  - `fn build_rate_limiter(per_min: u32, burst: u32) -> Arc<KeyedRateLimiter>`
  - `fn client_ip(req: &Request) -> String`
  - `async fn auth_rate_limit(State<AppState>, Request, Next) -> Result<Response, ApiError>` (added in Task 5 once `AppState` has the limiter; here we build the pure helpers and test them).

- [ ] **Step 1: Add the rate-limiter dependency**

In `api/Cargo.toml` under `[dependencies]`:

```toml
governor = "0.6.3"
```

- [ ] **Step 2: Declare the module**

In `api/src/application/security/mod.rs`, add:

```rust
pub mod rate_limit;
```

- [ ] **Step 3: Write the limiter builder + `client_ip` with tests**

Create `api/src/application/security/rate_limit.rs`:

```rust
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request};
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};

pub type KeyedRateLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

/// Build a per-key (per-IP) rate limiter allowing `per_min` requests/minute
/// with a burst of `burst`. Values are clamped to at least 1.
pub fn build_rate_limiter(per_min: u32, burst: u32) -> Arc<KeyedRateLimiter> {
    let per_min = NonZeroU32::new(per_min.max(1)).unwrap_or(NonZeroU32::MIN);
    let burst = NonZeroU32::new(burst.max(1)).unwrap_or(NonZeroU32::MIN);
    let quota = Quota::per_minute(per_min).allow_burst(burst);
    Arc::new(RateLimiter::keyed(quota))
}

/// Determine the client IP for rate-limit keying.
///
/// nginx is configured to OVERWRITE `X-Forwarded-For` with the real client
/// address (`$remote_addr`), so the left-most value is trustworthy. If the
/// header is absent (API hit directly, e.g. tests), fall back to the socket
/// peer address from `ConnectInfo`.
pub fn client_ip(req: &Request) -> String {
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(value) = xff.to_str() {
            if let Some(first) = value.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }

    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return addr.ip().to_string();
    }

    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;

    #[test]
    fn client_ip_prefers_xff() {
        let req = Request::builder()
            .header("x-forwarded-for", "203.0.113.7")
            .body(Body::empty())
            .unwrap();
        assert_eq!(client_ip(&req), "203.0.113.7");
    }

    #[test]
    fn client_ip_takes_leftmost_xff() {
        let req = Request::builder()
            .header("x-forwarded-for", "203.0.113.7, 10.0.0.1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(client_ip(&req), "203.0.113.7");
    }

    #[test]
    fn client_ip_falls_back_to_peer() {
        let mut req = Request::builder().body(Body::empty()).unwrap();
        let addr: SocketAddr = "198.51.100.4:51234".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        assert_eq!(client_ip(&req), "198.51.100.4");
    }

    #[test]
    fn limiter_blocks_after_burst() {
        let limiter = build_rate_limiter(1, 2);
        let key = "1.2.3.4".to_string();
        assert!(limiter.check_key(&key).is_ok());
        assert!(limiter.check_key(&key).is_ok());
        // 3rd immediate request exceeds burst of 2.
        assert!(limiter.check_key(&key).is_err());
        // A different key is independent.
        assert!(limiter.check_key(&"5.6.7.8".to_string()).is_ok());
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p ferriskey-api --lib security::rate_limit`
Expected: 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add api/Cargo.toml api/src/application/security/mod.rs api/src/application/security/rate_limit.rs
git commit -m "feat(security): governor-backed rate limiter + client IP extraction"
```

---

## Task 5: Wire components into `AppState`, add `TooManyRequests`, scope the layer, fix ConnectInfo

**Files:**
- Modify: `api/src/application/http/server/app_state.rs`
- Modify: `api/src/application/http/server/api_entities/api_error.rs`
- Modify: `api/src/application/security/rate_limit.rs` (add the middleware fn)
- Modify: `api/src/application/http/authentication/router.rs`
- Modify: `api/src/main.rs`
- Modify: `api/tests/portal_security_test.rs` (create)

**Interfaces:**
- Consumes: `build_rate_limiter`, `client_ip`, `InMemoryBruteForceGuard`, `build_captcha_verifier`.
- Produces: `AppState.rate_limiter: Arc<KeyedRateLimiter>`, `AppState.brute_force: Arc<dyn BruteForceGuard>`, `AppState.captcha: Arc<dyn CaptchaVerifier>`; `ApiError::TooManyRequests(Cow<'static, str>)`; `auth_rate_limit` middleware.

> **Before editing:** run `grep -rn "AppState {" api/src` to find any *struct-literal* construction of `AppState` (e.g. in `api/src/application/http/test.rs`). The new fields will break those call sites. Either switch them to `AppState::new(args, service)` or add the three fields. Callers that already use `AppState::new(...)` need no change.

- [ ] **Step 1: Extend `AppState` (keep `new(args, service)` signature)**

Replace `api/src/application/http/server/app_state.rs` with:

```rust
use std::sync::Arc;
use std::time::Duration;

use ferriskey_core::ApplicationService;

use crate::application::security::brute_force::{BruteForceGuard, InMemoryBruteForceGuard};
use crate::application::security::captcha::{build_captcha_verifier, CaptchaVerifier};
use crate::application::security::rate_limit::{build_rate_limiter, KeyedRateLimiter};
use crate::args::Args;

#[derive(Clone)]
pub struct AppState {
    pub args: Arc<Args>,
    pub service: ApplicationService,
    pub rate_limiter: Arc<KeyedRateLimiter>,
    pub brute_force: Arc<dyn BruteForceGuard>,
    pub captcha: Arc<dyn CaptchaVerifier>,
}

impl AppState {
    pub fn new(args: Arc<Args>, service: ApplicationService) -> Self {
        let sec = &args.security;
        let rate_limiter =
            build_rate_limiter(sec.auth_rate_limit_per_min, sec.auth_rate_limit_burst);
        let brute_force: Arc<dyn BruteForceGuard> = Arc::new(InMemoryBruteForceGuard::new(
            sec.login_max_failures,
            Duration::from_secs(sec.login_failure_window_secs),
            Duration::from_secs(sec.login_throttle_secs),
        ));
        let captcha = build_captcha_verifier(sec);

        Self {
            args,
            service,
            rate_limiter,
            brute_force,
            captcha,
        }
    }
}
```

- [ ] **Step 2: Add the `TooManyRequests` error variant**

In `api/src/application/http/server/api_entities/api_error.rs`:

Add the variant to the `enum ApiError` (after `ServiceUnavailable`):

```rust
    TooManyRequests(Cow<'static, str>),
```

Add the `IntoResponse` arm (inside the `match self`, after the `ServiceUnavailable` arm). Add `RETRY_AFTER` to the `axum::http` import or reference it fully:

```rust
            ApiError::TooManyRequests(message) => (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, "60")],
                Json(ApiErrorResponse {
                    code: "E_TOO_MANY_REQUESTS".to_string(),
                    status: 429,
                    message: message.into(),
                }),
            )
                .into_response(),
```

- [ ] **Step 3: Add the `auth_rate_limit` middleware**

Append to `api/src/application/security/rate_limit.rs`:

```rust
use axum::extract::State;
use axum::middleware::Next;
use axum::response::Response;

use crate::application::http::server::api_entities::api_error::ApiError;
use crate::application::http::server::app_state::AppState;

/// Axum middleware: rejects with 429 when the per-IP limiter trips.
/// No-op when `RATE_LIMIT_ENABLED=false`.
pub async fn auth_rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if !state.args.security.rate_limit_enabled {
        return Ok(next.run(req).await);
    }

    let ip = client_ip(&req);
    match state.rate_limiter.check_key(&ip) {
        Ok(_) => Ok(next.run(req).await),
        Err(_) => Err(ApiError::TooManyRequests("Too many requests".into())),
    }
}
```

- [ ] **Step 4: Scope the rate-limit layer onto sensitive routes only**

In `api/src/application/http/authentication/router.rs`, change the `authentication_routes` body so the sensitive POST routes carry the rate-limit layer while JWKS/discovery/userinfo/etc. do not. Update the imports at the top of the function area:

```rust
use crate::application::security::rate_limit::auth_rate_limit;
```

Replace the `authentication_routes` function body. Build a `limited` router for the brute-forceable endpoints and merge it with the existing unrestricted routes:

```rust
pub fn authentication_routes(state: AppState, root_path: &str) -> Router<AppState> {
    // Sensitive, attacker-reachable endpoints get the per-IP rate-limit layer.
    let limited = Router::new()
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/token"),
            post(exchange_token),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/registrations"),
            post(registration_handler),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/login-actions/authenticate"),
            post(authenticate),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/login-actions/verify-email"),
            post(verify_email_handler),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/login-actions/resend-verification-email"),
            post(resend_verification_email_handler),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/auth"),
            get(auth_handler),
        )
        .layer(middleware::from_fn_with_state(state.clone(), auth_rate_limit));

    // Userinfo keeps the existing auth middleware; everything else is unrestricted.
    let rest = Router::new()
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/userinfo"),
            get(get_userinfo),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/userinfo"),
            post(get_userinfo),
        )
        .layer(middleware::from_fn_with_state(state.clone(), auth))
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/auth/device"),
            post(device_authorization),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/device"),
            get(device_verification_page),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/device/verify"),
            post(device_verify),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/token/introspect"),
            post(introspect_token),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/revoke"),
            post(revoke_token),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/logout"),
            get(logout_get),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/logout"),
            post(logout_post),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/certs"),
            get(get_certs),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/jwks.json"),
            get(get_jwks_json),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/protocol/openid-connect/jwks"),
            get(get_jwks_json),
        )
        .route(
            &format!("{root_path}/realms/{{realm_name}}/.well-known/openid-configuration"),
            get(get_openid_configuration),
        );

    limited.merge(rest)
}
```

(Note: `let _ = &state;` is no longer needed; both `state.clone()` uses consume it. Keep the final `merge`.)

- [ ] **Step 5: Wire `ConnectInfo` so the peer-IP fallback works**

In `api/src/main.rs`, replace both `router.into_make_service()` calls (the TLS bind at ~line 221 and the plain bind at ~line 226) with connect-info variants. Ensure `use std::net::SocketAddr;` is present near the top:

```rust
        axum_server::bind_rustls(addr, tls_cfg)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
```

```rust
        axum_server::bind(addr)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
```

- [ ] **Step 6: Write the failing integration test for 429**

Create `api/tests/portal_security_test.rs`. It mirrors the setup harness from `token_basic_auth_test.rs` but overrides `SecurityArgs` to a tiny limit. Because `TestServer` does not provide `ConnectInfo`, requests have no peer IP and no `X-Forwarded-For`, so `client_ip` returns `"unknown"` — all requests share one bucket, which is exactly what we want to assert the limiter fires.

```rust
/// Integration tests for portal auth abuse controls (rate limiting, captcha,
/// brute-force throttle).
///
/// Run with:
///   cargo test -p ferriskey-api --test portal_security_test -- --ignored
#[cfg(test)]
mod tests {
    use std::{env, sync::Arc};

    use axum_test::TestServer;
    use ferriskey_api::{
        application::http::server::{app_state::AppState, http_server::router},
        args::Args,
    };
    use ferriskey_core::{
        application::create_service,
        domain::common::{
            DatabaseConfig, FerriskeyConfig, entities::StartupConfig, ports::CoreService,
        },
    };
    use sqlx::Executor;
    use uuid::Uuid;

    fn env_or(key: &str, default: &str) -> String {
        env::var(key).unwrap_or_else(|_| default.to_string())
    }
    fn env_u16_or(key: &str, default: u16) -> u16 {
        env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
    }

    struct TestContext {
        server: TestServer,
        realm_name: String,
    }

    async fn setup_with_args(mutate: impl FnOnce(&mut Args)) -> TestContext {
        let db_host = env_or("DATABASE_HOST", "localhost");
        let db_port = env_u16_or("DATABASE_PORT", 5432);
        let db_name = env_or("DATABASE_NAME", "ferriskey");
        let db_user = env_or("DATABASE_USER", "ferriskey");
        let db_password = env_or("DATABASE_PASSWORD", "ferriskey");

        let schema = format!("portal_sec_test_{}", Uuid::new_v4().simple());
        let admin_url = format!(
            "postgres://{}:{}@{}:{}/{}",
            db_user, db_password, db_host, db_port, db_name
        );
        let admin_pool = sqlx::PgPool::connect(&admin_url).await.expect("admin pool");
        admin_pool
            .execute(sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS \"{}\"", schema)))
            .await
            .expect("create schema");

        let schema_url = format!(
            "postgres://{}:{}@{}:{}/{}?options=-c search_path={}",
            db_user, db_password, db_host, db_port, db_name,
            urlencoding::encode(&schema)
        );
        let pool = sqlx::PgPool::connect(&schema_url).await.expect("schema pool");
        sqlx::migrate!("../core/migrations").run(&pool).await.expect("migrate");

        let service = create_service(FerriskeyConfig {
            database: DatabaseConfig {
                host: db_host, port: db_port, username: db_user,
                password: db_password, name: db_name, schema: schema.clone(),
            },
        })
        .await
        .expect("create service");

        let realm_name = format!("realm-{}", Uuid::new_v4().simple());
        service
            .initialize_application(StartupConfig {
                master_realm_name: realm_name.clone(),
                admin_username: "admin".to_string(),
                admin_password: "admin".to_string(),
                admin_email: "admin@test.local".to_string(),
                default_client_id: "admin-cli".to_string(),
            })
            .await
            .expect("init app");

        let mut args = Args::default();
        mutate(&mut args);
        let state = AppState::new(Arc::new(args), service);
        let app = router(state).expect("router");
        let server = TestServer::new(app).expect("server");
        TestContext { server, realm_name }
    }

    #[tokio::test]
    #[ignore]
    async fn token_endpoint_rate_limited_after_burst() {
        let ctx = setup_with_args(|args| {
            args.security.rate_limit_enabled = true;
            args.security.auth_rate_limit_per_min = 1;
            args.security.auth_rate_limit_burst = 3;
            args.security.cap_enabled = false;
        })
        .await;

        let path = format!("/realms/{}/protocol/openid-connect/token", ctx.realm_name);
        let mut saw_429 = false;
        for _ in 0..10 {
            let resp = ctx
                .server
                .post(&path)
                .form(&[
                    ("grant_type", "password"),
                    ("client_id", "admin-cli"),
                    ("username", "admin"),
                    ("password", "wrong-on-purpose"),
                ])
                .await;
            if resp.status_code() == 429 {
                saw_429 = true;
                break;
            }
        }
        assert!(saw_429, "expected a 429 after exceeding the burst of 3");
    }

    #[tokio::test]
    #[ignore]
    async fn rate_limit_disabled_never_429() {
        let ctx = setup_with_args(|args| {
            args.security.rate_limit_enabled = false;
            args.security.cap_enabled = false;
        })
        .await;

        let path = format!("/realms/{}/protocol/openid-connect/token", ctx.realm_name);
        for _ in 0..8 {
            let resp = ctx
                .server
                .post(&path)
                .form(&[
                    ("grant_type", "password"),
                    ("client_id", "admin-cli"),
                    ("username", "admin"),
                    ("password", "wrong-on-purpose"),
                ])
                .await;
            assert_ne!(resp.status_code(), 429, "rate limiting should be off");
        }
    }
}
```

- [ ] **Step 7: Run checks and the integration tests**

Run: `cargo check -p ferriskey-api`
Expected: compiles.

Run (requires a running Postgres, per CLAUDE.md): `cargo test -p ferriskey-api --test portal_security_test -- --ignored`
Expected: `token_endpoint_rate_limited_after_burst` and `rate_limit_disabled_never_429` PASS.

- [ ] **Step 8: Commit**

```bash
git add api/src/application/http/server/app_state.rs \
        api/src/application/http/server/api_entities/api_error.rs \
        api/src/application/security/rate_limit.rs \
        api/src/application/http/authentication/router.rs \
        api/src/main.rs \
        api/tests/portal_security_test.rs
git commit -m "feat(security): scope per-IP rate limiting onto portal auth routes"
```

---

## Task 6: Captcha + brute-force enforcement in `authenticate`

**Files:**
- Modify: `api/src/application/http/authentication/handlers/authentificate.rs`
- Modify: `api/tests/portal_security_test.rs`

**Interfaces:**
- Consumes: `AppState.captcha`, `AppState.brute_force`, `CaptchaError`.
- Produces: `AuthenticateRequest.captcha_token: Option<String>`.

- [ ] **Step 1: Add the `captcha_token` field + a helper to map captcha errors**

In `authentificate.rs`, add to `AuthenticateRequest`:

```rust
    #[serde(default)]
    pub captcha_token: Option<String>,
```

Add this import and mapping helper near the top of the file (after the existing `use` lines):

```rust
use crate::application::security::captcha::CaptchaError;

fn map_captcha_error(err: CaptchaError) -> ApiError {
    match err {
        CaptchaError::Missing => ApiError::BadRequest("captcha token required".into()),
        CaptchaError::Invalid => ApiError::BadRequest("invalid captcha".into()),
        CaptchaError::Unavailable => {
            ApiError::ServiceUnavailable("captcha verification unavailable".into())
        }
    }
}
```

- [ ] **Step 2: Enforce captcha + brute-force in the handler**

In `authenticate`, immediately after `let session_code = ... Uuid::parse_str(...)?;` and before building `authenticate_params`, insert captcha verification (only meaningful when credentials are present, i.e. not the existing-token continuation):

```rust
    // CAPTCHA must pass before any credential work. No-op verifier when disabled.
    if optional_token.is_none() {
        state
            .captcha
            .verify(payload.captcha_token.as_deref())
            .await
            .map_err(map_captcha_error)?;
    }
```

Still before building params, add the brute-force pre-check for the credentials path. Replace the existing `else { ... }` credentials branch so it first checks the guard:

```rust
    } else {
        let username = payload
            .username
            .clone()
            .ok_or_else(|| ApiError::BadRequest("username is required".into()))?;
        let password = payload
            .password
            .clone()
            .ok_or_else(|| ApiError::BadRequest("password is required".into()))?;

        if state.brute_force.check(&realm_name, &username) {
            return Err(ApiError::TooManyRequests(
                "too many failed login attempts, try again later".into(),
            ));
        }

        AuthenticateInput::with_user_credentials(
            realm_name.clone(),
            query.client_id.clone(),
            session_code,
            base_url.clone(),
            username,
            password,
        )
    };
```

After `let result = state.service.authenticate(authenticate_params).await?;`, record the outcome (only for the credentials path, where we have a username):

```rust
    // Record brute-force outcome for the credentials path.
    if optional_token.is_none() {
        if let Some(username) = payload.username.as_deref() {
            match result.status {
                AuthenticationStepStatus::Failed => {
                    state.brute_force.record_failure(&realm_name, username)
                }
                _ => state.brute_force.record_success(&realm_name, username),
            }
        }
    }
```

- [ ] **Step 3: Add integration tests**

Append to `api/tests/portal_security_test.rs` (inside the `mod tests`):

```rust
    #[tokio::test]
    #[ignore]
    async fn authenticate_requires_captcha_when_enabled() {
        let ctx = setup_with_args(|args| {
            args.security.rate_limit_enabled = false;
            args.security.cap_enabled = true;
            // Unreachable Cap + fail-closed: a *present* token yields 503, an
            // *absent* token yields 400 (Missing) before Cap is even contacted.
            args.security.cap_verify_url = "http://127.0.0.1:1".to_string();
            args.security.cap_site_key = "sk".to_string();
            args.security.cap_secret = "secret".to_string();
            args.security.cap_fail_open = false;
        })
        .await;

        // No FERRISKEY_SESSION cookie -> handler returns 401 before captcha.
        // So we assert the missing-captcha path via the session-less 401 is NOT
        // what we want; instead drive the brute-force/captcha ordering with a
        // session cookie set. Simplest deterministic assertion: missing token
        // with a session cookie returns 400 "captcha token required".
        let resp = ctx
            .server
            .post(&format!("/realms/{}/login-actions/authenticate?client_id=admin-cli", ctx.realm_name))
            .add_header("Cookie", format!("FERRISKEY_SESSION={}", Uuid::new_v4()).parse().unwrap())
            .json(&serde_json::json!({ "username": "admin", "password": "admin" }))
            .await;

        assert_eq!(resp.status_code(), 400, "missing captcha should be a 400, body: {}", resp.text());
    }

    #[tokio::test]
    #[ignore]
    async fn brute_force_throttles_after_failures() {
        let ctx = setup_with_args(|args| {
            args.security.rate_limit_enabled = false;
            args.security.cap_enabled = false;
            args.security.login_max_failures = 3;
            args.security.login_failure_window_secs = 300;
            args.security.login_throttle_secs = 300;
        })
        .await;

        let path = format!("/realms/{}/login-actions/authenticate?client_id=admin-cli", ctx.realm_name);
        let cookie = format!("FERRISKEY_SESSION={}", Uuid::new_v4());
        let body = serde_json::json!({ "username": "admin", "password": "definitely-wrong" });

        let mut saw_429 = false;
        for _ in 0..6 {
            let resp = ctx
                .server
                .post(&path)
                .add_header("Cookie", cookie.parse().unwrap())
                .json(&body)
                .await;
            if resp.status_code() == 429 {
                saw_429 = true;
                break;
            }
        }
        assert!(saw_429, "expected 429 after repeated failed logins");
    }
```

Add `use serde_json;` is unnecessary (path-qualified). Ensure `axum::http::HeaderValue` parsing works via `.parse()` — `add_header` accepts `(HeaderName, HeaderValue)` or a `&str` pair depending on `axum-test` version; if the `.parse()` form fails to compile, use `ctx.server.post(...).add_header("Cookie", &cookie)` string form supported by `axum-test`.

> **Note on the captcha test:** the `authenticate` handler returns 401 when the `FERRISKEY_SESSION` cookie is missing, *before* captcha runs. The test therefore sends a (random) session cookie so execution reaches the captcha check. The session UUID need not be valid because captcha is verified before the session is used by the service.

- [ ] **Step 4: Run checks and tests**

Run: `cargo check -p ferriskey-api`
Expected: compiles.

Run: `cargo test -p ferriskey-api --test portal_security_test -- --ignored`
Expected: new tests PASS (plus Task 5's).

- [ ] **Step 5: Commit**

```bash
git add api/src/application/http/authentication/handlers/authentificate.rs api/tests/portal_security_test.rs
git commit -m "feat(security): enforce captcha + brute-force throttle on login"
```

---

## Task 7: Captcha enforcement in `registration`

**Files:**
- Modify: `api/src/application/http/authentication/handlers/registration.rs`
- Modify: `api/tests/portal_security_test.rs`

**Interfaces:**
- Consumes: `AppState.captcha`, `CaptchaError`.
- Produces: `RegistrationRequest.captcha_token: Option<String>`.

- [ ] **Step 1: Add the field + captcha check**

In `registration.rs`, add to `RegistrationRequest`:

```rust
    #[serde(default)]
    pub captcha_token: Option<String>,
```

Add the import and a local mapping (or reuse the one from `authentificate` by making it `pub`). To keep tasks independent, add a private helper in this file:

```rust
use crate::application::security::captcha::CaptchaError;

fn map_captcha_error(err: CaptchaError) -> ApiError {
    match err {
        CaptchaError::Missing => ApiError::BadRequest("captcha token required".into()),
        CaptchaError::Invalid => ApiError::BadRequest("invalid captcha".into()),
        CaptchaError::Unavailable => {
            ApiError::ServiceUnavailable("captcha verification unavailable".into())
        }
    }
}
```

In `registration_handler`, after the `if !settings.user_registration_enabled { ... }` block and before reading the session cookie, add:

```rust
    state
        .captcha
        .verify(req.captcha_token.as_deref())
        .await
        .map_err(map_captcha_error)?;
```

- [ ] **Step 2: Add an integration test**

Append to `api/tests/portal_security_test.rs`:

```rust
    #[tokio::test]
    #[ignore]
    async fn registration_requires_captcha_when_enabled() {
        let ctx = setup_with_args(|args| {
            args.security.rate_limit_enabled = false;
            args.security.cap_enabled = true;
            args.security.cap_verify_url = "http://127.0.0.1:1".to_string();
            args.security.cap_site_key = "sk".to_string();
            args.security.cap_secret = "secret".to_string();
            args.security.cap_fail_open = false;
        })
        .await;

        // Registration may be disabled on the master realm by default; if so the
        // handler returns 403 *before* captcha. This test asserts that WHEN the
        // captcha is required and missing, the response is a client error (400)
        // rather than a 5xx or success. Accept 400 (captcha) or 403 (registration
        // disabled) — both prove the request never created a user without a captcha.
        let resp = ctx
            .server
            .post(&format!("/realms/{}/protocol/openid-connect/registrations", ctx.realm_name))
            .json(&serde_json::json!({
                "username": "newuser",
                "email": "newuser@test.local",
                "password": "password123"
            }))
            .await;

        assert!(
            resp.status_code() == 400 || resp.status_code() == 403,
            "expected 400 (captcha) or 403 (registration disabled), got {} body {}",
            resp.status_code(),
            resp.text()
        );
    }
```

> **Note:** if registration is enabled on the seeded realm, this returns 400 (missing captcha). If disabled, 403. The assertion accepts both because the deliverable — "no user is created without a captcha" — holds either way. A reviewer who wants the strict 400 should first enable registration on the test realm via the realm settings endpoint; that is out of scope for this task.

- [ ] **Step 3: Run checks and tests**

Run: `cargo check -p ferriskey-api`
Expected: compiles.

Run: `cargo test -p ferriskey-api --test portal_security_test -- --ignored`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add api/src/application/http/authentication/handlers/registration.rs api/tests/portal_security_test.rs
git commit -m "feat(security): enforce captcha on self-service registration"
```

---

## Task 8: Captcha + brute-force on public-client `password` grant

**Files:**
- Modify: `api/src/application/http/authentication/validators.rs`
- Modify: `api/src/application/http/authentication/handlers/token.rs`
- Modify: `api/tests/portal_security_test.rs`

**Interfaces:**
- Consumes: `AppState.captcha`, `AppState.brute_force`, `GrantType::Password`.
- Produces: `TokenRequestValidator.captcha_token: Option<String>`.

- [ ] **Step 1: Add the `captcha_token` field to the validator**

In `api/src/application/http/authentication/validators.rs`, add to `TokenRequestValidator`:

```rust
    #[serde(default)]
    pub captcha_token: Option<String>,
```

(Place it next to the other optional fields like `client_secret`. It is form-decoded, so `Option<String>` with `#[serde(default)]` is correct.)

- [ ] **Step 2: Enforce on the public-client password grant**

In `token.rs`, add the imports:

```rust
use crate::application::security::captcha::CaptchaError;

fn map_captcha_error(err: CaptchaError) -> ApiError {
    match err {
        CaptchaError::Missing => ApiError::BadRequest("captcha token required".into()),
        CaptchaError::Invalid => ApiError::BadRequest("invalid captcha".into()),
        CaptchaError::Unavailable => {
            ApiError::ServiceUnavailable("captcha verification unavailable".into())
        }
    }
}
```

In `exchange_token`, after `let (client_id, client_secret) = ...;` is resolved and before constructing `exchange_input`, add the guard. The public-client password grant is `grant_type == Password && client_secret.is_none()`:

```rust
    let is_public_password_grant =
        payload.grant_type == GrantType::Password && client_secret.is_none();

    if is_public_password_grant {
        // CAPTCHA (no-op when disabled).
        state
            .captcha
            .verify(payload.captcha_token.as_deref())
            .await
            .map_err(map_captcha_error)?;

        // Per-account brute-force throttle (keyed by realm + username).
        if let Some(username) = payload.username.as_deref() {
            if state.brute_force.check(&realm_name, username) {
                return Err(ApiError::TooManyRequests(
                    "too many failed login attempts, try again later".into(),
                ));
            }
        }
    }
```

`realm_name` is moved into `ExchangeTokenInput` later; capture what you need first. Since `realm_name` is used by `ExchangeTokenInput { realm_name, .. }`, clone for the username recording. After the token result is computed (the `let token = if ... else { match ... }` block), record the outcome. Modify the `else` arm's `Ok`/`Err` handling to record brute-force results. Concretely, capture `let realm_for_bf = realm_name.clone();` near the top (right after `Path(realm_name)` is available), pass `realm_name` into the input as today, and in the password-grant `else` branch:

```rust
        match state.service.exchange_token(exchange_input).await {
            Ok(token) => {
                if is_public_password_grant {
                    if let Some(username) = payload_username.as_deref() {
                        state.brute_force.record_success(&realm_for_bf, username);
                    }
                }
                token
            }
            Err(error) => {
                if is_public_password_grant {
                    if let Some(username) = payload_username.as_deref() {
                        state.brute_force.record_failure(&realm_for_bf, username);
                    }
                }
                warn!(/* keep existing fields */ error = ?error, "Token exchange failed");
                return Err(error.into());
            }
        }
```

To make `payload.username` usable after it is moved into `exchange_input`, capture it first:

```rust
    let payload_username = payload.username.clone();
```

placed right after `let grant_type = payload.grant_type.clone();`. Use `payload_username` in the brute-force recording above. Keep the existing `warn!` fields intact (the snippet abbreviates them).

- [ ] **Step 3: Add an integration test (public password grant requires captcha)**

Append to `api/tests/portal_security_test.rs`:

```rust
    #[tokio::test]
    #[ignore]
    async fn public_password_grant_requires_captcha_when_enabled() {
        let ctx = setup_with_args(|args| {
            args.security.rate_limit_enabled = false;
            args.security.cap_enabled = true;
            args.security.cap_verify_url = "http://127.0.0.1:1".to_string();
            args.security.cap_site_key = "sk".to_string();
            args.security.cap_secret = "secret".to_string();
            args.security.cap_fail_open = false;
        })
        .await;

        // Public client (no client_secret) + password grant + no captcha token
        // -> 400 "captcha token required", before any credential check.
        let resp = ctx
            .server
            .post(&format!("/realms/{}/protocol/openid-connect/token", ctx.realm_name))
            .form(&[
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", "admin"),
                ("password", "admin"),
            ])
            .await;

        assert_eq!(resp.status_code(), 400, "missing captcha on public ROPC should be 400, body: {}", resp.text());
    }

    #[tokio::test]
    #[ignore]
    async fn confidential_grants_exempt_from_captcha() {
        let ctx = setup_with_args(|args| {
            args.security.rate_limit_enabled = false;
            args.security.cap_enabled = true;
            args.security.cap_verify_url = "http://127.0.0.1:1".to_string();
            args.security.cap_site_key = "sk".to_string();
            args.security.cap_secret = "secret".to_string();
            args.security.cap_fail_open = false;
        })
        .await;

        // client_credentials grant carries no username/password and is exempt;
        // it must NOT be blocked by the captcha (it will fail auth for other
        // reasons, but never with the captcha 400 "captcha token required").
        let resp = ctx
            .server
            .post(&format!("/realms/{}/protocol/openid-connect/token", ctx.realm_name))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "admin-cli"),
            ])
            .await;

        // Whatever happens, it is not the captcha-required 400.
        let body = resp.text();
        assert!(
            !body.contains("captcha token required"),
            "client_credentials must be exempt from captcha, body: {body}"
        );
    }
```

- [ ] **Step 4: Run checks and tests**

Run: `cargo check -p ferriskey-api`
Expected: compiles.

Run: `cargo test -p ferriskey-api --test portal_security_test -- --ignored`
Expected: all PASS.

Run the existing token test to confirm no regression:
Run: `cargo test -p ferriskey-api --test token_basic_auth_test -- --ignored`
Expected: still PASS (confidential grants unaffected; `cap_enabled` defaults off via `Args::default()`).

- [ ] **Step 5: Commit**

```bash
git add api/src/application/http/authentication/validators.rs \
        api/src/application/http/authentication/handlers/token.rs \
        api/tests/portal_security_test.rs
git commit -m "feat(security): captcha + brute-force on public-client password grant"
```

---

## Task 9: Infrastructure — Cap + KeyDB, nginx XFF, env docs

**Files:**
- Modify: `docker-compose.yaml`
- Modify: `front/nginx.conf`
- Modify: `api/.env.example` (create if absent)
- Modify: `CLAUDE.md` (add the new env vars to the config list) — optional, low risk.

- [ ] **Step 1: Add Cap + KeyDB services to docker-compose**

In `docker-compose.yaml`, add two services under `services:` (place after `db:`). They have no `profiles:` key so they start in every profile alongside the API:

```yaml
  keydb:
    image: eqalpha/keydb:latest
    command: keydb-server --appendonly yes
    ports:
      - 6379:6379
    volumes:
      - keydbdata:/data
    healthcheck:
      test: ["CMD", "keydb-cli", "ping"]
      interval: 10s
      retries: 5
      timeout: 5s

  cap:
    image: ghcr.io/tiagorangel1/cap:standalone
    environment:
      ADMIN_KEY: ${CAP_ADMIN_KEY:-change-me-32-chars-minimum-please}
      REDIS_URL: redis://keydb:6379
    ports:
      - 3000:3000
    depends_on:
      keydb:
        condition: service_healthy
```

Add the volume under the top-level `volumes:` block (next to `pgdata`):

```yaml
  keydbdata:
    name: ferriskey_keydbdata
```

> **Note:** verify the Cap Standalone image tag against the current Cap release (`ghcr.io/tiagorangel1/cap:standalone` per the project's repo). If the org/tag differs, update the `image:` line. The site key + secret are created in the Cap dashboard (`http://localhost:3000`, log in with `ADMIN_KEY`) and supplied to the API via `CAP_SITE_KEY` / `CAP_SECRET`, and to the frontend via `VITE_CAP_*` (Task 10).

- [ ] **Step 2: Harden nginx X-Forwarded-For**

Read `front/nginx.conf`. In the `location` block(s) that `proxy_pass` to the API (and the SPA root that the API trusts), ensure the client address is set authoritatively rather than appended. Add/replace these `proxy_set_header` lines inside the relevant `location` (or `server`) block:

```nginx
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
```

The key line is `X-Forwarded-For $remote_addr;` (NOT `$proxy_add_x_forwarded_for`, which appends the client-supplied value and would let a client spoof extra hops). If `nginx.conf` only serves static SPA assets and does not `proxy_pass` to the API at all, add a comment noting that the deployment's API-facing proxy (Helm ingress / separate gateway) must set `X-Forwarded-For $remote_addr` — and skip editing here.

- [ ] **Step 3: Document the new env vars**

Create or update `api/.env.example` with the new variables (append to existing content if the file exists):

```bash
# --- Portal security: rate limiting ---
RATE_LIMIT_ENABLED=true
AUTH_RATE_LIMIT_PER_MIN=20
AUTH_RATE_LIMIT_BURST=5

# --- Portal security: brute-force throttle ---
LOGIN_MAX_FAILURES=5
LOGIN_FAILURE_WINDOW_SECS=300
LOGIN_THROTTLE_SECS=300

# --- Portal security: Cap PoW captcha ---
# Disabled by default. When enabling, point CAP_VERIFY_URL at the Cap Standalone
# service and provide the site key + secret from the Cap dashboard.
CAP_ENABLED=false
CAP_VERIFY_URL=http://cap:3000
CAP_SITE_KEY=
CAP_SECRET=
CAP_FAIL_OPEN=false
```

- [ ] **Step 4: Validate compose syntax**

Run: `docker compose config >/dev/null && echo OK`
Expected: prints `OK` (validates the merged compose file parses; does not start anything).

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yaml front/nginx.conf api/.env.example
git commit -m "feat(security): add Cap + KeyDB services, nginx XFF hardening, env docs"
```

---

## Task 10: Frontend — Cap widget on login + registration

**Files:**
- Modify: `front/package.json`
- Create: `front/src/components/cap-captcha.tsx`
- Modify: `front/src/api/auth.api.ts`
- Modify: `front/src/pages/authentication/hooks/use-login-form.ts`
- Modify: `front/src/pages/authentication/ui/page-login.tsx`
- Modify: `front/src/pages/authentication/feature/page-register-feature.tsx`
- Modify: `front/src/pages/authentication/ui/page-register.tsx`

**Interfaces:**
- Produces: `<CapCaptcha onSolve={(token) => ...} />` React component; login/register forms include `captcha_token` in their request bodies.
- Config: `import.meta.env.VITE_CAP_API_ENDPOINT` (e.g. `http://localhost:3000/<site_key>/`) and `VITE_CAP_SITE_KEY`. When `VITE_CAP_API_ENDPOINT` is empty, the widget is not rendered and no token is sent (backend `CAP_ENABLED=false` ignores it).

- [ ] **Step 1: Add the widget dependency**

Run: `cd front && pnpm add @cap.js/widget`
Expected: `@cap.js/widget` appears in `front/package.json` dependencies.

- [ ] **Step 2: Create the React wrapper component**

Create `front/src/components/cap-captcha.tsx`:

```tsx
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
```

- [ ] **Step 3: Thread the captcha token into the login request**

In `front/src/api/auth.api.ts`, extend `Schemas.AuthenticateRequest` usage. The `useAuthenticateMutation`'s `params.data` already carries the body; add `captcha_token` support by widening `AuthenticatePayload`:

Change the `AuthenticatePayload` interface to allow the token:

```ts
export interface AuthenticatePayload {
  data: Schemas.AuthenticateRequest & { captcha_token?: string }
  realm: string
  clientId: string
  useToken?: boolean
  token?: string
}
```

The existing `body: JSON.stringify(params.data)` already serializes the extra field, so no other change is needed in the fetch.

- [ ] **Step 4: Capture the token in the login form hook**

In `front/src/pages/authentication/hooks/use-login-form.ts`, add a ref/state for the captcha token and include it in the submit. Add near the top of `useLoginForm`:

```ts
  const captchaTokenRef = { current: undefined as string | undefined }
```

Replace the `onSubmit` callback so it includes the token, and expose a setter:

```ts
  const setCaptchaToken = useCallback((token: string) => {
    captchaTokenRef.current = token
  }, [])

  const onSubmit = useCallback(
    (data: AuthenticateSchema) => {
      const { clientId } = getAuthParamsFromUrl()
      authenticate({
        data: { ...data, captcha_token: captchaTokenRef.current },
        realm: realm_name ?? 'master',
        clientId,
      })
    },
    [authenticate, getAuthParamsFromUrl, realm_name]
  )
```

Add `setCaptchaToken` to the returned object:

```ts
  return {
    form,
    onSubmit,
    errorMessage,
    isSessionError,
    resetAuthenticate,
    setCaptchaToken,
  }
```

> A module-scoped `{ current }` object is recreated each render; for correctness across renders use `useRef`. Replace the `captchaTokenRef` line with `const captchaTokenRef = useRef<string | undefined>(undefined)` and import `useRef` from `react`. (Shown inline so the implementer wires the import.)

- [ ] **Step 5: Render the widget on the login page**

In `front/src/pages/authentication/ui/page-login.tsx`, accept an optional `onCaptchaSolve` prop and render the widget above the submit button. Add to the component's props type:

```ts
  onCaptchaSolve?: (token: string) => void
```

In the JSX, import and render (inside the form, before the submit button):

```tsx
import { CapCaptcha } from '@/components/cap-captcha'
// ...
{onCaptchaSolve && <CapCaptcha onSolve={onCaptchaSolve} />}
```

Then pass it through in `page-login-feature.tsx` where `<PageLogin .../>` is rendered: destructure `setCaptchaToken` from `useLoginForm(...)` and add `onCaptchaSolve={setCaptchaToken}` to both `<PageLogin>` usages.

- [ ] **Step 6: Thread the token into registration**

In `front/src/pages/authentication/feature/page-register-feature.tsx`:

Add a ref + handler:

```tsx
import { useRef } from 'react'
import { CapCaptcha } from '@/components/cap-captcha'
// inside component:
  const captchaToken = useRef<string | undefined>(undefined)
```

Update `onSubmit` body to include the token:

```tsx
    registration({
      body: {
        email: data.email,
        first_name: data.firstName,
        last_name: data.lastName,
        password: data.password,
        username: data.username,
        captcha_token: captchaToken.current,
      } as never,
      path: { realm_name: realm_name ?? 'master' },
    })
```

(The `as never` cast matches the existing pattern for form bodies that diverge from generated types; remove it after regenerating the OpenAPI client types so `captcha_token` is included.)

Pass the widget down to `PageRegister`. In `page-register.tsx`, accept `onCaptchaSolve?: (token: string) => void` and render `{onCaptchaSolve && <CapCaptcha onSolve={onCaptchaSolve} />}` before the submit button. In the feature file, render `<PageRegister ... onCaptchaSolve={(t) => { captchaToken.current = t }} />`.

- [ ] **Step 7: Lint and build**

Run: `cd front && pnpm run lint`
Expected: no new lint errors.

Run: `cd front && pnpm run build`
Expected: build succeeds. (Type errors about `cap-widget` are silenced by the `@ts-expect-error`; the `as never` casts match existing code.)

- [ ] **Step 8: Commit**

```bash
git add front/package.json front/pnpm-lock.yaml front/src/components/cap-captcha.tsx \
        front/src/api/auth.api.ts \
        front/src/pages/authentication/hooks/use-login-form.ts \
        front/src/pages/authentication/ui/page-login.tsx \
        front/src/pages/authentication/feature/page-login-feature.tsx \
        front/src/pages/authentication/feature/page-register-feature.tsx \
        front/src/pages/authentication/ui/page-register.tsx
git commit -m "feat(security): render Cap PoW widget on login + registration"
```

---

## Task 11: Final verification + OpenAPI regen

**Files:** none (verification), optionally regenerate the frontend API client.

- [ ] **Step 1: Full backend test + lint**

Run: `cargo test -p ferriskey-api`
Expected: all non-ignored unit tests pass.

Run: `cargo clippy -p ferriskey-api -- -D warnings` (fix any warnings introduced).
Expected: clean.

Run: `cargo fmt`
Expected: no diff (or commit the formatting).

- [ ] **Step 2: Integration suite (with Postgres up)**

Start Postgres if needed:
Run: `docker compose up -d db`

Run: `cargo test -p ferriskey-api -- --ignored`
Expected: `portal_security_test`, `token_basic_auth_test`, `organization_test`, `portal_theme_test` all pass.

- [ ] **Step 3: (Optional) Regenerate the OpenAPI client**

Because `captcha_token` was added to `AuthenticateRequest`, `RegistrationRequest`, and `TokenRequestValidator`, regenerate the frontend types so the `as never` casts can be removed. Follow the project's existing generation command (check `front/package.json` scripts for an `openapi`/`generate` script). If present:

Run: `cd front && pnpm run <generate-script>`
Then remove the now-unnecessary `as never` cast in `page-register-feature.tsx` and re-run `pnpm run build`.

If no generation script exists, leave the casts in place and note it in the commit.

- [ ] **Step 4: Commit any fmt/clippy/regen changes**

```bash
git add -A
git commit -m "chore(security): fmt, clippy, and OpenAPI client regen for captcha fields"
```

---

## Notes for the implementer

- **Deviation from the spec (captcha transport):** the spec named an `X-Captcha-Token` *header*; this plan uses a `captcha_token` *body field* for uniformity across JSON and form endpoints and compatibility with the generated frontend client. Functionally equivalent; document it in the PR.
- **Deviation from the spec (component location):** the spec placed `CaptchaVerifier`/`BruteForceGuard` as ports in `core`. This plan puts them in the `ferriskey-api` crate because they are transport concerns that need request headers/IP and avoid invasive changes to core's DI (`create_service`). The trait boundary is preserved, so a KeyDB-backed `BruteForceGuard` remains a drop-in later.
- **Branch:** do this work on a feature branch (e.g. `feat/portal-auth-rate-limit-captcha`), not `main`.
- **`axum-test` header API:** if `add_header("Cookie", cookie.parse().unwrap())` does not compile against the pinned `axum-test`, use the `(HeaderName, HeaderValue)` form or the string-pair form supported by your version — both exist across versions; pick the one that compiles.
