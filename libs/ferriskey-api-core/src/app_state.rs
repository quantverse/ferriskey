use std::sync::Arc;
use std::time::Duration;

use ferriskey_core::ApplicationService;

use crate::args::Args;
use crate::cors::{RealmOriginCache, WEB_ORIGIN_CACHE_TTL};
use crate::security::brute_force::{BruteForceGuard, InMemoryBruteForceGuard};
use crate::security::captcha::{CaptchaVerifier, build_captcha_verifier};
use crate::security::rate_limit::{KeyedRateLimiter, build_rate_limiter};

#[derive(Clone)]
pub struct AppState {
    pub args: Arc<Args>,
    pub service: ApplicationService,
    pub web_origin_cache: Arc<RealmOriginCache>,
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
            web_origin_cache: Arc::new(RealmOriginCache::new(WEB_ORIGIN_CACHE_TTL)),
            rate_limiter,
            brute_force,
            captcha,
        }
    }
}
