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
