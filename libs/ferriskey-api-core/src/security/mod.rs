pub mod brute_force;
pub mod captcha;
pub mod credential_failure;
pub mod rate_limit;

use std::sync::Arc;
use std::time::Duration;

use brute_force::BruteForceGuard;
use rate_limit::KeyedRateLimiter;

/// Interval between background eviction sweeps of the in-memory abuse-control maps.
const REAPER_INTERVAL: Duration = Duration::from_secs(60);

/// Spawn a background task that periodically evicts stale entries from the
/// in-memory brute-force guard and the rate limiter, bounding their memory use
/// under username/IP probing. Single-instance only; a KeyDB-backed impl would
/// handle this via key TTLs instead.
pub fn spawn_security_reaper(
    brute_force: Arc<dyn BruteForceGuard>,
    rate_limiter: Arc<KeyedRateLimiter>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REAPER_INTERVAL);
        // Skip the immediate first tick.
        interval.tick().await;
        loop {
            interval.tick().await;
            brute_force.sweep();
            rate_limiter.retain_recent();
        }
    });
}
