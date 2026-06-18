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
