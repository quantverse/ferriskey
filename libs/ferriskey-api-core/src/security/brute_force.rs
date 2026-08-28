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
    /// Evict entries that are no longer active (throttle expired AND failure
    /// window elapsed). Called periodically so the map cannot grow without
    /// bound under username/IP probing.
    fn sweep(&self);
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

    fn sweep(&self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
            // Still actively throttled — must keep.
            let actively_throttled = entry.throttled_until.is_some_and(|until| now < until);
            // Failure window still open — could still accumulate; keep.
            let window_open = now.duration_since(entry.window_start) <= self.window;
            actively_throttled || window_open
        });
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
    fn sweep_evicts_stale_entries() {
        // window=0 and throttle=0: a recorded entry becomes stale almost immediately.
        let g = InMemoryBruteForceGuard::new(1, Duration::from_secs(0), Duration::from_secs(0));
        g.record_failure("master", "ghost");
        assert_eq!(g.entries.len(), 1);
        // Advance past window_start / throttled_until.
        std::thread::sleep(Duration::from_millis(5));
        g.sweep();
        assert_eq!(g.entries.len(), 0, "stale entry should be evicted");
    }

    #[test]
    fn sweep_keeps_actively_throttled_entries() {
        let g = InMemoryBruteForceGuard::new(1, Duration::from_secs(300), Duration::from_secs(300));
        g.record_failure("master", "alice"); // throttled for 300s
        g.sweep();
        assert_eq!(g.entries.len(), 1, "active throttle must be retained");
        assert!(g.check("master", "alice"));
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
