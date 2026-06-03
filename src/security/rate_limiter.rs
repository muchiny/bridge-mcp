//! Rate limiting using Token Bucket algorithm
//!
//! Provides per-host rate limiting to prevent abuse.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Error returned when rate limit is exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Rate limit exceeded")]
pub struct RateLimitExceeded;

/// Token bucket for a single host
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
}

impl TokenBucket {
    fn new(tokens_per_second: u32) -> Self {
        let max = f64::from(tokens_per_second);
        Self {
            tokens: max,
            last_update: Instant::now(),
            max_tokens: max,
            refill_rate: max,
        }
    }

    fn try_consume(&mut self) -> Result<(), RateLimitExceeded> {
        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = elapsed
            .mul_add(self.refill_rate, self.tokens)
            .min(self.max_tokens);
        self.last_update = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(RateLimitExceeded)
        }
    }
}

/// Rate limiter with per-host token buckets
///
/// # Examples
///
/// ```
/// use bridge_mcp::security::RateLimiter;
///
/// // Allow 5 requests per second per host
/// let limiter = RateLimiter::new(5);
/// assert!(limiter.is_enabled());
///
/// // Each host has its own token bucket
/// assert!(limiter.check("server-a").is_ok());
/// assert!(limiter.check("server-b").is_ok());
///
/// // Disabled limiter (0 = unlimited)
/// let unlimited = RateLimiter::new(0);
/// assert!(!unlimited.is_enabled());
/// assert!(unlimited.check("any-host").is_ok());
/// ```
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    tokens_per_second: u32,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    ///
    /// * `tokens_per_second` - Maximum requests per second per host (0 = disabled)
    #[must_use]
    pub fn new(tokens_per_second: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            tokens_per_second,
        }
    }

    /// Check if a request is allowed for the given host
    ///
    /// Returns `Ok(())` if the request is allowed, or `Err(RateLimitExceeded)` if not.
    ///
    /// # Arguments
    ///
    /// * `host` - The host identifier to check rate limit for
    ///
    /// # Errors
    ///
    /// Returns `Err(RateLimitExceeded)` if the rate limit for this host
    /// has been exceeded.
    pub fn check(&self, host: &str) -> Result<(), RateLimitExceeded> {
        // If rate limiting is disabled, always allow
        if self.tokens_per_second == 0 {
            return Ok(());
        }

        self.buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(host.to_string())
            .or_insert_with(|| TokenBucket::new(self.tokens_per_second))
            .try_consume()
    }

    /// Check if rate limiting is enabled
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.tokens_per_second > 0
    }

    /// Get the configured rate limit
    #[must_use]
    pub const fn rate_limit(&self) -> u32 {
        self.tokens_per_second
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread::{self, sleep};
    use std::time::Duration;

    #[test]
    fn test_disabled_rate_limiter() {
        let limiter = RateLimiter::new(0);
        assert!(!limiter.is_enabled());

        // Should always succeed when disabled
        for _ in 0..100 {
            assert!(limiter.check("host1").is_ok());
        }
    }

    #[test]
    fn test_rate_limit_exceeded() {
        let limiter = RateLimiter::new(2); // 2 requests per second
        assert!(limiter.is_enabled());

        // First 2 should succeed (initial tokens)
        assert!(limiter.check("host1").is_ok());
        assert!(limiter.check("host1").is_ok());

        // Third should fail (no tokens left)
        assert!(limiter.check("host1").is_err());
    }

    #[test]
    fn test_token_refill() {
        let limiter = RateLimiter::new(10); // 10 requests per second

        // Exhaust all tokens
        for _ in 0..10 {
            let _ = limiter.check("host1");
        }

        // Should fail now
        assert!(limiter.check("host1").is_err());

        // Wait for token refill (at least 100ms for 1 token at 10/s)
        sleep(Duration::from_millis(150));

        // Should succeed after refill
        assert!(limiter.check("host1").is_ok());
    }

    #[test]
    fn test_per_host_isolation() {
        let limiter = RateLimiter::new(1); // 1 request per second

        // host1 uses its token
        assert!(limiter.check("host1").is_ok());
        assert!(limiter.check("host1").is_err());

        // host2 should still have its token
        assert!(limiter.check("host2").is_ok());
        assert!(limiter.check("host2").is_err());
    }

    #[test]
    fn test_rate_limit_error_display() {
        let err = RateLimitExceeded;
        assert_eq!(format!("{err}"), "Rate limit exceeded");
    }

    // ============== Additional Tests ==============

    #[test]
    fn test_rate_limit_getter() {
        let limiter = RateLimiter::new(100);
        assert_eq!(limiter.rate_limit(), 100);
    }

    #[test]
    fn test_rate_limit_error_debug() {
        let err = RateLimitExceeded;
        let debug = format!("{err:?}");
        assert!(debug.contains("RateLimitExceeded"));
    }

    #[test]
    fn test_rate_limit_error_clone() {
        let err = RateLimitExceeded;
        let cloned = err;
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_rate_limit_error_eq() {
        let err1 = RateLimitExceeded;
        let err2 = RateLimitExceeded;
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_rate_limit_error_is_error() {
        let err: &dyn std::error::Error = &RateLimitExceeded;
        assert!(err.to_string().contains("Rate limit"));
    }

    #[test]
    fn test_high_rate_limit() {
        let limiter = RateLimiter::new(1000); // 1000 per second
        assert!(limiter.is_enabled());

        // Should allow many requests quickly
        for _ in 0..500 {
            assert!(limiter.check("host1").is_ok());
        }
    }

    #[test]
    fn test_single_token_rate_limit() {
        let limiter = RateLimiter::new(1); // 1 per second

        assert!(limiter.check("host1").is_ok());
        assert!(limiter.check("host1").is_err());

        // Wait for refill
        sleep(Duration::from_millis(1100));
        assert!(limiter.check("host1").is_ok());
    }

    #[test]
    fn test_many_hosts() {
        let limiter = RateLimiter::new(1);

        // Each host gets its own bucket
        for i in 0..100 {
            let host = format!("host{i}");
            assert!(limiter.check(&host).is_ok());
        }
    }

    #[test]
    fn test_empty_host_name() {
        let limiter = RateLimiter::new(1);
        assert!(limiter.check("").is_ok());
        assert!(limiter.check("").is_err());
    }

    #[test]
    fn test_unicode_host_name() {
        let limiter = RateLimiter::new(1);
        assert!(limiter.check("サーバー").is_ok());
        assert!(limiter.check("サーバー").is_err());
    }

    #[test]
    fn test_partial_refill() {
        let limiter = RateLimiter::new(10); // 10 per second

        // Exhaust all tokens
        for _ in 0..10 {
            let _ = limiter.check("host1");
        }
        assert!(limiter.check("host1").is_err());

        // Wait for partial refill (5 tokens)
        sleep(Duration::from_millis(550));

        // Should get about 5 tokens back
        let mut success_count = 0;
        for _ in 0..10 {
            if limiter.check("host1").is_ok() {
                success_count += 1;
            }
        }
        assert!((4..=7).contains(&success_count));
    }

    #[test]
    fn test_tokens_capped_at_max() {
        let limiter = RateLimiter::new(5);

        // Use one token
        assert!(limiter.check("host1").is_ok());

        // Wait long enough for many tokens to accumulate
        sleep(Duration::from_millis(1000));

        // Should be capped at 5 tokens, not more
        let mut success_count = 0;
        for _ in 0..10 {
            if limiter.check("host1").is_ok() {
                success_count += 1;
            }
        }
        assert_eq!(success_count, 5);
    }

    #[test]
    fn test_concurrent_access() {
        let limiter = Arc::new(RateLimiter::new(100));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let lim = Arc::clone(&limiter);
                thread::spawn(move || {
                    let host = format!("host{i}");
                    for _ in 0..50 {
                        let _ = lim.check(&host);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_concurrent_same_host() {
        let limiter = Arc::new(RateLimiter::new(100));
        let success_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let lim = Arc::clone(&limiter);
                let count = Arc::clone(&success_count);
                thread::spawn(move || {
                    for _ in 0..50 {
                        if lim.check("shared-host").is_ok() {
                            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Total successes should be at most the token count (100) plus a small
        // margin for tokens refilled during test execution (100 tokens/sec).
        let total = success_count.load(std::sync::atomic::Ordering::Relaxed);
        assert!(total <= 110, "expected at most ~100 successes, got {total}");
    }

    #[test]
    fn test_rate_limit_max_value() {
        let limiter = RateLimiter::new(u32::MAX);
        assert!(limiter.is_enabled());
        assert_eq!(limiter.rate_limit(), u32::MAX);

        // Should still work with max value
        assert!(limiter.check("host1").is_ok());
    }
}
