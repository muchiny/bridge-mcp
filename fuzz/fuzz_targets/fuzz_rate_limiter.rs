#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::RateLimiter;

fuzz_target!(|data: (u32, &str)| {
    let (tokens_per_sec, host) = data;

    // Create rate limiter (0 = disabled, so use at least 1)
    let limiter = RateLimiter::new(tokens_per_sec);

    // Perform multiple checks
    for _ in 0..100 {
        let _ = limiter.check(host);
    }

    // Invariants:
    // 1. Should never panic
    // 2. Should handle empty host names
    // 3. Should handle very high token rates
});
