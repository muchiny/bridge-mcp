use std::future::Future;
use std::time::Duration;

use tokio::time::sleep;
use tracing::{debug, warn};

use crate::error::BridgeError;

/// Configuration for retry behavior
///
/// # Examples
///
/// ```
/// use bridge_mcp::ssh::RetryConfig;
///
/// // Default: 3 attempts, 100ms initial delay, exponential backoff
/// let config = RetryConfig::default();
/// assert_eq!(config.max_attempts, 3);
///
/// // No retries (single attempt)
/// let no_retry = RetryConfig::no_retry();
/// assert_eq!(no_retry.max_attempts, 1);
///
/// // Custom retry count
/// let custom = RetryConfig::with_max_attempts(5);
/// assert_eq!(custom.max_attempts, 5);
/// ```
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay between retries
    pub initial_delay_ms: u64,
    /// Maximum delay between retries
    pub max_delay_ms: u64,
    /// Multiplier for exponential backoff
    pub backoff_multiplier: f64,
    /// Add random jitter to delays (0.0 to 1.0)
    pub jitter: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
            jitter: 0.1,
        }
    }
}

impl RetryConfig {
    /// Create a config for no retries
    #[must_use]
    pub fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            ..Default::default()
        }
    }

    /// Create a config with specified max attempts
    #[must_use]
    pub fn with_max_attempts(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            ..Default::default()
        }
    }

    /// Calculate delay for a given attempt number (0-indexed)
    #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        // Safe: attempt is at least 1, so exponent is non-negative
        let exponent = attempt.saturating_sub(1);
        // Safe: initial_delay_ms is typically small (< 2^52), so no precision loss in practice
        #[expect(clippy::cast_precision_loss)]
        let base_delay = (self.initial_delay_ms as f64)
            * self
                .backoff_multiplier
                .powi(i32::try_from(exponent).unwrap_or(i32::MAX));

        #[expect(clippy::cast_precision_loss)]
        let capped_delay = base_delay.min(self.max_delay_ms as f64);

        // Add jitter
        let jitter_range = capped_delay * self.jitter;
        let jitter = if jitter_range > 0.0 {
            rand_simple().mul_add(2.0, -1.0) * jitter_range
        } else {
            0.0
        };

        // Ensure final delay stays within [0, max_delay_ms]
        #[expect(clippy::cast_precision_loss)]
        let final_delay = (capped_delay + jitter).clamp(0.0, self.max_delay_ms as f64);

        Duration::from_millis(final_delay as u64)
    }
}

/// Simple pseudo-random number generator (0.0 to 1.0)
/// Using a basic approach to avoid adding rand as a dependency
fn rand_simple() -> f64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (f64::from(nanos) / f64::from(u32::MAX)).fract()
}

/// Check if an error is retryable
///
/// `BridgeError::Cancelled` is explicitly non-retryable: a cancellation
/// signal from the MCP client via `notifications/cancelled` must stop the
/// operation immediately. Retrying would defeat the purpose of the cancel
/// and could spin forever if the client re-sends the same request.
///
/// The `Cancelled` arm is documented explicitly even though it returns
/// `false` like the wildcard — keeping it visible makes the cancellation
/// contract obvious to future maintainers and lets the test suite assert
/// on the intent (see `test_not_retryable_cancelled`).
#[must_use]
#[allow(
    clippy::match_same_arms,
    reason = "Cancelled arm kept explicit for documentation and test coverage"
)]
pub fn is_retryable_error(error: &BridgeError) -> bool {
    match error {
        BridgeError::Cancelled => false,
        BridgeError::SshConnection { .. } | BridgeError::SshTimeout { .. } => true,
        BridgeError::SshExec { reason } => {
            reason.contains("channel") || reason.contains("connection")
        }
        _ => false,
    }
}

/// Execute an async operation with retry logic
///
/// # Errors
///
/// Returns the last error from the operation if all retry attempts fail.
///
/// # Behavior
///
/// `max_attempts` is clamped to a minimum of 1 — passing 0 results in a
/// single attempt rather than a panic. This is defense-in-depth against
/// callers that build a `RetryConfig` with `max_attempts: 0` by mistake.
pub async fn with_retry<T, E, F, Fut>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    // Clamp to at least 1 attempt so the loop body always runs and the
    // last iteration's error is returned directly via `return Err(e)` —
    // this eliminates the "Option<E> accumulator + .expect()" pattern
    // that previously panicked when `max_attempts` was 0.
    let max_attempts = config.max_attempts.max(1);
    let mut attempt: u32 = 0;

    loop {
        // Wait before retry (except first attempt)
        let delay = config.delay_for_attempt(attempt);
        if !delay.is_zero() {
            debug!(
                operation = %operation_name,
                attempt = attempt + 1,
                delay_ms = delay.as_millis(),
                "Retrying after delay"
            );
            sleep(delay).await;
        }

        match operation().await {
            Ok(result) => {
                if attempt > 0 {
                    debug!(
                        operation = %operation_name,
                        attempt = attempt + 1,
                        "Operation succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                let is_last_attempt = attempt + 1 >= max_attempts;
                warn!(
                    operation = %operation_name,
                    attempt = attempt + 1,
                    max_attempts = max_attempts,
                    error = %e,
                    "Operation failed"
                );
                if is_last_attempt {
                    return Err(e);
                }
                attempt += 1;
            }
        }
    }
}

/// Execute an async operation with retry, using a predicate to determine if retry should happen
///
/// # Errors
///
/// Returns the last error from the operation if all retry attempts fail or if the predicate
/// returns false for a non-retryable error.
///
/// # Behavior
///
/// `max_attempts` is clamped to a minimum of 1 — passing 0 results in a
/// single attempt rather than a panic. This is defense-in-depth against
/// callers that build a `RetryConfig` with `max_attempts: 0` by mistake.
pub async fn with_retry_if<T, E, F, Fut, P>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: F,
    should_retry: P,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
    P: Fn(&E) -> bool,
{
    // Clamp to at least 1 attempt so the loop body always runs and the
    // last iteration's error is returned directly via `return Err(e)`.
    let max_attempts = config.max_attempts.max(1);
    let mut attempt: u32 = 0;

    loop {
        // Wait before retry (except first attempt)
        let delay = config.delay_for_attempt(attempt);
        if !delay.is_zero() {
            debug!(
                operation = %operation_name,
                attempt = attempt + 1,
                delay_ms = delay.as_millis(),
                "Retrying after delay"
            );
            sleep(delay).await;
        }

        match operation().await {
            Ok(result) => {
                if attempt > 0 {
                    debug!(
                        operation = %operation_name,
                        attempt = attempt + 1,
                        "Operation succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                let is_last_attempt = attempt + 1 >= max_attempts;
                let should_retry_this = !is_last_attempt && should_retry(&e);

                if should_retry_this {
                    warn!(
                        operation = %operation_name,
                        attempt = attempt + 1,
                        max_attempts = max_attempts,
                        error = %e,
                        "Operation failed, will retry"
                    );
                    attempt += 1;
                } else {
                    warn!(
                        operation = %operation_name,
                        attempt = attempt + 1,
                        error = %e,
                        "Operation failed, not retrying"
                    );
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_delay_ms, 100);
        assert!((config.backoff_multiplier - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_retry_config_no_retry() {
        let config = RetryConfig::no_retry();
        assert_eq!(config.max_attempts, 1);
    }

    #[test]
    fn test_delay_calculation() {
        let config = RetryConfig {
            initial_delay_ms: 100,
            max_delay_ms: 1000,
            backoff_multiplier: 2.0,
            jitter: 0.0,
            ..Default::default()
        };

        // First attempt has no delay
        assert_eq!(config.delay_for_attempt(0), Duration::ZERO);

        // Subsequent attempts have exponential backoff
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(100));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(200));
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(400));
        assert_eq!(config.delay_for_attempt(4), Duration::from_millis(800));

        // Capped at max
        assert_eq!(config.delay_for_attempt(5), Duration::from_millis(1000));
        assert_eq!(config.delay_for_attempt(10), Duration::from_millis(1000));
    }

    #[test]
    fn test_is_retryable_error() {
        assert!(is_retryable_error(&BridgeError::SshConnection {
            host: "test".to_string(),
            reason: "connection refused".to_string(),
        }));

        assert!(is_retryable_error(&BridgeError::SshTimeout { seconds: 30 }));

        assert!(!is_retryable_error(&BridgeError::CommandDenied {
            reason: "blacklisted".to_string(),
        }));

        assert!(!is_retryable_error(&BridgeError::SshKeyNotFound {
            path: "/path/to/key".to_string(),
        }));
    }

    #[tokio::test]
    async fn test_with_retry_success_first_attempt() {
        let config = RetryConfig::default();
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry(&config, "test", || {
            call_count += 1;
            async { Ok(42) }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 1);
    }

    #[tokio::test]
    async fn test_with_retry_success_after_retries() {
        let config = RetryConfig {
            max_attempts: 3,
            initial_delay_ms: 1,
            jitter: 0.0,
            ..Default::default()
        };
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry(&config, "test", || {
            call_count += 1;
            async move {
                if call_count < 3 {
                    Err("temporary error".to_string())
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 3);
    }

    #[tokio::test]
    async fn test_with_retry_all_attempts_fail() {
        let config = RetryConfig {
            max_attempts: 3,
            initial_delay_ms: 1,
            jitter: 0.0,
            ..Default::default()
        };
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry(&config, "test", || {
            call_count += 1;
            async { Err("permanent error".to_string()) }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(call_count, 3);
    }

    /// Regression test for FIND-010: previously panicked with
    /// `expect("at least one attempt was made")` when `max_attempts == 0`.
    /// Now clamped to 1 attempt and returns the operation's `Err` cleanly.
    #[tokio::test]
    async fn test_with_retry_max_attempts_zero_does_not_panic() {
        let config = RetryConfig {
            max_attempts: 0,
            initial_delay_ms: 1,
            jitter: 0.0,
            ..Default::default()
        };
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry(&config, "test", || {
            call_count += 1;
            async { Err("op failed".to_string()) }
        })
        .await;

        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(result.unwrap_err(), "op failed");
        assert_eq!(call_count, 1, "loop should clamp to one attempt");
    }

    /// Regression test for FIND-011: previously panicked with
    /// `expect("at least one attempt was made")` when `max_attempts == 0`.
    #[tokio::test]
    async fn test_with_retry_if_max_attempts_zero_does_not_panic() {
        let config = RetryConfig {
            max_attempts: 0,
            initial_delay_ms: 1,
            jitter: 0.0,
            ..Default::default()
        };
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry_if(
            &config,
            "test",
            || {
                call_count += 1;
                async { Err("op failed".to_string()) }
            },
            |_| true,
        )
        .await;

        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(result.unwrap_err(), "op failed");
        assert_eq!(call_count, 1, "loop should clamp to one attempt");
    }

    // ============== with_retry_if Tests ==============

    #[tokio::test]
    async fn test_with_retry_if_success_first_attempt() {
        let config = RetryConfig::default();
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry_if(
            &config,
            "test",
            || {
                call_count += 1;
                async { Ok(42) }
            },
            |_| true,
        )
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 1);
    }

    #[tokio::test]
    async fn test_with_retry_if_retries_on_matching_predicate() {
        let config = RetryConfig {
            max_attempts: 3,
            initial_delay_ms: 1,
            jitter: 0.0,
            ..Default::default()
        };
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry_if(
            &config,
            "test",
            || {
                call_count += 1;
                async move {
                    if call_count < 3 {
                        Err("retryable error".to_string())
                    } else {
                        Ok(42)
                    }
                }
            },
            |e| e.contains("retryable"),
        )
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 3);
    }

    #[tokio::test]
    async fn test_with_retry_if_no_retry_on_non_matching_predicate() {
        let config = RetryConfig {
            max_attempts: 3,
            initial_delay_ms: 1,
            jitter: 0.0,
            ..Default::default()
        };
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry_if(
            &config,
            "test",
            || {
                call_count += 1;
                async { Err("permanent error".to_string()) }
            },
            |e| e.contains("retryable"), // Won't match "permanent"
        )
        .await;

        assert!(result.is_err());
        assert_eq!(call_count, 1); // Only one attempt
    }

    #[tokio::test]
    async fn test_with_retry_if_mixed_errors() {
        let config = RetryConfig {
            max_attempts: 5,
            initial_delay_ms: 1,
            jitter: 0.0,
            ..Default::default()
        };
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry_if(
            &config,
            "test",
            || {
                call_count += 1;
                async move {
                    match call_count {
                        1 => Err("retryable: network timeout".to_string()),
                        2 => Err("retryable: connection reset".to_string()),
                        3 => Ok(42),
                        _ => Err("should not reach".to_string()),
                    }
                }
            },
            |e| e.starts_with("retryable"),
        )
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 3);
    }

    // ============== RetryConfig Edge Cases ==============

    #[test]
    fn test_retry_config_with_max_attempts() {
        let config = RetryConfig::with_max_attempts(5);
        assert_eq!(config.max_attempts, 5);
        // Other fields should be default
        assert_eq!(config.initial_delay_ms, 100);
    }

    #[test]
    fn test_retry_config_clone() {
        let config = RetryConfig::default();
        let cloned = config.clone();
        assert_eq!(config.max_attempts, cloned.max_attempts);
        assert_eq!(config.initial_delay_ms, cloned.initial_delay_ms);
    }

    #[test]
    fn test_retry_config_debug() {
        let config = RetryConfig::default();
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("RetryConfig"));
        assert!(debug_str.contains("max_attempts"));
    }

    #[test]
    fn test_delay_with_high_attempt_number() {
        let config = RetryConfig {
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
            jitter: 0.0,
            ..Default::default()
        };

        // Very high attempt number should still cap at max_delay_ms
        let delay = config.delay_for_attempt(100);
        assert_eq!(delay, Duration::from_millis(5000));
    }

    #[test]
    fn test_delay_with_jitter() {
        let config = RetryConfig {
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
            jitter: 0.5, // 50% jitter
            ..Default::default()
        };

        // Delay should be in range [50, 150] for attempt 1
        let delay = config.delay_for_attempt(1);
        let ms = delay.as_millis();
        assert!((50..=150).contains(&ms));
    }

    #[test]
    fn test_delay_with_zero_jitter() {
        let config = RetryConfig {
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
            jitter: 0.0,
            ..Default::default()
        };

        // With zero jitter, delay should be exactly calculated
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(100));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(200));
    }

    // ============== is_retryable_error Tests ==============

    #[test]
    fn test_is_retryable_error_ssh_exec_channel() {
        assert!(is_retryable_error(&BridgeError::SshExec {
            reason: "channel closed unexpectedly".to_string(),
        }));
    }

    #[test]
    fn test_is_retryable_error_ssh_exec_connection() {
        assert!(is_retryable_error(&BridgeError::SshExec {
            reason: "connection reset by peer".to_string(),
        }));
    }

    #[test]
    fn test_is_retryable_error_ssh_exec_other() {
        assert!(!is_retryable_error(&BridgeError::SshExec {
            reason: "command not found".to_string(),
        }));
    }

    #[test]
    fn test_is_retryable_error_config_errors() {
        assert!(!is_retryable_error(&BridgeError::ConfigNotFound {
            path: "/path/to/config".to_string(),
        }));

        assert!(!is_retryable_error(&BridgeError::ConfigInvalid {
            field: "hosts".to_string(),
            reason: "empty".to_string(),
        }));
    }

    #[test]
    fn test_is_retryable_error_file_transfer() {
        assert!(!is_retryable_error(&BridgeError::FileTransfer {
            reason: "file not found".to_string(),
        }));
    }

    #[test]
    fn test_not_retryable_host_key_mismatch() {
        assert!(!is_retryable_error(&BridgeError::SshHostKeyMismatch {
            host: "server1".to_string(),
            expected: "SHA256:abc".to_string(),
            actual: "SHA256:xyz".to_string(),
        }));
    }

    #[test]
    fn test_not_retryable_host_key_unknown() {
        assert!(!is_retryable_error(&BridgeError::SshHostKeyUnknown {
            host: "server1".to_string(),
            fingerprint: "SHA256:abc".to_string(),
        }));
    }

    #[test]
    fn test_not_retryable_auth() {
        assert!(!is_retryable_error(&BridgeError::SshAuth {
            user: "admin".to_string(),
            host: "server1".to_string(),
        }));
    }

    #[test]
    fn test_not_retryable_key_invalid() {
        assert!(!is_retryable_error(&BridgeError::SshKeyInvalid {
            path: "/path/to/key".to_string(),
        }));
    }

    #[test]
    fn test_not_retryable_output_too_large() {
        assert!(!is_retryable_error(&BridgeError::SshOutputTooLarge {
            limit_bytes: 10_485_760,
        }));
    }

    #[test]
    fn test_not_retryable_unknown_host() {
        assert!(!is_retryable_error(&BridgeError::UnknownHost {
            host: "nonexistent".to_string(),
        }));
    }

    #[test]
    fn test_not_retryable_mcp_protocol() {
        assert!(!is_retryable_error(&BridgeError::McpProtocol(
            "invalid".to_string(),
        )));
    }

    #[test]
    fn test_not_retryable_tunnel() {
        assert!(!is_retryable_error(&BridgeError::Tunnel {
            reason: "port in use".to_string(),
        }));
    }

    #[test]
    fn test_not_retryable_database_command() {
        assert!(!is_retryable_error(&BridgeError::DatabaseCommand {
            reason: "query failed".to_string(),
        }));
    }

    #[test]
    fn test_not_retryable_sftp() {
        assert!(!is_retryable_error(&BridgeError::Sftp {
            reason: "no such file".to_string(),
        }));
    }

    #[test]
    fn test_is_retryable_ssh_exec_timeout_keyword() {
        assert!(is_retryable_error(&BridgeError::SshExec {
            reason: "connection timeout".to_string(),
        }));
    }

    // ============== Single Attempt Tests ==============

    #[tokio::test]
    async fn test_with_retry_single_attempt_success() {
        let config = RetryConfig::no_retry();
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry(&config, "test", || {
            call_count += 1;
            async { Ok(42) }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 1);
    }

    #[tokio::test]
    async fn test_with_retry_single_attempt_failure() {
        let config = RetryConfig::no_retry();
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry(&config, "test", || {
            call_count += 1;
            async { Err("error".to_string()) }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(call_count, 1); // Only one attempt with no_retry
    }

    #[test]
    fn test_delay_with_jitter_exercises_rand_simple() {
        let config = RetryConfig {
            max_attempts: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
            jitter: 0.5,
        };

        for _ in 0..20 {
            let delay = config.delay_for_attempt(2);
            assert!(
                delay.as_millis() <= 5000,
                "delay {} exceeds max",
                delay.as_millis()
            );
        }
    }

    // ============== RetryConfig Edge Cases ==============

    #[test]
    fn test_retry_config_backoff_multiplier_one() {
        // With multiplier 1.0, delay should be constant (no exponential growth)
        let config = RetryConfig {
            initial_delay_ms: 200,
            max_delay_ms: 5000,
            backoff_multiplier: 1.0,
            jitter: 0.0,
            ..Default::default()
        };

        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(200));
        assert_eq!(config.delay_for_attempt(5), Duration::from_millis(200));
    }

    #[test]
    fn test_retry_config_zero_initial_delay() {
        let config = RetryConfig {
            initial_delay_ms: 0,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
            jitter: 0.0,
            ..Default::default()
        };

        // All delays should be zero since 0 * anything = 0
        assert_eq!(config.delay_for_attempt(0), Duration::ZERO);
        assert_eq!(config.delay_for_attempt(1), Duration::ZERO);
        assert_eq!(config.delay_for_attempt(5), Duration::ZERO);
    }

    #[test]
    fn test_retry_config_max_delay_less_than_initial() {
        let config = RetryConfig {
            initial_delay_ms: 1000,
            max_delay_ms: 100, // Max is less than initial
            backoff_multiplier: 2.0,
            jitter: 0.0,
            ..Default::default()
        };

        // Should be capped at max_delay_ms
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(100));
    }

    #[test]
    fn test_retry_config_fractional_multiplier() {
        let config = RetryConfig {
            initial_delay_ms: 1000,
            max_delay_ms: 5000,
            backoff_multiplier: 0.5, // Decreasing backoff
            jitter: 0.0,
            ..Default::default()
        };

        // With 0.5 multiplier, delays decrease: 1000, 500, 250, ...
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(1000));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(500));
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(250));
    }

    #[test]
    fn test_retry_config_with_max_attempts_zero() {
        let config = RetryConfig::with_max_attempts(0);
        assert_eq!(config.max_attempts, 0);
    }

    #[test]
    fn test_retry_config_with_max_attempts_one() {
        let config = RetryConfig::with_max_attempts(1);
        assert_eq!(config.max_attempts, 1);
        // Should be equivalent to no_retry
        assert_eq!(config.max_attempts, RetryConfig::no_retry().max_attempts);
    }

    #[test]
    fn test_retry_config_default_jitter_value() {
        let config = RetryConfig::default();
        assert!((config.jitter - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_retry_config_default_max_delay() {
        let config = RetryConfig::default();
        assert_eq!(config.max_delay_ms, 5000);
    }

    // ============== is_retryable_error Additional Tests ==============

    #[test]
    fn test_is_retryable_ssh_connection_empty_reason() {
        assert!(is_retryable_error(&BridgeError::SshConnection {
            host: "h".to_string(),
            reason: String::new(),
        }));
    }

    #[test]
    fn test_is_retryable_ssh_timeout_zero() {
        assert!(is_retryable_error(&BridgeError::SshTimeout { seconds: 0 }));
    }

    #[test]
    fn test_is_retryable_ssh_exec_both_keywords() {
        // Contains both "channel" and "connection"
        assert!(is_retryable_error(&BridgeError::SshExec {
            reason: "channel connection reset".to_string(),
        }));
    }

    #[test]
    fn test_not_retryable_cancelled() {
        // Cancelled errors must NEVER retry. Retrying would defeat the
        // purpose of `notifications/cancelled` and could spin indefinitely.
        assert!(!is_retryable_error(&BridgeError::Cancelled));
    }

    #[test]
    fn test_not_retryable_config_error() {
        assert!(!is_retryable_error(&BridgeError::Config(
            "bad config".to_string(),
        )));
    }

    #[tokio::test]
    async fn test_with_retry_if_all_attempts_fail_matching_predicate() {
        let config = RetryConfig {
            max_attempts: 3,
            initial_delay_ms: 1,
            jitter: 0.0,
            ..Default::default()
        };
        let mut call_count = 0;

        let result: Result<i32, String> = with_retry_if(
            &config,
            "test",
            || {
                call_count += 1;
                async { Err("retryable error".to_string()) }
            },
            |e| e.contains("retryable"),
        )
        .await;

        assert!(result.is_err());
        // Last attempt fails without retry check, so all 3 attempts are made
        assert_eq!(call_count, 3);
    }

    // ============== rand_simple Tests ==============

    #[test]
    fn test_rand_simple_produces_values_in_range() {
        // Call rand_simple multiple times and verify it produces values in [0, 1)
        for _ in 0..100 {
            let val = rand_simple();
            assert!(val >= 0.0, "rand_simple produced negative value: {val}");
            assert!(val < 1.0, "rand_simple produced value >= 1.0: {val}");
        }
    }
}
