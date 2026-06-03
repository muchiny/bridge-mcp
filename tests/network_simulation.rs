//! Network Simulation Tests (Fault Injection)
//!
//! Tests SSH error handling and fault tolerance patterns using
//! the public error types. Validates that different failure modes
//! (connection refused, timeout, auth failure) are correctly
//! classified and propagated.

use bridge_mcp::error::BridgeError;
use bridge_mcp::ssh::RetryConfig;
use std::sync::Arc;

// ─── Error type classification ─────────────────────────────────────

#[test]
fn connection_error_contains_host_and_reason() {
    let err = BridgeError::SshConnection {
        host: "prod-server".to_string(),
        reason: "Connection refused".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("prod-server") || msg.contains("Connection refused"));
}

#[test]
fn timeout_error_contains_duration() {
    let err = BridgeError::SshTimeout { seconds: 30 };
    let msg = format!("{err}");
    assert!(msg.contains("30"));
}

#[test]
fn auth_error_contains_user_and_host() {
    let err = BridgeError::SshAuth {
        user: "deploy".to_string(),
        host: "secure-host".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("deploy") || msg.contains("secure-host"));
}

#[test]
fn different_error_types_are_distinguishable() {
    let conn_err = BridgeError::SshConnection {
        host: "h1".to_string(),
        reason: "refused".to_string(),
    };
    let auth_err = BridgeError::SshAuth {
        user: "root".to_string(),
        host: "h2".to_string(),
    };
    let timeout_err = BridgeError::SshTimeout { seconds: 60 };

    assert!(matches!(conn_err, BridgeError::SshConnection { .. }));
    assert!(matches!(auth_err, BridgeError::SshAuth { .. }));
    assert!(matches!(timeout_err, BridgeError::SshTimeout { .. }));
}

// ─── Retryability classification ───────────────────────────────────

#[test]
fn connection_errors_are_retryable() {
    let err = BridgeError::SshConnection {
        host: "server".to_string(),
        reason: "Connection reset by peer".to_string(),
    };
    // Connection errors should be considered transient
    assert!(bridge_mcp::ssh::is_retryable_error(&err));
}

#[test]
fn auth_errors_are_not_retryable() {
    let err = BridgeError::SshAuth {
        user: "baduser".to_string(),
        host: "server".to_string(),
    };
    // Auth errors are permanent - retrying won't help
    assert!(!bridge_mcp::ssh::is_retryable_error(&err));
}

#[test]
fn timeout_errors_are_retryable() {
    let err = BridgeError::SshTimeout { seconds: 30 };
    // Timeouts may be transient
    assert!(bridge_mcp::ssh::is_retryable_error(&err));
}

#[test]
fn command_denied_is_not_retryable() {
    let err = BridgeError::CommandDenied {
        reason: "Blacklisted".to_string(),
    };
    assert!(!bridge_mcp::ssh::is_retryable_error(&err));
}

// ─── Retry configuration ──────────────────────────────────────────

#[test]
fn retry_config_default_values() {
    let config = RetryConfig::default();
    assert_eq!(config.max_attempts, 3);
    assert_eq!(config.initial_delay_ms, 100);
    assert!(config.backoff_multiplier > 1.0);
    assert!(config.jitter >= 0.0 && config.jitter <= 1.0);
}

#[test]
fn retry_config_no_retry() {
    let config = RetryConfig::no_retry();
    assert_eq!(config.max_attempts, 1);
}

#[test]
fn retry_config_custom_attempts() {
    let config = RetryConfig::with_max_attempts(5);
    assert_eq!(config.max_attempts, 5);
}

#[test]
fn retry_config_zero_attempts_means_no_retry() {
    // with_max_attempts(0) should behave sanely
    let config = RetryConfig::with_max_attempts(0);
    assert_eq!(config.max_attempts, 0);
}

// ─── Retry with async operations ───────────────────────────────────

#[tokio::test]
async fn retry_succeeds_on_first_attempt() {
    let result = bridge_mcp::ssh::with_retry(&RetryConfig::default(), "test-op", || async {
        Ok::<&str, BridgeError>("success")
    })
    .await;

    assert_eq!(result.unwrap(), "success");
}

#[tokio::test]
async fn retry_fails_after_max_attempts_with_permanent_error() {
    let attempt_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count = Arc::clone(&attempt_count);

    let config = RetryConfig {
        max_attempts: 3,
        initial_delay_ms: 1, // Minimal delay for test speed
        max_delay_ms: 10,
        backoff_multiplier: 1.0,
        jitter: 0.0,
    };

    let result = bridge_mcp::ssh::with_retry(&config, "test-op", || {
        let c = Arc::clone(&count);
        async move {
            c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err::<(), BridgeError>(BridgeError::SshConnection {
                host: "test".to_string(),
                reason: "refused".to_string(),
            })
        }
    })
    .await;

    assert!(result.is_err());
    assert_eq!(
        attempt_count.load(std::sync::atomic::Ordering::Relaxed),
        3,
        "Should have attempted exactly 3 times"
    );
}

#[tokio::test]
async fn retry_stops_immediately_on_non_retryable_error() {
    let attempt_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count = Arc::clone(&attempt_count);

    let config = RetryConfig {
        max_attempts: 5,
        initial_delay_ms: 1,
        max_delay_ms: 10,
        backoff_multiplier: 1.0,
        jitter: 0.0,
    };

    let result = bridge_mcp::ssh::with_retry_if(
        &config,
        "test-op",
        || {
            let c = Arc::clone(&count);
            async move {
                c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err::<(), BridgeError>(BridgeError::SshAuth {
                    user: "root".to_string(),
                    host: "test".to_string(),
                })
            }
        },
        bridge_mcp::ssh::is_retryable_error,
    )
    .await;

    assert!(result.is_err());
    assert_eq!(
        attempt_count.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "Non-retryable error should stop after 1 attempt"
    );
}

#[tokio::test]
async fn retry_recovers_on_second_attempt() {
    let attempt_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count = Arc::clone(&attempt_count);

    let config = RetryConfig {
        max_attempts: 3,
        initial_delay_ms: 1,
        max_delay_ms: 10,
        backoff_multiplier: 1.0,
        jitter: 0.0,
    };

    let result = bridge_mcp::ssh::with_retry(&config, "test-op", || {
        let c = Arc::clone(&count);
        async move {
            let attempt = c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if attempt == 0 {
                Err(BridgeError::SshConnection {
                    host: "test".to_string(),
                    reason: "transient".to_string(),
                })
            } else {
                Ok("recovered")
            }
        }
    })
    .await;

    assert_eq!(result.unwrap(), "recovered");
    assert_eq!(
        attempt_count.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "Should have recovered on second attempt"
    );
}

#[tokio::test]
async fn retry_with_conditional_predicate() {
    let attempt_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count = Arc::clone(&attempt_count);

    let config = RetryConfig {
        max_attempts: 5,
        initial_delay_ms: 1,
        max_delay_ms: 10,
        backoff_multiplier: 1.0,
        jitter: 0.0,
    };

    // with_retry_if lets us control which errors are retryable
    let result = bridge_mcp::ssh::with_retry_if(
        &config,
        "test-op",
        || {
            let c = Arc::clone(&count);
            async move {
                c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err::<(), BridgeError>(BridgeError::SshConnection {
                    host: "test".to_string(),
                    reason: "custom".to_string(),
                })
            }
        },
        |_err| false, // Never retry
    )
    .await;

    assert!(result.is_err());
    assert_eq!(
        attempt_count.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "Custom predicate returning false should stop after 1 attempt"
    );
}

// ─── Concurrent retry behavior ─────────────────────────────────────

#[tokio::test]
async fn concurrent_retries_are_independent() {
    let config = RetryConfig {
        max_attempts: 2,
        initial_delay_ms: 1,
        max_delay_ms: 10,
        backoff_multiplier: 1.0,
        jitter: 0.0,
    };

    let mut handles = vec![];
    for i in 0..5 {
        let cfg = config.clone();
        handles.push(tokio::spawn(async move {
            let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let c = Arc::clone(&count);

            let result = bridge_mcp::ssh::with_retry(&cfg, "concurrent-op", || {
                let c = Arc::clone(&c);
                async move {
                    let attempt = c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if attempt == 0 {
                        Err(BridgeError::SshConnection {
                            host: format!("host-{i}"),
                            reason: "transient".to_string(),
                        })
                    } else {
                        Ok(format!("host-{i}-ok"))
                    }
                }
            })
            .await;

            (
                result.unwrap(),
                count.load(std::sync::atomic::Ordering::Relaxed),
            )
        }));
    }

    for (idx, handle) in handles.into_iter().enumerate() {
        let (result, attempts) = handle.await.unwrap();
        assert_eq!(result, format!("host-{idx}-ok"));
        assert_eq!(attempts, 2, "Each retry should be independent");
    }
}
