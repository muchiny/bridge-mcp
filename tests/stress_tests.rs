//! Stress and concurrency tests for MCP SSH Bridge
//!
//! These tests verify the system behaves correctly under concurrent load.
//! They don't require actual SSH connections - they test the internal
//! components like validators, sanitizers, pools, and sessions.

use bridge_mcp::config::{SecurityConfig, SecurityMode, SessionConfig};
use bridge_mcp::security::{CommandValidator, RateLimiter, Sanitizer};
use bridge_mcp::ssh::{ConnectionPool, PoolConfig, SessionManager};
use std::sync::Arc;
use std::time::Instant;

// ============== Concurrent Validator Tests ==============

#[tokio::test]
async fn test_concurrent_validation_same_command() {
    let config = SecurityConfig {
        mode: SecurityMode::Permissive,
        whitelist: vec![],
        blacklist: vec!["rm\\s+-rf".to_string()],
        ..Default::default()
    };
    let validator = Arc::new(CommandValidator::new(&config));

    let mut handles = vec![];
    for _ in 0..100 {
        let v = Arc::clone(&validator);
        handles.push(tokio::spawn(async move { v.validate("ls -la").is_ok() }));
    }

    for handle in handles {
        assert!(handle.await.unwrap());
    }
}

#[tokio::test]
async fn test_concurrent_validation_different_commands() {
    let config = SecurityConfig {
        mode: SecurityMode::Permissive,
        whitelist: vec![],
        blacklist: vec!["rm\\s+-rf".to_string(), "mkfs".to_string()],
        ..Default::default()
    };
    let validator = Arc::new(CommandValidator::new(&config));

    let commands = vec![
        "ls -la",
        "pwd",
        "whoami",
        "cat /etc/passwd",
        "grep pattern file",
        "find . -name '*.rs'",
        "ps aux",
        "df -h",
        "free -m",
        "uptime",
    ];

    let mut handles = vec![];
    for i in 0..100 {
        let v = Arc::clone(&validator);
        let cmd = commands[i % commands.len()].to_string();
        handles.push(tokio::spawn(async move { v.validate(&cmd).is_ok() }));
    }

    for handle in handles {
        assert!(handle.await.unwrap());
    }
}

#[tokio::test]
async fn test_concurrent_validation_mixed_allowed_denied() {
    let config = SecurityConfig {
        mode: SecurityMode::Permissive,
        whitelist: vec![],
        blacklist: vec!["rm\\s+-rf".to_string()],
        ..Default::default()
    };
    let validator = Arc::new(CommandValidator::new(&config));

    let mut handles = vec![];

    // Half allowed commands
    for _ in 0..50 {
        let v = Arc::clone(&validator);
        handles.push(tokio::spawn(async move { v.validate("ls -la") }));
    }

    // Half denied commands
    for _ in 0..50 {
        let v = Arc::clone(&validator);
        handles.push(tokio::spawn(async move { v.validate("rm -rf /") }));
    }

    let mut allowed = 0;
    let mut denied = 0;

    for handle in handles {
        match handle.await.unwrap() {
            Ok(()) => allowed += 1,
            Err(_) => denied += 1,
        }
    }

    assert_eq!(allowed, 50);
    assert_eq!(denied, 50);
}

// ============== Concurrent Sanitizer Tests ==============

#[tokio::test]
async fn test_concurrent_sanitization() {
    let sanitizer = Arc::new(Sanitizer::with_defaults());

    let test_outputs = [
        "password=secret123",
        "API_KEY=ghp_abcd1234567890",
        "Normal output without secrets",
        "aws_secret_access_key=AKIAIOSFODNN7EXAMPLE",
    ];

    let mut handles = vec![];
    for i in 0..100 {
        let s = Arc::clone(&sanitizer);
        let output = test_outputs[i % test_outputs.len()].to_string();
        handles.push(tokio::spawn(async move { s.sanitize(&output).to_string() }));
    }

    for handle in handles {
        let result = handle.await.unwrap();
        // Ensure no raw secrets in output
        assert!(!result.contains("secret123"));
        assert!(!result.contains("ghp_abcd1234567890"));
        assert!(!result.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}

#[tokio::test]
async fn test_concurrent_sanitization_large_output() {
    let sanitizer = Arc::new(Sanitizer::with_defaults());

    // Create a large output string
    let large_output = "password=secret\n".repeat(1000);

    let mut handles = vec![];
    for _ in 0..20 {
        let s = Arc::clone(&sanitizer);
        let output = large_output.clone();
        handles.push(tokio::spawn(async move { s.sanitize(&output).to_string() }));
    }

    for handle in handles {
        let result = handle.await.unwrap();
        assert!(!result.contains("secret"));
    }
}

// ============== Concurrent Rate Limiter Tests ==============

#[tokio::test]
async fn test_concurrent_rate_limiting() {
    // Create rate limiter with 100 requests per second burst
    let rate_limiter = Arc::new(RateLimiter::new(100));

    let mut handles = vec![];
    for i in 0..50 {
        let rl = Arc::clone(&rate_limiter);
        let host = format!("host{}", i % 5);
        handles.push(tokio::spawn(async move { rl.check(&host) }));
    }

    let mut allowed = 0;
    let mut _denied = 0;

    for handle in handles {
        match handle.await.unwrap() {
            Ok(()) => allowed += 1,
            Err(_) => _denied += 1,
        }
    }

    // Most should be allowed with 100/s burst
    assert!(allowed > 0);
}

#[tokio::test]
async fn test_rate_limiter_disabled() {
    // Rate limiter with 0 = disabled
    let rate_limiter = Arc::new(RateLimiter::new(0));

    let mut handles = vec![];
    for _ in 0..100 {
        let rl = Arc::clone(&rate_limiter);
        handles.push(tokio::spawn(async move { rl.check("any-host") }));
    }

    for handle in handles {
        // All should be allowed when disabled
        assert!(handle.await.unwrap().is_ok());
    }
}

// ============== Concurrent Pool Tests ==============

#[tokio::test]
async fn test_concurrent_pool_stats() {
    let pool = Arc::new(ConnectionPool::with_defaults());

    let mut handles = vec![];
    for _ in 0..100 {
        let p = Arc::clone(&pool);
        handles.push(tokio::spawn(async move { p.stats().await }));
    }

    for handle in handles {
        let stats = handle.await.unwrap();
        assert_eq!(stats.total_connections, 0);
    }
}

#[tokio::test]
async fn test_concurrent_pool_cleanup() {
    let pool = Arc::new(ConnectionPool::with_defaults());

    let mut handles = vec![];
    for _ in 0..50 {
        let p = Arc::clone(&pool);
        handles.push(tokio::spawn(async move { p.cleanup().await }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let stats = pool.stats().await;
    assert_eq!(stats.total_connections, 0);
}

#[tokio::test]
async fn test_concurrent_pool_health_check() {
    let pool = Arc::new(ConnectionPool::with_defaults());

    let mut handles = vec![];
    for _ in 0..20 {
        let p = Arc::clone(&pool);
        handles.push(tokio::spawn(async move { p.health_check().await }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let stats = pool.stats().await;
    assert_eq!(stats.total_connections, 0);
}

// ============== Concurrent Session Manager Tests ==============

#[tokio::test]
async fn test_concurrent_session_list() {
    let manager = Arc::new(SessionManager::new(SessionConfig::default()));

    let mut handles = vec![];
    for _ in 0..100 {
        let m = Arc::clone(&manager);
        handles.push(tokio::spawn(async move { m.list().await }));
    }

    for handle in handles {
        let list = handle.await.unwrap();
        assert!(list.is_empty());
    }
}

#[tokio::test]
async fn test_concurrent_session_cleanup() {
    let manager = Arc::new(SessionManager::new(SessionConfig::default()));

    let mut handles = vec![];
    for _ in 0..50 {
        let m = Arc::clone(&manager);
        handles.push(tokio::spawn(async move { m.cleanup().await }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_concurrent_session_close_nonexistent() {
    let manager = Arc::new(SessionManager::new(SessionConfig::default()));

    let mut handles = vec![];
    for i in 0..50 {
        let m = Arc::clone(&manager);
        let id = format!("nonexistent-{i}");
        handles.push(tokio::spawn(async move { m.close(&id).await }));
    }

    for handle in handles {
        // All should fail since sessions don't exist
        assert!(handle.await.unwrap().is_err());
    }
}

// ============== Performance Tests ==============

#[tokio::test]
async fn test_validator_performance_1000_validations() {
    let config = SecurityConfig {
        mode: SecurityMode::Permissive,
        whitelist: vec![],
        blacklist: vec![
            "rm\\s+-rf".to_string(),
            "mkfs".to_string(),
            "dd\\s+if=".to_string(),
            "chmod\\s+777".to_string(),
        ],
        ..Default::default()
    };
    let validator = CommandValidator::new(&config);

    let start = Instant::now();
    for _ in 0..1000 {
        let _ = validator.validate("ls -la /tmp");
    }
    let elapsed = start.elapsed();

    // Should complete in under 1 second
    assert!(
        elapsed.as_secs() < 1,
        "Validation took too long: {elapsed:?}"
    );
}

#[tokio::test]
async fn test_sanitizer_performance_1000_sanitizations() {
    let sanitizer = Sanitizer::with_defaults();
    let output = "password=secret\nAPI_KEY=test123\n".repeat(10);

    let start = Instant::now();
    for _ in 0..1000 {
        let _ = sanitizer.sanitize(&output);
    }
    let elapsed = start.elapsed();

    // Should complete in under 2 seconds
    assert!(
        elapsed.as_secs() < 2,
        "Sanitization took too long: {elapsed:?}"
    );
}

#[tokio::test]
async fn test_pool_config_variations() {
    // Test various pool configurations work correctly
    let configs = vec![
        PoolConfig {
            max_connections_per_host: 1,
            max_idle_seconds: 1,
            max_age_seconds: 1,
        },
        PoolConfig {
            max_connections_per_host: 100,
            max_idle_seconds: 86_400,
            max_age_seconds: 604_800,
        },
        PoolConfig {
            max_connections_per_host: 0,
            max_idle_seconds: 0,
            max_age_seconds: 0,
        },
    ];

    for config in configs {
        let pool = ConnectionPool::new(config);
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
        pool.cleanup().await;
        pool.health_check().await;
        pool.close_all().await;
    }
}
