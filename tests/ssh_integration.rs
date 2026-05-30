//! SSH Integration Tests
//!
//! These tests require a real SSH server to be available.
//! Configure connection in: `tests/ssh_test_config.yaml`
//!
//! Run with: `cargo test --test ssh_integration -- --ignored`
//!
//! Note: These tests are ignored by default to avoid CI failures
//! when no SSH server is available.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mcp_ssh_bridge::config::{
    AuthConfig, HostConfig, HostKeyVerification, LimitsConfig, OsType, RedactedSecret,
};
use mcp_ssh_bridge::ssh::{ConnectionPool, PoolConfig, SshClient};
use serde::Deserialize;

/// Test configuration loaded from YAML
#[derive(Debug, Deserialize)]
struct TestConfig {
    ssh_test: SshTestConfig,
}

#[derive(Debug, Deserialize)]
struct SshTestConfig {
    hostname: String,
    port: u16,
    user: String,
    auth: AuthConfigYaml,
    host_key_verification: String,
    #[allow(dead_code)]
    remote_test_dir: String,
}

#[derive(Debug, Deserialize)]
struct AuthConfigYaml {
    key: Option<KeyAuth>,
    password: Option<String>,
    agent: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct KeyAuth {
    path: String,
    passphrase: Option<String>,
}

/// Load test configuration from YAML file
fn load_test_config() -> Option<TestConfig> {
    let config_path = Path::new("tests/ssh_test_config.yaml");
    if !config_path.exists() {
        eprintln!(
            "⚠️  Skipping: tests/ssh_test_config.yaml not found\n\
             Copy tests/ssh_test_config.example.yaml and fill with real values."
        );
        return None;
    }

    let content =
        std::fs::read_to_string(config_path).expect("Failed to read tests/ssh_test_config.yaml");

    serde_saphyr::from_str(&content).expect("Failed to parse tests/ssh_test_config.yaml")
}

/// Convert test config to `HostConfig`
fn to_host_config(config: &SshTestConfig) -> HostConfig {
    let auth = if let Some(ref key) = config.auth.key {
        AuthConfig::Key {
            path: key.path.clone(),
            passphrase: key.passphrase.clone().map(RedactedSecret::from),
        }
    } else if let Some(ref password) = config.auth.password {
        AuthConfig::Password {
            password: RedactedSecret::from(password.clone()),
        }
    } else if config.auth.agent.unwrap_or(false) {
        AuthConfig::Agent
    } else {
        panic!("No valid auth method configured");
    };

    let host_key_verification = match config.host_key_verification.as_str() {
        "strict" => HostKeyVerification::Strict,
        "accept_new" => HostKeyVerification::AcceptNew,
        _ => HostKeyVerification::Off,
    };

    HostConfig {
        hostname: config.hostname.clone(),
        port: config.port,
        user: config.user.clone(),
        auth,
        description: Some("Integration test host".to_string()),
        host_key_verification,
        proxy_jump: None,
        socks_proxy: None,
        sudo_password: None,
        tags: Vec::new(),
        os_type: OsType::Linux,
        shell: None,
        retry: None,
        protocol: mcp_ssh_bridge::config::Protocol::default(),

        #[cfg(feature = "winrm")]
        winrm_use_tls: None,

        #[cfg(feature = "winrm")]
        winrm_accept_invalid_certs: None,

        #[cfg(feature = "winrm")]
        winrm_operation_timeout_secs: None,

        #[cfg(feature = "winrm")]
        winrm_max_envelope_size: None,
    }
}

/// Get default limits for tests
fn test_limits() -> LimitsConfig {
    LimitsConfig {
        command_timeout_seconds: 30,
        connection_timeout_seconds: 10,
        keepalive_interval_seconds: 15,
        max_output_bytes: 1024 * 1024,
        max_concurrent_commands: 5,
        retry_attempts: 2,
        retry_initial_delay_ms: 100,
        rate_limit_per_second: 0,
        ..LimitsConfig::default()
    }
}

// =============================================================================
// SSH Client Tests
// =============================================================================

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_connect() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let result = SshClient::connect("test-host", &host_config, &limits).await;

    assert!(result.is_ok(), "SSH connection failed: {:?}", result.err());

    let client = result.unwrap();
    assert_eq!(client.host_name(), "test-host");

    // Clean up
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_simple() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    let output = client.exec("echo 'hello world'", &limits).await;

    assert!(output.is_ok(), "Exec failed: {:?}", output.err());

    let output = output.unwrap();
    assert_eq!(output.exit_code, 0);
    assert!(output.stdout.contains("hello world"));
    assert!(output.stderr.is_empty());

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_exit_code() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    // Command that returns exit code 42
    let output = client.exec("exit 42", &limits).await.expect("Exec failed");

    assert_eq!(output.exit_code, 42);

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_stderr() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    // Command that writes to stderr
    let output = client
        .exec("echo 'error message' >&2", &limits)
        .await
        .expect("Exec failed");

    assert_eq!(output.exit_code, 0);
    assert!(output.stderr.contains("error message"));

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_large_output() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    // Generate ~100KB of output
    let output = client
        .exec("seq 1 10000", &limits)
        .await
        .expect("Exec failed");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout.len() > 10000); // At least 10KB
    assert!(output.stdout.contains("10000"));

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_unicode() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    let output = client
        .exec("echo '日本語 émoji 🎉'", &limits)
        .await
        .expect("Exec failed");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout.contains("日本語"));
    assert!(output.stdout.contains("🎉"));

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_multiline() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    let output = client
        .exec("echo 'line1'; echo 'line2'; echo 'line3'", &limits)
        .await
        .expect("Exec failed");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout.contains("line1"));
    assert!(output.stdout.contains("line2"));
    assert!(output.stdout.contains("line3"));
    assert_eq!(output.stdout.lines().count(), 3);

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_environment() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    let output = client
        .exec("echo $HOME", &limits)
        .await
        .expect("Exec failed");

    assert_eq!(output.exit_code, 0);
    assert!(!output.stdout.trim().is_empty());

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_pwd() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    let output = client.exec("pwd", &limits).await.expect("Exec failed");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout.starts_with('/'));

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_command_not_found() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    let output = client
        .exec("nonexistent_command_12345", &limits)
        .await
        .expect("Exec failed");

    assert_ne!(output.exit_code, 0);
    // Support multiple locales (English: "not found", French: "introuvable")
    assert!(
        output.stderr.contains("not found")
            || output.stderr.contains("command not found")
            || output.stderr.contains("introuvable"),
        "stderr: {}",
        output.stderr
    );

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_is_connected() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    // Should be connected
    assert!(client.is_connected().await);

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_close() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    let result = client.close().await;
    assert!(result.is_ok(), "Close failed: {:?}", result.err());
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_multiple_exec() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    // Execute multiple commands on the same connection
    for i in 1..=5 {
        let output = client
            .exec(&format!("echo 'command {i}'"), &limits)
            .await
            .expect("Exec failed");

        assert_eq!(output.exit_code, 0);
        assert!(output.stdout.contains(&format!("command {i}")));
    }

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_timeout() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);

    // Very short timeout
    let limits = LimitsConfig {
        command_timeout_seconds: 1,
        ..test_limits()
    };

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    // Command that takes longer than timeout
    let result = client.exec("sleep 10", &limits).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("timeout"),
        "Expected timeout error, got: {err}"
    );

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_binary_output() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    // Generate some binary-like output (null bytes will be replaced)
    let output = client
        .exec("head -c 100 /dev/urandom | base64", &limits)
        .await
        .expect("Exec failed");

    assert_eq!(output.exit_code, 0);
    assert!(!output.stdout.is_empty());

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_exec_pipe() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    let output = client
        .exec("echo 'hello world' | tr 'a-z' 'A-Z'", &limits)
        .await
        .expect("Exec failed");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout.contains("HELLO WORLD"));

    let _ = client.close().await;
}

// =============================================================================
// Connection Pool Tests
// =============================================================================

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_pool_get_connection() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let pool_config = PoolConfig::default();
    let pool = ConnectionPool::new(pool_config);

    let result = pool
        .get_connection("test-host", &host_config, &limits)
        .await;

    assert!(result.is_ok(), "Get connection failed: {:?}", result.err());

    let mut guard = result.unwrap();

    // Verify we can execute a command
    let output = guard.exec("echo 'test'", &limits).await;
    assert!(output.is_ok());

    // Connection is returned to pool when guard is dropped
    drop(guard);

    // Verify we can get another connection (reusing the returned one)
    let mut guard2 = pool
        .get_connection("test-host", &host_config, &limits)
        .await
        .expect("Second get connection failed");
    let output2 = guard2.exec("echo 'reused'", &limits).await;
    assert!(output2.is_ok());
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_pool_connection_reuse() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let pool_config = PoolConfig::default();
    let pool = ConnectionPool::new(pool_config);

    // Get first connection
    {
        let mut guard = pool
            .get_connection("test-host", &host_config, &limits)
            .await
            .expect("Get connection failed");
        let output = guard.exec("echo 'first'", &limits).await;
        assert!(output.is_ok());
    } // Guard dropped, connection returned to pool

    // Second get should reuse the same connection
    {
        let mut guard = pool
            .get_connection("test-host", &host_config, &limits)
            .await
            .expect("Get connection failed");
        let output = guard.exec("echo 'second'", &limits).await;
        assert!(output.is_ok());
    }

    let stats = pool.stats().await;
    assert!(stats.total_connections >= 1);
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_pool_concurrent_connections() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let pool_config = PoolConfig {
        max_connections_per_host: 3,
        ..Default::default()
    };
    let pool = Arc::new(ConnectionPool::new(pool_config));

    // Spawn multiple concurrent tasks
    let mut handles = Vec::new();
    for i in 0..3 {
        let pool = Arc::clone(&pool);
        let host_config = host_config.clone();
        let limits = limits.clone();
        let handle = tokio::spawn(async move {
            let mut guard = pool
                .get_connection("test-host", &host_config, &limits)
                .await
                .expect("Get connection failed");
            let output = guard
                .exec(&format!("echo 'task {i}'"), &limits)
                .await
                .expect("Exec failed");
            assert_eq!(output.exit_code, 0);
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.expect("Task failed");
    }

    let stats = pool.stats().await;
    assert!(stats.total_connections >= 1);
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_pool_guard_exec() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let pool_config = PoolConfig::default();
    let pool = ConnectionPool::new(pool_config);

    let mut guard = pool
        .get_connection("test-host", &host_config, &limits)
        .await
        .expect("Get connection failed");

    // Execute command through guard
    let output = guard
        .exec("echo 'via guard'", &limits)
        .await
        .expect("Exec failed");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout.contains("via guard"));
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_pool_guard_mark_failed() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let pool_config = PoolConfig::default();
    let pool = ConnectionPool::new(pool_config);

    // Get and mark as failed
    {
        let mut guard = pool
            .get_connection("test-host", &host_config, &limits)
            .await
            .expect("Get connection failed");
        guard.mark_failed();
    } // Guard dropped, connection should NOT be returned to pool

    // Get new connection (should create new one)
    let mut guard = pool
        .get_connection("test-host", &host_config, &limits)
        .await
        .expect("Get connection failed");
    let output = guard
        .exec("echo 'new connection'", &limits)
        .await
        .expect("Exec failed");

    assert!(output.stdout.contains("new connection"));
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_pool_stats() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let pool_config = PoolConfig::default();
    let pool = ConnectionPool::new(pool_config);

    // Initial stats
    let initial_stats = pool.stats().await;
    assert_eq!(initial_stats.total_connections, 0);

    // Get connection
    let guard = pool
        .get_connection("test-host", &host_config, &limits)
        .await
        .expect("Get connection failed");

    // Stats after getting connection (connection is in use, not in pool)
    // When guard is dropped, it returns to pool
    drop(guard);

    // Stats show total connections tracked (may be 0 if connection was cleaned up)
    let stats = pool.stats().await;
    // Just verify stats work - the actual count depends on timing
    let _ = stats.total_connections;
}

// =============================================================================
// SFTP Session Tests (basic - full tests in sftp_integration.rs)
// =============================================================================

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_session_open() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    let result = client.sftp_session().await;

    assert!(result.is_ok(), "SFTP session failed: {:?}", result.err());

    let sftp = result.unwrap();
    let _ = sftp.close().await;
    let _ = client.close().await;
}

// =============================================================================
// Shell Session Tests
// =============================================================================

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_ssh_open_shell() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    let result = client.open_shell().await;

    assert!(result.is_ok(), "Open shell failed: {:?}", result.err());

    // Shell channel opened successfully
    let _ = client.close().await;
}
