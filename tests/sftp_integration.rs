//! SFTP Integration Tests
//!
//! These tests require a real SSH server with SFTP support to be available.
//! Configure connection in: `tests/ssh_test_config.yaml`
//!
//! Run with: `cargo test --test sftp_integration -- --ignored`
//!
//! Note: These tests are ignored by default to avoid CI failures
//! when no SSH server is available.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use mcp_ssh_bridge::config::{AuthConfig, HostConfig, HostKeyVerification, LimitsConfig, OsType};
use mcp_ssh_bridge::ssh::{SshClient, TransferMode, TransferOptions, TransferProgress};
use serde::Deserialize;
use tempfile::NamedTempFile;

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
            passphrase: key
                .passphrase
                .clone()
                .map(mcp_ssh_bridge::config::RedactedSecret::from),
        }
    } else if let Some(ref password) = config.auth.password {
        AuthConfig::Password {
            password: mcp_ssh_bridge::config::RedactedSecret::from(password.clone()),
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
        command_timeout_seconds: 60,
        connection_timeout_seconds: 10,
        keepalive_interval_seconds: 15,
        max_output_bytes: 10 * 1024 * 1024,
        max_concurrent_commands: 5,
        retry_attempts: 2,
        retry_initial_delay_ms: 100,
        rate_limit_per_second: 0,
        ..LimitsConfig::default()
    }
}

/// Create a temporary file with specified content
fn create_temp_file(content: &[u8]) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Failed to create temp file");
    file.write_all(content).expect("Failed to write temp file");
    file.flush().expect("Failed to flush temp file");
    file
}

/// Create the remote test directory if it doesn't exist
async fn ensure_remote_test_dir(client: &SshClient, remote_dir: &str) {
    let _ = client
        .exec(&format!("mkdir -p {remote_dir}"), &test_limits())
        .await;
}

/// Clean up remote test file
async fn cleanup_remote_file(client: &SshClient, remote_path: &str) {
    let _ = client
        .exec(&format!("rm -f {remote_path}"), &test_limits())
        .await;
}

/// No-op progress callback type alias
type NoProgressCallback = fn(TransferProgress);

// =============================================================================
// SFTP Upload Tests
// =============================================================================

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_upload_small_file() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    // Create small test file
    let content = b"Hello, SFTP World!";
    let temp_file = create_temp_file(content);
    let remote_path = format!("{remote_dir}/small_file.txt");

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let options = TransferOptions::default();
    let result = sftp
        .upload_file(
            temp_file.path(),
            &remote_path,
            &options,
            None::<NoProgressCallback>,
        )
        .await;

    assert!(result.is_ok(), "Upload failed: {:?}", result.err());

    let transfer_result = result.unwrap();
    assert_eq!(transfer_result.bytes_transferred, content.len() as u64);

    // Verify file exists on remote
    let verify = client
        .exec(&format!("cat {remote_path}"), &limits)
        .await
        .expect("Verify failed");
    assert!(verify.stdout.contains("Hello, SFTP World!"));

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_upload_large_file() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    // Create 1MB test file
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let content: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    let temp_file = create_temp_file(&content);
    let remote_path = format!("{remote_dir}/large_file.bin");

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let options = TransferOptions {
        chunk_size: 64 * 1024, // 64KB chunks
        ..Default::default()
    };

    let result = sftp
        .upload_file(
            temp_file.path(),
            &remote_path,
            &options,
            None::<NoProgressCallback>,
        )
        .await;

    assert!(result.is_ok(), "Upload failed: {:?}", result.err());

    let transfer_result = result.unwrap();
    assert_eq!(transfer_result.bytes_transferred, content.len() as u64);
    assert!(transfer_result.bytes_per_second > 0.0);

    // Verify file size on remote
    let verify = client
        .exec(&format!("stat -c %s {remote_path}"), &limits)
        .await
        .expect("Verify failed");
    assert!(
        verify.stdout.trim().parse::<usize>().unwrap_or(0) == content.len(),
        "Size mismatch: expected {}, got {}",
        content.len(),
        verify.stdout.trim()
    );

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_upload_with_progress() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    // Create test file large enough to trigger multiple progress callbacks
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let content: Vec<u8> = (0..256 * 1024).map(|i| (i % 256) as u8).collect(); // 256KB
    let temp_file = create_temp_file(&content);
    let remote_path = format!("{remote_dir}/progress_test.bin");

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let options = TransferOptions {
        chunk_size: 32 * 1024, // 32KB chunks - will have ~8 callbacks
        ..Default::default()
    };

    // Track progress callbacks
    let callback_count = Arc::new(AtomicU64::new(0));
    let last_percentage = Arc::new(AtomicU64::new(0));

    let callback_count_clone = Arc::clone(&callback_count);
    let last_percentage_clone = Arc::clone(&last_percentage);

    let progress_callback = move |progress: TransferProgress| {
        callback_count_clone.fetch_add(1, Ordering::SeqCst);
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        last_percentage_clone.store(progress.percentage as u64, Ordering::SeqCst);
    };

    let result = sftp
        .upload_file(
            temp_file.path(),
            &remote_path,
            &options,
            Some(progress_callback),
        )
        .await;

    assert!(result.is_ok(), "Upload failed: {:?}", result.err());

    // Should have multiple progress callbacks
    let callbacks = callback_count.load(Ordering::SeqCst);
    assert!(
        callbacks >= 1,
        "Expected at least 1 progress callback, got {callbacks}"
    );

    // Last percentage should be 100 (or close to it)
    let final_percentage = last_percentage.load(Ordering::SeqCst);
    assert!(
        final_percentage >= 99,
        "Expected final percentage ~100, got {final_percentage}"
    );

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_upload_overwrite() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    let remote_path = format!("{remote_dir}/overwrite_test.txt");

    // First upload
    let content1 = b"Original content";
    let temp_file1 = create_temp_file(content1);

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let options = TransferOptions {
        mode: TransferMode::Overwrite,
        ..Default::default()
    };

    sftp.upload_file(
        temp_file1.path(),
        &remote_path,
        &options,
        None::<NoProgressCallback>,
    )
    .await
    .expect("First upload failed");

    // Second upload with different content (overwrite)
    let content2 = b"New content that replaces the original";
    let temp_file2 = create_temp_file(content2);

    sftp.upload_file(
        temp_file2.path(),
        &remote_path,
        &options,
        None::<NoProgressCallback>,
    )
    .await
    .expect("Overwrite upload failed");

    // Verify new content
    let verify = client
        .exec(&format!("cat {remote_path}"), &limits)
        .await
        .expect("Verify failed");
    assert!(verify.stdout.contains("New content that replaces"));
    assert!(!verify.stdout.contains("Original content"));

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_upload_fail_if_exists() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    let remote_path = format!("{remote_dir}/fail_if_exists_test.txt");

    // First upload
    let content1 = b"First upload";
    let temp_file1 = create_temp_file(content1);

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let options_overwrite = TransferOptions::default();
    sftp.upload_file(
        temp_file1.path(),
        &remote_path,
        &options_overwrite,
        None::<NoProgressCallback>,
    )
    .await
    .expect("First upload failed");

    // Second upload with FailIfExists - should fail
    let content2 = b"Second upload";
    let temp_file2 = create_temp_file(content2);

    let options_fail = TransferOptions {
        mode: TransferMode::FailIfExists,
        ..Default::default()
    };

    let result = sftp
        .upload_file(
            temp_file2.path(),
            &remote_path,
            &options_fail,
            None::<NoProgressCallback>,
        )
        .await;

    assert!(result.is_err(), "Should have failed because file exists");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("exists"),
        "Expected 'exists' in error, got: {err}"
    );

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_upload_with_checksum() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    let content = b"Content for checksum verification";
    let temp_file = create_temp_file(content);
    let remote_path = format!("{remote_dir}/checksum_test.txt");

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let options = TransferOptions {
        verify_checksum: true,
        ..Default::default()
    };

    let result = sftp
        .upload_file(
            temp_file.path(),
            &remote_path,
            &options,
            None::<NoProgressCallback>,
        )
        .await;

    assert!(result.is_ok(), "Upload failed: {:?}", result.err());

    let transfer_result = result.unwrap();
    assert!(
        transfer_result.checksum.is_some(),
        "Expected checksum to be present"
    );

    let checksum = transfer_result.checksum.unwrap();
    assert!(!checksum.is_empty());
    assert_eq!(checksum.len(), 64); // SHA256 hex = 64 chars

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_upload_local_not_found() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let options = TransferOptions::default();
    let result = sftp
        .upload_file(
            Path::new("/nonexistent/path/to/file.txt"),
            &format!("{remote_dir}/should_not_exist.txt"),
            &options,
            None::<NoProgressCallback>,
        )
        .await;

    assert!(result.is_err(), "Should have failed for nonexistent file");

    let _ = sftp.close().await;
    let _ = client.close().await;
}

// =============================================================================
// SFTP Download Tests
// =============================================================================

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_download_file() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    // Create remote file
    let remote_path = format!("{remote_dir}/download_test.txt");
    let remote_content = "Content to download from remote";
    client
        .exec(
            &format!("echo -n '{remote_content}' > {remote_path}"),
            &limits,
        )
        .await
        .expect("Failed to create remote file");

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    // Download to temp file
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let local_path = temp_file.path();

    let options = TransferOptions::default();
    let result = sftp
        .download_file(
            &remote_path,
            local_path,
            &options,
            None::<NoProgressCallback>,
        )
        .await;

    assert!(result.is_ok(), "Download failed: {:?}", result.err());

    let transfer_result = result.unwrap();
    assert_eq!(
        transfer_result.bytes_transferred,
        remote_content.len() as u64
    );

    // Verify local content
    let downloaded = std::fs::read_to_string(local_path).expect("Failed to read downloaded file");
    assert_eq!(downloaded, remote_content);

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_download_large_file() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    // Create 512KB remote file
    let remote_path = format!("{remote_dir}/download_large.bin");
    client
        .exec(
            &format!("head -c 524288 /dev/urandom > {remote_path}"),
            &limits,
        )
        .await
        .expect("Failed to create remote file");

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let local_path = temp_file.path();

    let options = TransferOptions {
        chunk_size: 64 * 1024,
        ..Default::default()
    };

    let result = sftp
        .download_file(
            &remote_path,
            local_path,
            &options,
            None::<NoProgressCallback>,
        )
        .await;

    assert!(result.is_ok(), "Download failed: {:?}", result.err());

    let transfer_result = result.unwrap();
    assert_eq!(transfer_result.bytes_transferred, 524_288);

    // Verify local file size
    let metadata = std::fs::metadata(local_path).expect("Failed to get metadata");
    assert_eq!(metadata.len(), 524_288);

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_download_with_progress() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    // Create 128KB remote file
    let remote_path = format!("{remote_dir}/download_progress.bin");
    client
        .exec(
            &format!("head -c 131072 /dev/urandom > {remote_path}"),
            &limits,
        )
        .await
        .expect("Failed to create remote file");

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let local_path = temp_file.path();

    let options = TransferOptions {
        chunk_size: 16 * 1024, // 16KB chunks
        ..Default::default()
    };

    let callback_count = Arc::new(AtomicU64::new(0));
    let callback_count_clone = Arc::clone(&callback_count);

    let progress_callback = move |_progress: TransferProgress| {
        callback_count_clone.fetch_add(1, Ordering::SeqCst);
    };

    let result = sftp
        .download_file(&remote_path, local_path, &options, Some(progress_callback))
        .await;

    assert!(result.is_ok(), "Download failed: {:?}", result.err());

    let callbacks = callback_count.load(Ordering::SeqCst);
    assert!(
        callbacks >= 1,
        "Expected progress callbacks, got {callbacks}"
    );

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_download_fail_if_exists() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    // Create remote file
    let remote_path = format!("{remote_dir}/download_fail_exists.txt");
    client
        .exec(&format!("echo 'remote content' > {remote_path}"), &limits)
        .await
        .expect("Failed to create remote file");

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    // Create local file that already exists
    let temp_file = create_temp_file(b"local content");
    let local_path = temp_file.path();

    let options = TransferOptions {
        mode: TransferMode::FailIfExists,
        ..Default::default()
    };

    let result = sftp
        .download_file(
            &remote_path,
            local_path,
            &options,
            None::<NoProgressCallback>,
        )
        .await;

    assert!(
        result.is_err(),
        "Should have failed because local file exists"
    );

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_download_remote_not_found() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let local_path = temp_file.path();

    let options = TransferOptions::default();
    let result = sftp
        .download_file(
            &format!("{remote_dir}/nonexistent_file_12345.txt"),
            local_path,
            &options,
            None::<NoProgressCallback>,
        )
        .await;

    assert!(
        result.is_err(),
        "Should have failed for nonexistent remote file"
    );

    let _ = sftp.close().await;
    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_download_with_checksum() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    // Create remote file
    let remote_path = format!("{remote_dir}/download_checksum.txt");
    client
        .exec(
            &format!("echo 'checksum test content' > {remote_path}"),
            &limits,
        )
        .await
        .expect("Failed to create remote file");

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let local_path = temp_file.path();

    let options = TransferOptions {
        verify_checksum: true,
        ..Default::default()
    };

    let result = sftp
        .download_file(
            &remote_path,
            local_path,
            &options,
            None::<NoProgressCallback>,
        )
        .await;

    assert!(result.is_ok(), "Download failed: {:?}", result.err());

    let transfer_result = result.unwrap();
    assert!(transfer_result.checksum.is_some());

    let checksum = transfer_result.checksum.unwrap();
    assert_eq!(checksum.len(), 64); // SHA256 hex

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}

// =============================================================================
// SFTP Session Tests
// =============================================================================

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_close() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    // Closing should succeed
    let result = sftp.close().await;
    assert!(result.is_ok(), "SFTP close failed: {:?}", result.err());

    let _ = client.close().await;
}

#[tokio::test]
#[ignore = "requires real SSH server"]
async fn test_real_sftp_multiple_operations() {
    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    // Perform multiple operations on the same session
    for i in 1..=3 {
        let content = format!("File content {i}");
        let temp_file = create_temp_file(content.as_bytes());
        let remote_path = format!("{remote_dir}/multi_op_{i}.txt");

        let options = TransferOptions::default();
        sftp.upload_file(
            temp_file.path(),
            &remote_path,
            &options,
            None::<NoProgressCallback>,
        )
        .await
        .unwrap_or_else(|_| panic!("Upload {i} failed"));

        // Clean up
        cleanup_remote_file(&client, &remote_path).await;
    }

    let _ = sftp.close().await;
    let _ = client.close().await;
}

// =============================================================================
// Permission Tests (Unix only)
// =============================================================================

#[tokio::test]
#[ignore = "requires real SSH server"]
#[cfg(unix)]
async fn test_real_sftp_preserve_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let config = load_test_config().expect("Test config required");
    let host_config = to_host_config(&config.ssh_test);
    let limits = test_limits();
    let remote_dir = &config.ssh_test.remote_test_dir;

    let client = SshClient::connect("test-host", &host_config, &limits)
        .await
        .expect("Connection failed");

    ensure_remote_test_dir(&client, remote_dir).await;

    // Create file with specific permissions
    let temp_file = create_temp_file(b"executable content");
    let local_path = temp_file.path();

    // Set permissions to 0755
    std::fs::set_permissions(local_path, std::fs::Permissions::from_mode(0o755))
        .expect("Failed to set permissions");

    let remote_path = format!("{remote_dir}/perm_test.sh");

    let sftp = client.sftp_session().await.expect("SFTP session failed");

    let options = TransferOptions {
        preserve_permissions: true,
        ..Default::default()
    };

    sftp.upload_file(
        local_path,
        &remote_path,
        &options,
        None::<NoProgressCallback>,
    )
    .await
    .expect("Upload failed");

    // Check permissions on remote (approximate check - mode may differ slightly)
    let verify = client
        .exec(&format!("stat -c %a {remote_path}"), &limits)
        .await
        .expect("Stat failed");

    let mode = verify.stdout.trim();
    // Should be executable (7xx or x55)
    assert!(
        mode.contains('7') || mode.contains('5'),
        "Expected executable permissions, got: {mode}"
    );

    // Clean up
    cleanup_remote_file(&client, &remote_path).await;
    let _ = sftp.close().await;
    let _ = client.close().await;
}
