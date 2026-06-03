//! End-to-End Integration Tests on Raspberry Pi
//!
//! Tests **50 out of 111 tools** using a stock Raspberry Pi (no extra software).
//! All writes go to `/tmp/bridge-mcp-tests/` and are cleaned up.
//!
//! ## Connection
//! Configured via `tests/ssh_test_config.yaml` (gitignored).
//! See `tests/ssh_test_config.example.yaml` for the expected format.
//!
//! ## Run
//! ```bash
//! cargo test --test e2e_raspberry -- --ignored --test-threads=1
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use bridge_mcp::ExecutorRouter;
use bridge_mcp::config::{
    AuditConfig, AuthConfig, Config, HostConfig, HostKeyVerification, HttpTransportConfig,
    LimitsConfig, OsType, RedactedSecret, SecurityConfig, SessionConfig, SshConfigDiscovery,
    ToolGroupsConfig,
};
use bridge_mcp::domain::history::HistoryConfig;
use bridge_mcp::domain::{CommandHistory, ExecuteCommandUseCase, TunnelManager};
use bridge_mcp::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
use bridge_mcp::ssh::SessionManager;
use bridge_mcp::{ToolContext, ToolHandler};

use bridge_mcp::mcp::tool_handlers::*;

use serde::Deserialize;
use serde_json::json;

// All tests are wrapped in a `rpi` module so their fully qualified test
// names become `rpi::test_*`, which lets the CI coverage job skip them
// cleanly with `--skip rpi::`. `libtest --skip` only matches test-name
// substrings, not file/binary names, so without the module the
// `--skip e2e_raspberry` filter used by tarpaulin never fires.
mod rpi {
    use super::*;

    // =============================================================================
    // Test Configuration (reuses ssh_test_config.yaml)
    // =============================================================================

    const TEST_DIR: &str = "/tmp/bridge-mcp-tests";

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

    fn load_test_config() -> Option<TestConfig> {
        let config_path = Path::new("tests/ssh_test_config.yaml");
        if !config_path.exists() {
            eprintln!("Skipping: tests/ssh_test_config.yaml not found");
            return None;
        }
        let content = std::fs::read_to_string(config_path)
            .expect("Failed to read tests/ssh_test_config.yaml");
        serde_saphyr::from_str(&content).expect("Failed to parse tests/ssh_test_config.yaml")
    }

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
            description: Some("Raspberry Pi test host".to_string()),
            host_key_verification,
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::Linux,
            shell: None,
            retry: None,
            protocol: bridge_mcp::config::Protocol::default(),

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

    /// Build a full `ToolContext` with the Raspberry Pi as "raspberry" host.
    fn build_ctx(host_config: HostConfig) -> ToolContext {
        let mut hosts = HashMap::new();
        hosts.insert("raspberry".to_string(), host_config);

        // Use permissive mode with empty blacklist for E2E tests
        let security = SecurityConfig {
            mode: bridge_mcp::config::SecurityMode::Permissive,
            whitelist: vec![],
            blacklist: vec![],
            ..SecurityConfig::default()
        };

        let config = Config {
            hosts,
            security,
            limits: LimitsConfig {
                command_timeout_seconds: 10,
                connection_timeout_seconds: 10,
                keepalive_interval_seconds: 15,
                max_output_bytes: 1024 * 1024,
                max_concurrent_commands: 5,
                retry_attempts: 2,
                retry_initial_delay_ms: 100,
                rate_limit_per_second: 0,
                ..LimitsConfig::default()
            },
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: bridge_mcp::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let validator = Arc::new(CommandValidator::new(&config.security));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::with_defaults()),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            pending_requests: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    /// Helper: execute a tool handler and return the text content from the result.
    async fn exec_tool(
        handler: &dyn ToolHandler,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> String {
        let result = handler
            .execute(Some(args), ctx)
            .await
            .expect("Tool execution failed");
        assert!(
            result.is_error.is_none() || result.is_error == Some(false),
            "Tool returned error: {:?}",
            result.content
        );
        match &result.content[0] {
            bridge_mcp::ports::protocol::ToolContent::Text { text } => text.clone(),
            _ => panic!("Expected Text content"),
        }
    }

    /// Helper: execute a tool and allow errors (returns (text, `is_error`)).
    /// Handles both `Err(...)` from the handler and `is_error: true` in the result.
    async fn exec_tool_raw(
        handler: &dyn ToolHandler,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> (String, bool) {
        match handler.execute(Some(args), ctx).await {
            Ok(result) => {
                let text = match &result.content[0] {
                    bridge_mcp::ports::protocol::ToolContent::Text { text } => text.clone(),
                    _ => panic!("Expected Text content"),
                };
                (text, result.is_error == Some(true))
            }
            Err(e) => (format!("{e}"), true),
        }
    }

    // =============================================================================
    // Phase 1: Setup & Teardown
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_00_setup_test_directory() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshExecHandler;

        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "command": format!("mkdir -p {TEST_DIR}")}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("Exit code: 0") || text.contains("exit code: 0") || text.contains('0'),
            "mkdir failed: {text}"
        );
    }

    // =============================================================================
    // Phase 2: Core tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_core_ssh_exec() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshExecHandler;

        // Test basic command
        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "command": "uname -a"}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("Linux"),
            "uname should contain 'Linux': {text}"
        );

        // Test working_dir
        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "command": "pwd", "working_dir": "/tmp"}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("/tmp"),
            "pwd in /tmp should show /tmp: {text}"
        );

        // Test failed command (exit code != 0)
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"host": "raspberry", "command": "false"}),
            &ctx,
        )
        .await;
        // A non-zero exit code may or may not be an "error" in MCP terms,
        // but the output should contain exit code info
        assert!(
            text.contains('1') || is_error,
            "false command should show non-zero exit: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_core_ssh_exec_multi() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshExecMultiHandler;

        let text = exec_tool(
            &handler,
            json!({"hosts": ["raspberry"], "command": "hostname"}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("succeeded") || text.contains("total_hosts"),
            "Multi-exec should return structured result: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_core_ssh_status() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshStatusHandler;

        let text = exec_tool(&handler, json!({}), &ctx).await;
        assert!(
            text.contains("raspberry"),
            "Status should list raspberry host: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_core_ssh_health() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshHealthHandler;

        let text = exec_tool(&handler, json!({}), &ctx).await;
        assert!(
            text.contains("Connection Pool") || text.contains("Configuration"),
            "Health should show diagnostics: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_core_ssh_history() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));

        // Execute a command first to populate history
        let exec_handler = SshExecHandler;
        let _ = exec_tool(
            &exec_handler,
            json!({"host": "raspberry", "command": "echo history_test"}),
            &ctx,
        )
        .await;

        // Now query history
        let history_handler = SshHistoryHandler;
        let text = exec_tool(&history_handler, json!({"limit": 5}), &ctx).await;
        assert!(
            text.contains("history_test") || text.contains("echo"),
            "History should contain previous command: {text}"
        );
    }

    // =============================================================================
    // Phase 3: File Transfer tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_file_upload() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));

        // Create local temp file
        let local_path = "/tmp/mcp-e2e-upload-test.txt";
        std::fs::write(local_path, "hello from e2e test").expect("Failed to create local file");

        // Ensure remote dir exists
        let exec_handler = SshExecHandler;
        let _ = exec_tool(
            &exec_handler,
            json!({"host": "raspberry", "command": format!("mkdir -p {TEST_DIR}")}),
            &ctx,
        )
        .await;

        // Upload
        let upload_handler = SshUploadHandler;
        let text = exec_tool(
            &upload_handler,
            json!({
                "host": "raspberry",
                "local_path": local_path,
                "remote_path": format!("{TEST_DIR}/uploaded.txt")
            }),
            &ctx,
        )
        .await;
        assert!(
            text.contains("bytes") || text.contains("success") || text.contains("Upload"),
            "Upload should succeed: {text}"
        );

        // Verify remote content
        let text = exec_tool(
            &exec_handler,
            json!({"host": "raspberry", "command": format!("cat {TEST_DIR}/uploaded.txt")}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("hello from e2e test"),
            "Remote file should contain uploaded content: {text}"
        );

        // Cleanup
        std::fs::remove_file(local_path).ok();
        let _ = exec_tool(
            &exec_handler,
            json!({"host": "raspberry", "command": format!("rm -f {TEST_DIR}/uploaded.txt")}),
            &ctx,
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_file_download() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let exec_handler = SshExecHandler;

        // Create remote file
        let _ = exec_tool(
        &exec_handler,
        json!({"host": "raspberry", "command": format!("mkdir -p {TEST_DIR} && echo 'download test content' > {TEST_DIR}/to_download.txt")}),
        &ctx,
    )
    .await;

        // Download
        let local_path = "/tmp/mcp-e2e-download-test.txt";
        let download_handler = SshDownloadHandler;
        let text = exec_tool(
            &download_handler,
            json!({
                "host": "raspberry",
                "remote_path": format!("{TEST_DIR}/to_download.txt"),
                "local_path": local_path
            }),
            &ctx,
        )
        .await;
        assert!(
            text.contains("bytes") || text.contains("success") || text.contains("Download"),
            "Download should succeed: {text}"
        );

        // Verify local content
        let content = std::fs::read_to_string(local_path).expect("Downloaded file should exist");
        assert!(
            content.contains("download test content"),
            "Downloaded content mismatch: {content}"
        );

        // Cleanup
        std::fs::remove_file(local_path).ok();
        let _ = exec_tool(
            &exec_handler,
            json!({"host": "raspberry", "command": format!("rm -f {TEST_DIR}/to_download.txt")}),
            &ctx,
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_file_sync() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let exec_handler = SshExecHandler;

        // Create local directory with files
        let local_dir = "/tmp/mcp-e2e-sync-src";
        std::fs::create_dir_all(local_dir).expect("Failed to create sync dir");
        std::fs::write(format!("{local_dir}/file1.txt"), "sync file 1").unwrap();
        std::fs::write(format!("{local_dir}/file2.txt"), "sync file 2").unwrap();

        // Ensure remote dir
        let _ = exec_tool(
            &exec_handler,
            json!({"host": "raspberry", "command": format!("mkdir -p {TEST_DIR}/synced")}),
            &ctx,
        )
        .await;

        // Sync upload
        let sync_handler = SshSyncHandler;
        let text = exec_tool(
            &sync_handler,
            json!({
                "host": "raspberry",
                "source": local_dir,
                "destination": format!("{TEST_DIR}/synced"),
                "direction": "upload"
            }),
            &ctx,
        )
        .await;
        assert!(
            text.contains("file") || text.contains("sync") || text.contains("Sync"),
            "Sync should report results: {text}"
        );

        // Verify remote files exist
        let text = exec_tool(
            &exec_handler,
            json!({"host": "raspberry", "command": format!("ls {TEST_DIR}/synced/")}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("file1.txt") && text.contains("file2.txt"),
            "Remote should have both synced files: {text}"
        );

        // Cleanup
        std::fs::remove_dir_all(local_dir).ok();
        let _ = exec_tool(
            &exec_handler,
            json!({"host": "raspberry", "command": format!("rm -rf {TEST_DIR}/synced")}),
            &ctx,
        )
        .await;
    }

    // =============================================================================
    // Phase 4: Session tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_session_lifecycle() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));

        // Create session
        let create_handler = SshSessionCreateHandler;
        let text = exec_tool(&create_handler, json!({"host": "raspberry"}), &ctx).await;
        assert!(
            text.contains("id") || text.contains("session"),
            "Create should return session info: {text}"
        );

        // Extract session_id from JSON output ({"id": "uuid", "host": ...})
        let session_id = {
            let v: serde_json::Value = serde_json::from_str(&text)
                .unwrap_or_else(|_| panic!("Session create output not JSON: {text}"));
            v["id"]
                .as_str()
                .unwrap_or_else(|| panic!("No 'id' field in session output: {text}"))
                .to_string()
        };

        // Execute in session: test working directory persistence
        let exec_handler = SshSessionExecHandler;
        let _ = exec_tool(
            &exec_handler,
            json!({"session_id": &session_id, "command": "cd /tmp"}),
            &ctx,
        )
        .await;

        let text = exec_tool(
            &exec_handler,
            json!({"session_id": &session_id, "command": "pwd"}),
            &ctx,
        )
        .await;
        assert!(text.contains("/tmp"), "Session should remember cd: {text}");

        // List sessions
        let list_handler = SshSessionListHandler;
        let text = exec_tool(&list_handler, json!({}), &ctx).await;
        assert!(
            text.contains(&session_id) || text.contains("raspberry"),
            "List should show our session: {text}"
        );

        // Close session
        let close_handler = SshSessionCloseHandler;
        let text = exec_tool(&close_handler, json!({"session_id": &session_id}), &ctx).await;
        assert!(
            text.contains("closed") || text.contains("Close") || text.contains("success"),
            "Close should confirm: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_session_close_invalid() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));

        let handler = SshSessionCloseHandler;
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"session_id": "nonexistent-session-id"}),
            &ctx,
        )
        .await;
        assert!(is_error, "Closing invalid session should error: {text}");
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_session_exec_invalid() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));

        let handler = SshSessionExecHandler;
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"session_id": "nonexistent-session-id", "command": "echo test"}),
            &ctx,
        )
        .await;
        assert!(is_error, "Exec on invalid session should error: {text}");
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_session_list_empty() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));

        let handler = SshSessionListHandler;
        let text = exec_tool(&handler, json!({}), &ctx).await;
        assert!(
            text.contains('0') || text.contains("No") || text.contains("empty"),
            "Empty session list should indicate none: {text}"
        );
    }

    // =============================================================================
    // Phase 5: Monitoring tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_monitoring_metrics() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));

        let handler = SshMetricsHandler;
        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "metrics": ["cpu", "memory", "disk", "load"]}),
            &ctx,
        )
        .await;

        // Should contain structured metrics
        assert!(
            text.contains("cpu") || text.contains("CPU"),
            "Should have CPU metrics: {text}"
        );
        assert!(
            text.contains("memory") || text.contains("Memory") || text.contains("total"),
            "Should have memory metrics: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_monitoring_metrics_multi() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));

        let handler = SshMetricsMultiHandler;
        let text = exec_tool(
            &handler,
            json!({"hosts": ["raspberry"], "metrics": ["cpu", "memory"]}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("raspberry") || text.contains("succeeded"),
            "Multi metrics should show results: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_monitoring_tail() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let exec_handler = SshExecHandler;

        // Create a log file
        let _ = exec_tool(
        &exec_handler,
        json!({"host": "raspberry", "command": format!(
            "mkdir -p {TEST_DIR} && seq 1 50 | while read i; do echo \"line $i\"; done > {TEST_DIR}/test.log"
        )}),
        &ctx,
    )
    .await;

        // Tail last 10 lines
        let tail_handler = SshTailHandler;
        let text = exec_tool(
            &tail_handler,
            json!({
                "host": "raspberry",
                "file": format!("{TEST_DIR}/test.log"),
                "lines": 10
            }),
            &ctx,
        )
        .await;
        assert!(
            text.contains("line 50"),
            "Tail should show last lines: {text}"
        );

        // Tail with grep filter
        let text = exec_tool(
            &tail_handler,
            json!({
                "host": "raspberry",
                "file": format!("{TEST_DIR}/test.log"),
                "lines": 50,
                "grep": "line 4"
            }),
            &ctx,
        )
        .await;
        assert!(
            text.contains("line 4"),
            "Grep filtered tail should contain 'line 4': {text}"
        );

        // Cleanup
        let _ = exec_tool(
            &exec_handler,
            json!({"host": "raspberry", "command": format!("rm -f {TEST_DIR}/test.log")}),
            &ctx,
        )
        .await;
    }

    // =============================================================================
    // Phase 6: Tunnel tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_tunnel_list_empty() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));

        let handler = SshTunnelListHandler;
        let text = exec_tool(&handler, json!({}), &ctx).await;
        assert!(
            text.contains('0') || text.contains("No") || text.contains("empty"),
            "Empty tunnel list: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_tunnel_close_invalid() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));

        let handler = SshTunnelCloseHandler;
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"tunnel_id": "nonexistent-tunnel-id"}),
            &ctx,
        )
        .await;
        assert!(is_error, "Closing invalid tunnel should error: {text}");
    }

    // =============================================================================
    // Phase 7: Directory tool
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_directory_ls() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let exec_handler = SshExecHandler;

        // Create test directory with files
        let _ = exec_tool(
        &exec_handler,
        json!({"host": "raspberry", "command": format!(
            "mkdir -p {TEST_DIR}/ls_test && echo a > {TEST_DIR}/ls_test/file_a.txt && echo b > {TEST_DIR}/ls_test/file_b.txt && echo c > {TEST_DIR}/ls_test/file_c.txt"
        )}),
        &ctx,
    )
    .await;

        // List directory
        let ls_handler = SshLsHandler;
        let text = exec_tool(
            &ls_handler,
            json!({
                "host": "raspberry",
                "path": format!("{TEST_DIR}/ls_test/")
            }),
            &ctx,
        )
        .await;
        assert!(text.contains("file_a"), "ls should list file_a: {text}");
        assert!(text.contains("file_b"), "ls should list file_b: {text}");
        assert!(text.contains("file_c"), "ls should list file_c: {text}");

        // Cleanup
        let _ = exec_tool(
            &exec_handler,
            json!({"host": "raspberry", "command": format!("rm -rf {TEST_DIR}/ls_test")}),
            &ctx,
        )
        .await;
    }

    // =============================================================================
    // Phase 8: Backup tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_backup_create() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let exec_handler = SshExecHandler;

        // Create source files
        let _ = exec_tool(
        &exec_handler,
        json!({"host": "raspberry", "command": format!(
            "mkdir -p {TEST_DIR}/backup_src && echo 'backup content 1' > {TEST_DIR}/backup_src/data1.txt && echo 'backup content 2' > {TEST_DIR}/backup_src/data2.txt"
        )}),
        &ctx,
    )
    .await;

        // Create backup
        let backup_handler = SshBackupCreateHandler::new();
        let text = exec_tool(
            &backup_handler,
            json!({
                "host": "raspberry",
                "source_paths": [format!("{TEST_DIR}/backup_src")],
                "output_file": format!("{TEST_DIR}/backup.tar.gz"),
                "compress": "gzip"
            }),
            &ctx,
        )
        .await;
        assert!(
            text.contains("backup") || text.contains("Backup") || text.contains("tar"),
            "Backup create should succeed: {text}"
        );

        // Verify archive exists
        let text = exec_tool(
            &exec_handler,
            json!({"host": "raspberry", "command": format!("ls -la {TEST_DIR}/backup.tar.gz")}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("backup.tar.gz"),
            "Archive should exist: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_backup_list() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let exec_handler = SshExecHandler;

        // Ensure backup exists (create if needed)
        let _ = exec_tool(
        &exec_handler,
        json!({"host": "raspberry", "command": format!(
            "mkdir -p {TEST_DIR}/backup_src && echo x > {TEST_DIR}/backup_src/data1.txt && echo y > {TEST_DIR}/backup_src/data2.txt && tar czf {TEST_DIR}/backup.tar.gz -C {TEST_DIR} backup_src"
        )}),
        &ctx,
    )
    .await;

        // List backup contents
        let list_handler = SshBackupListHandler::new();
        let text = exec_tool(
            &list_handler,
            json!({
                "host": "raspberry",
                "archive_file": format!("{TEST_DIR}/backup.tar.gz")
            }),
            &ctx,
        )
        .await;
        assert!(
            text.contains("data1") || text.contains("backup_src"),
            "Backup list should show contents: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_backup_restore() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let exec_handler = SshExecHandler;

        // Ensure backup exists
        let _ = exec_tool(
        &exec_handler,
        json!({"host": "raspberry", "command": format!(
            "mkdir -p {TEST_DIR}/backup_src && echo restored > {TEST_DIR}/backup_src/data1.txt && tar czf {TEST_DIR}/backup.tar.gz -C {TEST_DIR} backup_src"
        )}),
        &ctx,
    )
    .await;

        // Restore
        let restore_handler = SshBackupRestoreHandler::new();
        let text = exec_tool(
            &restore_handler,
            json!({
                "host": "raspberry",
                "archive_file": format!("{TEST_DIR}/backup.tar.gz"),
                "destination": format!("{TEST_DIR}/restored")
            }),
            &ctx,
        )
        .await;
        assert!(
            text.contains("restore") || text.contains("Restore") || text.contains("extract"),
            "Restore should succeed: {text}"
        );

        // Verify restored content
        let text = exec_tool(
        &exec_handler,
        json!({"host": "raspberry", "command": format!("cat {TEST_DIR}/restored/backup_src/data1.txt")}),
        &ctx,
    )
    .await;
        assert!(
            text.contains("restored"),
            "Restored file should contain original content: {text}"
        );
    }

    // =============================================================================
    // Phase 9: Security tests
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_security_command_denied() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let host_config = to_host_config(&config.ssh_test);

        // Build ctx with strict security (only allow safe commands)
        let mut hosts = HashMap::new();
        hosts.insert("raspberry".to_string(), host_config);

        let security = SecurityConfig {
            mode: bridge_mcp::config::SecurityMode::Strict,
            whitelist: vec!["uname".to_string(), "ls".to_string(), "echo".to_string()],
            ..SecurityConfig::default()
        };

        let mcp_config = Config {
            hosts,
            security: security.clone(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: bridge_mcp::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let validator = Arc::new(CommandValidator::new(&security));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        let ctx = ToolContext {
            config: Arc::new(mcp_config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::with_defaults()),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            pending_requests: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        };

        let handler = SshExecHandler;

        // Allowed command should succeed
        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "command": "uname"}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("Linux"),
            "Allowed command should work: {text}"
        );

        // Denied command should be blocked (never reaches the RPi)
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"host": "raspberry", "command": "rm -rf /"}),
            &ctx,
        )
        .await;
        assert!(is_error, "Dangerous command should be denied: {text}");
        assert!(
            text.contains("denied") || text.contains("Denied") || text.contains("blocked"),
            "Error should mention denial: {text}"
        );
    }

    // =============================================================================
    // Phase 10: Robustness tests
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_robustness_timeout() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshExecHandler;

        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"host": "raspberry", "command": "sleep 30", "timeout_seconds": 2}),
            &ctx,
        )
        .await;
        assert!(
            is_error || text.contains("timeout") || text.contains("Timeout"),
            "Sleep 30 with 2s timeout should timeout: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_robustness_large_output() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshExecHandler;

        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "command": "seq 1 100000", "max_output": 5000}),
            &ctx,
        )
        .await;
        // Output should be present and possibly truncated
        assert!(!text.is_empty(), "Should have output");
        // The output should contain the beginning (seq starts at 1)
        assert!(
            text.contains('1'),
            "Output should contain start of sequence"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_robustness_unicode() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshExecHandler;

        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "command": "echo 'Hello Unicode: àéîõü 日本語'"}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("àéîõü") && text.contains("日本語"),
            "Unicode should be preserved: {text}"
        );
    }

    // =============================================================================
    // Phase 11: Systemd tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase11_service_status() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshServiceStatusHandler::new();

        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "service": "ssh"}),
            &ctx,
        )
        .await;
        assert!(
            text.to_lowercase().contains("ssh"),
            "Service status should mention ssh: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase11_service_list() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshServiceListHandler::new();

        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "state": "running"}),
            &ctx,
        )
        .await;
        assert!(
            text.to_lowercase().contains("ssh"),
            "Running services should include ssh: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase11_service_logs() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshServiceLogsHandler::new();

        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "service": "ssh", "lines": 10}),
            &ctx,
        )
        .await;
        assert!(!text.is_empty(), "Service logs should not be empty: {text}");
    }

    // =============================================================================
    // Phase 12: Network tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase12_net_connections() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshNetConnectionsHandler::new();

        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "listening": true}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("LISTEN") || text.contains("listen") || text.contains(":22"),
            "Listening connections should show SSH port: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase12_net_interfaces() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshNetInterfacesHandler::new();

        let text = exec_tool(&handler, json!({"host": "raspberry"}), &ctx).await;
        assert!(
            text.contains("eth0") || text.contains("wlan0") || text.contains("lo"),
            "Should list network interfaces: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase12_net_routes() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshNetRoutesHandler::new();

        let text = exec_tool(&handler, json!({"host": "raspberry"}), &ctx).await;
        assert!(
            text.contains("default") || text.contains("0.0.0.0"),
            "Routes should include default gateway: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase12_net_ping() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshNetPingHandler::new();

        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "target": "127.0.0.1", "count": 2}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("2 packets") || text.contains("2 received"),
            "Ping should report 2 packets: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase12_net_traceroute() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshNetTracerouteHandler::new();

        // traceroute may not be installed — tolerate errors
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"host": "raspberry", "target": "127.0.0.1"}),
            &ctx,
        )
        .await;
        if !is_error {
            assert!(
                text.contains("127.0.0.1") || text.contains("localhost"),
                "Traceroute to localhost should resolve: {text}"
            );
        }
        // If is_error, traceroute not installed — that's OK
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase12_net_dns() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshNetDnsHandler::new();

        // dig/nslookup may not be installed — tolerate errors
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"host": "raspberry", "domain": "localhost"}),
            &ctx,
        )
        .await;
        if !is_error {
            assert!(
                !text.is_empty(),
                "DNS lookup should return something: {text}"
            );
        }
    }

    // =============================================================================
    // Phase 13: Process tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase13_process_list() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshProcessListHandler::new();

        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "filter": "sshd"}),
            &ctx,
        )
        .await;
        assert!(
            text.contains("sshd"),
            "Process list filtered by sshd should contain sshd: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase13_process_top() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshProcessTopHandler::new();

        let text = exec_tool(&handler, json!({"host": "raspberry", "count": 5}), &ctx).await;
        assert!(
            !text.is_empty(),
            "Top processes should not be empty: {text}"
        );
    }

    // =============================================================================
    // Phase 14: Package tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase14_pkg_list() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshPkgListHandler::new();

        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "filter": "ssh"}),
            &ctx,
        )
        .await;
        assert!(
            text.to_lowercase().contains("ssh"),
            "Package list should contain ssh packages: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase14_pkg_search() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshPkgSearchHandler::new();

        let text = exec_tool(
            &handler,
            json!({"host": "raspberry", "query": "curl"}),
            &ctx,
        )
        .await;
        assert!(
            text.to_lowercase().contains("curl"),
            "Package search for curl should find results: {text}"
        );
    }

    // =============================================================================
    // Phase 15: Cron tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase15_cron_list() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshCronListHandler::new();

        // Crontab may be empty — tolerate errors
        let (_text, _is_error) =
            exec_tool_raw(&handler, json!({"host": "raspberry", "system": true}), &ctx).await;
        // Just verifying it doesn't panic; cron list may be empty
    }

    // =============================================================================
    // Phase 16: Certificate tools
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase16_cert_check() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshCertCheckHandler::new();

        // openssl may not be installed or network may block 443
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"host": "raspberry", "target": "google.com", "port": 443}),
            &ctx,
        )
        .await;
        if !is_error {
            assert!(
                text.to_lowercase().contains("certificate")
                    || text.contains("issuer")
                    || text.contains("subject"),
                "Certificate check should show cert info: {text}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase16_cert_info() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshCertInfoHandler::new();

        // ca-certificates.crt should exist on most Linux systems
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"host": "raspberry", "path": "/etc/ssl/certs/ca-certificates.crt"}),
            &ctx,
        )
        .await;
        if !is_error {
            assert!(
                !text.is_empty(),
                "Certificate info should return something: {text}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase16_cert_expiry() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshCertExpiryHandler::new();

        // openssl may not be installed or network may block 443
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"host": "raspberry", "target": "google.com"}),
            &ctx,
        )
        .await;
        if !is_error {
            assert!(
                !text.is_empty(),
                "Certificate expiry should return something: {text}"
            );
        }
    }

    // =============================================================================
    // Phase 17: Firewall tools (read-only)
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase17_firewall_status() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshFirewallStatusHandler::new();

        // ufw/iptables/firewalld may not be configured
        let (_text, _is_error) = exec_tool_raw(&handler, json!({"host": "raspberry"}), &ctx).await;
        // Just verifying it doesn't panic
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase17_firewall_list() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshFirewallListHandler::new();

        // ufw/iptables/firewalld may not be configured
        let (_text, _is_error) = exec_tool_raw(&handler, json!({"host": "raspberry"}), &ctx).await;
        // Just verifying it doesn't panic
    }

    // =============================================================================
    // Phase 18: Nginx tools (read-only, optional)
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase18_nginx_status() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshNginxStatusHandler::new();

        let (_text, _is_error) = exec_tool_raw(&handler, json!({"host": "raspberry"}), &ctx).await;
        // Nginx may not be installed — just verifying no panic
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase18_nginx_test() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshNginxTestHandler::new();

        let (_text, _is_error) = exec_tool_raw(&handler, json!({"host": "raspberry"}), &ctx).await;
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase18_nginx_list_sites() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshNginxListSitesHandler::new();

        let (_text, _is_error) = exec_tool_raw(&handler, json!({"host": "raspberry"}), &ctx).await;
    }

    // =============================================================================
    // Phase 19: Redis tools (read-only, optional)
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase19_redis_info() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshRedisInfoHandler::new();

        let (_text, _is_error) = exec_tool_raw(&handler, json!({"host": "raspberry"}), &ctx).await;
        // Redis may not be installed — just verifying no panic
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase19_redis_keys() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshRedisKeysHandler::new();

        let (_text, _is_error) =
            exec_tool_raw(&handler, json!({"host": "raspberry", "pattern": "*"}), &ctx).await;
    }

    // =============================================================================
    // Phase 20: Security validation tests (no SSH execution)
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase20_service_name_injection() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshServiceStatusHandler::new();

        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"host": "raspberry", "service": "ssh; rm -rf /"}),
            &ctx,
        )
        .await;
        assert!(
            is_error,
            "Service name with injection should be rejected: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase20_empty_service_name() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshServiceStatusHandler::new();

        let (text, is_error) =
            exec_tool_raw(&handler, json!({"host": "raspberry", "service": ""}), &ctx).await;
        assert!(is_error, "Empty service name should be rejected: {text}");
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase20_ping_target_escaping() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshNetPingHandler::new();

        // Injection attempt in ping target — should be escaped or rejected
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({"host": "raspberry", "target": "127.0.0.1; whoami", "count": 1}),
            &ctx,
        )
        .await;
        // Either rejected outright or the injected command is NOT executed
        if !is_error {
            assert!(
                !text.contains("muchini") && !text.contains("root"),
                "Injected whoami should not execute: {text}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase20_cron_schedule_injection() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshCronAddHandler::new();

        // Schedule with newline injection — should be rejected by builder validation
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({
                "host": "raspberry",
                "schedule": "* * * * *\nmalicious",
                "command": "echo test"
            }),
            &ctx,
        )
        .await;
        assert!(
            is_error,
            "Cron schedule with newline injection should be rejected: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_phase20_firewall_source_injection() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshFirewallAllowHandler::new();

        // Source with shell injection — should be rejected by validate_source()
        let (text, is_error) = exec_tool_raw(
            &handler,
            json!({
                "host": "raspberry",
                "port": "80",
                "source": "10.0.0.1; rm -rf /"
            }),
            &ctx,
        )
        .await;
        assert!(
            is_error,
            "Firewall source with injection should be rejected: {text}"
        );
    }

    // =============================================================================
    // Phase 99: Cleanup
    // =============================================================================

    #[tokio::test]
    #[ignore = "requires Raspberry Pi"]
    async fn test_99_cleanup_test_directory() {
        let config = load_test_config().expect("Need tests/ssh_test_config.yaml");
        let ctx = build_ctx(to_host_config(&config.ssh_test));
        let handler = SshExecHandler;

        let _ = exec_tool(
            &handler,
            json!({"host": "raspberry", "command": format!("rm -rf {TEST_DIR}")}),
            &ctx,
        )
        .await;
    }
} // mod rpi
