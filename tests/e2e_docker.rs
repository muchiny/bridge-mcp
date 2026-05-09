//! Docker-based End-to-End Integration Tests
//!
//! Tests the **full pipeline** including real SSH execution against an
//! OpenSSH server running in Docker.
//!
//! ## Prerequisites
//! ```bash
//! docker compose -f docker-compose.test.yml up -d
//! # Wait for healthcheck to pass (~5-10s)
//! ```
//!
//! ## Run
//! ```bash
//! cargo test --test e2e_docker -- --ignored --test-threads=1
//! ```
//!
//! ## Cleanup
//! ```bash
//! docker compose -f docker-compose.test.yml down -v
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use mcp_ssh_bridge::ExecutorRouter;
use mcp_ssh_bridge::config::{
    AuditConfig, AuthConfig, Config, HostConfig, HostKeyVerification, HttpTransportConfig,
    LimitsConfig, OsType, SecurityConfig, SecurityMode, SessionConfig, SshConfigDiscovery,
    ToolGroupsConfig,
};
use mcp_ssh_bridge::domain::history::HistoryConfig;
use mcp_ssh_bridge::domain::{CommandHistory, ExecuteCommandUseCase, TunnelManager};
use mcp_ssh_bridge::ports::protocol::ToolContent;
use mcp_ssh_bridge::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
use mcp_ssh_bridge::ssh::SessionManager;
use mcp_ssh_bridge::{BridgeError, ToolContext, ToolHandler};

use mcp_ssh_bridge::mcp::tool_handlers::*;

use serde_json::json;

const TEST_DIR: &str = "/tmp/mcp-ssh-bridge-tests";

// =============================================================================
// Context Builder
// =============================================================================

/// Build a `ToolContext` pointing to the Docker SSH server at `127.0.0.1:2222`.
fn build_docker_ctx() -> ToolContext {
    let mut hosts = HashMap::new();
    hosts.insert(
        "docker".to_string(),
        HostConfig {
            hostname: "127.0.0.1".to_string(),
            port: 2222,
            user: "testuser".to_string(),
            auth: AuthConfig::Password {
                password: zeroize::Zeroizing::new("testpass123".to_string()),
            },
            description: Some("Docker test SSH server".to_string()),
            host_key_verification: HostKeyVerification::Off,
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: Some(zeroize::Zeroizing::new("testpass123".to_string())),
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
        },
    );

    let security = SecurityConfig {
        mode: SecurityMode::Permissive,
        whitelist: vec![],
        blacklist: vec![],
        ..SecurityConfig::default()
    };

    let config = Config {
        hosts,
        security: security.clone(),
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
        rbac: mcp_ssh_bridge::security::rbac::RbacConfig::default(),
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

/// Helper: execute a tool handler and return the text content.
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
        ToolContent::Text { text } => text.clone(),
        _ => panic!("Expected Text content"),
    }
}

/// Helper: execute a tool and allow errors.
async fn exec_tool_raw(
    handler: &dyn ToolHandler,
    args: serde_json::Value,
    ctx: &ToolContext,
) -> (String, bool) {
    match handler.execute(Some(args), ctx).await {
        Ok(result) => {
            let text = match &result.content[0] {
                ToolContent::Text { text } => text.clone(),
                _ => panic!("Expected Text content"),
            };
            (text, result.is_error == Some(true))
        }
        Err(e) => (format!("{e}"), true),
    }
}

/// Check if Docker SSH is reachable. Skip tests if not.
async fn require_docker_ssh() -> ToolContext {
    let ctx = build_docker_ctx();
    let handler = SshExecHandler;
    match handler
        .execute(Some(json!({"host": "docker", "command": "echo ok"})), &ctx)
        .await
    {
        Ok(result) => {
            assert_ne!(
                result.is_error,
                Some(true),
                "Docker SSH server not available. Run: docker compose -f docker-compose.test.yml up -d"
            );
        }
        Err(e) => {
            panic!(
                "Docker SSH server not available ({e}). Run: docker compose -f docker-compose.test.yml up -d"
            );
        }
    }
    ctx
}

// =============================================================================
// Phase 1: Connection & Core Commands
// =============================================================================

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_ssh_exec_uname() {
    let ctx = require_docker_ssh().await;
    let handler = SshExecHandler;
    let text = exec_tool(
        &handler,
        json!({"host": "docker", "command": "uname -a"}),
        &ctx,
    )
    .await;
    assert!(text.contains("Linux"), "uname should contain Linux: {text}");
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_ssh_exec_whoami() {
    let ctx = require_docker_ssh().await;
    let handler = SshExecHandler;
    let text = exec_tool(
        &handler,
        json!({"host": "docker", "command": "whoami"}),
        &ctx,
    )
    .await;
    assert!(
        text.contains("testuser"),
        "whoami should return testuser: {text}"
    );
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_ssh_exec_working_dir() {
    let ctx = require_docker_ssh().await;
    let handler = SshExecHandler;
    let text = exec_tool(
        &handler,
        json!({"host": "docker", "command": "pwd", "working_dir": "/tmp"}),
        &ctx,
    )
    .await;
    assert!(text.contains("/tmp"), "Should run in /tmp: {text}");
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_ssh_exec_nonzero_exit() {
    let ctx = require_docker_ssh().await;
    let handler = SshExecHandler;
    let result = handler
        .execute(Some(json!({"host": "docker", "command": "false"})), &ctx)
        .await
        .unwrap();
    // "false" returns exit code 1 — should be reflected in structured content
    if let Some(structured) = &result.structured_content {
        assert_ne!(structured["exit_code"], 0);
    }
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_ssh_status() {
    let ctx = require_docker_ssh().await;
    let handler = SshStatusHandler;
    let text = exec_tool(&handler, json!({}), &ctx).await;
    assert!(
        text.contains("docker"),
        "Status should list docker host: {text}"
    );
}

// =============================================================================
// Phase 2: File Operations
// =============================================================================

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_file_write_and_read() {
    let ctx = require_docker_ssh().await;
    let test_file = format!("{TEST_DIR}/e2e_test.txt");
    let test_content = "Hello from E2E Docker test!";

    // Write file. The shell path (content < sftp_write_threshold_bytes,
    // default 64 KiB) returns the raw stdout of the write command, which
    // is empty on success — so we don't assert on the response text here.
    // The read-back below is the actual semantic check that the write
    // landed on disk.
    let write_handler = SshFileWriteHandler;
    let _ = exec_tool(
        &write_handler,
        json!({"host": "docker", "path": &test_file, "content": test_content}),
        &ctx,
    )
    .await;

    // Read it back
    let read_handler = SshFileReadHandler::new();
    let text = exec_tool(
        &read_handler,
        json!({"host": "docker", "path": &test_file}),
        &ctx,
    )
    .await;
    assert!(
        text.contains(test_content),
        "Should read back the written content: {text}"
    );

    // Cleanup
    let handler = SshExecHandler;
    let _ = exec_tool(
        &handler,
        json!({"host": "docker", "command": format!("rm -f {test_file}")}),
        &ctx,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_ls() {
    let ctx = require_docker_ssh().await;
    let handler = SshLsHandler;
    let text = exec_tool(&handler, json!({"host": "docker", "path": "/tmp"}), &ctx).await;
    // /tmp always has content on a running system
    assert!(!text.is_empty(), "ls /tmp should return content");
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_find() {
    let ctx = require_docker_ssh().await;

    // Create a test file first
    let handler = SshExecHandler;
    let _ = exec_tool(
        &handler,
        json!({"host": "docker", "command": format!("touch {TEST_DIR}/findme.txt")}),
        &ctx,
    )
    .await;

    let find_handler = SshFindHandler;
    let text = exec_tool(
        &find_handler,
        json!({"host": "docker", "path": TEST_DIR, "name": "findme.txt"}),
        &ctx,
    )
    .await;
    assert!(
        text.contains("findme.txt"),
        "find should locate the file: {text}"
    );

    // Cleanup
    let _ = exec_tool(
        &handler,
        json!({"host": "docker", "command": format!("rm -f {TEST_DIR}/findme.txt")}),
        &ctx,
    )
    .await;
}

// =============================================================================
// Phase 3: System Information
// =============================================================================

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_process_list() {
    let ctx = require_docker_ssh().await;
    let handler = SshProcessListHandler::new();
    let text = exec_tool(&handler, json!({"host": "docker"}), &ctx).await;
    // Should contain at least sshd or some process
    assert!(!text.is_empty(), "Process list should not be empty");
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_net_interfaces() {
    let ctx = require_docker_ssh().await;
    let handler = SshNetInterfacesHandler::new();
    let text = exec_tool(&handler, json!({"host": "docker"}), &ctx).await;
    // Should have at least lo or eth0
    assert!(
        text.contains("lo") || text.contains("eth") || text.contains("inet"),
        "Should list network interfaces: {text}"
    );
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_disk_usage() {
    let ctx = require_docker_ssh().await;
    let handler = SshDiskUsageHandler;
    let text = exec_tool(&handler, json!({"host": "docker"}), &ctx).await;
    assert!(!text.is_empty(), "Disk usage should return data");
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_net_dns() {
    let ctx = require_docker_ssh().await;
    let handler = SshNetDnsHandler::new();
    let (text, _is_error) = exec_tool_raw(
        &handler,
        json!({"host": "docker", "domain": "localhost"}),
        &ctx,
    )
    .await;
    // DNS lookup for localhost may succeed or fail depending on container config
    assert!(!text.is_empty(), "DNS query should return something");
}

// =============================================================================
// Phase 4: Security Pipeline (Full E2E)
// =============================================================================

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_command_denied_by_blacklist() {
    // Create ctx with a blacklist
    let mut ctx = build_docker_ctx();
    let security = SecurityConfig {
        mode: SecurityMode::Permissive,
        whitelist: vec![],
        blacklist: vec![r"rm\s+-rf\s+/".to_string()],
        ..SecurityConfig::default()
    };
    let validator = Arc::new(CommandValidator::new(&security));
    let sanitizer = Arc::clone(&ctx.sanitizer);
    let audit_logger = Arc::clone(&ctx.audit_logger);
    let history = Arc::clone(&ctx.history);
    ctx.execute_use_case = Arc::new(ExecuteCommandUseCase::new(
        Arc::clone(&validator),
        sanitizer,
        audit_logger,
        history,
    ));
    ctx.validator = validator;

    let handler = SshExecHandler;
    let err = handler
        .execute(Some(json!({"host": "docker", "command": "rm -rf /"})), &ctx)
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::CommandDenied { .. }));
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_output_sanitization() {
    let ctx = require_docker_ssh().await;
    let handler = SshExecHandler;
    // Echo something that looks like a secret
    let text = exec_tool(
        &handler,
        json!({
            "host": "docker",
            "command": "echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
        }),
        &ctx,
    )
    .await;
    assert!(
        !text.contains("wJalrXUtnFEMI"),
        "AWS key should be redacted in output: {text}"
    );
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_unknown_command_returns_error() {
    let ctx = require_docker_ssh().await;
    let handler = SshExecHandler;
    let result = handler
        .execute(
            Some(json!({"host": "docker", "command": "definitely_not_a_real_command_xyz"})),
            &ctx,
        )
        .await
        .unwrap();
    // Should succeed (no SSH error) but with non-zero exit code
    if let Some(structured) = &result.structured_content {
        assert_ne!(
            structured["exit_code"], 0,
            "Unknown command should have non-zero exit"
        );
    }
}

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_output_truncation() {
    let ctx = require_docker_ssh().await;
    let handler = SshExecHandler;
    // Generate large output but limit to 100 chars
    let text = exec_tool(
        &handler,
        json!({
            "host": "docker",
            "command": "seq 1 10000",
            "max_output": 100
        }),
        &ctx,
    )
    .await;
    // Output should be truncated (not all 10000 lines)
    assert!(
        text.len() < 5000,
        "Output should be truncated, got {} chars",
        text.len()
    );
}

// =============================================================================
// Phase 5: Git Operations
// =============================================================================

#[tokio::test]
#[ignore = "requires docker: docker compose -f docker-compose.test.yml up -d"]
async fn test_docker_git_init_and_status() {
    let ctx = require_docker_ssh().await;
    let exec = SshExecHandler;
    let git_dir = format!("{TEST_DIR}/git-test");

    // Initialize a git repo
    let _ = exec_tool(
        &exec,
        json!({"host": "docker", "command": format!("mkdir -p {git_dir} && cd {git_dir} && git init && git config user.email test@test.com && git config user.name test")}),
        &ctx,
    )
    .await;

    // Use git_status tool
    let handler = SshGitStatusHandler::new();
    let text = exec_tool(&handler, json!({"host": "docker", "path": &git_dir}), &ctx).await;
    assert!(
        text.contains("branch")
            || text.contains("master")
            || text.contains("main")
            || text.contains("Initial"),
        "Git status should show branch info: {text}"
    );

    // Cleanup
    let _ = exec_tool(
        &exec,
        json!({"host": "docker", "command": format!("rm -rf {git_dir}")}),
        &ctx,
    )
    .await;
}
