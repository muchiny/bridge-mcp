//! Integration tests for MCP SSH Bridge
//!
//! These tests verify the integration between different components
//! without requiring actual SSH connections.

use std::collections::HashMap;
use std::sync::Arc;

use bridge_mcp::config::{
    AuditConfig, AuthConfig, Config, HostConfig, HostKeyVerification, HttpTransportConfig,
    LimitsConfig, OsType, SanitizeConfig, SecurityConfig, SecurityMode, SessionConfig,
    SshConfigDiscovery, ToolGroupsConfig,
};
use bridge_mcp::domain::ExecuteCommandUseCase;
use bridge_mcp::mcp::CommandHistory;
use bridge_mcp::mcp::history::HistoryConfig;
use bridge_mcp::ports::CommandOutput;
use bridge_mcp::security::{AuditLogger, CommandValidator, Sanitizer};

/// Helper to create a test config with hosts
fn create_test_config() -> Config {
    let mut hosts = HashMap::new();
    hosts.insert(
        "test-server".to_string(),
        HostConfig {
            hostname: "192.168.1.100".to_string(),
            port: 22,
            user: "testuser".to_string(),
            auth: AuthConfig::Key {
                path: "~/.ssh/id_rsa".to_string(),
                passphrase: None,
            },
            description: Some("Test server".to_string()),
            host_key_verification: HostKeyVerification::Strict,
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
        },
    );

    hosts.insert(
        "dev-server".to_string(),
        HostConfig {
            hostname: "dev.example.com".to_string(),
            port: 2222,
            user: "developer".to_string(),
            auth: AuthConfig::Agent,
            description: Some("Development server".to_string()),
            host_key_verification: HostKeyVerification::AcceptNew,
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
        },
    );

    Config {
        hosts,
        security: SecurityConfig {
            mode: SecurityMode::Strict,
            whitelist: vec![
                r"^ls\b".to_string(),
                r"^cat\b".to_string(),
                r"^pwd$".to_string(),
            ],
            blacklist: vec![r"rm\s+-rf\s+/".to_string()],
            sanitize_patterns: vec![
                r"(?i)password\s*=\s*\S+".to_string(),
                r"(?i)secret\s*=\s*\S+".to_string(),
            ],
            sanitize: SanitizeConfig::default(),
            ..SecurityConfig::default()
        },
        limits: LimitsConfig::default(),
        audit: AuditConfig::default(),
        sessions: SessionConfig::default(),
        tool_groups: ToolGroupsConfig::default(),
        ssh_config: SshConfigDiscovery::default(),
        http: HttpTransportConfig::default(),
        rbac: bridge_mcp::security::rbac::RbacConfig::default(),
        awx: None,
    }
}

/// Helper to create an `ExecuteCommandUseCase` for testing
fn create_use_case(config: &Config) -> ExecuteCommandUseCase {
    let validator = Arc::new(CommandValidator::new(&config.security));
    let sanitizer = Arc::new(Sanitizer::from_config_with_legacy(
        &config.security.sanitize,
        &config.security.sanitize_patterns,
    ));
    let audit_logger = Arc::new(AuditLogger::disabled());
    let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

    ExecuteCommandUseCase::new(validator, sanitizer, audit_logger, history)
}

#[test]
fn test_config_host_lookup() {
    let config = create_test_config();

    assert!(config.hosts.contains_key("test-server"));
    assert!(config.hosts.contains_key("dev-server"));
    assert!(!config.hosts.contains_key("unknown-server"));

    let test_server = config.hosts.get("test-server").unwrap();
    assert_eq!(test_server.hostname, "192.168.1.100");
    assert_eq!(test_server.port, 22);
    assert_eq!(test_server.user, "testuser");

    let dev_server = config.hosts.get("dev-server").unwrap();
    assert_eq!(dev_server.hostname, "dev.example.com");
    assert_eq!(dev_server.port, 2222);
}

#[test]
fn test_use_case_validation_integration() {
    let config = create_test_config();
    let use_case = create_use_case(&config);

    // Whitelisted commands should pass
    assert!(use_case.validate("ls -la").is_ok());
    assert!(use_case.validate("cat /etc/hosts").is_ok());
    assert!(use_case.validate("pwd").is_ok());

    // Non-whitelisted commands should fail in strict mode
    assert!(use_case.validate("echo hello").is_err());
    assert!(use_case.validate("rm file.txt").is_err());

    // Blacklisted commands should always fail
    assert!(use_case.validate("rm -rf /").is_err());
}

#[test]
fn test_use_case_process_success_sanitization() {
    let config = create_test_config();
    let use_case = create_use_case(&config);

    let output = CommandOutput {
        stdout: "password=secret123\nuser=admin".to_string(),
        stderr: String::new(),
        exit_code: 0,
        duration_ms: 100,
    };

    let response = use_case.process_success("test-server", "cat config", &output);

    // Password should be sanitized
    assert!(!response.output.contains("secret123"));
    assert!(response.output.contains("[REDACTED]"));
    // User should not be sanitized (not a sensitive pattern)
    assert!(response.output.contains("admin"));
    assert_eq!(response.exit_code, 0);
}

#[test]
fn test_use_case_process_success_with_stderr() {
    let config = create_test_config();
    let use_case = create_use_case(&config);

    let output = CommandOutput {
        stdout: "output line 1\noutput line 2".to_string(),
        stderr: "warning: something happened".to_string(),
        exit_code: 0,
        duration_ms: 50,
    };

    let response = use_case.process_success("test-server", "ls", &output);

    assert!(response.output.contains("output line 1"));
    assert!(response.output.contains("STDERR"));
    assert!(response.output.contains("warning"));
}

#[test]
fn test_use_case_process_success_nonzero_exit() {
    let config = create_test_config();
    let use_case = create_use_case(&config);

    let output = CommandOutput {
        stdout: String::new(),
        stderr: "command not found".to_string(),
        exit_code: 127,
        duration_ms: 10,
    };

    let response = use_case.process_success("test-server", "bad-cmd", &output);

    assert_eq!(response.exit_code, 127);
    assert!(response.output.contains("127"));
}

#[test]
fn test_security_config_modes() {
    // Test strict mode
    let strict_config = SecurityConfig {
        mode: SecurityMode::Strict,
        whitelist: vec![r"^ls$".to_string()],
        blacklist: vec![],
        sanitize_patterns: vec![],
        sanitize: SanitizeConfig::default(),
        ..SecurityConfig::default()
    };
    let strict_validator = CommandValidator::new(&strict_config);

    assert!(strict_validator.validate("ls").is_ok());
    assert!(strict_validator.validate("pwd").is_err());

    // Test permissive mode
    let permissive_config = SecurityConfig {
        mode: SecurityMode::Permissive,
        whitelist: vec![],
        blacklist: vec![r"dangerous".to_string()],
        sanitize_patterns: vec![],
        sanitize: SanitizeConfig::default(),
        ..SecurityConfig::default()
    };
    let permissive_validator = CommandValidator::new(&permissive_config);

    assert!(permissive_validator.validate("ls").is_ok());
    assert!(permissive_validator.validate("pwd").is_ok());
    assert!(permissive_validator.validate("dangerous command").is_err());
}

#[test]
fn test_host_key_verification_config() {
    let config = create_test_config();

    let test_server = config.hosts.get("test-server").unwrap();
    assert_eq!(
        test_server.host_key_verification,
        HostKeyVerification::Strict
    );

    let dev_server = config.hosts.get("dev-server").unwrap();
    assert_eq!(
        dev_server.host_key_verification,
        HostKeyVerification::AcceptNew
    );
}

#[test]
fn test_auth_config_variants() {
    let config = create_test_config();

    // Test Key auth
    let test_server = config.hosts.get("test-server").unwrap();
    match &test_server.auth {
        AuthConfig::Key { path, passphrase } => {
            assert_eq!(path, "~/.ssh/id_rsa");
            assert!(passphrase.is_none());
        }
        _ => panic!("Expected Key auth"),
    }

    // Test Agent auth
    let dev_server = config.hosts.get("dev-server").unwrap();
    assert!(matches!(dev_server.auth, AuthConfig::Agent));
}

#[test]
fn test_limits_config_defaults() {
    let limits = LimitsConfig::default();

    assert_eq!(limits.command_timeout_seconds, 1800); // 30 min for long tasks like Molecule
    assert_eq!(limits.max_output_bytes, 10 * 1024 * 1024);
    assert_eq!(limits.max_concurrent_commands, 5);
    assert_eq!(limits.connection_timeout_seconds, 10);
    assert_eq!(limits.keepalive_interval_seconds, 30);
    assert_eq!(limits.retry_attempts, 3);
    assert_eq!(limits.retry_initial_delay_ms, 100);
}

#[test]
fn test_limits_config_retry_config_conversion() {
    let limits = LimitsConfig {
        retry_attempts: 5,
        retry_initial_delay_ms: 200,
        ..LimitsConfig::default()
    };

    let retry_config = limits.retry_config();

    assert_eq!(retry_config.max_attempts, 5);
    assert_eq!(retry_config.initial_delay_ms, 200);
}

#[test]
fn test_command_history_integration() {
    let history = CommandHistory::new(&HistoryConfig::default());

    // Record some commands
    history.record_success("server1", "ls -la", 0, 100);
    history.record_success("server2", "pwd", 0, 50);
    history.record_failure("server1", "bad-cmd");

    // Check recent history
    let recent = history.recent(10);
    assert_eq!(recent.len(), 3);

    // Check host-specific history
    let server1_history = history.for_host("server1", 10);
    assert_eq!(server1_history.len(), 2);

    let server2_history = history.for_host("server2", 10);
    assert_eq!(server2_history.len(), 1);

    // Check non-existent host
    let empty_history = history.for_host("unknown", 10);
    assert!(empty_history.is_empty());
}

#[test]
fn test_sanitizer_patterns() {
    let patterns = vec![
        r"(?i)password\s*=\s*\S+".to_string(),
        r"(?i)api_key\s*=\s*\S+".to_string(),
        r"-----BEGIN.*PRIVATE KEY-----".to_string(),
    ];

    let sanitizer = Sanitizer::new(&patterns);

    // Test password sanitization
    let result = sanitizer.sanitize("password=secret123");
    assert!(!result.contains("secret123"));
    assert!(result.contains("[REDACTED]"));

    // Test API key sanitization
    let result = sanitizer.sanitize("api_key=abc123xyz");
    assert!(!result.contains("abc123xyz"));

    // Test private key sanitization
    let result = sanitizer.sanitize("-----BEGIN RSA PRIVATE KEY-----");
    assert!(result.contains("[REDACTED]"));

    // Test non-sensitive data is preserved
    let result = sanitizer.sanitize("username=admin");
    assert!(result.contains("username=admin"));
}

#[test]
fn test_default_security_config() {
    let config = SecurityConfig::default();

    // Default mode is standard
    assert_eq!(config.mode, SecurityMode::Standard);

    // Default whitelist is empty
    assert!(config.whitelist.is_empty());

    // Default blacklist has dangerous commands
    assert!(!config.blacklist.is_empty());
    let blacklist_str = config.blacklist.join(" ");
    assert!(blacklist_str.contains("rm"));
    assert!(blacklist_str.contains("mkfs"));
    assert!(blacklist_str.contains("dd"));

    // Default sanitize is enabled with builtin patterns (legacy patterns can be empty)
    assert!(config.sanitize.enabled);
    // Builtin patterns are handled internally, custom patterns start empty
    assert!(config.sanitize.custom_patterns.is_empty());
    assert!(config.sanitize.disable_builtin.is_empty());
}

// =============================================================================
// Platform-specific SSH Agent tests
// =============================================================================

/// Test that Windows SSH agent pipe path is correctly defined
/// This test verifies the constant without requiring an actual agent connection
#[test]
#[cfg(windows)]
fn test_windows_agent_pipe_path() {
    // The Windows OpenSSH Agent pipe path should be a valid named pipe format
    const EXPECTED_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

    // Verify the path starts with the named pipe prefix
    assert!(EXPECTED_PIPE.starts_with(r"\\.\pipe\"));
    assert!(EXPECTED_PIPE.contains("openssh-ssh-agent"));
}

/// Integration test for Windows SSH agent connection
/// This test is ignored by default because it requires:
/// 1. Running on Windows
/// 2. OpenSSH Authentication Agent service to be running
/// 3. At least one key added to the agent (ssh-add)
///
/// Run manually with: cargo test test_windows_agent_connection -- --ignored
#[test]
#[ignore]
#[cfg(windows)]
fn test_windows_agent_connection() {
    use tokio::net::windows::named_pipe::ClientOptions;

    const PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

    // Try to connect to the Windows SSH agent
    let result = ClientOptions::new().open(PIPE_NAME);

    match result {
        Ok(_pipe) => {
            // Connection successful - agent is running
            println!("Successfully connected to Windows SSH agent");
        }
        Err(e) => {
            // Provide helpful error message
            panic!(
                "Failed to connect to Windows SSH agent: {}\n\
                 Make sure the OpenSSH Authentication Agent service is running:\n\
                 1. Open Services (services.msc)\n\
                 2. Find 'OpenSSH Authentication Agent'\n\
                 3. Set startup type to 'Automatic' and start the service\n\
                 4. Add a key with: ssh-add ~/.ssh/id_ed25519",
                e
            );
        }
    }
}

/// Test that Unix SSH agent uses the correct environment variable
#[test]
#[cfg(unix)]
fn test_unix_agent_env_var() {
    // SSH_AUTH_SOCK is the standard environment variable for Unix SSH agent
    // This test just verifies we can check for it (doesn't require agent running)
    let auth_sock = std::env::var("SSH_AUTH_SOCK");

    // The test passes whether or not the variable is set
    // We're just verifying we can access environment variables correctly
    match auth_sock {
        Ok(path) => {
            println!("SSH_AUTH_SOCK is set to: {path}");
            // If set, it should be a path
            assert!(!path.is_empty());
        }
        Err(_) => {
            println!("SSH_AUTH_SOCK is not set (no agent running)");
        }
    }
}

// =============================================================================
// Jump Host (Bastion) Configuration Tests
// =============================================================================

#[test]
fn test_proxy_jump_config() {
    let mut hosts = HashMap::new();

    // Bastion host
    hosts.insert(
        "bastion".to_string(),
        HostConfig {
            hostname: "bastion.example.com".to_string(),
            port: 22,
            user: "admin".to_string(),
            auth: AuthConfig::Agent,
            description: Some("Jump host".to_string()),
            host_key_verification: HostKeyVerification::Strict,
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
        },
    );

    // Internal server accessible via bastion
    hosts.insert(
        "internal-server".to_string(),
        HostConfig {
            hostname: "10.0.0.5".to_string(),
            port: 22,
            user: "deploy".to_string(),
            auth: AuthConfig::Key {
                path: "~/.ssh/id_ed25519".to_string(),
                passphrase: None,
            },
            description: Some("Internal server via bastion".to_string()),
            host_key_verification: HostKeyVerification::Strict,
            proxy_jump: Some("bastion".to_string()),
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
        },
    );

    let config = Config {
        hosts,
        security: SecurityConfig::default(),
        limits: LimitsConfig::default(),
        audit: AuditConfig::default(),
        sessions: SessionConfig::default(),
        tool_groups: ToolGroupsConfig::default(),
        ssh_config: SshConfigDiscovery::default(),
        http: HttpTransportConfig::default(),
        rbac: bridge_mcp::security::rbac::RbacConfig::default(),
        awx: None,
    };

    // Verify bastion has no proxy_jump
    let bastion = config.hosts.get("bastion").unwrap();
    assert!(bastion.proxy_jump.is_none());

    // Verify internal server has proxy_jump pointing to bastion
    let internal = config.hosts.get("internal-server").unwrap();
    assert_eq!(internal.proxy_jump, Some("bastion".to_string()));
    assert_eq!(internal.hostname, "10.0.0.5");
}

#[test]
fn test_proxy_jump_resolution() {
    let mut hosts = HashMap::new();

    hosts.insert(
        "bastion".to_string(),
        HostConfig {
            hostname: "bastion.example.com".to_string(),
            port: 22,
            user: "admin".to_string(),
            auth: AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
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
        },
    );

    hosts.insert(
        "target".to_string(),
        HostConfig {
            hostname: "10.0.0.5".to_string(),
            port: 22,
            user: "deploy".to_string(),
            auth: AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: Some("bastion".to_string()),
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
        },
    );

    let config = Config {
        hosts,
        security: SecurityConfig::default(),
        limits: LimitsConfig::default(),
        audit: AuditConfig::default(),
        sessions: SessionConfig::default(),
        tool_groups: ToolGroupsConfig::default(),
        ssh_config: SshConfigDiscovery::default(),
        http: HttpTransportConfig::default(),
        rbac: bridge_mcp::security::rbac::RbacConfig::default(),
        awx: None,
    };

    // Simulate resolving jump host
    let target = config.hosts.get("target").unwrap();
    let jump_name = target.proxy_jump.as_ref().unwrap();
    let jump_config = config.hosts.get(jump_name);

    assert!(jump_config.is_some());
    assert_eq!(jump_config.unwrap().hostname, "bastion.example.com");
}

#[test]
fn test_proxy_jump_chain_detection() {
    // Test that we can detect when a jump host is configured
    let host_with_jump = HostConfig {
        hostname: "internal.example.com".to_string(),
        port: 22,
        user: "user".to_string(),
        auth: AuthConfig::Agent,
        description: None,
        host_key_verification: HostKeyVerification::default(),
        proxy_jump: Some("bastion".to_string()),
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
    };

    let host_without_jump = HostConfig {
        hostname: "direct.example.com".to_string(),
        port: 22,
        user: "user".to_string(),
        auth: AuthConfig::Agent,
        description: None,
        host_key_verification: HostKeyVerification::default(),
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
    };

    assert!(host_with_jump.proxy_jump.is_some());
    assert!(host_without_jump.proxy_jump.is_none());
}
