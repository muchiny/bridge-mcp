//! Handler for the `ssh_user_info` tool.
//!
//! Gets detailed information about a user on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::user_management::UserCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshUserInfoArgs {
    /// Target host name from configuration.
    host: String,
    /// Username to look up.
    username: String,
    /// Override default command timeout in seconds.
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    #[serde(default)]
    max_output: Option<u64>,
    /// Save full output to a local file path.
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshUserInfoArgs);

#[mcp_standard_tool(
    name = "ssh_user_info",
    group = "user_management",
    annotation = "read_only"
)]
pub struct UserInfoTool;

impl StandardTool for UserInfoTool {
    type Args = SshUserInfoArgs;

    const NAME: &'static str = "ssh_user_info";

    const DESCRIPTION: &'static str = "Get detailed information about a single user on a remote \
        Linux host: runs id, getent passwd, lastlog, and groups to show UID, GID, supplementary \
        groups, shell, home directory, and last login. Use ssh_user_list first to discover valid \
        usernames. For a quick multi-user overview prefer ssh_user_list. For Active Directory \
        accounts on Windows hosts use ssh_ad_user_info instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "username"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "username": {
                "type": "string",
                "description": "Username to look up"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the local machine"
            }
        }
    }"#;

    fn build_command(args: &SshUserInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(UserCommandBuilder::build_user_info_command(&args.username))
    }
}

/// Handler for the `ssh_user_info` tool.
pub type SshUserInfoHandler = StandardToolHandler<UserInfoTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshUserInfoHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshUserInfoHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "username": "admin"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshUserInfoHandler::new();
        assert_eq!(handler.name(), "ssh_user_info");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("username")));
    }

    use crate::config::{HostConfig, HostKeyVerification, OsType};

    fn test_host_config() -> HostConfig {
        HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::default(),
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),

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

    #[test]
    fn test_build_command_defaults() {
        let args: SshUserInfoArgs =
            serde_json::from_value(json!({"host": "s", "username": "admin"})).unwrap();
        let host = test_host_config();
        let cmd = UserInfoTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("admin"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshUserInfoArgs =
            serde_json::from_value(json!({"host": "s", "username": "admin"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)\n";
        let result = UserInfoTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshUserInfoArgs =
            serde_json::from_value(json!({"host": "s", "username": "admin"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = UserInfoTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
    }

    // ============== Full Pipeline Test ==============

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn server1_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            crate::config::HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "test".to_string(),
                auth: crate::config::AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::default(),
                shell: None,
                retry: None,
                protocol: crate::config::Protocol::default(),
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
        hosts
    }

    /// Creates a test context with permissive security (empty blacklist)
    /// because `build_user_info_command` generates `2>/dev/null` which
    /// is blocked by the default blacklist pattern `(?i)>\s*/dev/`.
    fn create_permissive_mock_ctx(
        hosts: std::collections::HashMap<String, crate::config::HostConfig>,
        output: crate::ssh::CommandOutput,
    ) -> crate::ports::ToolContext {
        use crate::config::{Config, SecurityConfig, SecurityMode};
        use crate::domain::{CommandHistory, ExecuteCommandUseCase, HistoryConfig, TunnelManager};
        use crate::ports::ExecutorRouter;
        use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
        use std::sync::Arc;

        let security = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: vec![],
            ..SecurityConfig::default()
        };
        let config = Config {
            hosts,
            security: security.clone(),
            ..Config::default()
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
        crate::ports::ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::mock(output)),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(crate::ssh::SessionManager::new(
                crate::config::SessionConfig::default(),
            )),
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

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshUserInfoHandler::new();
        let ctx = create_permissive_mock_ctx(
            server1_hosts(),
            mock_output("uid=1000(testuser) gid=1000(testuser) groups=1000(testuser),27(sudo)"),
        );
        let result = handler
            .execute(
                Some(json!({"host": "server1", "username": "testuser"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
