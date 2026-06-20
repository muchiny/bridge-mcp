//! Handler for the `ssh_user_delete` tool.
//!
//! Deletes a user from a remote Linux host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::user_management::UserCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshUserDeleteArgs {
    /// Target host name from configuration.
    host: String,
    /// Username to delete.
    username: String,
    /// Also remove the user's home directory.
    #[serde(default)]
    remove_home: Option<bool>,
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

impl_common_args!(SshUserDeleteArgs);

#[mcp_standard_tool(
    name = "ssh_user_delete",
    group = "user_management",
    annotation = "destructive"
)]
pub struct UserDeleteTool;

impl StandardTool for UserDeleteTool {
    type Args = SshUserDeleteArgs;

    const NAME: &'static str = "ssh_user_delete";

    const DESCRIPTION: &'static str = "Permanently delete a user from a remote Linux host via \
        userdel. Set remove_home=true to also remove the user's home directory and mail spool \
        (irreversible). Prompts for confirmation before executing. Use ssh_user_list to discover \
        the username and ssh_user_info to review account details before deletion. \
        Linux-only — for Windows hosts use ssh_exec with net user /delete.";

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
                "description": "Username to delete"
            },
            "remove_home": {
                "type": "boolean",
                "description": "Also remove the user's home directory. Default: false"
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

    fn build_command(args: &SshUserDeleteArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(UserCommandBuilder::build_user_delete_command(
            &args.username,
            args.remove_home.unwrap_or(false),
        ))
    }

    /// Ask the client to confirm the user deletion at runtime via
    /// `elicitation/create`. The home-directory removal flag is
    /// surfaced so the user knows the full impact before approving.
    /// Falls back to a no-op when the client does not advertise
    /// elicitation support.
    async fn pre_execute(
        args: &SshUserDeleteArgs,
        ctx: &ToolContext,
    ) -> Result<Option<ToolCallResult>> {
        let summary = format!(
            "Delete user `{}` from `{}` (remove_home={})?",
            args.username,
            args.host,
            args.remove_home.unwrap_or(false),
        );
        match ctx.elicit_confirm(Self::NAME, &summary).await? {
            Some(false) => Ok(Some(ToolCallResult::error(format!(
                "User declined deletion of account `{}`",
                args.username
            )))),
            _ => Ok(None),
        }
    }
}

/// Handler for the `ssh_user_delete` tool.
pub type SshUserDeleteHandler = StandardToolHandler<UserDeleteTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshUserDeleteHandler::new();
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
        let handler = SshUserDeleteHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "username": "olduser"})),
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
        let handler = SshUserDeleteHandler::new();
        assert_eq!(handler.name(), "ssh_user_delete");
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
        let args: SshUserDeleteArgs =
            serde_json::from_value(json!({"host": "s", "username": "olduser"})).unwrap();
        let host = test_host_config();
        let cmd = UserDeleteTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("olduser"));
    }

    #[test]
    fn test_build_command_remove_home() {
        let args: SshUserDeleteArgs = serde_json::from_value(json!({
            "host": "s", "username": "olduser", "remove_home": true
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = UserDeleteTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("olduser"));
        assert!(cmd.contains("-r"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshUserDeleteArgs =
            serde_json::from_value(json!({"host": "s", "username": "olduser"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "userdel: user olduser removed\n";
        let result = UserDeleteTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshUserDeleteArgs =
            serde_json::from_value(json!({"host": "s", "username": "olduser"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = UserDeleteTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
    }

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn server1_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "test".to_string(),
                auth: AuthConfig::Agent,
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

    fn permissive_ctx(mock_out: crate::ssh::CommandOutput) -> crate::ports::ToolContext {
        use crate::config::SessionConfig;
        use crate::config::{Config, LimitsConfig, SecurityConfig, SecurityMode};
        use crate::domain::CommandHistory;
        use crate::domain::ExecuteCommandUseCase;
        use crate::domain::TunnelManager;
        use crate::domain::history::HistoryConfig;
        use crate::ports::ExecutorRouter;
        use crate::security::AuditLogger;
        use crate::security::RateLimiter;
        use crate::security::{CommandValidator, Sanitizer};
        use crate::ssh::SessionManager;
        use std::sync::Arc;
        let sec = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: Vec::new(),
            ..SecurityConfig::default()
        };
        let config = Config {
            hosts: server1_hosts(),
            security: sec.clone(),
            limits: LimitsConfig::default(),
            ..Config::default()
        };
        let validator = Arc::new(CommandValidator::new(&sec));
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
            connection_pool: Arc::new(ExecutorRouter::mock(mock_out)),
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

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshUserDeleteHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(
                Some(json!({"host": "server1", "username": "olduser"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
