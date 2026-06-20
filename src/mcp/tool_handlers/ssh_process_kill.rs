//! Handler for the `ssh_process_kill` tool.
//!
//! Sends a signal to a process on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::process::ProcessCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshProcessKillArgs {
    /// Target host name from configuration.
    host: String,
    /// Process ID to signal.
    pid: u32,
    /// Signal name or number (default: TERM).
    signal: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshProcessKillArgs);

#[mcp_standard_tool(
    name = "ssh_process_kill",
    group = "process",
    annotation = "destructive"
)]
pub struct ProcessKillTool;

impl StandardTool for ProcessKillTool {
    type Args = SshProcessKillArgs;

    const NAME: &'static str = "ssh_process_kill";

    const DESCRIPTION: &'static str = "Send a signal to a process on a Linux host. Default signal is TERM (graceful \
        shutdown). Use signal KILL (or 9) to force-kill a process that ignores TERM. Protected \
        PIDs (0, 1) are blocked. Use ssh_process_list or ssh_process_top first to find target \
        PIDs. For Windows hosts use ssh_win_process_kill instead.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to signal",
                        "minimum": 2
                    },
                    "signal": {
                        "type": "string",
                        "description": "Signal name or number (default: TERM). Named: TERM, KILL, HUP, INT, QUIT, USR1, USR2, STOP, CONT. Numeric: 1, 2, 3, 9, 10, 12, 15, 18, 19.",
                        "enum": ["TERM", "KILL", "HUP", "INT", "QUIT", "USR1", "USR2", "STOP", "CONT", "1", "2", "3", "9", "10", "12", "15", "18", "19"]
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters before truncation",
                        "minimum": 100
                    },
                    "save_output": {
                        "type": "string",
                        "description": "Save full output to a local file path"
                    }
                },
                "required": ["host", "pid"]
            }"#;

    fn build_command(args: &SshProcessKillArgs, _host_config: &HostConfig) -> Result<String> {
        ProcessCommandBuilder::build_kill_command(args.pid, args.signal.as_deref())
    }

    fn validate(args: &SshProcessKillArgs, _host_config: &HostConfig) -> Result<()> {
        if let Some(ref sig) = args.signal {
            ProcessCommandBuilder::validate_signal(sig)?;
        }
        Ok(())
    }

    /// Confirm destructive operation via `elicitation/create` before
    /// running the underlying command. Falls back to a no-op when the
    /// client does not advertise the elicitation capability — the
    /// global `security.require_elicitation_on_destructive` gate still
    /// applies in that case.
    async fn pre_execute(args: &Self::Args, ctx: &ToolContext) -> Result<Option<ToolCallResult>> {
        let summary = format!(
            "Send signal `{}` to PID `{}` on host `{}`",
            args.signal.as_deref().unwrap_or("TERM"),
            args.pid,
            args.host,
        );
        match ctx.elicit_confirm(Self::NAME, &summary).await? {
            Some(false) => Ok(Some(ToolCallResult::error(
                "User declined destructive operation".to_string(),
            ))),
            _ => Ok(None),
        }
    }
}

/// Handler for the `ssh_process_kill` tool.
pub type SshProcessKillHandler = StandardToolHandler<ProcessKillTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshProcessKillHandler::new();
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
        let handler = SshProcessKillHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "pid": 1234})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshProcessKillHandler::new();
        assert_eq!(handler.name(), "ssh_process_kill");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_process_kill");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("pid")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "pid": 1234,
            "signal": "KILL",
            "timeout_seconds": 10,
            "max_output": 5000,
            "save_output": "/tmp/kill.txt"
        });
        let args: SshProcessKillArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pid, 1234);
        assert_eq!(args.signal.as_deref(), Some("KILL"));
        assert_eq!(args.timeout_seconds, Some(10));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/kill.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "pid": 5678});
        let args: SshProcessKillArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pid, 5678);
        assert!(args.signal.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshProcessKillHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("signal"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "pid": 1234});
        let args: SshProcessKillArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshProcessKillArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshProcessKillHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "pid": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
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
        let args: SshProcessKillArgs =
            serde_json::from_value(json!({"host": "s", "pid": 1234})).unwrap();
        let host = test_host_config();
        let cmd = ProcessKillTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("1234"));
    }

    #[test]
    fn test_build_command_with_signal() {
        let args: SshProcessKillArgs =
            serde_json::from_value(json!({"host": "s", "pid": 1234, "signal": "9"})).unwrap();
        let host = test_host_config();
        let cmd = ProcessKillTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("1234"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshProcessKillArgs =
            serde_json::from_value(json!({"host": "s", "pid": 1234})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "kill: process 1234 signalled\n";
        let result = ProcessKillTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshProcessKillArgs =
            serde_json::from_value(json!({"host": "s", "pid": 1234})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = ProcessKillTool::post_process(result, &args, "", &dr);
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
        let handler = SshProcessKillHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(Some(json!({"host": "server1", "pid": 1234})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
