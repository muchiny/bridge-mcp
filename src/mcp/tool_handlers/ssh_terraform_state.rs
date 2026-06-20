use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::terraform::TerraformCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshTerraformStateArgs {
    host: String,
    dir: String,
    subcommand: String,
    resource: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshTerraformStateArgs);

#[mcp_standard_tool(
    name = "ssh_terraform_state",
    group = "terraform",
    annotation = "read_only"
)]
pub struct TerraformStateTool;

impl StandardTool for TerraformStateTool {
    type Args = SshTerraformStateArgs;

    const NAME: &'static str = "ssh_terraform_state";

    const DESCRIPTION: &'static str = "Inspect Terraform state on a remote host (read-only). Supported subcommands: \
        list (list all managed resource addresses), show (show one resource's detailed attributes — \
        pass resource=ADDR), pull (download the full raw state JSON to stdout). \
        State-mutating subcommands (mv, rm, push) are intentionally blocked — perform those \
        manually after review. Use ssh_terraform_output to read declared output values; use \
        ssh_terraform_plan to see what changes are pending.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "dir": {
                        "type": "string",
                        "description": "Path to Terraform directory"
                    },
                    "subcommand": {
                        "type": "string",
                        "enum": ["list", "show", "pull"],
                        "description": "State subcommand (read-only): list, show, or pull. Any other value (mv/rm/push) is rejected."
                    },
                    "resource": {
                        "type": "string",
                        "description": "Resource address — required for the `show` subcommand (e.g. aws_instance.web); ignored by list/pull"
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Command timeout in seconds"
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters"
                    },
                    "save_output": {
                        "type": "string",
                        "description": "File path to save full output"
                    }
                },
                "required": ["host", "dir", "subcommand"]
            }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshTerraformStateArgs, _host_config: &HostConfig) -> Result<String> {
        TerraformCommandBuilder::build_state_command(
            &args.dir,
            &args.subcommand,
            args.resource.as_deref(),
        )
    }
}

/// Handler for the `ssh_terraform_state` tool.
pub type SshTerraformStateHandler = StandardToolHandler<TerraformStateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTerraformStateHandler::new();
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
        let handler = SshTerraformStateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "dir": "/opt/terraform", "subcommand": "list"})),
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
        let handler = SshTerraformStateHandler::new();
        assert_eq!(handler.name(), "ssh_terraform_state");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_terraform_state");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("dir")));
        assert!(required.contains(&json!("subcommand")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "dir": "/opt/terraform",
            "subcommand": "show",
            "resource": "aws_instance.web",
            "timeout_seconds": 60,
            "max_output": 10000,
            "save_output": "/tmp/tf_state.txt"
        });
        let args: SshTerraformStateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.dir, "/opt/terraform");
        assert_eq!(args.subcommand, "show");
        assert_eq!(args.resource.as_deref(), Some("aws_instance.web"));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/tf_state.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "dir": "/opt/terraform", "subcommand": "list"});
        let args: SshTerraformStateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.dir, "/opt/terraform");
        assert_eq!(args.subcommand, "list");
        assert!(args.resource.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTerraformStateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("resource"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "dir": "/opt/terraform", "subcommand": "list"});
        let args: SshTerraformStateArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshTerraformStateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshTerraformStateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "dir": 456, "subcommand": 789})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
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
        let handler = SshTerraformStateHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(
                Some(json!({"host": "server1", "dir": "/opt/terraform", "subcommand": "list"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
