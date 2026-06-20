//! SSH Nginx Reload Tool Handler
//!
//! Reloads web server configuration on a remote host.

use serde::Deserialize;

use crate::config::{HostConfig, OsType};
use crate::domain::use_cases::nginx::NginxCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshNginxReloadArgs {
    host: String,
    server: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshNginxReloadArgs);

#[mcp_standard_tool(
    name = "ssh_nginx_reload",
    group = "nginx",
    annotation = "mutating_idempotent"
)]
pub struct NginxReloadTool;

impl StandardTool for NginxReloadTool {
    type Args = SshNginxReloadArgs;

    const NAME: &'static str = "ssh_nginx_reload";

    const DESCRIPTION: &'static str = "Reload web server configuration on a remote Linux host \
        (runs config test then `systemctl reload`). Built-in safety: rejects reload if the config \
        test fails, preventing downtime. Defaults to nginx when `server` is omitted. For a \
        dry-run without reloading use ssh_nginx_test first. To check server state use \
        ssh_nginx_status; to inspect enabled sites use ssh_nginx_list_sites.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "server": {
                "type": "string",
                "description": "Web server to reload: nginx (default when omitted), apache2, or httpd. Custom servers (e.g. openresty) also accepted."
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
        "required": ["host"]
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshNginxReloadArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(NginxCommandBuilder::build_reload_command(
            args.server.as_deref(),
        ))
    }
}

/// Handler for the `ssh_nginx_reload` tool.
pub type SshNginxReloadHandler = StandardToolHandler<NginxReloadTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshNginxReloadHandler::new();
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
        let handler = SshNginxReloadHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshNginxReloadHandler::new();
        assert_eq!(handler.name(), "ssh_nginx_reload");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_nginx_reload");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "server": "httpd",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/reload.txt"
        });
        let args: SshNginxReloadArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.server.as_deref(), Some("httpd"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/reload.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshNginxReloadArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.server.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshNginxReloadHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("server"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost"});
        let args: SshNginxReloadArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshNginxReloadArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshNginxReloadHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    fn test_host_config() -> crate::config::HostConfig {
        crate::config::HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: crate::config::HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: crate::config::OsType::default(),
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
        let args: SshNginxReloadArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = NginxReloadTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_build_command_with_server() {
        let args: SshNginxReloadArgs =
            serde_json::from_value(json!({"host": "s", "server": "httpd"})).unwrap();
        let host = test_host_config();
        let cmd = NginxReloadTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("reload"));
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

    fn pipeline_ctx(output: crate::ssh::CommandOutput) -> crate::ports::ToolContext {
        use crate::config::{Config, SecurityConfig, SecurityMode};
        use crate::domain::TunnelManager;
        use crate::domain::{CommandHistory, ExecuteCommandUseCase};
        use crate::ports::ExecutorRouter;
        use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
        use crate::ssh::SessionManager;
        use std::sync::Arc;
        let security = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: Vec::new(),
            ..SecurityConfig::default()
        };
        let config = Config {
            hosts: server1_hosts(),
            security: security.clone(),
            ..Config::default()
        };
        let validator = Arc::new(CommandValidator::new(&security));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(
            &crate::domain::history::HistoryConfig::default(),
        ));
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
            session_manager: Arc::new(SessionManager::new(crate::config::SessionConfig::default())),
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
        let handler = SshNginxReloadHandler::new();
        let ctx = pipeline_ctx(mock_output("Reloading nginx configuration...done"));
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        assert!(!result.content.is_empty());
    }
}
