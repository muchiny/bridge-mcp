//! Handler for the `ssh_port_scan` tool.
//!
//! Scans for open ports on a remote host or target.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::network_security::{NetworkSecurityCommandBuilder, validate_target};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshPortScanArgs {
    /// Target host name from configuration.
    host: String,
    /// Target address to scan (default: local).
    #[serde(default)]
    target: Option<String>,
    /// Comma-separated list of ports to scan.
    #[serde(default)]
    ports: Option<String>,
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

impl_common_args!(SshPortScanArgs);

#[mcp_standard_tool(
    name = "ssh_port_scan",
    group = "network_security",
    annotation = "read_only"
)]
pub struct PortScanTool;

impl StandardTool for PortScanTool {
    type Args = SshPortScanArgs;

    const NAME: &'static str = "ssh_port_scan";

    const DESCRIPTION: &'static str = "Scan for open ports on a remote Linux host. When `target` is omitted (or \
        is localhost/127.0.0.1), runs `ss -tlnp` (falling back to `netstat`) to list all \
        listening sockets on the SSH host itself — prefer `ssh_net_connections` if you need \
        established connections too. When `target` is a remote IP or hostname, runs `nmap -sT` \
        (falling back to a TCP bash probe) against the specified ports (default: \
        22,80,443,8080,8443,3306,5432,6379,27017). For a full SSL/TLS inspection of an open \
        port, follow up with `ssh_ssl_audit`.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "target": {
                        "type": "string",
                        "description": "Remote IP or hostname to scan via nmap; omit (or use localhost/127.0.0.1) to scan listening ports on the SSH host itself via ss/netstat"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Comma-separated ports for remote scan (e.g., '22,80,443'); default: 22,80,443,8080,8443,3306,5432,6379,27017; ignored for local scans"
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
                "required": ["host"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn validate(args: &SshPortScanArgs, _host_config: &HostConfig) -> Result<()> {
        if let Some(ref target) = args.target {
            validate_target(target)?;
        }
        Ok(())
    }

    fn build_command(args: &SshPortScanArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(NetworkSecurityCommandBuilder::build_port_scan_command(
            args.target.as_deref(),
            args.ports.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        _args: &SshPortScanArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        // ss/netstat output is columnar — convert to TSV for token efficiency
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        ToolCallResult::text(parsed.to_tsv())
    }
}

/// Handler for the `ssh_port_scan` tool.
pub type SshPortScanHandler = StandardToolHandler<PortScanTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPortScanHandler::new();
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
        let handler = SshPortScanHandler::new();
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
        let handler = SshPortScanHandler::new();
        assert_eq!(handler.name(), "ssh_port_scan");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_port_scan");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "target": "192.168.1.1",
            "ports": "22,80,443",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/port_scan.txt"
        });
        let args: SshPortScanArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.target.as_deref(), Some("192.168.1.1"));
        assert_eq!(args.ports.as_deref(), Some("22,80,443"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/port_scan.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshPortScanArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.target.is_none());
        assert!(args.ports.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshPortScanHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("target"));
        assert!(props.contains_key("ports"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshPortScanArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshPortScanArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshPortScanHandler::new();
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
        let args: SshPortScanArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = PortScanTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_build_command_with_target_and_ports() {
        let args: SshPortScanArgs = serde_json::from_value(json!({
            "host": "s",
            "target": "192.168.1.1",
            "ports": "22,80,443"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = PortScanTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshPortScanArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "STATE\tPORT\tPROCESS\nLISTEN\t22\tsshd\nLISTEN\t80\tnginx\n";
        let result = PortScanTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshPortScanArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "";
        let result = PortScanTool::post_process(result, &args, output, &dr);
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
        let handler = SshPortScanHandler::new();
        let ctx = pipeline_ctx(mock_output(
            "22/tcp open ssh\n80/tcp open http\n443/tcp open https",
        ));
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        assert!(!result.content.is_empty());
    }
}
