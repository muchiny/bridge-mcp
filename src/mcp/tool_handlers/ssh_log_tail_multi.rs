//! Handler for the `ssh_log_tail_multi` tool.
//!
//! Tails log files on a remote host, showing the last N lines.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::log_aggregation::LogAggregationCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshLogTailMultiArgs {
    /// Target host name from configuration.
    host: String,
    /// Log files to tail (space-separated). Defaults to common log paths.
    #[serde(default)]
    log_files: Option<String>,
    /// Number of lines to show (default: 50, max: 5000).
    #[serde(default)]
    lines: Option<u64>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshLogTailMultiArgs);

#[mcp_standard_tool(
    name = "ssh_log_tail_multi",
    group = "log_aggregation",
    annotation = "read_only"
)]
pub struct LogTailMultiTool;

impl StandardTool for LogTailMultiTool {
    type Args = SshLogTailMultiArgs;

    const NAME: &'static str = "ssh_log_tail_multi";

    const DESCRIPTION: &'static str = "Show the last N lines of one or more flat log files on a \
        Linux host (default: 50 lines, max: 5000). The '_multi' suffix means multiple files \
        on a single host — for multi-host fan-out use ssh_exec_multi. Use this tool to \
        read recent raw log content; use ssh_log_search_multi to filter by pattern, and \
        ssh_log_aggregate to get per-file error/warning counts without reading content. \
        For systemd unit logs prefer ssh_service_logs; for journald queries with boot/priority \
        filters prefer ssh_journal_query. Windows hosts are not supported — \
        use ssh_win_event_logs for Windows event logs.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "log_files": {
                        "type": "string",
                        "description": "Space-separated log file paths (default: /var/log/syslog /var/log/messages /var/log/auth.log)"
                    },
                    "lines": {
                        "type": "integer",
                        "description": "Number of lines to show (default: 50, max: 5000)",
                        "minimum": 1,
                        "maximum": 5000
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

    fn build_command(args: &SshLogTailMultiArgs, _host_config: &HostConfig) -> Result<String> {
        LogAggregationCommandBuilder::build_log_tail_command(args.log_files.as_deref(), args.lines)
    }
}

/// Handler for the `ssh_log_tail_multi` tool.
pub type SshLogTailMultiHandler = StandardToolHandler<LogTailMultiTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshLogTailMultiHandler::new();
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
        let handler = SshLogTailMultiHandler::new();
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
        let handler = SshLogTailMultiHandler::new();
        assert_eq!(handler.name(), "ssh_log_tail_multi");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_log_tail_multi");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "log_files": "/var/log/app.log",
            "lines": 200,
            "timeout_seconds": 30,
            "max_output": 8000,
            "save_output": "/tmp/tail.txt"
        });
        let args: SshLogTailMultiArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.log_files.as_deref(), Some("/var/log/app.log"));
        assert_eq!(args.lines, Some(200));
        assert_eq!(args.timeout_seconds, Some(30));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshLogTailMultiArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.log_files.is_none());
        assert!(args.lines.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshLogTailMultiHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("log_files"));
        assert!(props.contains_key("lines"));
        assert!(props.contains_key("timeout_seconds"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshLogTailMultiArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshLogTailMultiArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshLogTailMultiHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    fn test_host_config() -> HostConfig {
        HostConfig {
            hostname: "test".to_string(),
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
        }
    }

    #[test]
    fn test_build_command_defaults() {
        let args = SshLogTailMultiArgs {
            host: "s".to_string(),
            log_files: None,
            lines: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = LogTailMultiTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("tail -n 50"));
    }

    #[test]
    fn test_build_command_custom_lines() {
        let args = SshLogTailMultiArgs {
            host: "s".to_string(),
            log_files: None,
            lines: Some(100),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = LogTailMultiTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("tail -n 100"));
    }
}
