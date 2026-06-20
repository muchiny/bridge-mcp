//! Handler for the `ssh_log_search_multi` tool.
//!
//! Searches logs across remote hosts for a given pattern.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::log_aggregation::LogAggregationCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshLogSearchMultiArgs {
    /// Target host name from configuration.
    host: String,
    /// Search pattern (grep-compatible regex).
    pattern: String,
    /// Log files to search (space-separated). Defaults to common log paths.
    #[serde(default)]
    log_files: Option<String>,
    /// Only show logs since this time (e.g., "1 hour ago", "2024-01-01").
    #[serde(default)]
    since: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshLogSearchMultiArgs);

#[mcp_standard_tool(
    name = "ssh_log_search_multi",
    group = "log_aggregation",
    annotation = "read_only"
)]
pub struct LogSearchMultiTool;

impl StandardTool for LogSearchMultiTool {
    type Args = SshLogSearchMultiArgs;

    const NAME: &'static str = "ssh_log_search_multi";

    const DESCRIPTION: &'static str = "Search multiple log files on a single Linux host for a \
        pattern (the '_multi' suffix means multiple files, not multiple hosts — for multi-host \
        fan-out use ssh_exec_multi). Uses journalctl --grep when available, falling back to \
        grep -r across flat log files (grep results are capped at 100 lines via tail -100). \
        Prefer ssh_journal_query for structured journald filtering by unit, priority, or \
        boot ID; use this tool for specific flat log files (e.g. /var/log/auth.log) or when \
        journald is unavailable. Use ssh_log_tail_multi to read recent lines without filtering, \
        or ssh_log_aggregate to count error/warning occurrences. Windows hosts are not \
        supported — use ssh_win_event_query for Windows Event Log searches.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Search pattern — journalctl uses PCRE2 (avoid PCRE-only syntax like \\d when the grep fallback matters; use [0-9] instead); grep fallback uses basic regex (BRE)"
                    },
                    "log_files": {
                        "type": "string",
                        "description": "Space-separated log file paths (default: /var/log/syslog /var/log/messages /var/log/auth.log)"
                    },
                    "since": {
                        "type": "string",
                        "description": "Only show logs since this time (e.g., '1 hour ago', '2024-01-01')"
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
                "required": ["host", "pattern"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshLogSearchMultiArgs, _host_config: &HostConfig) -> Result<String> {
        LogAggregationCommandBuilder::build_log_search_command(
            &args.pattern,
            args.log_files.as_deref(),
            args.since.as_deref(),
        )
    }
}

/// Handler for the `ssh_log_search_multi` tool.
pub type SshLogSearchMultiHandler = StandardToolHandler<LogSearchMultiTool>;

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
        let handler = SshLogSearchMultiHandler::new();
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
        let handler = SshLogSearchMultiHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "pattern": "error"})),
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
        let handler = SshLogSearchMultiHandler::new();
        assert_eq!(handler.name(), "ssh_log_search_multi");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_log_search_multi");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("pattern")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "pattern": "ERROR|CRITICAL",
            "log_files": "/var/log/app.log",
            "since": "1 hour ago",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/search.txt"
        });
        let args: SshLogSearchMultiArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pattern, "ERROR|CRITICAL");
        assert_eq!(args.log_files.as_deref(), Some("/var/log/app.log"));
        assert_eq!(args.since.as_deref(), Some("1 hour ago"));
        assert_eq!(args.timeout_seconds, Some(30));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "pattern": "error"});
        let args: SshLogSearchMultiArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pattern, "error");
        assert!(args.log_files.is_none());
        assert!(args.since.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshLogSearchMultiHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("log_files"));
        assert!(props.contains_key("since"));
        assert!(props.contains_key("timeout_seconds"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "pattern": "test"});
        let args: SshLogSearchMultiArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshLogSearchMultiArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshLogSearchMultiHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "pattern": 456})), &ctx)
            .await;
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
        let args = SshLogSearchMultiArgs {
            host: "s".to_string(),
            pattern: "error".to_string(),
            log_files: None,
            since: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = LogSearchMultiTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("journalctl"));
        assert!(cmd.contains("error"));
    }

    #[test]
    fn test_build_command_with_since() {
        let args = SshLogSearchMultiArgs {
            host: "s".to_string(),
            pattern: "warn".to_string(),
            log_files: None,
            since: Some("1 hour ago".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = LogSearchMultiTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("1 hour ago"));
    }
}
