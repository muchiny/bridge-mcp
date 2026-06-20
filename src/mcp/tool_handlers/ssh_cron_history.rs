//! Handler for the `ssh_cron_history` tool.
//!
//! Shows cron execution history from system logs.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::cron_analysis::CronAnalysisCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshCronHistoryArgs {
    /// Target host name from configuration.
    host: String,
    /// Number of log lines to return (default: 100).
    #[serde(default)]
    lines: Option<u64>,
    /// Show entries since this time (e.g., "24 hours ago").
    #[serde(default)]
    since: Option<String>,
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

impl_common_args!(SshCronHistoryArgs);

#[mcp_standard_tool(
    name = "ssh_cron_history",
    group = "cron_analysis",
    annotation = "read_only"
)]
pub struct CronHistoryTool;

impl StandardTool for CronHistoryTool {
    type Args = SshCronHistoryArgs;

    const NAME: &'static str = "ssh_cron_history";

    const DESCRIPTION: &'static str = "Show cron execution history from system logs. Displays \
        recent cron job runs with timestamps, exit statuses, and any error messages. Use \
        ssh_cron_analyze first for an overview, then this tool for detailed history.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "lines": {
                        "type": "integer",
                        "description": "Number of log lines to return (default: 100, max: 5000)",
                        "minimum": 1,
                        "maximum": 5000,
                        "default": 100
                    },
                    "since": {
                        "type": "string",
                        "description": "Show entries since this time. On systemd hosts accepts journalctl-style relative strings (e.g. '24 hours ago', 'yesterday') or ISO date ('2024-01-01'). On hosts without journald the tool falls back to syslog grep, which does not support relative strings — prefer ISO dates for portability."
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

    fn build_command(args: &SshCronHistoryArgs, _host_config: &HostConfig) -> Result<String> {
        CronAnalysisCommandBuilder::build_cron_history_command(args.lines, args.since.as_deref())
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshCronHistoryArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Cron History");
        for h in &parsed.headers {
            tbl = tbl.column(h, h.to_uppercase());
        }
        for row in &parsed.rows {
            let first = row.first().map_or("", String::as_str);
            if first.is_empty() {
                continue;
            }
            let mut obj = serde_json::Map::new();
            for (i, h) in parsed.headers.iter().enumerate() {
                obj.insert(
                    h.clone(),
                    serde_json::Value::String(row.get(i).map_or_else(String::new, Clone::clone)),
                );
            }
            tbl = tbl.row(serde_json::Value::Object(obj));
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_cron_history",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_cron_history` tool.
pub type SshCronHistoryHandler = StandardToolHandler<CronHistoryTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCronHistoryHandler::new();
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
        let handler = SshCronHistoryHandler::new();
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
        let handler = SshCronHistoryHandler::new();
        assert_eq!(handler.name(), "ssh_cron_history");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_cron_history");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "lines": 200,
            "since": "24 hours ago",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshCronHistoryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.lines, Some(200));
        assert_eq!(args.since.as_deref(), Some("24 hours ago"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/out.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshCronHistoryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.lines.is_none());
        assert!(args.since.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCronHistoryHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("lines"));
        assert!(props.contains_key("since"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h"});
        let args: SshCronHistoryArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshCronHistoryArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCronHistoryHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

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
        let args = SshCronHistoryArgs {
            host: "s".to_string(),
            lines: None,
            since: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CronHistoryTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("journalctl"));
        assert!(cmd.contains("-n 100"));
    }

    #[test]
    fn test_build_command_with_lines() {
        let args = SshCronHistoryArgs {
            host: "s".to_string(),
            lines: Some(50),
            since: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CronHistoryTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-n 50"));
    }

    #[test]
    fn test_build_command_with_since() {
        let args = SshCronHistoryArgs {
            host: "s".to_string(),
            lines: None,
            since: Some("24 hours ago".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CronHistoryTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("24 hours ago"));
    }

    #[test]
    fn test_build_command_lines_too_large() {
        let args = SshCronHistoryArgs {
            host: "s".to_string(),
            lines: Some(5001),
            since: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = CronHistoryTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
