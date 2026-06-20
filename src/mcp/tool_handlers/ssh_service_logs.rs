//! Handler for the `ssh_service_logs` tool.
//!
//! Views journalctl logs for a systemd service on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::systemd::{SystemdCommandBuilder, validate_service_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshServiceLogsArgs {
    host: String,
    service: String,
    lines: Option<u64>,
    since: Option<String>,
    until: Option<String>,
    priority: Option<String>,
    #[serde(rename = "output")]
    output_format: Option<String>,
    reverse: Option<bool>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshServiceLogsArgs);

#[mcp_standard_tool(name = "ssh_service_logs", group = "systemd", annotation = "read_only")]
pub struct ServiceLogsTool;

impl StandardTool for ServiceLogsTool {
    type Args = SshServiceLogsArgs;

    const NAME: &'static str = "ssh_service_logs";

    const DESCRIPTION: &'static str = "View journalctl logs for a systemd service on a remote host. Prefer this over \
        ssh_exec as it provides structured filtering by time range, priority level, and \
        output format. Use 'lines' to limit volume, 'since'/'until' for time ranges, \
        'priority' to filter by severity, and 'output=json' for machine-readable logs. \
        Use ssh_service_status for a concise current-state summary instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "service"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "service": {
                "type": "string",
                "description": "Name of the systemd service (e.g., nginx, sshd, docker)"
            },
            "lines": {
                "type": "integer",
                "description": "Number of recent log lines to return (default: journalctl default)"
            },
            "since": {
                "type": "string",
                "description": "Show entries since this time (e.g., '1 hour ago', '2024-01-01', 'today')"
            },
            "until": {
                "type": "string",
                "description": "Show entries until this time (e.g., 'now', '2024-01-02')"
            },
            "priority": {
                "type": "string",
                "description": "Filter by priority level",
                "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
            },
            "output": {
                "type": "string",
                "description": "Output format (default: short)",
                "enum": ["short", "short-iso", "json", "cat", "verbose"]
            },
            "reverse": {
                "type": "boolean",
                "description": "Show newest entries first (default: false)"
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

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshServiceLogsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(SystemdCommandBuilder::build_logs_command(
            &args.service,
            args.lines,
            args.since.as_deref(),
            args.until.as_deref(),
            args.priority.as_deref(),
            args.output_format.as_deref(),
            args.reverse.unwrap_or(false),
        ))
    }

    fn validate(args: &SshServiceLogsArgs, _host_config: &HostConfig) -> Result<()> {
        validate_service_name(&args.service)?;
        Ok(())
    }
}

/// Handler for the `ssh_service_logs` tool.
pub type SshServiceLogsHandler = StandardToolHandler<ServiceLogsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshServiceLogsHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshServiceLogsHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "service": "nginx"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshServiceLogsHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_service_logs");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("service")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "service": "nginx",
            "lines": 100,
            "since": "1 hour ago",
            "until": "now",
            "priority": "err",
            "output": "json",
            "reverse": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshServiceLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.service, "nginx");
        assert_eq!(args.lines, Some(100));
        assert_eq!(args.since, Some("1 hour ago".to_string()));
        assert_eq!(args.until, Some("now".to_string()));
        assert_eq!(args.priority, Some("err".to_string()));
        assert_eq!(args.output_format, Some("json".to_string()));
        assert_eq!(args.reverse, Some(true));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "service": "nginx"});
        let args: SshServiceLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.service, "nginx");
        assert!(args.lines.is_none());
        assert!(args.since.is_none());
        assert!(args.until.is_none());
        assert!(args.priority.is_none());
        assert!(args.output_format.is_none());
        assert!(args.reverse.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshServiceLogsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("lines"));
        assert!(props.contains_key("since"));
        assert!(props.contains_key("until"));
        assert!(props.contains_key("priority"));
        assert!(props.contains_key("output"));
        assert!(props.contains_key("reverse"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "service": "s"});
        let args: SshServiceLogsArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshServiceLogsArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "service": "nginx"});
        let result = serde_json::from_value::<SshServiceLogsArgs>(json);
        assert!(result.is_err());
    }

    // ============== build_command Tests ==============

    use crate::config::{HostKeyVerification, OsType};

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
        let args = SshServiceLogsArgs {
            host: "server1".to_string(),
            service: "nginx".to_string(),
            lines: None,
            since: None,
            until: None,
            priority: None,
            output_format: None,
            reverse: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = ServiceLogsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("journalctl -u 'nginx'"));
        assert!(cmd.contains("--no-pager"));
    }

    #[test]
    fn test_build_command_with_lines_since() {
        let args = SshServiceLogsArgs {
            host: "server1".to_string(),
            service: "nginx".to_string(),
            lines: Some(100),
            since: Some("1 hour ago".to_string()),
            until: None,
            priority: None,
            output_format: None,
            reverse: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = ServiceLogsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--lines=100"));
        assert!(cmd.contains("--since '1 hour ago'"));
    }

    #[test]
    fn test_build_command_with_priority_format() {
        let args = SshServiceLogsArgs {
            host: "server1".to_string(),
            service: "docker".to_string(),
            lines: None,
            since: None,
            until: Some("now".to_string()),
            priority: Some("err".to_string()),
            output_format: Some("json".to_string()),
            reverse: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = ServiceLogsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--until 'now'"));
        assert!(cmd.contains("--priority='err'"));
        assert!(cmd.contains("--output='json'"));
        assert!(cmd.contains("--reverse"));
    }
}
