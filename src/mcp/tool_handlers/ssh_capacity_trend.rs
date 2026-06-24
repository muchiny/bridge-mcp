//! Handler for the `ssh_capacity_trend` tool.
//!
//! Shows resource usage trends on a remote host using sar or current snapshot.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::capacity::CapacityCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshCapacityTrendArgs {
    /// Target host name from configuration.
    host: String,
    /// Resource to analyze (cpu, memory, disk, all). Defaults to "all".
    #[serde(default)]
    resource: Option<String>,
    /// Number of days to look back. Defaults to 7, max 365.
    #[serde(default)]
    days: Option<u32>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshCapacityTrendArgs);

#[mcp_standard_tool(
    name = "ssh_capacity_trend",
    group = "capacity",
    annotation = "read_only"
)]
pub struct CapacityTrendTool;

impl StandardTool for CapacityTrendTool {
    type Args = SshCapacityTrendArgs;

    const NAME: &'static str = "ssh_capacity_trend";

    const DESCRIPTION: &'static str = "Show a human-readable resource usage trend report on a \
        remote host for cpu, memory, disk, or all resources over a configurable lookback window \
        (default 7 days, up to 365). Uses sar (sysstat) for historical data when available. \
        If sar/sysstat is not installed the tool falls back to a current-only snapshot \u{2014} \
        historical trend data will be absent; install sysstat on the remote host to enable full \
        historical reporting. Use this tool when you need a readable summary of usage over time. \
        For machine-structured raw historical data for LLM forecasting use ssh_capacity_predict. \
        For a current-only snapshot across all resources use ssh_capacity_collect.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "resource": {
                        "type": "string",
                        "description": "Resource to analyze (cpu, memory, disk, all). Defaults to 'all'.",
                        "enum": ["cpu", "memory", "disk", "all"]
                    },
                    "days": {
                        "type": "integer",
                        "description": "Number of days to look back (1-365). Defaults to 7.",
                        "minimum": 1,
                        "maximum": 365
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

    fn build_command(args: &SshCapacityTrendArgs, _host_config: &HostConfig) -> Result<String> {
        CapacityCommandBuilder::build_capacity_trend_command(args.resource.as_deref(), args.days)
    }
}

/// Handler for the `ssh_capacity_trend` tool.
pub type SshCapacityTrendHandler = StandardToolHandler<CapacityTrendTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCapacityTrendHandler::new();
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
        let handler = SshCapacityTrendHandler::new();
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
        let handler = SshCapacityTrendHandler::new();
        assert_eq!(handler.name(), "ssh_capacity_trend");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_capacity_trend");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "resource": "cpu",
            "days": 14,
            "timeout_seconds": 30,
            "max_output": 10000,
            "save_output": "/tmp/trend.txt"
        });
        let args: SshCapacityTrendArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource.as_deref(), Some("cpu"));
        assert_eq!(args.days, Some(14));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/trend.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshCapacityTrendArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.resource.is_none());
        assert!(args.days.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCapacityTrendHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("resource"));
        assert!(props.contains_key("days"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshCapacityTrendArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCapacityTrendArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCapacityTrendHandler::new();
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
        let args = SshCapacityTrendArgs {
            host: "s".to_string(),
            resource: None,
            days: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CapacityTrendTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("sar"));
    }

    #[test]
    fn test_build_command_cpu() {
        let args = SshCapacityTrendArgs {
            host: "s".to_string(),
            resource: Some("cpu".to_string()),
            days: Some(14),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CapacityTrendTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-u"));
        assert!(cmd.contains("14"));
    }
}
