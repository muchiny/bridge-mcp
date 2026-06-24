//! Handler for the `ssh_alert_check` tool.
//!
//! Checks a specific metric against an optional threshold on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::alerting::AlertingCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshAlertCheckArgs {
    /// Target host name from configuration.
    host: String,
    /// Metric to check (cpu, memory, disk, load, swap).
    metric: String,
    /// Optional threshold value to compare against.
    #[serde(default)]
    threshold: Option<f64>,
    /// Optional comparison operator (>, <, >=, <=, ==). Defaults to ">" if threshold is set.
    #[serde(default)]
    operator: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshAlertCheckArgs);

#[mcp_standard_tool(name = "ssh_alert_check", group = "alerting", annotation = "read_only")]
pub struct AlertCheckTool;

impl StandardTool for AlertCheckTool {
    type Args = SshAlertCheckArgs;

    const NAME: &'static str = "ssh_alert_check";

    const DESCRIPTION: &'static str = "One-shot metric check on a remote host: reads the \
        current value of a metric and, if threshold is supplied, compares it and prints ALERT \
        or OK; if no threshold is given, returns the raw value. Both threshold and operator are \
        optional. Use this for flexible probing; use ssh_alert_set when both threshold and \
        operator are always known (they are required there). For an overview of all five metrics \
        at once use ssh_alert_list. Threshold units: cpu/memory/disk/swap as percentage 0-100; \
        load as a raw float (1-minute average from /proc/loadavg). \
        Supported metrics: cpu, memory, disk, load, swap.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "metric": {
                        "type": "string",
                        "description": "Metric to check (cpu, memory, disk, load, swap)",
                        "enum": ["cpu", "memory", "disk", "load", "swap"]
                    },
                    "threshold": {
                        "type": "number",
                        "description": "Threshold value to compare against. Units: percentage 0-100 for cpu/memory/disk/swap; raw float (1-min average) for load. Omit to return the raw value without comparison."
                    },
                    "operator": {
                        "type": "string",
                        "description": "Comparison operator (>, <, >=, <=, ==). Defaults to '>' if threshold is set.",
                        "enum": [">", "<", ">=", "<=", "=="]
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
                "required": ["host", "metric"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshAlertCheckArgs, _host_config: &HostConfig) -> Result<String> {
        AlertingCommandBuilder::build_alert_check_metric_command(
            &args.metric,
            args.threshold,
            args.operator.as_deref(),
        )
    }
}

/// Handler for the `ssh_alert_check` tool.
pub type SshAlertCheckHandler = StandardToolHandler<AlertCheckTool>;

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
        let handler = SshAlertCheckHandler::new();
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
        let handler = SshAlertCheckHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "metric": "cpu"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshAlertCheckHandler::new();
        assert_eq!(handler.name(), "ssh_alert_check");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_alert_check");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("metric")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "metric": "cpu",
            "threshold": 80.0,
            "operator": ">",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/check.txt"
        });
        let args: SshAlertCheckArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.metric, "cpu");
        assert!((args.threshold.unwrap() - 80.0).abs() < f64::EPSILON);
        assert_eq!(args.operator.as_deref(), Some(">"));
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/check.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "metric": "cpu"});
        let args: SshAlertCheckArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.metric, "cpu");
        assert!(args.threshold.is_none());
        assert!(args.operator.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAlertCheckHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("threshold"));
        assert!(props.contains_key("operator"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "metric": "cpu"});
        let args: SshAlertCheckArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAlertCheckArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAlertCheckHandler::new();
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
    fn test_build_command_no_threshold() {
        let args = SshAlertCheckArgs {
            host: "s".to_string(),
            metric: "cpu".to_string(),
            threshold: None,
            operator: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = AlertCheckTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("cpu="));
    }

    #[test]
    fn test_build_command_with_threshold() {
        let args = SshAlertCheckArgs {
            host: "s".to_string(),
            metric: "memory".to_string(),
            threshold: Some(90.0),
            operator: Some(">=".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = AlertCheckTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("memory"));
        assert!(cmd.contains("90"));
    }
}
