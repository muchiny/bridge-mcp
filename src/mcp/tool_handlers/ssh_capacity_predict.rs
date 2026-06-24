//! Handler for the `ssh_capacity_predict` tool.
//!
//! Collects current and historical data for LLM-based capacity prediction.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::capacity::CapacityCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshCapacityPredictArgs {
    /// Target host name from configuration.
    host: String,
    /// Resource to predict (cpu, memory, disk, all).
    resource: String,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshCapacityPredictArgs);

#[mcp_standard_tool(
    name = "ssh_capacity_predict",
    group = "capacity",
    annotation = "read_only"
)]
pub struct CapacityPredictTool;

impl StandardTool for CapacityPredictTool {
    type Args = SshCapacityPredictArgs;

    const NAME: &'static str = "ssh_capacity_predict";

    const DESCRIPTION: &'static str = "Collect current and historical capacity data for a \
        specific resource (cpu, memory, disk, or all) on a remote host. \
        Returns a current snapshot plus sar historical samples and growth indicators designed \
        for LLM-based extrapolation — this tool does NOT compute a forecast itself. \
        Use this tool when you need machine-structured raw data to extrapolate or forecast \
        resource exhaustion programmatically. \
        For a human-readable trend report with a configurable lookback window use \
        ssh_capacity_trend instead. \
        For a combined current-only snapshot across all resources use ssh_capacity_collect.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "resource": {
                        "type": "string",
                        "description": "Resource to collect historical data for (cpu, memory, disk, all). Use 'all' to gather data across all resource types in a single call.",
                        "enum": ["cpu", "memory", "disk", "all"]
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
                "required": ["host", "resource"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshCapacityPredictArgs, _host_config: &HostConfig) -> Result<String> {
        CapacityCommandBuilder::build_capacity_predict_command(&args.resource)
    }
}

/// Handler for the `ssh_capacity_predict` tool.
pub type SshCapacityPredictHandler = StandardToolHandler<CapacityPredictTool>;

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
        let handler = SshCapacityPredictHandler::new();
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
        let handler = SshCapacityPredictHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "resource": "cpu"})),
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
        let handler = SshCapacityPredictHandler::new();
        assert_eq!(handler.name(), "ssh_capacity_predict");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_capacity_predict");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("resource")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "resource": "cpu",
            "timeout_seconds": 60,
            "max_output": 20000,
            "save_output": "/tmp/predict.txt"
        });
        let args: SshCapacityPredictArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "cpu");
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(20000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/predict.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "resource": "memory"});
        let args: SshCapacityPredictArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "memory");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCapacityPredictHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "resource": "cpu"});
        let args: SshCapacityPredictArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCapacityPredictArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCapacityPredictHandler::new();
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
    fn test_build_command_cpu() {
        let args = SshCapacityPredictArgs {
            host: "s".to_string(),
            resource: "cpu".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CapacityPredictTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("Prediction"));
        assert!(cmd.contains("-u"));
    }

    #[test]
    fn test_build_command_disk() {
        let args = SshCapacityPredictArgs {
            host: "s".to_string(),
            resource: "disk".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CapacityPredictTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-d"));
    }
}
