//! SSH `ESXi` Host Info Tool Handler
//!
//! Retrieves `ESXi` host information via `esxcli` and `vim-cmd`.
//! Supports subsystems: hostname, memory, cpu, version, maintenance, all.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::esxi::EsxiCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshEsxiHostInfoArgs {
    host: String,
    #[serde(default)]
    subsystem: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshEsxiHostInfoArgs);

#[mcp_standard_tool(name = "ssh_esxi_host_info", group = "esxi", annotation = "read_only")]
pub struct EsxiHostInfoTool;

impl StandardTool for EsxiHostInfoTool {
    type Args = SshEsxiHostInfoArgs;

    const NAME: &'static str = "ssh_esxi_host_info";

    const DESCRIPTION: &'static str = "Get VMware ESXi host information. Subsystems: hostname, memory, cpu, version, \
        maintenance (read-only check of current maintenance mode status — to enter or exit maintenance mode \
        use esxcli system maintenanceMode set via ssh_exec), or all (default, returns everything). \
        Uses esxcli and vim-cmd commands.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml — must be an ESXi host (use ssh_status to list hosts)"
            },
            "subsystem": {
                "type": "string",
                "description": "Host info subsystem to query (default: all)",
                "enum": ["hostname", "memory", "cpu", "version", "maintenance", "all"]
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host"]
    }"#;

    fn validate(args: &SshEsxiHostInfoArgs, _host_config: &HostConfig) -> Result<()> {
        if let Some(subsystem) = &args.subsystem {
            EsxiCommandBuilder::validate_host_subsystem(subsystem)?;
        }
        Ok(())
    }

    fn build_command(args: &SshEsxiHostInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(EsxiCommandBuilder::build_host_info_command(
            args.subsystem.as_deref(),
        ))
    }
}

/// Handler for the `ssh_esxi_host_info` tool.
pub type SshEsxiHostInfoHandler = StandardToolHandler<EsxiHostInfoTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshEsxiHostInfoHandler::new();
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
        let handler = SshEsxiHostInfoHandler::new();
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

    #[tokio::test]
    async fn test_invalid_subsystem() {
        let handler = SshEsxiHostInfoHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(Some(json!({"host": "server1", "subsystem": "disk"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("disk"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshEsxiHostInfoHandler::new();
        assert_eq!(handler.name(), "ssh_esxi_host_info");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_esxi_host_info");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "esxi1",
            "subsystem": "cpu",
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshEsxiHostInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert_eq!(args.subsystem, Some("cpu".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "esxi1"});
        let args: SshEsxiHostInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert!(args.subsystem.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshEsxiHostInfoHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("subsystem"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "esxi1"});
        let args: SshEsxiHostInfoArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshEsxiHostInfoArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshEsxiHostInfoHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
