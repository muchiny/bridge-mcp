//! SSH `ESXi` VM Info Tool Handler
//!
//! Retrieves detailed summary of a specific VM on an `ESXi` host
//! via `vim-cmd vmsvc/get.summary`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::esxi::EsxiCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshEsxiVmInfoArgs {
    host: String,
    vm_id: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshEsxiVmInfoArgs);

#[mcp_standard_tool(name = "ssh_esxi_vm_info", group = "esxi", annotation = "read_only")]
pub struct EsxiVmInfoTool;

impl StandardTool for EsxiVmInfoTool {
    type Args = SshEsxiVmInfoArgs;

    const NAME: &'static str = "ssh_esxi_vm_info";

    const DESCRIPTION: &'static str = "Get detailed summary of a VM on a VMware ESXi host. Returns guest OS, power state, \
        CPU/memory config, IP address, tools status, and more. Use ssh_esxi_vm_list first to \
        find the VM ID.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml — must be an ESXi host (use ssh_status to list hosts)"
            },
            "vm_id": {
                "type": "string",
                "description": "VM ID from vim-cmd vmsvc/getallvms (use ssh_esxi_vm_list to find IDs)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 40000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "vm_id"]
    }"#;

    fn build_command(args: &SshEsxiVmInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(EsxiCommandBuilder::build_vm_info_command(&args.vm_id))
    }
}

/// Handler for the `ssh_esxi_vm_info` tool.
pub type SshEsxiVmInfoHandler = StandardToolHandler<EsxiVmInfoTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshEsxiVmInfoHandler::new();
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
        let handler = SshEsxiVmInfoHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "vm_id": "42"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshEsxiVmInfoHandler::new();
        assert_eq!(handler.name(), "ssh_esxi_vm_info");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("vm_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "esxi1",
            "vm_id": "42",
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshEsxiVmInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert_eq!(args.vm_id, "42");
        assert_eq!(args.timeout_seconds, Some(30));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "esxi1", "vm_id": "1"});
        let args: SshEsxiVmInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert_eq!(args.vm_id, "1");
        assert!(args.timeout_seconds.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshEsxiVmInfoHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": "esxi1"})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshEsxiVmInfoHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "esxi1", "vm_id": "42"});
        let args: SshEsxiVmInfoArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshEsxiVmInfoArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshEsxiVmInfoHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "vm_id": "42"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
