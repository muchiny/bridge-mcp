//! SSH `ESXi` VM Power Tool Handler
//!
//! Performs power operations on a VM on an `ESXi` host
//! via `vim-cmd vmsvc/power.*`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::esxi::EsxiCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshEsxiVmPowerArgs {
    host: String,
    vm_id: String,
    action: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshEsxiVmPowerArgs);

#[mcp_standard_tool(name = "ssh_esxi_vm_power", group = "esxi", annotation = "mutating")]
pub struct EsxiVmPowerTool;

impl StandardTool for EsxiVmPowerTool {
    type Args = SshEsxiVmPowerArgs;

    const NAME: &'static str = "ssh_esxi_vm_power";

    const DESCRIPTION: &'static str = "Perform power operations on a VM on a VMware ESXi host. Actions: on (power on), off \
        (hard power off), reset (hard reset), shutdown (graceful via VMware Tools), suspend, \
        getstate (check current power state). Use ssh_esxi_vm_list first to find VM IDs.";

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
            "action": {
                "type": "string",
                "description": "Power action to perform",
                "enum": ["on", "off", "reset", "shutdown", "suspend", "getstate"]
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
        "required": ["host", "vm_id", "action"]
    }"#;

    fn validate(args: &SshEsxiVmPowerArgs, _host_config: &HostConfig) -> Result<()> {
        EsxiCommandBuilder::validate_power_action(&args.action)
    }

    fn build_command(args: &SshEsxiVmPowerArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(EsxiCommandBuilder::build_vm_power_command(
            &args.vm_id,
            &args.action,
        ))
    }
}

/// Handler for the `ssh_esxi_vm_power` tool.
pub type SshEsxiVmPowerHandler = StandardToolHandler<EsxiVmPowerTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshEsxiVmPowerHandler::new();
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
        let handler = SshEsxiVmPowerHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "vm_id": "1", "action": "on"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_action() {
        let handler = SshEsxiVmPowerHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "vm_id": "1", "action": "destroy"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("destroy"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshEsxiVmPowerHandler::new();
        assert_eq!(handler.name(), "ssh_esxi_vm_power");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("vm_id")));
        assert!(required.contains(&json!("action")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "esxi1",
            "vm_id": "42",
            "action": "on",
            "timeout_seconds": 60
        });
        let args: SshEsxiVmPowerArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert_eq!(args.vm_id, "42");
        assert_eq!(args.action, "on");
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshEsxiVmPowerHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "esxi1", "vm_id": "1"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "esxi1", "vm_id": "1", "action": "on"});
        let args: SshEsxiVmPowerArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshEsxiVmPowerArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshEsxiVmPowerHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "vm_id": "1", "action": "on"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
