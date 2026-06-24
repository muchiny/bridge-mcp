//! SSH AWX Inventory Hosts Tool Handler
//!
//! Lists hosts in an AWX inventory via REST API relayed through SSH.

use std::fmt::Write;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_awx_inventory_hosts` tool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SshAwxInventoryHostsArgs {
    inventory_id: u64,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

/// Handler for the `ssh_awx_inventory_hosts` tool.
#[mcp_tool(
    name = "ssh_awx_inventory_hosts",
    group = "awx",
    annotation = "read_only"
)]
pub struct SshAwxInventoryHostsHandler;

impl Default for SshAwxInventoryHostsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxInventoryHostsHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "inventory_id": {
                "type": "integer",
                "description": "AWX inventory ID",
                "minimum": 1
            },
            "page_size": {
                "type": "integer",
                "description": "Number of results per page (default: 50)",
                "minimum": 1,
                "maximum": 200
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            }
        },
        "required": ["inventory_id"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshAwxInventoryHostsHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_inventory_hosts"
    }

    fn description(&self) -> &'static str {
        "List hosts in an AWX inventory. Returns host names, IDs, and enabled status."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    fn output_kind(&self) -> OutputKind {
        OutputKind::Json
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let mut raw = args.ok_or_else(|| BridgeError::McpMissingParam {
            param: "arguments".to_string(),
        })?;
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut raw);
        let args: SshAwxInventoryHostsArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.inventory_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let mut endpoint = String::new();
        let _ = write!(endpoint, "/api/v2/inventories/{}/hosts/", args.inventory_id);

        let page_size_str = args.page_size.unwrap_or(50).to_string();
        let query_params: Vec<(&str, &str)> = vec![("page_size", &page_size_str)];

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            &endpoint,
            HttpMethod::Get,
            None,
            awx.verify_ssl,
            &query_params,
            awx.api_timeout,
        );

        let host = &awx.ssh_host;
        let host_config = ctx
            .config
            .hosts
            .get(host)
            .ok_or_else(|| BridgeError::UnknownHost { host: host.clone() })?;

        let limits = ctx.config.limits.clone();
        let mut conn = ctx
            .connection_pool
            .get_connection_with_jump(host, host_config, &limits, None)
            .await?;
        let output = conn.exec(&cmd, &limits).await?;

        let raw = ctx
            .execute_use_case
            .process_success(host, &cmd, &output.into())
            .stdout;
        let mut stdout = AwxCommandBuilder::parse_checked_response(&raw)?;
        crate::mcp::standard_tool::apply_reduction(&mut stdout, &dr, OutputKind::Json)?;
        Ok(ToolCallResult::text(stdout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAwxInventoryHostsHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam error, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshAwxInventoryHostsHandler;
        assert_eq!(handler.name(), "ssh_awx_inventory_hosts");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_inventory_hosts");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("inventory_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "inventory_id": 10,
            "page_size": 25,
            "timeout_seconds": 60
        });

        let args: SshAwxInventoryHostsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.inventory_id, 10);
        assert_eq!(args.page_size, Some(25));
        assert_eq!(args.timeout_seconds, Some(60));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "inventory_id": 1
        });

        let args: SshAwxInventoryHostsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.inventory_id, 1);
        assert!(args.page_size.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"inventory_id": 5});
        let args: SshAwxInventoryHostsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxInventoryHostsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxInventoryHostsHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"inventory_id": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxInventoryHostsHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"inventory_id": 1})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("AWX not configured"));
            }
            e => panic!("Expected McpInvalidRequest about AWX config, got: {e:?}"),
        }
    }

    #[test]
    fn test_output_kind() {
        let handler = SshAwxInventoryHostsHandler;
        assert_eq!(handler.output_kind(), OutputKind::Json);
    }
}
