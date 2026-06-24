//! SSH AWX Inventory Sources Tool Handler
//!
//! Lists AWX inventory sources via REST API relayed through SSH.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_awx_inventory_sources` tool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SshAwxInventorySourcesArgs {
    #[serde(default)]
    inventory: Option<u64>,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

/// Handler for the `ssh_awx_inventory_sources` tool.
#[mcp_tool(
    name = "ssh_awx_inventory_sources",
    group = "awx",
    annotation = "read_only"
)]
pub struct SshAwxInventorySourcesHandler;

impl Default for SshAwxInventorySourcesHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxInventorySourcesHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "inventory": {
                "type": "integer",
                "description": "Filter by parent inventory ID",
                "minimum": 1
            },
            "page_size": {
                "type": "integer",
                "description": "Number of results per page (default: 25)",
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
        "required": []
    }"#;
}

#[async_trait]
impl ToolHandler for SshAwxInventorySourcesHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_inventory_sources"
    }

    fn description(&self) -> &'static str {
        "List AWX inventory sources. Returns source names, types, and sync status. \
         Reduce with jq_filter='.results[] | {id,name,source,status,last_updated}' \
         output_format=tsv."
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
        let args: SshAwxInventorySourcesArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        if let Some(inventory) = args.inventory {
            AwxCommandBuilder::validate_id(inventory)?;
        }

        let page_size_str = args.page_size.unwrap_or(25).to_string();
        let inventory_str = args.inventory.map(|id| id.to_string());
        let mut query_params: Vec<(&str, &str)> = vec![("page_size", &page_size_str)];
        if let Some(ref inventory) = inventory_str {
            query_params.push(("inventory", inventory));
        }

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            "/api/v2/inventory_sources/",
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
        let handler = SshAwxInventorySourcesHandler;
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
        let handler = SshAwxInventorySourcesHandler;
        assert_eq!(handler.name(), "ssh_awx_inventory_sources");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_inventory_sources");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "inventory": 7,
            "page_size": 25,
            "timeout_seconds": 60
        });

        let args: SshAwxInventorySourcesArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.inventory, Some(7));
        assert_eq!(args.page_size, Some(25));
        assert_eq!(args.timeout_seconds, Some(60));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({});

        let args: SshAwxInventorySourcesArgs = serde_json::from_value(json).unwrap();
        assert!(args.inventory.is_none());
        assert!(args.page_size.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAwxInventorySourcesHandler;
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();

        let props = &schema_json["properties"];
        assert!(props.get("inventory").is_some());
        assert!(props.get("page_size").is_some());
        assert!(props.get("timeout_seconds").is_some());
        assert!(schema_json["required"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({});
        let args: SshAwxInventorySourcesArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxInventorySourcesArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxInventorySourcesHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"page_size": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxInventorySourcesHandler;
        let ctx = create_test_context();

        let result = handler.execute(Some(json!({})), &ctx).await;
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
        let handler = SshAwxInventorySourcesHandler;
        assert_eq!(handler.output_kind(), OutputKind::Json);
    }
}
