//! Handler for the `ssh_awx_host_create` tool.
//!
//! Adds a host to an AWX inventory by building a `curl` POST command and
//! relaying it via SSH to the configured AWX host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_host_create` tool.
#[derive(Debug, Deserialize)]
struct SshAwxHostCreateArgs {
    /// Inventory ID to add the host to.
    inventory_id: u64,
    /// Name of the host (hostname or IP).
    name: String,
    /// Host variables (native JSON object).
    #[serde(default)]
    variables: Option<serde_json::Value>,
    /// Whether the host is enabled.
    #[serde(default)]
    enabled: Option<bool>,
    /// Optional description for the host.
    #[serde(default)]
    description: Option<String>,
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "inventory_id": {
            "type": "integer",
            "description": "Inventory ID to add the host to",
            "minimum": 1
        },
        "name": {
            "type": "string",
            "description": "Name of the host (hostname or IP)"
        },
        "variables": {
            "type": "object",
            "description": "Host variables (native JSON object)"
        },
        "enabled": {
            "type": "boolean",
            "description": "Whether the host is enabled"
        },
        "description": {
            "type": "string",
            "description": "Optional description for the host"
        }
    },
    "required": ["inventory_id", "name"]
}"#;

/// Handler for adding a host to an AWX inventory.
#[mcp_tool(name = "ssh_awx_host_create", group = "awx", annotation = "mutating")]
pub struct SshAwxHostCreateHandler;

impl Default for SshAwxHostCreateHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxHostCreateHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for SshAwxHostCreateHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_host_create"
    }

    fn description(&self) -> &'static str {
        "Add a host to an AWX inventory. Returns the created host object. \
         Use ssh_awx_inventory_hosts to list inventory hosts."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_host_create",
            description: self.description(),
            input_schema: SCHEMA,
        }
    }

    fn output_kind(&self) -> crate::domain::output_kind::OutputKind {
        crate::domain::output_kind::OutputKind::Json
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let mut raw = args.ok_or_else(|| BridgeError::McpMissingParam {
            param: "arguments".to_string(),
        })?;
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut raw);
        let args: SshAwxHostCreateArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.inventory_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        // Build JSON body with only non-None fields.
        let mut body_map = serde_json::Map::new();
        body_map.insert(
            "name".to_string(),
            serde_json::Value::String(args.name.clone()),
        );
        if let Some(ref description) = args.description {
            body_map.insert(
                "description".to_string(),
                serde_json::Value::String(description.clone()),
            );
        }
        if let Some(enabled) = args.enabled {
            body_map.insert("enabled".to_string(), serde_json::Value::Bool(enabled));
        }
        if let Some(ref variables) = args.variables {
            body_map.insert("variables".to_string(), variables.clone());
        }

        let endpoint = format!("/api/v2/inventories/{}/hosts/", args.inventory_id);
        let body_str = serde_json::Value::Object(body_map).to_string();

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            &endpoint,
            HttpMethod::Post,
            Some(&body_str),
            awx.verify_ssl,
            &[],
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
        crate::mcp::standard_tool::apply_reduction(
            &mut stdout,
            &dr,
            crate::domain::output_kind::OutputKind::Json,
        )?;
        Ok(ToolCallResult::text(stdout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAwxHostCreateHandler;
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxHostCreateHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"inventory_id": 7, "name": "web1"})), &ctx)
            .await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("AWX not configured"),
            "Expected AWX not configured error, got: {err_msg}"
        );
    }

    #[test]
    fn test_schema() {
        let handler = SshAwxHostCreateHandler;
        assert_eq!(handler.name(), "ssh_awx_host_create");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_host_create");
        let schema_json: Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("inventory_id")));
        assert!(required.contains(&json!("name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "inventory_id": 7,
            "name": "web1.internal",
            "variables": {"ansible_host": "10.0.0.5", "ansible_port": 22},
            "enabled": true,
            "description": "Front-end web server"
        });
        let args: SshAwxHostCreateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.inventory_id, 7);
        assert_eq!(args.name, "web1.internal");
        assert!(args.variables.is_some());
        assert_eq!(args.enabled, Some(true));
        assert_eq!(args.description.as_deref(), Some("Front-end web server"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"inventory_id": 1, "name": "host-a"});
        let args: SshAwxHostCreateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.inventory_id, 1);
        assert_eq!(args.name, "host-a");
        assert!(args.variables.is_none());
        assert!(args.enabled.is_none());
        assert!(args.description.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let schema_json: Value =
            serde_json::from_str(SshAwxHostCreateHandler.schema().input_schema).unwrap();
        assert!(schema_json["properties"].is_object());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"inventory_id": 1, "name": "host-a"});
        let args: SshAwxHostCreateArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxHostCreateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxHostCreateHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"inventory_id": "not_a_number", "name": "web1"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_body_has_name() {
        // The request body must carry the host `name` as a JSON string field so
        // AWX creates the host under the inventory. Mirror the body-building
        // logic the handler uses.
        let args: SshAwxHostCreateArgs =
            serde_json::from_value(json!({"inventory_id": 7, "name": "web1.internal"})).unwrap();
        let mut body_map = serde_json::Map::new();
        body_map.insert(
            "name".to_string(),
            serde_json::Value::String(args.name.clone()),
        );
        let body_str = serde_json::Value::Object(body_map).to_string();
        assert!(
            body_str.contains("\"name\":\"web1.internal\""),
            "body missing name field: {body_str}"
        );
    }
}
