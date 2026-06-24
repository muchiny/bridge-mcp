//! SSH AWX Workflow Launch Tool Handler
//!
//! Launches an AWX workflow job from a workflow job template via REST API relayed through SSH.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_workflow_launch` tool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SshAwxWorkflowLaunchArgs {
    /// Workflow job template ID to launch.
    workflow_template_id: u64,
    /// Extra variables to pass to the workflow (JSON object).
    #[serde(default)]
    extra_vars: Option<serde_json::Value>,
    /// Limit pattern (host subset) applied to the workflow's jobs.
    #[serde(default)]
    limit: Option<String>,
    /// Inventory ID to use instead of the workflow default.
    #[serde(default)]
    inventory: Option<u64>,
}

/// Handler for the `ssh_awx_workflow_launch` tool.
#[mcp_tool(
    name = "ssh_awx_workflow_launch",
    group = "awx",
    annotation = "mutating"
)]
pub struct SshAwxWorkflowLaunchHandler;

impl Default for SshAwxWorkflowLaunchHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxWorkflowLaunchHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    const SCHEMA: &'static str = r#"{
    "type": "object",
    "properties": {
        "workflow_template_id": {
            "type": "integer",
            "description": "Workflow job template ID to launch",
            "minimum": 1
        },
        "extra_vars": {
            "type": "object",
            "description": "Extra variables to pass to the workflow (JSON object)"
        },
        "limit": {
            "type": "string",
            "description": "Limit pattern (host subset) applied to the workflow's jobs"
        },
        "inventory": {
            "type": "integer",
            "description": "Inventory ID to use instead of the workflow default",
            "minimum": 1
        }
    },
    "required": ["workflow_template_id"]
}"#;
}

#[async_trait]
impl ToolHandler for SshAwxWorkflowLaunchHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_workflow_launch"
    }

    fn description(&self) -> &'static str {
        "Launch an AWX workflow job from a workflow job template. Returns the workflow job ID and \
         initial status. Monitor with ssh_awx_workflow_status and ssh_awx_workflow_nodes."
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
        let args: SshAwxWorkflowLaunchArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.workflow_template_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let mut body_map = serde_json::Map::new();
        if let Some(ref extra_vars) = args.extra_vars {
            body_map.insert(
                "extra_vars".to_string(),
                serde_json::Value::String(extra_vars.to_string()),
            );
        }
        if let Some(ref limit) = args.limit {
            body_map.insert(
                "limit".to_string(),
                serde_json::Value::String(limit.clone()),
            );
        }
        if let Some(inventory) = args.inventory {
            body_map.insert(
                "inventory".to_string(),
                serde_json::Value::Number(inventory.into()),
            );
        }

        let endpoint = format!(
            "/api/v2/workflow_job_templates/{}/launch/",
            args.workflow_template_id
        );
        let body_str = if body_map.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(body_map).to_string())
        };

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            &endpoint,
            HttpMethod::Post,
            body_str.as_deref(),
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
        let handler = SshAwxWorkflowLaunchHandler;
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshAwxWorkflowLaunchHandler;
        assert_eq!(handler.name(), "ssh_awx_workflow_launch");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_workflow_launch");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("workflow_template_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"workflow_template_id": 7, "extra_vars": {"env": "prod"}, "limit": "web", "inventory": 3});
        let args: SshAwxWorkflowLaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.workflow_template_id, 7);
        assert!(args.extra_vars.is_some());
        assert_eq!(args.limit.as_deref(), Some("web"));
        assert_eq!(args.inventory, Some(3));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"workflow_template_id": 1});
        let args: SshAwxWorkflowLaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.workflow_template_id, 1);
        assert!(args.extra_vars.is_none());
        assert!(args.limit.is_none());
        assert!(args.inventory.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"workflow_template_id": 1});
        let args: SshAwxWorkflowLaunchArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxWorkflowLaunchArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxWorkflowLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"workflow_template_id": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxWorkflowLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"workflow_template_id": 7})), &ctx)
            .await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("AWX not configured"),
            "Expected AWX not configured error, got: {err_msg}"
        );
    }

    #[test]
    fn test_output_kind() {
        let handler = SshAwxWorkflowLaunchHandler;
        assert_eq!(handler.output_kind(), OutputKind::Json);
    }
}
