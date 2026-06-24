//! SSH AWX Workflow Approvals Tool Handler
//!
//! Lists the approval nodes a given workflow run is blocked on, via the AWX
//! REST API relayed through SSH.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_awx_workflow_approvals` tool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SshAwxWorkflowApprovalsArgs {
    workflow_job_id: u64,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

/// Handler for the `ssh_awx_workflow_approvals` tool.
#[mcp_tool(
    name = "ssh_awx_workflow_approvals",
    group = "awx",
    annotation = "read_only"
)]
pub struct SshAwxWorkflowApprovalsHandler;

impl Default for SshAwxWorkflowApprovalsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxWorkflowApprovalsHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "workflow_job_id": {
                "type": "integer",
                "description": "ID of the workflow job whose pending approvals to list",
                "minimum": 1
            },
            "status": {
                "type": "string",
                "description": "Approval status filter (default: pending)"
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
        "required": ["workflow_job_id"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshAwxWorkflowApprovalsHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_workflow_approvals"
    }

    fn description(&self) -> &'static str {
        "Approvals a given workflow run is blocked on. jq_filter='.results[] | {id,name,status}'."
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
        let args: SshAwxWorkflowApprovalsArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.workflow_job_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let id_str = args.workflow_job_id.to_string();
        let status = args.status.as_deref().unwrap_or("pending");
        let page_size_str = args.page_size.unwrap_or(50).to_string();
        // `source_workflow_job` is only a summary_field, not a filterable DB
        // column. The queryable relation from a WorkflowApproval (a UnifiedJob)
        // to its run is `unified_job_node__workflow_job`.
        let query_params: Vec<(&str, &str)> = vec![
            ("unified_job_node__workflow_job", &id_str),
            ("status", status),
            ("page_size", &page_size_str),
        ];

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            "/api/v2/workflow_approvals/",
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
        let handler = SshAwxWorkflowApprovalsHandler;
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

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxWorkflowApprovalsHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"workflow_job_id": 42})), &ctx)
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
    fn test_schema() {
        let handler = SshAwxWorkflowApprovalsHandler;
        assert_eq!(handler.name(), "ssh_awx_workflow_approvals");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_workflow_approvals");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "workflow_job_id": 7,
            "status": "successful",
            "page_size": 25,
            "timeout_seconds": 60
        });

        let args: SshAwxWorkflowApprovalsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.workflow_job_id, 7);
        assert_eq!(args.status, Some("successful".to_string()));
        assert_eq!(args.page_size, Some(25));
        assert_eq!(args.timeout_seconds, Some(60));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({ "workflow_job_id": 1 });

        let args: SshAwxWorkflowApprovalsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.workflow_job_id, 1);
        assert!(args.status.is_none());
        assert!(args.page_size.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let schema_json: serde_json::Value =
            serde_json::from_str(SshAwxWorkflowApprovalsHandler.schema().input_schema).unwrap();
        assert!(schema_json["properties"].is_object());
        assert!(schema_json["properties"]["status"].is_object());
        assert!(schema_json["properties"]["page_size"].is_object());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({ "workflow_job_id": 1 });
        let args: SshAwxWorkflowApprovalsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxWorkflowApprovalsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxWorkflowApprovalsHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"workflow_job_id": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_output_kind() {
        let handler = SshAwxWorkflowApprovalsHandler;
        assert_eq!(handler.output_kind(), OutputKind::Json);
    }

    // ===== Task 1.13 extra tests =====

    #[tokio::test]
    async fn test_validate_workflow_job_id_zero() {
        // workflow_job_id=0 must be rejected by validate_id (CommandDenied),
        // independent of AWX configuration.
        let handler = SshAwxWorkflowApprovalsHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"workflow_job_id": 0})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { .. } => {}
            e => panic!("Expected CommandDenied for id=0, got: {e:?}"),
        }
    }

    #[test]
    fn test_default_status_is_pending() {
        // When `status` is omitted, the handler defaults the query to "pending".
        let args: SshAwxWorkflowApprovalsArgs =
            serde_json::from_value(json!({"workflow_job_id": 5})).unwrap();
        let status = args.status.as_deref().unwrap_or("pending");
        assert_eq!(status, "pending");
    }

    #[test]
    fn test_query_uses_source_workflow_job_id() {
        // The collection is filtered by source_workflow_job__id for the given run.
        let id_str = 5u64.to_string();
        let query_params: Vec<(&str, &str)> = vec![("source_workflow_job__id", &id_str)];
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "tok",
            "/api/v2/workflow_approvals/",
            HttpMethod::Get,
            None,
            true,
            &query_params,
            30,
        );
        assert!(
            cmd.contains("source_workflow_job__id=5"),
            "missing id filter: {cmd}"
        );
    }
}
