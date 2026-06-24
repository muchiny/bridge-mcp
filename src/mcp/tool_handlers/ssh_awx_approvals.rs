//! SSH AWX Approvals Tool Handler
//!
//! Lists AWX workflow approval nodes via REST API relayed through SSH.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Approval status filter.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ApprovalStatus {
    /// Awaiting an approve/deny decision.
    #[default]
    Pending,
    /// Already approved.
    Successful,
    /// Already denied or timed out.
    Failed,
}

impl ApprovalStatus {
    /// AWX query-string value for this status.
    fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Successful => "successful",
            Self::Failed => "failed",
        }
    }
}

/// Arguments for the `ssh_awx_approvals` tool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SshAwxApprovalsArgs {
    /// Filter by approval status (default: pending).
    #[serde(default)]
    status: ApprovalStatus,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

/// Handler for the `ssh_awx_approvals` tool.
#[mcp_tool(name = "ssh_awx_approvals", group = "awx", annotation = "read_only")]
pub struct SshAwxApprovalsHandler;

impl Default for SshAwxApprovalsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxApprovalsHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "description": "Filter by approval status (default: pending)",
                "enum": ["pending", "successful", "failed"]
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
        "required": []
    }"#;
}

#[async_trait]
impl ToolHandler for SshAwxApprovalsHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_approvals"
    }

    fn description(&self) -> &'static str {
        "List AWX workflow approval nodes (default: pending). Each pending approval blocks its \
         workflow until resolved with ssh_awx_approval_approve or ssh_awx_approval_deny. Use \
         jq_filter (e.g. '.results[] | {id, name, workflow_job: \
         .summary_fields.source_workflow_job.id}')."
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
        let args: SshAwxApprovalsArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let page_size_str = args.page_size.unwrap_or(50).to_string();
        let mut query_params: Vec<(&str, &str)> = vec![("page_size", &page_size_str)];
        query_params.push(("status", args.status.as_str()));

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
        let handler = SshAwxApprovalsHandler;
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
        let handler = SshAwxApprovalsHandler;
        assert_eq!(handler.name(), "ssh_awx_approvals");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_approvals");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"status": "successful", "page_size": 10, "timeout_seconds": 30});
        let args: SshAwxApprovalsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.status.as_str(), "successful");
        assert_eq!(args.page_size, Some(10));
        assert_eq!(args.timeout_seconds, Some(30));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({});
        let args: SshAwxApprovalsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.status.as_str(), "pending");
        assert!(args.page_size.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({});
        let args: SshAwxApprovalsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxApprovalsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxApprovalsHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"status": "bogus"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxApprovalsHandler;
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({})), &ctx).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("AWX not configured"),
            "Expected AWX not configured error, got: {err_msg}"
        );
    }

    #[test]
    fn test_output_kind() {
        let handler = SshAwxApprovalsHandler;
        assert_eq!(handler.output_kind(), OutputKind::Json);
    }

    #[test]
    fn test_status_default_is_pending() {
        let args: SshAwxApprovalsArgs = serde_json::from_value(json!({})).unwrap();
        assert_eq!(args.status.as_str(), "pending");
    }
}
