//! SSH AWX Approval Approve Tool Handler
//!
//! Approves a pending AWX workflow approval via REST API relayed through SSH.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_approval_approve` tool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SshAwxApprovalApproveArgs {
    /// AWX workflow approval ID to approve.
    approval_id: u64,
}

/// Handler for the `ssh_awx_approval_approve` tool.
#[mcp_tool(
    name = "ssh_awx_approval_approve",
    group = "awx",
    annotation = "mutating"
)]
pub struct SshAwxApprovalApproveHandler;

impl Default for SshAwxApprovalApproveHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxApprovalApproveHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    const SCHEMA: &'static str = r#"{
    "type": "object",
    "properties": {
        "approval_id": {
            "type": "integer",
            "description": "AWX workflow approval ID to approve",
            "minimum": 1
        }
    },
    "required": ["approval_id"]
}"#;
}

#[async_trait]
impl ToolHandler for SshAwxApprovalApproveHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_approval_approve"
    }

    fn description(&self) -> &'static str {
        "Approve a pending AWX workflow approval, allowing its workflow to proceed. Find the ID with ssh_awx_approvals."
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
        let args: SshAwxApprovalApproveArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.approval_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let endpoint = format!("/api/v2/workflow_approvals/{}/approve/", args.approval_id);

        let cmd = AwxCommandBuilder::build_api_call(
            &awx.url,
            &awx.token,
            &endpoint,
            HttpMethod::Post,
            None,
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

        let stdout = ctx
            .execute_use_case
            .process_success(host, &cmd, &output.into())
            .stdout;
        let mut stdout = stdout;
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
        let handler = SshAwxApprovalApproveHandler;
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
        let handler = SshAwxApprovalApproveHandler;
        assert_eq!(handler.name(), "ssh_awx_approval_approve");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_approval_approve");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("approval_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"approval_id": 42});
        let args: SshAwxApprovalApproveArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.approval_id, 42);
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"approval_id": 1});
        let args: SshAwxApprovalApproveArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.approval_id, 1);
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"approval_id": 1});
        let args: SshAwxApprovalApproveArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxApprovalApproveArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxApprovalApproveHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"approval_id": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxApprovalApproveHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"approval_id": 42})), &ctx)
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
        let handler = SshAwxApprovalApproveHandler;
        assert_eq!(handler.output_kind(), OutputKind::Json);
    }
}
