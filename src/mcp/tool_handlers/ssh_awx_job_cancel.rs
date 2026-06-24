//! Handler for the `ssh_awx_job_cancel` tool.
//!
//! Cancels a running AWX job by building a `curl` POST command
//! and relaying it via SSH to the configured AWX host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_job_cancel` tool.
#[derive(Debug, Deserialize)]
struct SshAwxJobCancelArgs {
    /// AWX job ID to cancel.
    job_id: u64,
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "job_id": {
            "type": "integer",
            "description": "AWX job ID to cancel",
            "minimum": 1
        }
    },
    "required": ["job_id"]
}"#;

/// Handler for cancelling running AWX jobs.
#[mcp_tool(name = "ssh_awx_job_cancel", group = "awx", annotation = "destructive")]
pub struct SshAwxJobCancelHandler;

impl Default for SshAwxJobCancelHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxJobCancelHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for SshAwxJobCancelHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_job_cancel"
    }

    fn description(&self) -> &'static str {
        "Cancel a running AWX job. Returns the updated job status."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_job_cancel",
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
        let args: SshAwxJobCancelArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.job_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let endpoint = format!("/api/v2/jobs/{}/cancel/", args.job_id);

        let cmd = AwxCommandBuilder::build_api_call_checked(
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
        let handler = SshAwxJobCancelHandler;
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
        let handler = SshAwxJobCancelHandler;
        assert_eq!(handler.name(), "ssh_awx_job_cancel");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_job_cancel");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("job_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"job_id": 123});
        let args: SshAwxJobCancelArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.job_id, 123);
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"job_id": 1});
        let args: SshAwxJobCancelArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.job_id, 1);
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"job_id": 42});
        let args: SshAwxJobCancelArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxJobCancelArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxJobCancelHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"job_id": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxJobCancelHandler;
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"job_id": 42})), &ctx).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("AWX not configured"),
            "Expected AWX not configured error, got: {err_msg}"
        );
    }
}
