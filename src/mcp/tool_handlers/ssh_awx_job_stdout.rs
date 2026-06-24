//! Handler for the `ssh_awx_job_stdout` tool.
//!
//! Retrieves the full stdout of an AWX job by building a `curl` GET
//! command and relaying it via SSH to the configured AWX host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_job_stdout` tool.
#[derive(Debug, Deserialize)]
struct SshAwxJobStdoutArgs {
    /// AWX job ID.
    job_id: u64,
    /// Output format: txt (default), json, or ansi.
    #[serde(default, rename = "format")]
    output_format: Option<String>,
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "job_id": {
            "type": "integer",
            "description": "AWX job ID",
            "minimum": 1
        },
        "format": {
            "type": "string",
            "description": "Output format: txt (default), json, or ansi",
            "enum": ["txt", "json", "ansi"]
        }
    },
    "required": ["job_id"]
}"#;

/// Handler for retrieving the full stdout of an AWX job.
#[mcp_tool(name = "ssh_awx_job_stdout", group = "awx", annotation = "read_only")]
pub struct SshAwxJobStdoutHandler;

impl Default for SshAwxJobStdoutHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxJobStdoutHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for SshAwxJobStdoutHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_job_stdout"
    }

    fn description(&self) -> &'static str {
        "Get the full stdout of an AWX job. Use format='txt' for plain text, 'json' for \
         structured JSON, 'ansi' for colored output. Warning: can be very large. Prefer \
         ssh_awx_job_summary for token-efficient monitoring."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_job_stdout",
            description: self.description(),
            input_schema: SCHEMA,
        }
    }

    fn output_kind(&self) -> crate::domain::output_kind::OutputKind {
        crate::domain::output_kind::OutputKind::RawText
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let args: SshAwxJobStdoutArgs = args
            .ok_or_else(|| BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            })
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))
            })?;

        AwxCommandBuilder::validate_id(args.job_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let endpoint = format!("/api/v2/jobs/{}/stdout/", args.job_id);

        let fmt = args.output_format.as_deref().unwrap_or("txt");
        let query_params = [("format", fmt)];

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
        let stdout = AwxCommandBuilder::parse_checked_response(&raw)?;
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
        let handler = SshAwxJobStdoutHandler;
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
        let handler = SshAwxJobStdoutHandler;
        assert_eq!(handler.name(), "ssh_awx_job_stdout");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_job_stdout");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("job_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "job_id": 123,
            "format": "json"
        });
        let args: SshAwxJobStdoutArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.job_id, 123);
        assert_eq!(args.output_format.as_deref(), Some("json"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"job_id": 42});
        let args: SshAwxJobStdoutArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.job_id, 42);
        assert!(args.output_format.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"job_id": 42});
        let args: SshAwxJobStdoutArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxJobStdoutArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxJobStdoutHandler;
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
        let handler = SshAwxJobStdoutHandler;
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
