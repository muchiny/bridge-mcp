//! Handler for the `ssh_awx_project_update_stdout` tool.
//!
//! Retrieves the full stdout of an AWX project update (SCM sync) by
//! building a `curl` GET command and relaying it via SSH to the
//! configured AWX host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_project_update_stdout` tool.
#[derive(Debug, Deserialize)]
struct SshAwxProjectUpdateStdoutArgs {
    /// AWX project update ID.
    project_update_id: u64,
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "project_update_id": {
            "type": "integer",
            "description": "AWX project update ID",
            "minimum": 1
        }
    },
    "required": ["project_update_id"]
}"#;

/// Handler for retrieving the full stdout of an AWX project update.
#[mcp_tool(
    name = "ssh_awx_project_update_stdout",
    group = "awx",
    annotation = "read_only"
)]
pub struct SshAwxProjectUpdateStdoutHandler;

impl Default for SshAwxProjectUpdateStdoutHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxProjectUpdateStdoutHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for SshAwxProjectUpdateStdoutHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_project_update_stdout"
    }

    fn description(&self) -> &'static str {
        "Get the full stdout (SCM sync log) of an AWX project update. Warning: can be \
         very large. Use ssh_awx_project_update_status for token-efficient polling."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_project_update_stdout",
            description: self.description(),
            input_schema: SCHEMA,
        }
    }

    fn output_kind(&self) -> crate::domain::output_kind::OutputKind {
        crate::domain::output_kind::OutputKind::RawText
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let args: SshAwxProjectUpdateStdoutArgs = args
            .ok_or_else(|| BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            })
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))
            })?;

        AwxCommandBuilder::validate_id(args.project_update_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let endpoint = format!("/api/v2/project_updates/{}/stdout/", args.project_update_id);

        let query_params = [("format", "txt")];

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
        let handler = SshAwxProjectUpdateStdoutHandler;
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
        let handler = SshAwxProjectUpdateStdoutHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"project_update_id": 42})), &ctx)
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
        let handler = SshAwxProjectUpdateStdoutHandler;
        assert_eq!(handler.name(), "ssh_awx_project_update_stdout");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_project_update_stdout");
        let schema_json: Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("project_update_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"project_update_id": 123});
        let args: SshAwxProjectUpdateStdoutArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.project_update_id, 123);
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"project_update_id": 42});
        let args: SshAwxProjectUpdateStdoutArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.project_update_id, 42);
    }

    #[test]
    fn test_schema_optional_fields() {
        let schema_json: Value =
            serde_json::from_str(SshAwxProjectUpdateStdoutHandler.schema().input_schema).unwrap();
        assert!(schema_json["properties"].is_object());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"project_update_id": 42});
        let args: SshAwxProjectUpdateStdoutArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxProjectUpdateStdoutArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxProjectUpdateStdoutHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"project_update_id": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_output_kind_is_raw_text() {
        let handler = SshAwxProjectUpdateStdoutHandler;
        assert!(matches!(
            handler.output_kind(),
            crate::domain::output_kind::OutputKind::RawText
        ));
    }

    #[tokio::test]
    async fn test_validate_id_zero() {
        let handler = SshAwxProjectUpdateStdoutHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"project_update_id": 0})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { .. } => {}
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }
}
