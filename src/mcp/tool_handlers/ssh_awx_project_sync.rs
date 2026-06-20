//! Handler for the `ssh_awx_project_sync` tool.
//!
//! Triggers a project SCM sync in AWX by building a `curl` POST command
//! and relaying it via SSH to the configured AWX host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_project_sync` tool.
#[derive(Debug, Deserialize)]
struct SshAwxProjectSyncArgs {
    /// AWX project ID to sync.
    project_id: u64,
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "project_id": {
            "type": "integer",
            "description": "AWX project ID to sync",
            "minimum": 1
        }
    },
    "required": ["project_id"]
}"#;

/// Handler for triggering AWX project SCM syncs.
#[mcp_tool(name = "ssh_awx_project_sync", group = "awx", annotation = "mutating")]
pub struct SshAwxProjectSyncHandler;

impl Default for SshAwxProjectSyncHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxProjectSyncHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for SshAwxProjectSyncHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_project_sync"
    }

    fn description(&self) -> &'static str {
        "Trigger a project SCM sync in AWX. Updates the project from its source control \
         repository. To discover project IDs, query the AWX API directly \
         (GET /api/v2/projects/) via ssh_exec or check the AWX web UI; there is no \
         dedicated list-projects tool in this group."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_project_sync",
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
        let args: SshAwxProjectSyncArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.project_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let endpoint = format!("/api/v2/projects/{}/update/", args.project_id);

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
        let handler = SshAwxProjectSyncHandler;
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
        let handler = SshAwxProjectSyncHandler;
        assert_eq!(handler.name(), "ssh_awx_project_sync");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_project_sync");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("project_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"project_id": 15});
        let args: SshAwxProjectSyncArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.project_id, 15);
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"project_id": 1});
        let args: SshAwxProjectSyncArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.project_id, 1);
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"project_id": 42});
        let args: SshAwxProjectSyncArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxProjectSyncArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxProjectSyncHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"project_id": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxProjectSyncHandler;
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"project_id": 42})), &ctx).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("AWX not configured"),
            "Expected AWX not configured error, got: {err_msg}"
        );
    }
}
