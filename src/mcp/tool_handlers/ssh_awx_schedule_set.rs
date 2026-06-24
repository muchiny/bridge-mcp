//! Handler for the `ssh_awx_schedule_set` tool.
//!
//! Enables or disables an AWX schedule by building a `curl` PATCH command
//! and relaying it via SSH to the configured AWX host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_schedule_set` tool.
#[derive(Debug, Deserialize)]
struct SshAwxScheduleSetArgs {
    /// Schedule ID to enable or disable.
    schedule_id: u64,
    /// Whether the schedule should be enabled (`true`) or disabled (`false`).
    enabled: bool,
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "schedule_id": {
            "type": "integer",
            "description": "Schedule ID to enable or disable",
            "minimum": 1
        },
        "enabled": {
            "type": "boolean",
            "description": "Whether the schedule should be enabled (true) or disabled (false)"
        }
    },
    "required": ["schedule_id", "enabled"]
}"#;

/// Handler for enabling/disabling AWX schedules.
#[mcp_tool(
    name = "ssh_awx_schedule_set",
    group = "awx",
    annotation = "mutating_idempotent"
)]
pub struct SshAwxScheduleSetHandler;

impl Default for SshAwxScheduleSetHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxScheduleSetHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for SshAwxScheduleSetHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_schedule_set"
    }

    fn description(&self) -> &'static str {
        "Enable or disable an AWX schedule by id. Returns the updated schedule. \
         Use ssh_awx_schedules to list schedules and find the id."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_schedule_set",
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
        let args: SshAwxScheduleSetArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.schedule_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let mut body_map = serde_json::Map::new();
        body_map.insert("enabled".to_string(), serde_json::Value::Bool(args.enabled));
        let body_str = serde_json::Value::Object(body_map).to_string();

        let endpoint = format!("/api/v2/schedules/{}/", args.schedule_id);

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            &endpoint,
            HttpMethod::Patch,
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
        let handler = SshAwxScheduleSetHandler;
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
        let handler = SshAwxScheduleSetHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"schedule_id": 5, "enabled": false})), &ctx)
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
        let handler = SshAwxScheduleSetHandler;
        assert_eq!(handler.name(), "ssh_awx_schedule_set");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_schedule_set");
        let schema_json: Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("schedule_id")));
        assert!(required.contains(&json!("enabled")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"schedule_id": 42, "enabled": true});
        let args: SshAwxScheduleSetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.schedule_id, 42);
        assert!(args.enabled);
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"schedule_id": 1, "enabled": false});
        let args: SshAwxScheduleSetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.schedule_id, 1);
        assert!(!args.enabled);
    }

    #[test]
    fn test_schema_optional_fields() {
        let schema_json: Value =
            serde_json::from_str(SshAwxScheduleSetHandler.schema().input_schema).unwrap();
        assert!(schema_json["properties"].is_object());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"schedule_id": 5, "enabled": false});
        let args: SshAwxScheduleSetArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxScheduleSetArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxScheduleSetHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"schedule_id": "not_a_number", "enabled": false})),
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
    fn test_patch_body_enabled() {
        // The PATCH body must carry the boolean `enabled` field verbatim.
        let cmd = AwxCommandBuilder::build_api_call_checked(
            "https://awx.internal",
            "tok",
            "/api/v2/schedules/5/",
            HttpMethod::Patch,
            Some(r#"{"enabled":false}"#),
            true,
            &[],
            30,
        );
        assert!(cmd.contains(r#"{"enabled":false}"#), "body missing: {cmd}");
    }

    #[test]
    fn test_method_is_patch() {
        let cmd = AwxCommandBuilder::build_api_call_checked(
            "https://awx.internal",
            "tok",
            "/api/v2/schedules/5/",
            HttpMethod::Patch,
            Some(r#"{"enabled":true}"#),
            true,
            &[],
            30,
        );
        assert!(cmd.contains("-X PATCH"), "method not PATCH: {cmd}");
    }
}
