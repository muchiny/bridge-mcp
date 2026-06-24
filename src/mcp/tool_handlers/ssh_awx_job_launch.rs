//! Handler for the `ssh_awx_job_launch` tool.
//!
//! Launches an AWX job from a template by building a `curl` POST command
//! and relaying it via SSH to the configured AWX host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_job_launch` tool.
#[derive(Debug, Deserialize)]
struct SshAwxJobLaunchArgs {
    /// Job template ID to launch.
    template_id: u64,
    /// Extra variables to pass to the job template (JSON object).
    #[serde(default)]
    extra_vars: Option<serde_json::Value>,
    /// Limit pattern for the job (host subset).
    #[serde(default)]
    limit: Option<String>,
    /// Inventory ID to use instead of the template default.
    #[serde(default)]
    inventory: Option<u64>,
    /// Credential ID to use instead of the template default.
    #[serde(default)]
    credential: Option<u64>,
    /// Verbosity level (0-5).
    #[serde(default)]
    verbosity: Option<u8>,
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "template_id": {
            "type": "integer",
            "description": "Job template ID to launch",
            "minimum": 1
        },
        "extra_vars": {
            "type": "object",
            "description": "Extra variables to pass to the job template (JSON object)"
        },
        "limit": {
            "type": "string",
            "description": "Limit pattern for the job (host subset)"
        },
        "inventory": {
            "type": "integer",
            "description": "Inventory ID to use instead of the template default",
            "minimum": 1
        },
        "credential": {
            "type": "integer",
            "description": "Credential ID to use instead of the template default",
            "minimum": 1
        },
        "verbosity": {
            "type": "integer",
            "description": "Verbosity level (0-5)",
            "minimum": 0,
            "maximum": 5
        }
    },
    "required": ["template_id"]
}"#;

/// Handler for launching AWX jobs from templates.
#[mcp_tool(name = "ssh_awx_job_launch", group = "awx", annotation = "mutating")]
pub struct SshAwxJobLaunchHandler;

impl Default for SshAwxJobLaunchHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxJobLaunchHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for SshAwxJobLaunchHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_job_launch"
    }

    fn description(&self) -> &'static str {
        "Launch an AWX job from a template. Returns the job ID and initial status. \
         Use ssh_awx_job_status or ssh_awx_job_events to monitor progress."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_job_launch",
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
        let args: SshAwxJobLaunchArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.template_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        // Build JSON body with only non-None fields
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
        if let Some(credential) = args.credential {
            body_map.insert(
                "credential".to_string(),
                serde_json::Value::Number(credential.into()),
            );
        }
        if let Some(verbosity) = args.verbosity {
            body_map.insert(
                "verbosity".to_string(),
                serde_json::Value::Number(verbosity.into()),
            );
        }

        let endpoint = format!("/api/v2/job_templates/{}/launch/", args.template_id);
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
        let handler = SshAwxJobLaunchHandler;
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
        let handler = SshAwxJobLaunchHandler;
        assert_eq!(handler.name(), "ssh_awx_job_launch");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_job_launch");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("template_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "template_id": 42,
            "extra_vars": {"env": "prod", "version": "1.2.3"},
            "limit": "webservers",
            "inventory": 5,
            "credential": 10,
            "verbosity": 2
        });
        let args: SshAwxJobLaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.template_id, 42);
        assert!(args.extra_vars.is_some());
        assert_eq!(args.limit.as_deref(), Some("webservers"));
        assert_eq!(args.inventory, Some(5));
        assert_eq!(args.credential, Some(10));
        assert_eq!(args.verbosity, Some(2));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"template_id": 1});
        let args: SshAwxJobLaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.template_id, 1);
        assert!(args.extra_vars.is_none());
        assert!(args.limit.is_none());
        assert!(args.inventory.is_none());
        assert!(args.credential.is_none());
        assert!(args.verbosity.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"template_id": 42});
        let args: SshAwxJobLaunchArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxJobLaunchArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxJobLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"template_id": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxJobLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"template_id": 42})), &ctx)
            .await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("AWX not configured"),
            "Expected AWX not configured error, got: {err_msg}"
        );
    }
}
