//! SSH AWX Template Detail Tool Handler
//!
//! Gets detailed information about an AWX job template via REST API relayed
//! through SSH.

use std::fmt::Write;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_awx_template_detail` tool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SshAwxTemplateDetailArgs {
    template_id: u64,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

/// Handler for the `ssh_awx_template_detail` tool.
#[mcp_tool(
    name = "ssh_awx_template_detail",
    group = "awx",
    annotation = "read_only"
)]
pub struct SshAwxTemplateDetailHandler;

impl Default for SshAwxTemplateDetailHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxTemplateDetailHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "template_id": {
                "type": "integer",
                "description": "AWX job template ID",
                "minimum": 1
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            }
        },
        "required": ["template_id"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshAwxTemplateDetailHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_template_detail"
    }

    fn description(&self) -> &'static str {
        "Get detailed information about an AWX job template including survey spec, credentials, \
         and last job run. Use ssh_awx_templates to list templates and discover their IDs before \
         calling this tool. Use jq_filter for specific fields."
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
        let args: SshAwxTemplateDetailArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.template_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let mut endpoint = String::new();
        let _ = write!(endpoint, "/api/v2/job_templates/{}/", args.template_id);

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            &endpoint,
            HttpMethod::Get,
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
        let handler = SshAwxTemplateDetailHandler;
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

    #[test]
    fn test_schema() {
        let handler = SshAwxTemplateDetailHandler;
        assert_eq!(handler.name(), "ssh_awx_template_detail");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_template_detail");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("template_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "template_id": 42,
            "timeout_seconds": 60
        });

        let args: SshAwxTemplateDetailArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.template_id, 42);
        assert_eq!(args.timeout_seconds, Some(60));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "template_id": 1
        });

        let args: SshAwxTemplateDetailArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.template_id, 1);
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"template_id": 5});
        let args: SshAwxTemplateDetailArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxTemplateDetailArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxTemplateDetailHandler;
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
        let handler = SshAwxTemplateDetailHandler;
        let ctx = create_test_context();

        let result = handler.execute(Some(json!({"template_id": 1})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("AWX not configured"));
            }
            e => panic!("Expected McpInvalidRequest about AWX config, got: {e:?}"),
        }
    }

    #[test]
    fn test_output_kind() {
        let handler = SshAwxTemplateDetailHandler;
        assert_eq!(handler.output_kind(), OutputKind::Json);
    }
}
