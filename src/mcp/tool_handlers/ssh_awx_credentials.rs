//! SSH AWX Credentials Tool Handler
//!
//! Lists AWX credentials (ids only — inputs/secrets are never returned by AWX)
//! via REST API relayed through SSH.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_awx_credentials` tool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SshAwxCredentialsArgs {
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    credential_type: Option<u64>,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

/// Handler for the `ssh_awx_credentials` tool.
#[mcp_tool(name = "ssh_awx_credentials", group = "awx", annotation = "read_only")]
pub struct SshAwxCredentialsHandler;

impl Default for SshAwxCredentialsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxCredentialsHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "search": {
                "type": "string",
                "description": "Search filter for credential names"
            },
            "credential_type": {
                "type": "integer",
                "description": "Filter by credential type id",
                "minimum": 1
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
impl ToolHandler for SshAwxCredentialsHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_credentials"
    }

    fn description(&self) -> &'static str {
        "List AWX credentials for id resolution. Inputs/secrets are never returned by AWX. \
         jq_filter='.results[] | {id,name,credential_type}'"
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
        let args: SshAwxCredentialsArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let page_size_str = args.page_size.unwrap_or(50).to_string();
        let mut query_params: Vec<(&str, &str)> = vec![("page_size", &page_size_str)];
        if let Some(ref search) = args.search {
            query_params.push(("search", search));
        }
        let credential_type_str;
        if let Some(credential_type) = args.credential_type {
            credential_type_str = credential_type.to_string();
            query_params.push(("credential_type", &credential_type_str));
        }

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            "/api/v2/credentials/",
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
        let handler = SshAwxCredentialsHandler;
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
        let handler = SshAwxCredentialsHandler;
        let ctx = create_test_context();

        let result = handler.execute(Some(json!({})), &ctx).await;
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
        let handler = SshAwxCredentialsHandler;
        assert_eq!(handler.name(), "ssh_awx_credentials");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_credentials");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "search": "vault",
            "credential_type": 5,
            "page_size": 25,
            "timeout_seconds": 60
        });

        let args: SshAwxCredentialsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.search, Some("vault".to_string()));
        assert_eq!(args.credential_type, Some(5));
        assert_eq!(args.page_size, Some(25));
        assert_eq!(args.timeout_seconds, Some(60));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({});

        let args: SshAwxCredentialsArgs = serde_json::from_value(json).unwrap();
        assert!(args.search.is_none());
        assert!(args.credential_type.is_none());
        assert!(args.page_size.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let schema_json: serde_json::Value =
            serde_json::from_str(SshAwxCredentialsHandler.schema().input_schema).unwrap();
        assert!(schema_json["properties"].is_object());
        assert!(schema_json["properties"]["credential_type"].is_object());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({});
        let args: SshAwxCredentialsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxCredentialsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxCredentialsHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"credential_type": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_output_kind() {
        let handler = SshAwxCredentialsHandler;
        assert_eq!(handler.output_kind(), OutputKind::Json);
    }
}
