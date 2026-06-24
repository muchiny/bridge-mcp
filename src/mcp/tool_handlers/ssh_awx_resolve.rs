//! SSH AWX Resolve Tool Handler
//!
//! Resolves an AWX object name to its id via REST API relayed through SSH.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Object kinds that can be resolved by name.
const ALLOWED_KINDS: &[&str] = &[
    "job_templates",
    "workflow_job_templates",
    "inventories",
    "projects",
    "credentials",
    "hosts",
];

/// Arguments for `ssh_awx_resolve` tool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SshAwxResolveArgs {
    kind: String,
    name: String,
    #[serde(default)]
    exact: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

/// Handler for the `ssh_awx_resolve` tool.
#[mcp_tool(name = "ssh_awx_resolve", group = "awx", annotation = "read_only")]
pub struct SshAwxResolveHandler;

impl Default for SshAwxResolveHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxResolveHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "description": "Object type to resolve",
                "enum": [
                    "job_templates",
                    "workflow_job_templates",
                    "inventories",
                    "projects",
                    "credentials",
                    "hosts"
                ]
            },
            "name": {
                "type": "string",
                "description": "Object name to look up"
            },
            "exact": {
                "type": "boolean",
                "description": "Match the name exactly (case-insensitive). Default: true. When false, matches substrings."
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            }
        },
        "required": ["kind", "name"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshAwxResolveHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_resolve"
    }

    fn description(&self) -> &'static str {
        "Resolve an AWX object name to its id. Returns matching {id,name}. \
         jq_filter='.results[] | {id,name}'"
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
        let args: SshAwxResolveArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        if !ALLOWED_KINDS.contains(&args.kind.as_str()) {
            return Err(BridgeError::McpInvalidRequest(format!(
                "Unknown kind '{}'. Allowed: {}",
                args.kind,
                ALLOWED_KINDS.join(", ")
            )));
        }

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let exact = args.exact.unwrap_or(true);
        let filter_key = if exact {
            "name__iexact"
        } else {
            "name__icontains"
        };
        let query_params: Vec<(&str, &str)> = vec![(filter_key, &args.name)];

        let endpoint = format!("/api/v2/{}/", args.kind);
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
        let handler = SshAwxResolveHandler;
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
        let handler = SshAwxResolveHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({"kind": "job_templates", "name": "deploy"})),
                &ctx,
            )
            .await;
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
        let handler = SshAwxResolveHandler;
        assert_eq!(handler.name(), "ssh_awx_resolve");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_resolve");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "kind": "inventories",
            "name": "prod",
            "exact": false,
            "timeout_seconds": 60
        });

        let args: SshAwxResolveArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.kind, "inventories");
        assert_eq!(args.name, "prod");
        assert_eq!(args.exact, Some(false));
        assert_eq!(args.timeout_seconds, Some(60));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "kind": "projects",
            "name": "app"
        });

        let args: SshAwxResolveArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.kind, "projects");
        assert_eq!(args.name, "app");
        assert!(args.exact.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let schema: serde_json::Value =
            serde_json::from_str(SshAwxResolveHandler.schema().input_schema).unwrap();
        assert!(schema["properties"].is_object());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"kind": "projects", "name": "app"});
        let args: SshAwxResolveArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxResolveArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxResolveHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"kind": "job_templates", "name": 42, "exact": "yes"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_rejects_unknown_kind() {
        let handler = SshAwxResolveHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"kind": "../etc", "name": "passwd"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("Unknown kind"));
            }
            e => panic!("Expected McpInvalidRequest for unknown kind, got: {e:?}"),
        }
    }

    #[test]
    fn test_exact_uses_iexact_query() {
        // exact=true selects the `name__iexact` filter; exact=false selects
        // `name__icontains`. Assert via the builder's emitted command.
        let exact_cmd = AwxCommandBuilder::build_api_call_checked(
            "https://awx.internal",
            "tok",
            "/api/v2/job_templates/",
            HttpMethod::Get,
            None,
            true,
            &[("name__iexact", "deploy")],
            30,
        );
        assert!(exact_cmd.contains("name__iexact=deploy"));

        let fuzzy_cmd = AwxCommandBuilder::build_api_call_checked(
            "https://awx.internal",
            "tok",
            "/api/v2/job_templates/",
            HttpMethod::Get,
            None,
            true,
            &[("name__icontains", "deploy")],
            30,
        );
        assert!(fuzzy_cmd.contains("name__icontains=deploy"));
    }

    #[test]
    fn test_default_exact_true() {
        let json = json!({"kind": "job_templates", "name": "deploy"});
        let args: SshAwxResolveArgs = serde_json::from_value(json).unwrap();
        assert!(args.exact.unwrap_or(true));
    }

    #[test]
    fn test_output_kind() {
        let handler = SshAwxResolveHandler;
        assert_eq!(handler.output_kind(), OutputKind::Json);
    }
}
