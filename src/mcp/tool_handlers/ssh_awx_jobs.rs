//! SSH AWX Jobs Tool Handler
//!
//! Lists recent unified jobs (jobs, workflow/project/inventory updates) via the
//! AWX REST API relayed through SSH.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_awx_jobs` tool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SshAwxJobsArgs {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    job_type: Option<String>,
    #[serde(default)]
    name_contains: Option<String>,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

/// Handler for the `ssh_awx_jobs` tool.
#[mcp_tool(name = "ssh_awx_jobs", group = "awx", annotation = "read_only")]
pub struct SshAwxJobsHandler;

impl Default for SshAwxJobsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxJobsHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "description": "Filter by job status (e.g. successful, failed, running, canceled)"
            },
            "job_type": {
                "type": "string",
                "description": "Filter by unified job type (maps to the AWX 'type' query)"
            },
            "name_contains": {
                "type": "string",
                "description": "Case-insensitive substring filter on the job name"
            },
            "page_size": {
                "type": "integer",
                "description": "Number of results per page (default: 25)",
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
impl ToolHandler for SshAwxJobsHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_jobs"
    }

    fn description(&self) -> &'static str {
        "List recent jobs/workflow/project/inventory updates across AWX (triage 'what ran/failed'). \
         jq_filter='.results[] | {id,name,type,status,finished}' output_format=tsv"
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
        let args: SshAwxJobsArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let page_size_str = args.page_size.unwrap_or(25).to_string();
        let mut query_params: Vec<(&str, &str)> = vec![("page_size", &page_size_str)];
        if let Some(ref status) = args.status {
            query_params.push(("status", status));
        }
        if let Some(ref job_type) = args.job_type {
            query_params.push(("type", job_type));
        }
        if let Some(ref name_contains) = args.name_contains {
            query_params.push(("name__icontains", name_contains));
        }
        query_params.push(("order_by", "-finished"));

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            "/api/v2/unified_jobs/",
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
        let handler = SshAwxJobsHandler;
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
        let handler = SshAwxJobsHandler;
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
        let handler = SshAwxJobsHandler;
        assert_eq!(handler.name(), "ssh_awx_jobs");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_jobs");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "status": "failed",
            "job_type": "job",
            "name_contains": "deploy",
            "page_size": 50,
            "timeout_seconds": 60
        });

        let args: SshAwxJobsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.status, Some("failed".to_string()));
        assert_eq!(args.job_type, Some("job".to_string()));
        assert_eq!(args.name_contains, Some("deploy".to_string()));
        assert_eq!(args.page_size, Some(50));
        assert_eq!(args.timeout_seconds, Some(60));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({});

        let args: SshAwxJobsArgs = serde_json::from_value(json).unwrap();
        assert!(args.status.is_none());
        assert!(args.job_type.is_none());
        assert!(args.name_contains.is_none());
        assert!(args.page_size.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let schema_json: serde_json::Value =
            serde_json::from_str(SshAwxJobsHandler.schema().input_schema).unwrap();
        assert!(schema_json["properties"].is_object());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({});
        let args: SshAwxJobsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxJobsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxJobsHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"page_size": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_output_kind() {
        let handler = SshAwxJobsHandler;
        assert_eq!(handler.output_kind(), OutputKind::Json);
    }

    // ============== Task 1.1 extra tests ==============

    #[test]
    fn test_query_includes_order_by() {
        // The unified-jobs feed must always sort by most-recently-finished so the
        // triage view surfaces the latest runs first.
        let cmd = AwxCommandBuilder::build_api_call_checked(
            "https://awx.internal",
            "tok",
            "/api/v2/unified_jobs/",
            HttpMethod::Get,
            None,
            true,
            &[("page_size", "25"), ("order_by", "-finished")],
            30,
        );
        // `-finished` percent-encodes to `-finished` (unreserved) so it survives verbatim.
        assert!(
            cmd.contains("order_by=-finished"),
            "order_by not present: {cmd}"
        );
    }

    #[test]
    fn test_status_filter_maps_to_query() {
        // A `status` filter must be relayed as a `status=` query parameter.
        let cmd = AwxCommandBuilder::build_api_call_checked(
            "https://awx.internal",
            "tok",
            "/api/v2/unified_jobs/",
            HttpMethod::Get,
            None,
            true,
            &[
                ("page_size", "25"),
                ("status", "failed"),
                ("order_by", "-finished"),
            ],
            30,
        );
        assert!(
            cmd.contains("status=failed"),
            "status filter missing: {cmd}"
        );
    }
}
