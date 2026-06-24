//! Handler for the `ssh_awx_job_events` tool.
//!
//! Retrieves structured events from an AWX job by building a `curl` GET
//! command and relaying it via SSH to the configured AWX host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_job_events` tool.
#[derive(Debug, Deserialize)]
struct SshAwxJobEventsArgs {
    /// AWX job ID.
    job_id: u64,
    /// Number of events per page (default: 20).
    #[serde(default)]
    page_size: Option<u32>,
    /// Filter by event type (e.g., `runner_on_failed`, `playbook_on_stats`).
    #[serde(default)]
    event_type: Option<String>,
    /// Only return events with counter greater than this value (for incremental polling).
    #[serde(default)]
    counter_gt: Option<u64>,
    /// Filter events by host name.
    #[serde(default)]
    host_name: Option<String>,
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "job_id": {
            "type": "integer",
            "description": "AWX job ID",
            "minimum": 1
        },
        "page_size": {
            "type": "integer",
            "description": "Number of events per page (default: 20)",
            "minimum": 1,
            "maximum": 200
        },
        "event_type": {
            "type": "string",
            "description": "Filter by event type (e.g., runner_on_failed, runner_on_changed, playbook_on_stats)"
        },
        "counter_gt": {
            "type": "integer",
            "description": "Only return events with counter greater than this value (for incremental polling)",
            "minimum": 0
        },
        "host_name": {
            "type": "string",
            "description": "Filter events by host name"
        }
    },
    "required": ["job_id"]
}"#;

/// Handler for retrieving structured events from AWX jobs.
#[mcp_tool(name = "ssh_awx_job_events", group = "awx", annotation = "read_only")]
pub struct SshAwxJobEventsHandler;

impl Default for SshAwxJobEventsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxJobEventsHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for SshAwxJobEventsHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_job_events"
    }

    fn description(&self) -> &'static str {
        "Get structured events from an AWX job. Filter by event type \
         (runner_on_failed, runner_on_changed, playbook_on_stats), by host, or use \
         counter_gt for incremental polling. Use jq_filter for extraction (e.g., \
         '.results[] | {event, host: .event_data.host, task: .event_data.task}')."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_job_events",
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
        let args: SshAwxJobEventsArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.job_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let endpoint = format!("/api/v2/jobs/{}/job_events/", args.job_id);

        // Build query params
        let page_size_str = args.page_size.unwrap_or(20).to_string();
        let mut query_params: Vec<(&str, &str)> = vec![("page_size", &page_size_str)];

        let event_type_str;
        if let Some(ref et) = args.event_type {
            event_type_str = et.clone();
            query_params.push(("event", &event_type_str));
        }

        let counter_gt_str;
        if let Some(cg) = args.counter_gt {
            counter_gt_str = cg.to_string();
            query_params.push(("counter__gt", &counter_gt_str));
        }

        let host_name_str;
        if let Some(ref hn) = args.host_name {
            host_name_str = hn.clone();
            query_params.push(("event_data__host", &host_name_str));
        }

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
        let handler = SshAwxJobEventsHandler;
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
        let handler = SshAwxJobEventsHandler;
        assert_eq!(handler.name(), "ssh_awx_job_events");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_job_events");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("job_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "job_id": 123,
            "page_size": 50,
            "event_type": "runner_on_failed",
            "counter_gt": 100,
            "host_name": "web01"
        });
        let args: SshAwxJobEventsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.job_id, 123);
        assert_eq!(args.page_size, Some(50));
        assert_eq!(args.event_type.as_deref(), Some("runner_on_failed"));
        assert_eq!(args.counter_gt, Some(100));
        assert_eq!(args.host_name.as_deref(), Some("web01"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"job_id": 42});
        let args: SshAwxJobEventsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.job_id, 42);
        assert!(args.page_size.is_none());
        assert!(args.event_type.is_none());
        assert!(args.counter_gt.is_none());
        assert!(args.host_name.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"job_id": 42});
        let args: SshAwxJobEventsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxJobEventsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxJobEventsHandler;
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
        let handler = SshAwxJobEventsHandler;
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
