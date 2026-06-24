//! Handler for the `ssh_awx_bulk_launch` tool.
//!
//! Launches N AWX jobs atomically via the bulk job-launch endpoint by building
//! a `curl` POST command and relaying it via SSH to the configured AWX host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// A single job entry in a bulk launch request.
#[derive(Debug, Deserialize)]
struct BulkJob {
    /// Unified job template ID to launch.
    unified_job_template: u64,
    /// Inventory ID to use instead of the template default.
    #[serde(default)]
    inventory: Option<u64>,
    /// Limit pattern for the job (host subset).
    #[serde(default)]
    limit: Option<String>,
    /// Extra variables to pass to the job template (JSON object).
    #[serde(default)]
    extra_vars: Option<serde_json::Value>,
}

/// Arguments for the `ssh_awx_bulk_launch` tool.
#[derive(Debug, Deserialize)]
struct SshAwxBulkLaunchArgs {
    /// Jobs to launch in a single atomic bulk request (must be non-empty).
    jobs: Vec<BulkJob>,
    /// Optional name for the bulk job.
    #[serde(default)]
    name: Option<String>,
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "jobs": {
            "type": "array",
            "description": "Jobs to launch in a single atomic bulk request (must be non-empty)",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "unified_job_template": {
                        "type": "integer",
                        "description": "Unified job template ID to launch",
                        "minimum": 1
                    },
                    "inventory": {
                        "type": "integer",
                        "description": "Inventory ID to use instead of the template default",
                        "minimum": 1
                    },
                    "limit": {
                        "type": "string",
                        "description": "Limit pattern for the job (host subset)"
                    },
                    "extra_vars": {
                        "type": "object",
                        "description": "Extra variables to pass to the job template (JSON object)"
                    }
                },
                "required": ["unified_job_template"]
            }
        },
        "name": {
            "type": "string",
            "description": "Name for the bulk job (defaults to 'bridge-mcp bulk launch' if omitted)"
        }
    },
    "required": ["jobs"]
}"#;

/// Build the bulk job-launch request body.
///
/// `name` is ALWAYS emitted (defaulted when the caller omits it) because AWX's
/// bulk serializer treats it as required on some releases; per-job `None` fields
/// are omitted. Each job entry always carries `unified_job_template`.
fn build_bulk_body(args: &SshAwxBulkLaunchArgs) -> Value {
    let mut jobs_arr = Vec::with_capacity(args.jobs.len());
    for job in &args.jobs {
        let mut job_map = serde_json::Map::new();
        job_map.insert(
            "unified_job_template".to_string(),
            Value::Number(job.unified_job_template.into()),
        );
        if let Some(inventory) = job.inventory {
            job_map.insert("inventory".to_string(), Value::Number(inventory.into()));
        }
        if let Some(ref limit) = job.limit {
            job_map.insert("limit".to_string(), Value::String(limit.clone()));
        }
        if let Some(ref extra_vars) = job.extra_vars {
            job_map.insert("extra_vars".to_string(), extra_vars.clone());
        }
        jobs_arr.push(Value::Object(job_map));
    }
    let mut body_map = serde_json::Map::new();
    let name = args.name.as_deref().unwrap_or("bridge-mcp bulk launch");
    body_map.insert("name".to_string(), Value::String(name.to_string()));
    body_map.insert("jobs".to_string(), Value::Array(jobs_arr));
    Value::Object(body_map)
}

/// Handler for launching N AWX jobs atomically.
#[mcp_tool(name = "ssh_awx_bulk_launch", group = "awx", annotation = "mutating")]
pub struct SshAwxBulkLaunchHandler;

impl Default for SshAwxBulkLaunchHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxBulkLaunchHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for SshAwxBulkLaunchHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_bulk_launch"
    }

    fn description(&self) -> &'static str {
        "Launch N AWX jobs atomically in a single bulk request. Returns the bulk \
         job and the spawned job IDs. Use ssh_awx_job_status to monitor each."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_bulk_launch",
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
        let args: SshAwxBulkLaunchArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        if args.jobs.is_empty() {
            return Err(BridgeError::McpInvalidRequest(
                "jobs must contain at least one job".to_string(),
            ));
        }

        for job in &args.jobs {
            AwxCommandBuilder::validate_id(job.unified_job_template)?;
            if let Some(inventory) = job.inventory {
                AwxCommandBuilder::validate_id(inventory)?;
            }
        }

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let body_str = build_bulk_body(&args).to_string();

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            "/api/v2/bulk/job_launch/",
            HttpMethod::Post,
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
        let handler = SshAwxBulkLaunchHandler;
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
        let handler = SshAwxBulkLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"jobs": [{"unified_job_template": 1}]})), &ctx)
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
        let handler = SshAwxBulkLaunchHandler;
        assert_eq!(handler.name(), "ssh_awx_bulk_launch");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_bulk_launch");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("jobs")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "name": "deploy wave",
            "jobs": [
                {
                    "unified_job_template": 42,
                    "inventory": 5,
                    "limit": "webservers",
                    "extra_vars": {"env": "prod"}
                },
                {"unified_job_template": 7}
            ]
        });
        let args: SshAwxBulkLaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.name.as_deref(), Some("deploy wave"));
        assert_eq!(args.jobs.len(), 2);
        assert_eq!(args.jobs[0].unified_job_template, 42);
        assert_eq!(args.jobs[0].inventory, Some(5));
        assert_eq!(args.jobs[0].limit.as_deref(), Some("webservers"));
        assert!(args.jobs[0].extra_vars.is_some());
        assert_eq!(args.jobs[1].unified_job_template, 7);
        assert!(args.jobs[1].inventory.is_none());
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"jobs": [{"unified_job_template": 1}]});
        let args: SshAwxBulkLaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.jobs.len(), 1);
        assert_eq!(args.jobs[0].unified_job_template, 1);
        assert!(args.name.is_none());
        assert!(args.jobs[0].inventory.is_none());
        assert!(args.jobs[0].limit.is_none());
        assert!(args.jobs[0].extra_vars.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let schema_json: serde_json::Value =
            serde_json::from_str(SshAwxBulkLaunchHandler.schema().input_schema).unwrap();
        assert!(schema_json["properties"].is_object());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"jobs": [{"unified_job_template": 1}]});
        let args: SshAwxBulkLaunchArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxBulkLaunchArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxBulkLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"jobs": "not_an_array"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_rejects_empty_jobs() {
        let handler = SshAwxBulkLaunchHandler;
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"jobs": []})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(
                    msg.contains("at least one job"),
                    "unexpected message: {msg}"
                );
            }
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_body_has_jobs_array() {
        // The serialized body sent to AWX must carry a top-level "jobs" array
        // whose entries omit None fields but always include the template id.
        let args: SshAwxBulkLaunchArgs = serde_json::from_value(json!({
            "name": "wave",
            "jobs": [
                {"unified_job_template": 42, "inventory": 5},
                {"unified_job_template": 7}
            ]
        }))
        .unwrap();

        let body = build_bulk_body(&args);
        let jobs = body["jobs"].as_array().expect("jobs must be an array");
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0]["unified_job_template"], 42);
        assert_eq!(jobs[0]["inventory"], 5);
        assert_eq!(jobs[1]["unified_job_template"], 7);
        assert!(jobs[1].get("inventory").is_none());
        assert_eq!(body["name"], "wave");
    }

    #[test]
    fn test_body_always_sends_name_when_omitted() {
        // AWX requires `name` on the bulk request on some releases; the body must
        // carry a non-empty default even when the caller omits it.
        let args: SshAwxBulkLaunchArgs =
            serde_json::from_value(json!({"jobs": [{"unified_job_template": 1}]})).unwrap();
        assert!(args.name.is_none());

        let body = build_bulk_body(&args);
        let name = body["name"].as_str().expect("name must be present");
        assert!(!name.is_empty(), "default name must be non-empty");
    }
}
