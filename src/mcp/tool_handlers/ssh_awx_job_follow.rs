//! SSH AWX Job Follow Tool Handler
//!
//! Launches an AWX job and polls until completion, returning a structured
//! summary. Combines `job_launch` + polling `job_status` + `job_host_summaries`
//! into a single atomic operation.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_awx_job_follow` tool.
#[derive(Debug, Deserialize)]
struct SshAwxJobFollowArgs {
    template_id: u64,
    #[serde(default)]
    extra_vars: Option<Value>,
    #[serde(default)]
    limit: Option<String>,
    /// Poll interval in seconds (default: 5, min: 2, max: 30).
    #[serde(default = "default_poll_interval")]
    poll_interval: u32,
    /// Maximum wait time in seconds (default: 600 = 10 min).
    #[serde(default = "default_max_wait")]
    max_wait: u64,
}

fn default_poll_interval() -> u32 {
    5
}

fn default_max_wait() -> u64 {
    600
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "template_id": {
            "type": "integer",
            "description": "AWX job template ID to launch",
            "minimum": 1
        },
        "extra_vars": {
            "type": "object",
            "description": "Extra variables to pass to the job template"
        },
        "limit": {
            "type": "string",
            "description": "AWX host-filter pattern passed to the job template (e.g. 'webservers' or 'host1,host2'). This is NOT a row/pagination limit — it restricts which inventory hosts participate in the run."
        },
        "poll_interval": {
            "type": "integer",
            "description": "Seconds between status polls (default: 5, min: 2, max: 30)",
            "minimum": 2,
            "maximum": 30
        },
        "max_wait": {
            "type": "integer",
            "description": "Maximum seconds to wait for job completion (default: 600 = 10 min)",
            "minimum": 10,
            "maximum": 3600
        }
    },
    "required": ["template_id"]
}"#;

/// Handler for the `ssh_awx_job_follow` tool.
#[mcp_tool(name = "ssh_awx_job_follow", group = "awx", annotation = "mutating")]
pub struct SshAwxJobFollowHandler;

impl Default for SshAwxJobFollowHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxJobFollowHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[allow(clippy::too_many_lines)]
#[async_trait]
impl ToolHandler for SshAwxJobFollowHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_job_follow"
    }

    fn description(&self) -> &'static str {
        "Launch an AWX job and wait for completion, returning a structured summary. \
         Combines launch + poll + summary into one call. Returns per-host ok/changed/failed \
         counts and failure details. Use poll_interval and max_wait to control timing. \
         For long jobs, prefer ssh_awx_job_launch + ssh_awx_job_status polling instead. \
         Requires AWX — for direct SSH-based playbook execution with a compact summary, \
         use ssh_ansible_recap instead."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_job_follow",
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
        let args: SshAwxJobFollowArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.template_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let host = &awx.ssh_host;
        let host_config = ctx
            .config
            .hosts
            .get(host)
            .ok_or_else(|| BridgeError::UnknownHost { host: host.clone() })?;

        let limits = ctx.config.limits.clone();

        // Build a shell script that: 1) launches the job, 2) polls status, 3) fetches summary
        let poll_interval = args.poll_interval.clamp(2, 30);
        let max_wait = args.max_wait.clamp(10, 3600);

        // Build launch body
        let mut body_obj = serde_json::Map::new();
        if let Some(extra) = &args.extra_vars {
            body_obj.insert("extra_vars".to_string(), extra.clone());
        }
        if let Some(lim) = &args.limit {
            body_obj.insert("limit".to_string(), Value::String(lim.clone()));
        }
        let body = if body_obj.is_empty() {
            "{}".to_string()
        } else {
            serde_json::to_string(&body_obj).unwrap_or_else(|_| "{}".to_string())
        };

        // Construct the all-in-one shell script
        let launch_cmd = AwxCommandBuilder::build_api_call(
            &awx.url,
            &awx.token,
            &format!("/api/v2/job_templates/{}/launch/", args.template_id),
            HttpMethod::Post,
            Some(&body),
            awx.verify_ssl,
            &[],
            awx.api_timeout,
        );

        // Shell script: launch → extract job_id → poll → fetch summary
        let script = format!(
            r#"set -e
JOB_JSON=$({launch_cmd})
JOB_ID=$(echo "$JOB_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "$JOB_JSON" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
if [ -z "$JOB_ID" ]; then echo '{{"error":"Failed to launch job","response":'"$JOB_JSON"'}}'; exit 1; fi
echo '{{"launched":true,"job_id":'$JOB_ID'}}' >&2
ELAPSED=0
while [ $ELAPSED -lt {max_wait} ]; do
  sleep {poll_interval}
  ELAPSED=$((ELAPSED + {poll_interval}))
  STATUS_JSON=$({status_cmd})
  STATUS=$(echo "$STATUS_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")
  case "$STATUS" in
    successful|failed|error|canceled)
      SUMMARY=$({summary_cmd})
      echo '{{"job_id":'$JOB_ID',"status":"'$STATUS'","elapsed":'$ELAPSED',"summary":'$SUMMARY'}}'
      exit 0
      ;;
  esac
done
echo '{{"job_id":'$JOB_ID',"status":"timeout","elapsed":'$ELAPSED',"message":"Job still running after {max_wait}s. Use ssh_awx_job_status to check."}}'
"#,
            launch_cmd = launch_cmd,
            max_wait = max_wait,
            poll_interval = poll_interval,
            status_cmd = AwxCommandBuilder::build_api_call(
                &awx.url,
                &awx.token,
                "/api/v2/jobs/'$JOB_ID'/",
                HttpMethod::Get,
                None,
                awx.verify_ssl,
                &[],
                awx.api_timeout,
            ),
            summary_cmd = AwxCommandBuilder::build_api_call(
                &awx.url,
                &awx.token,
                "/api/v2/jobs/'$JOB_ID'/job_host_summaries/",
                HttpMethod::Get,
                None,
                awx.verify_ssl,
                &[],
                awx.api_timeout,
            ),
        );

        let cmd = format!(
            "bash -c {}",
            crate::domain::use_cases::shell::escape(&script, crate::config::ShellType::Posix)
        );

        // Execute with extended timeout
        let mut exec_limits = limits.clone();
        exec_limits.command_timeout_seconds = max_wait + 30; // extra buffer

        let mut conn = ctx
            .connection_pool
            .get_connection_with_jump(host, host_config, &exec_limits, None)
            .await?;
        let output = conn.exec(&cmd, &exec_limits).await?;

        let stdout = ctx
            .execute_use_case
            .process_success(host, "ssh_awx_job_follow", &output.into())
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
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAwxJobFollowHandler::new();
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
        let handler = SshAwxJobFollowHandler::new();
        assert_eq!(handler.name(), "ssh_awx_job_follow");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_job_follow");
        let schema_json: Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("template_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "template_id": 42,
            "extra_vars": {"env": "prod"},
            "limit": "webservers",
            "poll_interval": 10,
            "max_wait": 300
        });
        let args: SshAwxJobFollowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.template_id, 42);
        assert!(args.extra_vars.is_some());
        assert_eq!(args.limit, Some("webservers".to_string()));
        assert_eq!(args.poll_interval, 10);
        assert_eq!(args.max_wait, 300);
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"template_id": 1});
        let args: SshAwxJobFollowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.template_id, 1);
        assert!(args.extra_vars.is_none());
        assert!(args.limit.is_none());
        assert_eq!(args.poll_interval, 5);
        assert_eq!(args.max_wait, 600);
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"template_id": 1});
        let args: SshAwxJobFollowArgs = serde_json::from_value(json).unwrap();
        assert!(format!("{args:?}").contains("SshAwxJobFollowArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxJobFollowHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"template_id": "abc"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxJobFollowHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"template_id": 1})), &ctx).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("AWX not configured"));
    }
}
