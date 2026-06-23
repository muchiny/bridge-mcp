//! SSH AWX Job Relaunch Tool Handler
//!
//! Relaunches a finished AWX job via REST API relayed through SSH, optionally targeting only the
//! hosts that failed.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Which hosts to relaunch against.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RelaunchHosts {
    /// Relaunch against all hosts in the original run.
    All,
    /// Relaunch only against hosts that failed.
    Failed,
}

impl RelaunchHosts {
    /// AWX `hosts` body value.
    fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Failed => "failed",
        }
    }
}

/// Arguments for the `ssh_awx_job_relaunch` tool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SshAwxJobRelaunchArgs {
    /// AWX job ID to relaunch.
    job_id: u64,
    /// Which hosts to relaunch (default: AWX server default, i.e. all).
    #[serde(default)]
    hosts: Option<RelaunchHosts>,
}

/// Handler for the `ssh_awx_job_relaunch` tool.
#[mcp_tool(name = "ssh_awx_job_relaunch", group = "awx", annotation = "mutating")]
pub struct SshAwxJobRelaunchHandler;

impl Default for SshAwxJobRelaunchHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxJobRelaunchHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    const SCHEMA: &'static str = r#"{
    "type": "object",
    "properties": {
        "job_id": {
            "type": "integer",
            "description": "AWX job ID to relaunch",
            "minimum": 1
        },
        "hosts": {
            "type": "string",
            "description": "Which hosts to relaunch: 'all' or 'failed' (default: all)",
            "enum": ["all", "failed"]
        }
    },
    "required": ["job_id"]
}"#;
}

#[async_trait]
impl ToolHandler for SshAwxJobRelaunchHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_job_relaunch"
    }

    fn description(&self) -> &'static str {
        "Relaunch a finished AWX job. Pass hosts='failed' to re-run only the hosts that failed \
         — the canonical post-failure recovery. Returns the new job ID and status."
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
        let args: SshAwxJobRelaunchArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.job_id)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        let mut body_map = serde_json::Map::new();
        if let Some(ref hosts) = args.hosts {
            body_map.insert(
                "hosts".to_string(),
                serde_json::Value::String(hosts.as_str().to_string()),
            );
        }

        let endpoint = format!("/api/v2/jobs/{}/relaunch/", args.job_id);
        let body_str = if body_map.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(body_map).to_string())
        };

        let cmd = AwxCommandBuilder::build_api_call(
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

        let stdout = ctx
            .execute_use_case
            .process_success(host, &cmd, &output.into())
            .stdout;
        let mut stdout = stdout;
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
        let handler = SshAwxJobRelaunchHandler;
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
        let handler = SshAwxJobRelaunchHandler;
        assert_eq!(handler.name(), "ssh_awx_job_relaunch");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_job_relaunch");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("job_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"job_id": 99, "hosts": "failed"});
        let args: SshAwxJobRelaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.job_id, 99);
        assert_eq!(
            args.hosts.as_ref().map(RelaunchHosts::as_str),
            Some("failed")
        );
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"job_id": 1});
        let args: SshAwxJobRelaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.job_id, 1);
        assert!(args.hosts.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"job_id": 1});
        let args: SshAwxJobRelaunchArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxJobRelaunchArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxJobRelaunchHandler;
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
        let handler = SshAwxJobRelaunchHandler;
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"job_id": 99})), &ctx).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("AWX not configured"),
            "Expected AWX not configured error, got: {err_msg}"
        );
    }

    #[test]
    fn test_output_kind() {
        let handler = SshAwxJobRelaunchHandler;
        assert_eq!(handler.output_kind(), OutputKind::Json);
    }

    #[test]
    fn test_hosts_enum_rejects_invalid() {
        let r =
            serde_json::from_value::<SshAwxJobRelaunchArgs>(json!({"job_id": 1, "hosts": "bogus"}));
        assert!(r.is_err());
    }
}
