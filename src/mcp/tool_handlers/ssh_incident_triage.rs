//! SSH Incident Triage Tool Handler
//!
//! Automated incident triage that adapts diagnostic commands based on
//! the reported symptom type (slow, crash, OOM, disk, network).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::diagnostics::DiagnosticsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::{ToolCallResult, ToolContent};

#[derive(Debug, Deserialize)]
pub struct SshIncidentTriageArgs {
    host: String,
    /// When `true`, append an LLM-side summary of the output to the
    /// response. Requires the client to advertise the sampling
    /// capability; falls back to raw-only output otherwise.
    #[serde(default)]
    summarize: Option<bool>,
    /// Maximum tokens for the LLM summary (default: 512). Only
    /// meaningful with summarize=true.
    #[serde(default)]
    summary_max_tokens: Option<u32>,
    symptom: String,
    #[serde(default = "default_since")]
    since: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

fn default_since() -> String {
    "1 hour ago".to_string()
}

impl_common_args!(SshIncidentTriageArgs);

#[mcp_standard_tool(
    name = "ssh_incident_triage",
    group = "diagnostics",
    annotation = "read_only"
)]
pub struct IncidentTriageTool;

impl StandardTool for IncidentTriageTool {
    type Args = SshIncidentTriageArgs;

    const NAME: &'static str = "ssh_incident_triage";

    const DESCRIPTION: &'static str = "Automated incident triage that adapts diagnostics to the \
        reported symptom. Supports: slow/performance, crash/restart, oom/memory, disk/storage, \
        network/connectivity. Correlates logs, metrics, and service states in one call. \
        Use this as the first call when you already know the symptom type. For an unknown or \
        general health check, use ssh_diagnose first. For deeper log correlation across services \
        after triage, chain with ssh_incident_correlate or ssh_incident_timeline (incident group).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "symptom": {
                "type": "string",
                "description": "Type of issue. Each pair is equivalent — use either form: slow=performance, crash=restart, oom=memory, disk=storage, network=connectivity.",
                "enum": ["slow", "performance", "crash", "restart", "oom", "memory", "disk", "storage", "network", "connectivity"]
            },
            "since": {
                "type": "string",
                "description": "Time range for log analysis (default: '1 hour ago'). Accepts journalctl-style time specs."
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds (default: 90)",
                "minimum": 1,
                "maximum": 300
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to local file"
            }
        },
        "required": ["host", "symptom"]
    }"#;

    fn build_command(args: &SshIncidentTriageArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DiagnosticsCommandBuilder::build_triage_command(
            &args.symptom,
            &args.since,
        ))
    }

    /// Optional LLM-side summary appended after the raw output. Falls
    /// back to raw-only when the client does not advertise the
    /// sampling capability.
    async fn enrich(
        result: ToolCallResult,
        args: &Self::Args,
        output: &str,
        ctx: &ToolContext,
    ) -> Result<ToolCallResult> {
        if !args.summarize.unwrap_or(false) {
            return Ok(result);
        }
        let max_tokens = args.summary_max_tokens.unwrap_or(512);
        let prompt = "You are an on-call engineer. Triage this incident — list the top 3 next actions to investigate, ranked by impact. Bullet points only, one line each, no preamble.";
        let Some(summary) = ctx.sample(prompt, output, max_tokens).await? else {
            return Ok(result);
        };
        let mut text = String::new();
        for content in &result.content {
            if let ToolContent::Text { text: t } = content {
                text.push_str(t);
            }
        }
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str("\n=== LLM SUMMARY ===\n");
        text.push_str(&summary);
        let mut enriched = ToolCallResult::text(text);
        enriched.structured_content = result.structured_content;
        enriched.is_error = result.is_error;
        Ok(enriched)
    }
}

pub type SshIncidentTriageHandler = StandardToolHandler<IncidentTriageTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshIncidentTriageHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshIncidentTriageHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "symptom": "slow"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshIncidentTriageHandler::new();
        assert_eq!(handler.name(), "ssh_incident_triage");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("symptom")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "symptom": "oom", "since": "2 hours ago"});
        let args: SshIncidentTriageArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.symptom, "oom");
        assert_eq!(args.since, "2 hours ago");
    }

    #[test]
    fn test_args_default_since() {
        let json = json!({"host": "server1", "symptom": "disk"});
        let args: SshIncidentTriageArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.since, "1 hour ago");
    }

    #[test]
    fn test_build_command_oom() {
        use crate::config::{HostConfig, HostKeyVerification, OsType};
        let host_config = HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::default(),
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),

            #[cfg(feature = "winrm")]
            winrm_use_tls: None,

            #[cfg(feature = "winrm")]
            winrm_accept_invalid_certs: None,

            #[cfg(feature = "winrm")]
            winrm_operation_timeout_secs: None,

            #[cfg(feature = "winrm")]
            winrm_max_envelope_size: None,
        };
        let args = SshIncidentTriageArgs {
            host: "server1".to_string(),
            symptom: "oom".to_string(),
            since: "1 hour ago".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = IncidentTriageTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("MEMORY DETAIL"));
        assert!(cmd.contains("TOP MEM"));
    }
}
