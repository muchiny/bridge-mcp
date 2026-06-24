//! SSH Compare State Tool Handler
//!
//! Captures current system state (packages, services, listeners, kernel)
//! for comparison against a known baseline.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::diagnostics::DiagnosticsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::{ToolCallResult, ToolContent};

#[derive(Debug, Deserialize)]
pub struct SshCompareStateArgs {
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
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshCompareStateArgs);

#[mcp_standard_tool(
    name = "ssh_compare_state",
    group = "diagnostics",
    annotation = "read_only"
)]
pub struct CompareStateTool;

impl StandardTool for CompareStateTool {
    type Args = SshCompareStateArgs;

    const NAME: &'static str = "ssh_compare_state";

    const DESCRIPTION: &'static str = "Capture the current system state of a host including \
        installed packages, active services, network listeners, and kernel version. Save the \
        output to a file and use it later to compare against the same or different hosts. \
        Output can be large; pass save_output=/tmp/state-<host>.txt to avoid truncation — \
        if truncated, use ssh_output_fetch with the returned output_id. \
        For richer snapshots that also include config file checksums and user accounts, use \
        ssh_env_snapshot (drift group). To compare a snapshot against a desired state \
        specification, use ssh_env_drift.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds (default: 60)",
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
                "description": "Save full output to local file for later comparison (recommended)"
            }
        },
        "required": ["host"]
    }"#;

    fn build_command(_args: &SshCompareStateArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DiagnosticsCommandBuilder::build_state_snapshot_command())
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
        let prompt = "You are a config drift analyst. Summarize the top 3 most consequential differences between the compared states in bullet points. One line each, no preamble.";
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

pub type SshCompareStateHandler = StandardToolHandler<CompareStateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCompareStateHandler::new();
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
        let handler = SshCompareStateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshCompareStateHandler::new();
        assert_eq!(handler.name(), "ssh_compare_state");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "save_output": "/tmp/state.txt"});
        let args: SshCompareStateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.save_output, Some("/tmp/state.txt".to_string()));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshCompareStateArgs = serde_json::from_value(json).unwrap();
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_build_command() {
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
        let args = SshCompareStateArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = CompareStateTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("PACKAGES"));
        assert!(cmd.contains("SERVICES"));
        assert!(cmd.contains("uname -r"));
    }

    #[tokio::test]
    async fn test_enrich_no_summarize_returns_input() {
        let ctx = create_test_context();
        let args = SshCompareStateArgs {
            host: "h".to_string(),
            summarize: None,
            summary_max_tokens: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let base = ToolCallResult::text("state".to_string());
        let result = CompareStateTool::enrich(base, &args, "state", &ctx)
            .await
            .unwrap();
        if let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] {
            assert_eq!(text, "state");
        }
    }

    #[tokio::test]
    async fn test_enrich_summarize_without_sampling_falls_back() {
        let ctx = create_test_context();
        let args = SshCompareStateArgs {
            host: "h".to_string(),
            summarize: Some(true),
            summary_max_tokens: Some(128),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let base = ToolCallResult::text("state".to_string());
        let result = CompareStateTool::enrich(base, &args, "state", &ctx)
            .await
            .unwrap();
        if let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] {
            assert!(!text.contains("LLM SUMMARY"));
        }
    }

    #[test]
    fn test_args_debug() {
        let args: SshCompareStateArgs = serde_json::from_value(json!({"host": "h"})).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCompareStateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCompareStateHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 9})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
