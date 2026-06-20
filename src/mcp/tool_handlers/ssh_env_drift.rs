//! SSH Environment Drift Tool Handler
//!
//! Checks for environment drift by comparing current state against a desired state.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::drift::DriftCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::{ToolCallResult, ToolContent};

#[derive(Debug, Deserialize)]
pub struct SshEnvDriftArgs {
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

impl_common_args!(SshEnvDriftArgs);

#[mcp_standard_tool(name = "ssh_env_drift", group = "drift", annotation = "read_only")]
pub struct EnvDriftTool;

impl StandardTool for EnvDriftTool {
    type Args = SshEnvDriftArgs;

    const NAME: &'static str = "ssh_env_drift";

    const DESCRIPTION: &'static str = "Captures a fresh environment snapshot on the host \
        (OS, packages, services, listeners, users, config checksums — same data as \
        ssh_env_snapshot) and optionally appends an LLM-powered drift summary via the \
        enrich step. There is no built-in baseline: it does NOT compare against a stored \
        desired state. Use this tool when you want the snapshot data plus an automated \
        analysis of the top concerning drift events (pass summarize=true). To compare two \
        hosts or two points in time, use ssh_env_snapshot with save_output on each, then \
        call ssh_env_diff for instructions on diffing the saved files. For a one-shot \
        diagnostic snapshot without drift analysis, use ssh_env_snapshot directly. For \
        broader system-state capture including network listeners and kernel info, \
        ssh_compare_state (diagnostics group) covers similar ground.";

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
                "description": "Max output characters (default: from config)",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to local file"
            }
        },
        "required": ["host"]
    }"#;

    fn build_command(_args: &SshEnvDriftArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DriftCommandBuilder::build_snapshot_command())
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
        let prompt = "You are a config drift analyst. Identify the top 3 most concerning drift events (added/removed/changed entities) in this report. Bullet points only, one line each, no preamble.";
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

pub type SshEnvDriftHandler = StandardToolHandler<EnvDriftTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    fn test_host_config() -> HostConfig {
        HostConfig {
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
        }
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshEnvDriftHandler::new();
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
        let handler = SshEnvDriftHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshEnvDriftHandler::new();
        assert_eq!(handler.name(), "ssh_env_drift");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "timeout_seconds": 120});
        let args: SshEnvDriftArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshEnvDriftArgs = serde_json::from_value(json).unwrap();
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_build_command() {
        let args = SshEnvDriftArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = EnvDriftTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("PACKAGES"));
        assert!(cmd.contains("SERVICES"));
        assert!(cmd.contains("CHECKSUM"));
    }

    #[tokio::test]
    async fn test_enrich_no_summarize_returns_input() {
        let ctx = create_test_context();
        let args = SshEnvDriftArgs {
            host: "h".to_string(),
            summarize: None,
            summary_max_tokens: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let base = ToolCallResult::text("snapshot data".to_string());
        let result = EnvDriftTool::enrich(base, &args, "snapshot data", &ctx)
            .await
            .unwrap();
        if let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] {
            assert_eq!(text, "snapshot data");
        }
    }

    #[tokio::test]
    async fn test_enrich_summarize_without_sampling_falls_back() {
        let ctx = create_test_context();
        let args = SshEnvDriftArgs {
            host: "h".to_string(),
            summarize: Some(true),
            summary_max_tokens: Some(256),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let base = ToolCallResult::text("snap".to_string());
        let result = EnvDriftTool::enrich(base, &args, "snap", &ctx)
            .await
            .unwrap();
        if let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] {
            assert!(!text.contains("LLM SUMMARY"));
        }
    }

    #[test]
    fn test_args_debug() {
        let args: SshEnvDriftArgs = serde_json::from_value(json!({"host": "h"})).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshEnvDriftArgs"));
    }

    #[test]
    fn test_args_summarize_fields() {
        let json = json!({"host": "h", "summarize": true, "summary_max_tokens": 1024});
        let args: SshEnvDriftArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.summarize, Some(true));
        assert_eq!(args.summary_max_tokens, Some(1024));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshEnvDriftHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 12})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
