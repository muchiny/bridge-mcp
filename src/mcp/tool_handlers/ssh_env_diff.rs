//! SSH Environment Diff Tool Handler
//!
//! Provides instructions for comparing environment snapshots from two hosts.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::drift::DriftCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::{ToolCallResult, ToolContent};

#[derive(Debug, Deserialize)]
pub struct SshEnvDiffArgs {
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

impl_common_args!(SshEnvDiffArgs);

#[mcp_standard_tool(name = "ssh_env_diff", group = "drift", annotation = "read_only")]
pub struct EnvDiffTool;

impl StandardTool for EnvDiffTool {
    type Args = SshEnvDiffArgs;

    const NAME: &'static str = "ssh_env_diff";

    const DESCRIPTION: &'static str = "Returns step-by-step instructions for comparing two \
        host environments. Does NOT perform the diff itself — it outputs a static text guide \
        telling you to run ssh_env_snapshot on each host (with save_output), then diff the \
        saved files locally. Use ssh_env_snapshot to capture the actual snapshot data, or \
        ssh_env_drift to capture a snapshot with an optional LLM-powered drift summary. \
        Pass summarize=true to append an LLM summary of top differences (requires sampling \
        capability).";

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

    fn build_command(_args: &SshEnvDiffArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(format!(
            "echo '{}'",
            DriftCommandBuilder::build_diff_instruction()
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
        let prompt = "You are a config drift analyst. Summarize the top 3 most consequential package/service/config differences between snapshots in bullet points. One line each, no preamble.";
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

pub type SshEnvDiffHandler = StandardToolHandler<EnvDiffTool>;

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
        let handler = SshEnvDiffHandler::new();
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
        let handler = SshEnvDiffHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshEnvDiffHandler::new();
        assert_eq!(handler.name(), "ssh_env_diff");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "timeout_seconds": 120});
        let args: SshEnvDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshEnvDiffArgs = serde_json::from_value(json).unwrap();
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_build_command() {
        let args = SshEnvDiffArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = EnvDiffTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ssh_env_snapshot"));
        assert!(cmd.contains("diff"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshEnvDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.summarize.is_none());
        assert!(args.summary_max_tokens.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshEnvDiffHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshEnvDiffArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshEnvDiffArgs"));
        assert!(debug_str.contains("server1"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshEnvDiffHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host.
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_args_summarize_deserialization() {
        let json = json!({
            "host": "server1",
            "summarize": true,
            "summary_max_tokens": 256
        });
        let args: SshEnvDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.summarize, Some(true));
        assert_eq!(args.summary_max_tokens, Some(256));
    }

    #[test]
    fn test_build_command_wraps_diff_instruction() {
        let args = SshEnvDiffArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = EnvDiffTool::build_command(&args, &test_host_config()).unwrap();
        // build_command echoes the static diff instruction, quoted.
        assert!(cmd.starts_with("echo '"));
        assert!(cmd.ends_with('\''));
        assert!(cmd.contains("save outputs to local files"));
        assert!(cmd.contains("local diff"));
    }

    #[tokio::test]
    async fn test_enrich_skips_when_summarize_false() {
        let ctx = create_test_context();
        let args = SshEnvDiffArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: Some(false),
            summary_max_tokens: None,
        };
        let original = ToolCallResult::text("raw diff output");
        let enriched = EnvDiffTool::enrich(original, &args, "raw diff output", &ctx)
            .await
            .unwrap();
        // No LLM summary appended; the single text content is unchanged.
        match &enriched.content[0] {
            ToolContent::Text { text } => {
                assert_eq!(text, "raw diff output");
                assert!(!text.contains("LLM SUMMARY"));
            }
            other => panic!("Expected text content, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_enrich_skips_when_summarize_unset() {
        let ctx = create_test_context();
        let args = SshEnvDiffArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let original = ToolCallResult::text("snapshot delta");
        let enriched = EnvDiffTool::enrich(original, &args, "snapshot delta", &ctx)
            .await
            .unwrap();
        match &enriched.content[0] {
            ToolContent::Text { text } => assert_eq!(text, "snapshot delta"),
            other => panic!("Expected text content, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_enrich_falls_back_when_sampling_unsupported() {
        // The mock context advertises no sampling capability, so ctx.sample
        // returns None and enrich must return the raw result untouched even
        // though summarize=true.
        let ctx = create_test_context();
        let args = SshEnvDiffArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: Some(true),
            summary_max_tokens: Some(128),
        };
        let original = ToolCallResult::text("env differences");
        let enriched = EnvDiffTool::enrich(original, &args, "env differences", &ctx)
            .await
            .unwrap();
        match &enriched.content[0] {
            ToolContent::Text { text } => {
                assert_eq!(text, "env differences");
                assert!(!text.contains("LLM SUMMARY"));
            }
            other => panic!("Expected text content, got: {other:?}"),
        }
    }
}
