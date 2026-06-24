//! Handler for the `ssh_incident_correlate` tool.
//!
//! Correlates log entries across specific services on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::incident::IncidentCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::{ToolCallResult, ToolContent};

#[derive(Debug, Deserialize)]
pub struct SshIncidentCorrelateArgs {
    /// Target host name from configuration.
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
    /// Comma-separated list of service names to correlate (e.g., "nginx,postgresql").
    services: String,
    /// Start time for correlation (e.g., "1 hour ago", "2024-01-01 00:00:00").
    #[serde(default)]
    since: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshIncidentCorrelateArgs);

#[mcp_standard_tool(
    name = "ssh_incident_correlate",
    group = "incident",
    annotation = "read_only"
)]
pub struct IncidentCorrelateTool;

impl StandardTool for IncidentCorrelateTool {
    type Args = SshIncidentCorrelateArgs;

    const NAME: &'static str = "ssh_incident_correlate";

    const DESCRIPTION: &'static str = "Correlate log entries across specific services on a \
        remote host. Issues a single journalctl command with multiple -u unit filters to find \
        related events in one pass. Service names must be comma-separated (e.g., 'nginx,postgresql'); \
        only alphanumeric, '-', '_', and '.' characters are allowed per name. \
        Always set 'since' to bound the query — omitting it scans the entire journal and \
        can produce very large output. Use ssh_incident_timeline for a broader multi-source \
        overview, or ssh_service_logs / ssh_journal_query for a single service.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "services": {
                        "type": "string",
                        "description": "Comma-separated list of service names (e.g., 'nginx,postgresql')"
                    },
                    "since": {
                        "type": "string",
                        "description": "Start time for log query (e.g., '1 hour ago', '2024-01-01 00:00:00'). Defaults to no time bound (all journal entries) if omitted — strongly recommended to set this to avoid very large output."
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters before truncation",
                        "minimum": 100
                    },
                    "save_output": {
                        "type": "string",
                        "description": "Save full output to a local file path"
                    }
                },
                "required": ["host", "services"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshIncidentCorrelateArgs, _host_config: &HostConfig) -> Result<String> {
        IncidentCommandBuilder::build_incident_correlate_command(
            &args.services,
            args.since.as_deref(),
        )
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
        let prompt = "You are an SRE. Identify the top 3 most likely root causes from the correlated log events. Bullet points only, one line each, no preamble.";
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

/// Handler for the `ssh_incident_correlate` tool.
pub type SshIncidentCorrelateHandler = StandardToolHandler<IncidentCorrelateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshIncidentCorrelateHandler::new();
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
        let handler = SshIncidentCorrelateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "services": "nginx"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshIncidentCorrelateHandler::new();
        assert_eq!(handler.name(), "ssh_incident_correlate");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_incident_correlate");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("services")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "services": "nginx,postgresql",
            "since": "1 hour ago",
            "timeout_seconds": 30,
            "max_output": 10000,
            "save_output": "/tmp/correlate.txt"
        });
        let args: SshIncidentCorrelateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.services, "nginx,postgresql");
        assert_eq!(args.since.as_deref(), Some("1 hour ago"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/correlate.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "services": "nginx"});
        let args: SshIncidentCorrelateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.services, "nginx");
        assert!(args.since.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshIncidentCorrelateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("since"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "services": "nginx"});
        let args: SshIncidentCorrelateArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshIncidentCorrelateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshIncidentCorrelateHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    fn test_host_config() -> HostConfig {
        HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: AuthConfig::Agent,
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

    #[test]
    fn test_build_command_single_service() {
        let args = SshIncidentCorrelateArgs {
            host: "s".to_string(),
            services: "nginx".to_string(),
            since: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = IncidentCorrelateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-u 'nginx'"));
    }

    #[test]
    fn test_build_command_multiple_services() {
        let args = SshIncidentCorrelateArgs {
            host: "s".to_string(),
            services: "nginx,postgresql".to_string(),
            since: Some("1 hour ago".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = IncidentCorrelateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-u 'nginx'"));
        assert!(cmd.contains("-u 'postgresql'"));
        assert!(cmd.contains("--since"));
    }
}
