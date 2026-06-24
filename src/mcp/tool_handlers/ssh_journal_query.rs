//! Handler for the `ssh_journal_query` tool.
//!
//! Query systemd journal logs on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::journald::JournaldCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::{ToolCallResult, ToolContent};

#[derive(Debug, Deserialize)]
pub struct SshJournalQueryArgs {
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
    unit: Option<String>,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    lines: Option<u64>,
    #[serde(default)]
    grep: Option<String>,
    #[serde(default)]
    reverse: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshJournalQueryArgs);

#[mcp_standard_tool(
    name = "ssh_journal_query",
    group = "journald",
    annotation = "read_only"
)]
pub struct JournalQueryTool;

impl StandardTool for JournalQueryTool {
    type Args = SshJournalQueryArgs;

    const NAME: &'static str = "ssh_journal_query";

    const DESCRIPTION: &'static str = "Query systemd journal logs on a remote host. Use this \
        tool when you need system-wide queries (no mandatory service), grep pattern filtering, \
        or when unit is unknown. Prefer ssh_service_logs when you already know the service name \
        and want output_format control; prefer ssh_journal_follow for live tailing; use \
        ssh_journal_boots first to resolve boot IDs when scoping to a past boot. Always set \
        lines to cap output — default journalctl output is unbounded.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "unit": {
                "type": "string",
                "description": "Filter by systemd unit name (e.g., nginx.service, sshd.service)"
            },
            "priority": {
                "type": "string",
                "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
                "description": "Filter by minimum priority level (journalctl -p). Returns entries at this level AND higher severity. Accepts named levels or numeric 0-7. Example: \"err\" returns emerg+alert+crit+err entries."
            },
            "since": {
                "type": "string",
                "description": "Show entries since this time. Accepts journalctl timestamp formats: \"YYYY-MM-DD HH:MM:SS\", relative times (\"2 hours ago\", \"1 day ago\"), or keywords (\"today\", \"yesterday\", \"now\")."
            },
            "until": {
                "type": "string",
                "description": "Show entries until this time. Accepts journalctl timestamp formats: \"YYYY-MM-DD HH:MM:SS\", relative times (\"2 hours ago\", \"1 day ago\"), or keywords (\"today\", \"yesterday\", \"now\")."
            },
            "lines": {
                "type": "integer",
                "description": "RECOMMENDED: Maximum number of recent log lines to return (journalctl -n). Always set this to limit token consumption — default journalctl output is unbounded. Example: lines=100."
            },
            "grep": {
                "type": "string",
                "description": "Filter log entries matching this PCRE2 regular expression (journalctl --grep). Case-sensitive by default. Example: \"error|fail\" matches either word."
            },
            "reverse": {
                "type": "boolean",
                "description": "Show newest entries first (default: false)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the remote host"
            }
        }
    }"#;

    fn build_command(args: &SshJournalQueryArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(JournaldCommandBuilder::build_query_command(
            args.unit.as_deref(),
            args.priority.as_deref(),
            args.since.as_deref(),
            args.until.as_deref(),
            args.lines,
            args.grep.as_deref(),
            args.reverse.unwrap_or(false),
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
        let prompt = "You are an SRE. Identify the top 3 anomalies in these systemd journal entries. Bullet points only, one line each, no preamble. Focus on repeated failures, OOM kills, and unit crashes.";
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

/// Handler for the `ssh_journal_query` tool.
pub type SshJournalQueryHandler = StandardToolHandler<JournalQueryTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshJournalQueryHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshJournalQueryHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshJournalQueryHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_journal_query");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "unit": "nginx.service",
            "priority": "err",
            "since": "1 hour ago",
            "until": "now",
            "lines": 100,
            "grep": "error",
            "reverse": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshJournalQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.unit, Some("nginx.service".to_string()));
        assert_eq!(args.priority, Some("err".to_string()));
        assert_eq!(args.reverse, Some(true));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshJournalQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.unit.is_none());
        assert!(args.priority.is_none());
        assert!(args.since.is_none());
        assert!(args.until.is_none());
        assert!(args.lines.is_none());
        assert!(args.grep.is_none());
        assert!(args.reverse.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshJournalQueryHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h"});
        let args: SshJournalQueryArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshJournalQueryArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123});
        let result = serde_json::from_value::<SshJournalQueryArgs>(json);
        assert!(result.is_err());
    }

    // ============== build_command Tests ==============

    use crate::config::{HostConfig, HostKeyVerification, OsType};

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

    #[test]
    fn test_build_command_defaults() {
        let args: SshJournalQueryArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = JournalQueryTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("journalctl"));
    }

    #[test]
    fn test_build_command_with_options() {
        let args: SshJournalQueryArgs = serde_json::from_value(json!({
            "host": "s",
            "unit": "nginx.service",
            "priority": "err",
            "since": "1 hour ago",
            "until": "now",
            "lines": 100,
            "grep": "error",
            "reverse": true
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = JournalQueryTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("nginx.service"));
        assert!(cmd.contains("err"));
        assert!(cmd.contains("1 hour ago"));
        assert!(cmd.contains("100") || cmd.contains("-n"));
        assert!(cmd.contains("error"));
        assert!(cmd.contains("-r") || cmd.contains("reverse"));
    }

    // ============== Full Pipeline Test ==============

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn server1_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            crate::config::HostConfig {
                hostname: "192.168.1.100".to_string(),
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
            },
        );
        hosts
    }

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshJournalQueryHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("Jan 01 00:00:00 server1 systemd[1]: Started Nginx."),
        );
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
