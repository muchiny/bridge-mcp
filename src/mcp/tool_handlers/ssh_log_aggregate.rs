//! Handler for the `ssh_log_aggregate` tool.
//!
//! Aggregates log statistics (total, error, warning counts) on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::log_aggregation::LogAggregationCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::{ToolCallResult, ToolContent};

#[derive(Debug, Deserialize)]
pub struct SshLogAggregateArgs {
    /// Target host name from configuration.
    host: String,
    /// Log files to aggregate (space-separated). Defaults to common log paths.
    #[serde(default)]
    log_files: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
    /// When `true`, append an LLM-side summary of the log aggregation
    /// to the response. Requires the client to advertise the sampling
    /// capability; falls back to raw-only output otherwise.
    #[serde(default)]
    summarize: Option<bool>,
    /// Maximum tokens for the LLM summary (default: 512). Only
    /// meaningful with summarize=true.
    #[serde(default)]
    summary_max_tokens: Option<u32>,
}

impl_common_args!(SshLogAggregateArgs);

#[mcp_standard_tool(
    name = "ssh_log_aggregate",
    group = "log_aggregation",
    annotation = "read_only"
)]
pub struct LogAggregateTool;

impl StandardTool for LogAggregateTool {
    type Args = SshLogAggregateArgs;

    const NAME: &'static str = "ssh_log_aggregate";

    const DESCRIPTION: &'static str = "Aggregate log statistics on a remote host. Counts total lines, \
        error lines, and warning lines across specified log files. Useful for quick health \
        assessment and identifying problematic log files.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "log_files": {
                        "type": "string",
                        "description": "Space-separated log file paths (default: /var/log/syslog /var/log/messages /var/log/auth.log)"
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
                    },
                    "summarize": {
                        "type": "boolean",
                        "description": "When true, append an LLM-side summary of the aggregation to the response. Requires the client to advertise the sampling capability; falls back to raw-only output otherwise."
                    },
                    "summary_max_tokens": {
                        "type": "integer",
                        "description": "Maximum tokens for the LLM summary (default: 512). Only meaningful with summarize=true.",
                        "minimum": 32,
                        "maximum": 4096
                    }
                },
                "required": ["host"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshLogAggregateArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(LogAggregationCommandBuilder::build_log_aggregate_command(
            args.log_files.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        _args: &SshLogAggregateArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        // Output is already TSV (FILE\tTOTAL\tERRORS\tWARNINGS) — parse for table
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        ToolCallResult::text(parsed.to_tsv())
    }

    /// Optional LLM-side summary appended after the raw aggregation
    /// output. Falls back to raw-only when the client does not
    /// advertise the sampling capability.
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
        let prompt = "You are an SRE. Summarize the top 3 anomalies from \
                      this log aggregation in bullet points. One line each, \
                      no preamble. Focus on error spikes, repeated patterns, \
                      and time-correlation between logs.";
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

/// Handler for the `ssh_log_aggregate` tool.
pub type SshLogAggregateHandler = StandardToolHandler<LogAggregateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshLogAggregateHandler::new();
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
        let handler = SshLogAggregateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshLogAggregateHandler::new();
        assert_eq!(handler.name(), "ssh_log_aggregate");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_log_aggregate");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "log_files": "/var/log/app.log /var/log/nginx/error.log",
            "timeout_seconds": 60,
            "max_output": 10000,
            "save_output": "/tmp/aggregate.txt"
        });
        let args: SshLogAggregateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(
            args.log_files.as_deref(),
            Some("/var/log/app.log /var/log/nginx/error.log")
        );
        assert_eq!(args.timeout_seconds, Some(60));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshLogAggregateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.log_files.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshLogAggregateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("log_files"));
        assert!(props.contains_key("timeout_seconds"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshLogAggregateArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshLogAggregateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshLogAggregateHandler::new();
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
    fn test_build_command_defaults() {
        let args = SshLogAggregateArgs {
            host: "s".to_string(),
            log_files: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = LogAggregateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("FILE"));
        assert!(cmd.contains("wc -l"));
    }

    #[test]
    fn test_build_command_custom_files() {
        let args = SshLogAggregateArgs {
            host: "s".to_string(),
            log_files: Some("/var/log/nginx/access.log".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = LogAggregateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("/var/log/nginx/access.log"));
    }

    /// Build an args struct with all optionals set to `None` except those provided.
    fn minimal_args() -> SshLogAggregateArgs {
        SshLogAggregateArgs {
            host: "s".to_string(),
            log_files: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        }
    }

    #[test]
    fn test_full_args_deserialization() {
        let json = json!({
            "host": "server1",
            "log_files": "/var/log/app.log",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt",
            "summarize": true,
            "summary_max_tokens": 1024
        });
        let args: SshLogAggregateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.summarize, Some(true));
        assert_eq!(args.summary_max_tokens, Some(1024));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/out.txt"));
    }

    #[test]
    fn test_schema_summarize_fields() {
        let handler = SshLogAggregateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("summarize"));
        assert!(props.contains_key("summary_max_tokens"));
        // summary_max_tokens advertises explicit bounds.
        assert_eq!(props["summary_max_tokens"]["minimum"], json!(32));
        assert_eq!(props["summary_max_tokens"]["maximum"], json!(4096));
    }

    #[test]
    fn test_output_kind_is_tabular() {
        use crate::domain::output_kind::OutputKind;
        assert_eq!(LogAggregateTool::OUTPUT_KIND, OutputKind::Tabular);
    }

    #[test]
    fn test_os_guard_is_linux() {
        assert_eq!(LogAggregateTool::OS_GUARD, Some(OsType::Linux));
    }

    #[test]
    fn test_post_process_parses_tsv_table() {
        let args = minimal_args();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let raw = "FILE\tTOTAL\tERRORS\tWARNINGS\n\
                   /var/log/syslog\t100\t5\t2\n\
                   /var/log/auth.log\t50\t1\t0";
        let result = ToolCallResult::text("placeholder");
        let processed = LogAggregateTool::post_process(result, &args, raw, &dr);
        let ToolContent::Text { text } = &processed.content[0] else {
            panic!("expected text content");
        };
        // Headers are uppercased by to_tsv.
        assert!(text.starts_with("FILE\tTOTAL\tERRORS\tWARNINGS"));
        assert!(text.contains("/var/log/syslog\t100\t5\t2"));
        assert!(text.contains("/var/log/auth.log\t50\t1\t0"));
    }

    #[test]
    fn test_post_process_unparsable_returns_original() {
        let args = minimal_args();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        // A single line cannot be parsed as a table (needs >= 2 non-empty lines).
        let result = ToolCallResult::text("ORIGINAL_UNCHANGED");
        let processed = LogAggregateTool::post_process(result, &args, "only one line", &dr);
        let ToolContent::Text { text } = &processed.content[0] else {
            panic!("expected text content");
        };
        assert_eq!(text, "ORIGINAL_UNCHANGED");
    }

    #[test]
    fn test_post_process_column_filter() {
        let args = minimal_args();
        let dr = crate::domain::data_reduction::DataReductionArgs {
            columns: Some(vec!["FILE".to_string(), "ERRORS".to_string()]),
            ..Default::default()
        };
        let raw = "FILE\tTOTAL\tERRORS\tWARNINGS\n/var/log/syslog\t100\t5\t2";
        let result = ToolCallResult::text("placeholder");
        let processed = LogAggregateTool::post_process(result, &args, raw, &dr);
        let ToolContent::Text { text } = &processed.content[0] else {
            panic!("expected text content");
        };
        assert!(text.starts_with("FILE\tERRORS"));
        assert!(!text.contains("TOTAL"));
        assert!(!text.contains("WARNINGS"));
        assert!(text.contains("/var/log/syslog\t5"));
    }

    #[test]
    fn test_post_process_row_limit() {
        let args = minimal_args();
        let dr = crate::domain::data_reduction::DataReductionArgs {
            limit: Some(1),
            ..Default::default()
        };
        let raw = "FILE\tTOTAL\tERRORS\tWARNINGS\n\
                   /var/log/a\t1\t0\t0\n\
                   /var/log/b\t2\t0\t0";
        let result = ToolCallResult::text("placeholder");
        let processed = LogAggregateTool::post_process(result, &args, raw, &dr);
        let ToolContent::Text { text } = &processed.content[0] else {
            panic!("expected text content");
        };
        assert!(text.contains("/var/log/a"));
        assert!(!text.contains("/var/log/b"));
    }

    #[tokio::test]
    async fn test_enrich_noop_when_summarize_disabled() {
        let args = minimal_args(); // summarize = None
        let ctx = create_test_context();
        let result = ToolCallResult::text("RAW_AGGREGATION");
        let enriched = LogAggregateTool::enrich(result, &args, "RAW_AGGREGATION", &ctx)
            .await
            .unwrap();
        let ToolContent::Text { text } = &enriched.content[0] else {
            panic!("expected text content");
        };
        // No sampling attempted; raw result is returned unchanged.
        assert_eq!(text, "RAW_AGGREGATION");
        assert!(!text.contains("LLM SUMMARY"));
    }

    #[tokio::test]
    async fn test_enrich_falls_back_when_sampling_unavailable() {
        // summarize=true but the test context has no notification channel /
        // sampling capability, so ctx.sample(...) yields Ok(None) and enrich
        // must fall back to the raw result without an LLM summary.
        let mut args = minimal_args();
        args.summarize = Some(true);
        args.summary_max_tokens = Some(256);
        let ctx = create_test_context();
        let result = ToolCallResult::text("RAW_AGGREGATION");
        let enriched = LogAggregateTool::enrich(result, &args, "RAW_AGGREGATION", &ctx)
            .await
            .unwrap();
        let ToolContent::Text { text } = &enriched.content[0] else {
            panic!("expected text content");
        };
        assert_eq!(text, "RAW_AGGREGATION");
        assert!(!text.contains("LLM SUMMARY"));
    }

    #[test]
    fn test_build_command_empty_log_files_string() {
        let mut args = minimal_args();
        args.log_files = Some(String::new());
        // An empty override is passed through verbatim (not replaced by defaults),
        // so the default log paths must NOT appear in the generated command.
        let cmd = LogAggregateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("FILE"));
        assert!(!cmd.contains("/var/log/syslog"));
    }
}
