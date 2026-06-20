//! Handler for the `ssh_journal_boots` tool.
//!
//! List boot entries from the systemd journal on a remote host.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::domain::use_cases::journald::JournaldCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshJournalBootsArgs {
    host: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshJournalBootsArgs);

#[mcp_standard_tool(
    name = "ssh_journal_boots",
    group = "journald",
    annotation = "read_only"
)]
pub struct JournalBootsTool;

impl StandardTool for JournalBootsTool {
    type Args = SshJournalBootsArgs;

    const NAME: &'static str = "ssh_journal_boots";

    const DESCRIPTION: &'static str = "List boot entries from the systemd journal on a remote \
        host. Shows boot index, boot ID, and timestamps (journalctl --list-boots). Use this \
        before ssh_journal_query to orient the time range — pass the FIRST ENTRY or LAST ENTRY \
        timestamps as the since/until params in ssh_journal_query to scope a query to a specific \
        boot session. To check current disk consumption of all journal files use \
        ssh_journal_disk_usage.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
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
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(_args: &SshJournalBootsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(JournaldCommandBuilder::build_boots_command())
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshJournalBootsArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Journal Boots");
        for h in &parsed.headers {
            tbl = tbl.column(h, h.to_uppercase());
        }
        for row in &parsed.rows {
            let first = row.first().map_or("", String::as_str);
            if first.is_empty() {
                continue;
            }
            let mut obj = serde_json::Map::new();
            for (i, h) in parsed.headers.iter().enumerate() {
                obj.insert(
                    h.clone(),
                    serde_json::Value::String(row.get(i).map_or_else(String::new, Clone::clone)),
                );
            }
            tbl = tbl.row(serde_json::Value::Object(obj));
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_journal_boots",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_journal_boots` tool.
pub type SshJournalBootsHandler = StandardToolHandler<JournalBootsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshJournalBootsHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshJournalBootsHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshJournalBootsHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_journal_boots");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshJournalBootsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshJournalBootsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshJournalBootsHandler::new();
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
        let args: SshJournalBootsArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshJournalBootsArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123});
        let result = serde_json::from_value::<SshJournalBootsArgs>(json);
        assert!(result.is_err());
    }

    // ============== build_command & post_process Tests ==============

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
        let args: SshJournalBootsArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = JournalBootsTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("journalctl") || cmd.contains("boot"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshJournalBootsArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "IDX  BOOT ID   FIRST ENTRY  LAST ENTRY\n-1   abc123    2024-01-01   2024-01-02\n 0   def456    2024-01-02   2024-01-03\n";
        let result = JournalBootsTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
        assert!(result.content.len() > 1);
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshJournalBootsArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = JournalBootsTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
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
        let handler = SshJournalBootsHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(
                "IDX  BOOT ID                          FIRST ENTRY                 LAST ENTRY\n-1   abc123def456abc123def456abc123de   Mon 2026-04-01 00:00:00 UTC Mon 2026-04-02 00:00:00 UTC\n 0   def456abc123def456abc123def456ab   Tue 2026-04-02 00:00:01 UTC Tue 2026-04-06 12:00:00 UTC\n",
            ),
        );
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        // post_process adds App content for tabular output
        assert!(result.content.len() >= 2);
        assert!(result.structured_content.is_some());
    }
}
