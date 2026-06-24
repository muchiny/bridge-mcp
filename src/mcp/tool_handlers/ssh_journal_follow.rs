//! Handler for the `ssh_journal_follow` tool.
//!
//! Follow systemd journal output in real-time on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::journald::JournaldCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshJournalFollowArgs {
    host: String,
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    lines: Option<u64>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshJournalFollowArgs);

#[mcp_standard_tool(
    name = "ssh_journal_follow",
    group = "journald",
    annotation = "read_only"
)]
pub struct JournalFollowTool;

impl StandardTool for JournalFollowTool {
    type Args = SshJournalFollowArgs;

    const NAME: &'static str = "ssh_journal_follow";

    const DESCRIPTION: &'static str = "Stream systemd journal output in real-time (journalctl -f) \
        on a remote host. BLOCKING: runs until timeout_seconds elapses — always set it explicitly \
        (e.g., 10-30 s). Use only for live monitoring; for historical inspection use \
        ssh_journal_query (supports grep, priority, time range); for past boot logs use \
        ssh_journal_boots then ssh_journal_query. The lines param controls how many recent \
        entries are shown before following begins (default: 50).";

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
            "lines": {
                "type": "integer",
                "description": "Number of recent log lines to show before following"
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

    fn build_command(args: &SshJournalFollowArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(JournaldCommandBuilder::build_follow_command(
            args.unit.as_deref(),
            args.lines,
        ))
    }
}

/// Handler for the `ssh_journal_follow` tool.
pub type SshJournalFollowHandler = StandardToolHandler<JournalFollowTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshJournalFollowHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshJournalFollowHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshJournalFollowHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_journal_follow");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "unit": "nginx.service",
            "lines": 50,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshJournalFollowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.unit, Some("nginx.service".to_string()));
        assert_eq!(args.lines, Some(50));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshJournalFollowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.unit.is_none());
        assert!(args.lines.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshJournalFollowHandler::new();
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
        let args: SshJournalFollowArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshJournalFollowArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123});
        let result = serde_json::from_value::<SshJournalFollowArgs>(json);
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
        let args: SshJournalFollowArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = JournalFollowTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("journalctl"));
        assert!(cmd.contains("-f") || cmd.contains("follow"));
    }

    #[test]
    fn test_build_command_with_options() {
        let args: SshJournalFollowArgs = serde_json::from_value(json!({
            "host": "s",
            "unit": "nginx.service",
            "lines": 50
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = JournalFollowTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("nginx.service"));
        assert!(cmd.contains("50") || cmd.contains("-n"));
    }
}
