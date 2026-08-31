//! SSH Ansible Events Tool Handler
//!
//! Reads and filters events from a background Ansible run (started by
//! `ssh_ansible_run_background`). Extracts failed, changed, and stats
//! events from the JSON output file.

use std::fmt::Write;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshAnsibleEventsArgs {
    host: String,
    /// Run ID returned by `ssh_ansible_run_background`.
    run_id: String,
    /// Filter events by type. Default: show failed, changed, and stats only.
    #[serde(default)]
    event_filter: Option<String>,
    /// Check if the run is still in progress (check PID).
    #[serde(default)]
    check_status: Option<bool>,
    /// PID from `ssh_ansible_run_background` (required if `check_status=true`).
    #[serde(default)]
    pid: Option<u64>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshAnsibleEventsArgs);

#[mcp_standard_tool(
    name = "ssh_ansible_events",
    group = "ansible",
    annotation = "read_only"
)]
pub struct AnsibleEventsTool;

impl StandardTool for AnsibleEventsTool {
    type Args = SshAnsibleEventsArgs;

    const NAME: &'static str = "ssh_ansible_events";

    const DESCRIPTION: &'static str = "Read events from a background Ansible run. Extracts \
        failed, changed, and stats events from the JSON output file created by \
        ssh_ansible_run_background. Set check_status=true with pid to also check if the \
        playbook is still running. Use event_filter to customize which events to extract \
        (default: 'runner_on_failed|runner_on_changed|playbook_on_stats').";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "run_id": {
                "type": "string",
                "description": "Run ID returned by ssh_ansible_run_background"
            },
            "event_filter": {
                "type": "string",
                "description": "Pipe-separated event types to extract (default: 'runner_on_failed|runner_on_changed|playbook_on_stats')"
            },
            "check_status": {
                "type": "boolean",
                "description": "Also check if the playbook is still running (requires pid)"
            },
            "pid": {
                "type": "integer",
                "description": "PID from ssh_ansible_run_background (required if check_status=true)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file"
            }
        },
        "required": ["host", "run_id"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Json;

    fn build_command(args: &SshAnsibleEventsArgs, _host_config: &HostConfig) -> Result<String> {
        let output_file = format!("/tmp/ansible-run-{}.json", args.run_id);
        let event_filter = args
            .event_filter
            .as_deref()
            .unwrap_or("runner_on_failed|runner_on_changed|playbook_on_stats");

        let mut cmd = String::new();

        // Optionally check if process is still running
        if args.check_status.unwrap_or(false)
            && let Some(pid) = args.pid
        {
            let _ = write!(
                cmd,
                r#"if kill -0 {pid} 2>/dev/null; then echo '{{"running":true,"pid":{pid}}}'; else echo '{{"running":false,"pid":{pid}}}'; fi && "#
            );
        }

        // Extract matching events from the JSON output file using grep + python
        // The JSON callback writes one JSON object per line
        let _ = write!(
            cmd,
            r#"if [ -f '{output_file}' ]; then grep -E '"event"\s*:\s*"({event_filter})"' '{output_file}' || echo '{{"no_matching_events":true}}'; else echo '{{"error":"Output file not found","file":"{output_file}"}}'; fi"#
        );

        Ok(cmd)
    }

    fn validate(args: &SshAnsibleEventsArgs, _host_config: &HostConfig) -> Result<()> {
        // Validate run_id to prevent path injection
        if args.run_id.contains("..") || args.run_id.contains('/') || args.run_id.contains('\\') {
            return Err(crate::error::BridgeError::CommandDenied {
                reason: "Invalid run_id: must not contain path separators".to_string(),
            });
        }
        Ok(())
    }
}

/// Handler for the `ssh_ansible_events` tool.
pub type SshAnsibleEventsHandler = StandardToolHandler<AnsibleEventsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsibleEventsHandler::new();
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
        let handler = SshAnsibleEventsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "run_id": "abc123"})),
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
        let handler = SshAnsibleEventsHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_events");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("run_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "run_id": "20260407_12345",
            "event_filter": "runner_on_failed",
            "check_status": true,
            "pid": 12345
        });
        let args: SshAnsibleEventsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.run_id, "20260407_12345");
        assert_eq!(args.event_filter, Some("runner_on_failed".to_string()));
        assert_eq!(args.check_status, Some(true));
        assert_eq!(args.pid, Some(12345));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "run_id": "abc"});
        let args: SshAnsibleEventsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.run_id, "abc");
        assert!(args.event_filter.is_none());
        assert!(args.check_status.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsibleEventsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("event_filter"));
        assert!(props.contains_key("check_status"));
        assert!(props.contains_key("pid"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "s", "run_id": "r"});
        let args: SshAnsibleEventsArgs = serde_json::from_value(json).unwrap();
        assert!(format!("{args:?}").contains("SshAnsibleEventsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsibleEventsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "run_id": "abc"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_run_id_path_injection_rejected() {
        let handler = SshAnsibleEventsHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "run_id": "../../etc/shadow"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => assert!(reason.contains("path")),
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    use crate::config::{HostKeyVerification, OsType};

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
    fn test_build_command_basic() {
        let args = SshAnsibleEventsArgs {
            host: "server1".to_string(),
            run_id: "20260407_12345".to_string(),
            event_filter: None,
            check_status: None,
            pid: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = AnsibleEventsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ansible-run-20260407_12345.json"));
        assert!(cmd.contains("runner_on_failed"));
        assert!(cmd.contains("playbook_on_stats"));
    }

    #[test]
    fn test_build_command_with_status_check() {
        let args = SshAnsibleEventsArgs {
            host: "server1".to_string(),
            run_id: "abc".to_string(),
            event_filter: Some("runner_on_failed".to_string()),
            check_status: Some(true),
            pid: Some(42),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = AnsibleEventsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("kill -0 42"));
        assert!(cmd.contains("running"));
        assert!(cmd.contains("runner_on_failed"));
    }
}
