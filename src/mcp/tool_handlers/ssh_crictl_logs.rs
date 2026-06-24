//! crictl logs Tool Handler — stream/dump container logs from a K3s node.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::crictl::{CrictlCommandBuilder, validate_container_id};
use crate::error::{BridgeError, Result};
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_crictl_logs` tool.
#[derive(Debug, Deserialize)]
pub struct SshCrictlLogsArgs {
    host: String,
    container_id: String,
    #[serde(default)]
    tail: Option<u64>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    previous: bool,
    #[serde(default)]
    timestamps: bool,
    #[serde(default)]
    crictl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshCrictlLogsArgs);

/// Handler marker for `ssh_crictl_logs`.
#[mcp_standard_tool(name = "ssh_crictl_logs", group = "cri", annotation = "read_only")]
pub struct CrictlLogsTool;

impl StandardTool for CrictlLogsTool {
    type Args = SshCrictlLogsArgs;
    const NAME: &'static str = "ssh_crictl_logs";
    const DESCRIPTION: &'static str = "Fetch logs from a CRI container on a K3s node via `crictl logs`. \
        Use `tail` to limit output lines, `since` for a time window (e.g. '5m', '1h'), \
        `previous=true` for the last-terminated container, and `timestamps=true` to include \
        RFC3339 timestamps. Use save_output for large log capture.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml (use ssh_status to list hosts)"},
            "container_id": {"type": "string", "description": "Container ID to fetch logs from (from ssh_crictl_ps)"},
            "tail": {"type": "integer", "description": "Number of most recent log lines to show", "minimum": 1},
            "since": {"type": "string", "description": "Show logs since a duration ago (e.g. '5m', '1h', '30s')"},
            "previous": {"type": "boolean", "description": "Show logs from the previous (terminated) container instance. Default false."},
            "timestamps": {"type": "boolean", "description": "Prepend RFC3339 timestamps to each log line. Default false."},
            "crictl_bin": {"type": "string", "description": "Custom crictl binary/prefix (default: auto-detect 'k3s crictl')"},
            "timeout_seconds": {"type": "integer", "description": "Optional timeout in seconds (default: from config)", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit). Truncated output yields an output_id for ssh_output_fetch.", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a local file on the MCP server."}
        },
        "required": ["host", "container_id"]
    }"#;

    // RawText is the default output kind — no OUTPUT_KIND const needed.

    fn build_command(args: &SshCrictlLogsArgs, _host_config: &HostConfig) -> Result<String> {
        if args.container_id.is_empty() {
            return Err(BridgeError::McpMissingParam {
                param: "container_id".to_string(),
            });
        }
        validate_container_id(&args.container_id)?;
        Ok(CrictlCommandBuilder::build_logs_command(
            args.crictl_bin.as_deref(),
            &args.container_id,
            args.tail,
            args.since.as_deref(),
            args.previous,
            args.timestamps,
        ))
    }
}

/// Handler for `ssh_crictl_logs`.
pub type SshCrictlLogsHandler = StandardToolHandler<CrictlLogsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostKeyVerification, OsType};
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
        let handler = SshCrictlLogsHandler::new();
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
        let handler = SshCrictlLogsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "container_id": "abc123"})),
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
        let handler = SshCrictlLogsHandler::new();
        assert_eq!(handler.name(), "ssh_crictl_logs");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_crictl_logs");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("container_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k3s-node",
            "container_id": "abc123def456",
            "tail": 100,
            "since": "5m",
            "previous": true,
            "timestamps": true,
            "crictl_bin": "crictl",
            "timeout_seconds": 30,
            "max_output": 100000
        });
        let args: SshCrictlLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.container_id, "abc123def456");
        assert_eq!(args.tail, Some(100));
        assert_eq!(args.since, Some("5m".to_string()));
        assert!(args.previous);
        assert!(args.timestamps);
        assert_eq!(args.crictl_bin, Some("crictl".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(100000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k3s-node", "container_id": "abc123"});
        let args: SshCrictlLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.container_id, "abc123");
        assert!(args.tail.is_none());
        assert!(args.since.is_none());
        assert!(!args.previous);
        assert!(!args.timestamps);
        assert!(args.crictl_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCrictlLogsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("tail"));
        assert!(properties.contains_key("since"));
        assert!(properties.contains_key("previous"));
        assert!(properties.contains_key("timestamps"));
        assert!(properties.contains_key("crictl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k3s-node", "container_id": "abc123"});
        let args: SshCrictlLogsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCrictlLogsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCrictlLogsHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    #[test]
    fn test_build_command_logs_minimal() {
        let args = SshCrictlLogsArgs {
            host: "s1".into(),
            container_id: "abc123".into(),
            tail: None,
            since: None,
            previous: false,
            timestamps: false,
            crictl_bin: Some("crictl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlLogsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crictl logs"), "cmd: {cmd}");
        assert!(cmd.contains("'abc123'"), "cmd: {cmd}");
        assert!(!cmd.contains("-p"), "cmd: {cmd}");
        assert!(!cmd.contains("-t"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_logs_all_flags() {
        let args = SshCrictlLogsArgs {
            host: "s1".into(),
            container_id: "abc123".into(),
            tail: Some(50),
            since: Some("10m".into()),
            previous: true,
            timestamps: true,
            crictl_bin: Some("crictl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlLogsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-p"), "cmd: {cmd}");
        assert!(cmd.contains("--tail 50"), "cmd: {cmd}");
        assert!(cmd.contains("--since '10m'"), "cmd: {cmd}");
        assert!(cmd.contains("-t"), "cmd: {cmd}");
        assert!(cmd.contains("'abc123'"), "cmd: {cmd}");
    }
}
