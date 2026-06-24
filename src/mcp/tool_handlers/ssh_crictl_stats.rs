//! crictl stats Tool Handler — one-shot container resource stats on a K3s node.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::crictl::{CrictlCommandBuilder, validate_container_id};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_crictl_stats` tool.
#[derive(Debug, Deserialize)]
pub struct SshCrictlStatsArgs {
    host: String,
    #[serde(default = "default_true")]
    all: bool,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    crictl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

fn default_true() -> bool {
    true
}

impl_common_args!(SshCrictlStatsArgs);

/// Handler marker for `ssh_crictl_stats`.
#[mcp_standard_tool(name = "ssh_crictl_stats", group = "cri", annotation = "read_only")]
pub struct CrictlStatsTool;

impl StandardTool for CrictlStatsTool {
    type Args = SshCrictlStatsArgs;
    const NAME: &'static str = "ssh_crictl_stats";
    const DESCRIPTION: &'static str = "Collect one-shot CPU/memory stats for CRI containers on a \
        K3s node via `crictl stats`. Defaults to all containers (`all=true`) and JSON output \
        for jq_filter reduction. Filter to a single container with `id`.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml (use ssh_status to list hosts)"},
            "all": {"type": "boolean", "description": "Include all containers (crictl stats -a). Default true."},
            "id": {"type": "string", "description": "Filter stats to a single container ID"},
            "output": {"type": "string", "description": "Output format: json (default), table, yaml"},
            "crictl_bin": {"type": "string", "description": "Custom crictl binary/prefix (default: auto-detect 'k3s crictl')"},
            "timeout_seconds": {"type": "integer", "description": "Optional timeout in seconds (default: from config)", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit). Truncated output yields an output_id for ssh_output_fetch.", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a local file on the MCP server."}
        },
        "required": ["host"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshCrictlStatsArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(id) = args.id.as_deref() {
            validate_container_id(id)?;
        }
        Ok(CrictlCommandBuilder::build_stats_command(
            args.crictl_bin.as_deref(),
            args.all,
            args.id.as_deref(),
            args.output.as_deref(),
        ))
    }
}

/// Handler for `ssh_crictl_stats`.
pub type SshCrictlStatsHandler = StandardToolHandler<CrictlStatsTool>;

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
        let handler = SshCrictlStatsHandler::new();
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
        let handler = SshCrictlStatsHandler::new();
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
        let handler = SshCrictlStatsHandler::new();
        assert_eq!(handler.name(), "ssh_crictl_stats");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_crictl_stats");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k3s-node",
            "all": false,
            "id": "abc123",
            "output": "json",
            "crictl_bin": "crictl",
            "timeout_seconds": 30,
            "max_output": 50000
        });
        let args: SshCrictlStatsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert!(!args.all);
        assert_eq!(args.id, Some("abc123".to_string()));
        assert_eq!(args.output, Some("json".to_string()));
        assert_eq!(args.crictl_bin, Some("crictl".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(50000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k3s-node"});
        let args: SshCrictlStatsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert!(args.all); // default_true
        assert!(args.id.is_none());
        assert!(args.output.is_none());
        assert!(args.crictl_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCrictlStatsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("all"));
        assert!(properties.contains_key("id"));
        assert!(properties.contains_key("output"));
        assert!(properties.contains_key("crictl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k3s-node"});
        let args: SshCrictlStatsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCrictlStatsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCrictlStatsHandler::new();
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
    fn test_build_command_stats_all() {
        let args = SshCrictlStatsArgs {
            host: "s1".into(),
            all: true,
            id: None,
            output: None,
            crictl_bin: Some("crictl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlStatsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crictl stats -a"), "cmd: {cmd}");
        assert!(cmd.contains("-o 'json'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_stats_with_id() {
        let args = SshCrictlStatsArgs {
            host: "s1".into(),
            all: false,
            id: Some("abc123".into()),
            output: None,
            crictl_bin: Some("crictl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlStatsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crictl stats"), "cmd: {cmd}");
        assert!(cmd.contains("--id 'abc123'"), "cmd: {cmd}");
        assert!(!cmd.contains("-a"), "no -a flag: {cmd}");
    }
}
