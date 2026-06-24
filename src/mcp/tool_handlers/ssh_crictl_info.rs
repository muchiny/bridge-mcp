//! crictl info Tool Handler — CRI runtime/node info on a K3s node.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::crictl::CrictlCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_crictl_info` tool.
#[derive(Debug, Deserialize)]
pub struct SshCrictlInfoArgs {
    host: String,
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

impl_common_args!(SshCrictlInfoArgs);

/// Handler marker for `ssh_crictl_info`.
#[mcp_standard_tool(name = "ssh_crictl_info", group = "cri", annotation = "read_only")]
pub struct CrictlInfoTool;

impl StandardTool for CrictlInfoTool {
    type Args = SshCrictlInfoArgs;
    const NAME: &'static str = "ssh_crictl_info";
    const DESCRIPTION: &'static str = "Show CRI runtime and node-level information via `crictl info`. \
        Returns containerd version, runtime endpoint, config, and node status. \
        Defaults to JSON output for jq_filter reduction.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml (use ssh_status to list hosts)"},
            "output": {"type": "string", "description": "Output format: json (default), yaml"},
            "crictl_bin": {"type": "string", "description": "Custom crictl binary/prefix (default: auto-detect 'k3s crictl')"},
            "timeout_seconds": {"type": "integer", "description": "Optional timeout in seconds (default: from config)", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit). Truncated output yields an output_id for ssh_output_fetch.", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a local file on the MCP server."}
        },
        "required": ["host"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshCrictlInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(CrictlCommandBuilder::build_info_command(
            args.crictl_bin.as_deref(),
            args.output.as_deref(),
        ))
    }
}

/// Handler for `ssh_crictl_info`.
pub type SshCrictlInfoHandler = StandardToolHandler<CrictlInfoTool>;

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
        let handler = SshCrictlInfoHandler::new();
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
        let handler = SshCrictlInfoHandler::new();
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
        let handler = SshCrictlInfoHandler::new();
        assert_eq!(handler.name(), "ssh_crictl_info");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_crictl_info");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k3s-node",
            "output": "yaml",
            "crictl_bin": "crictl",
            "timeout_seconds": 10,
            "max_output": 10000
        });
        let args: SshCrictlInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.output, Some("yaml".to_string()));
        assert_eq!(args.crictl_bin, Some("crictl".to_string()));
        assert_eq!(args.timeout_seconds, Some(10));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k3s-node"});
        let args: SshCrictlInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert!(args.output.is_none());
        assert!(args.crictl_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCrictlInfoHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("output"));
        assert!(properties.contains_key("crictl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k3s-node"});
        let args: SshCrictlInfoArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCrictlInfoArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCrictlInfoHandler::new();
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
    fn test_build_command_info_default_output() {
        let args = SshCrictlInfoArgs {
            host: "s1".into(),
            output: None,
            crictl_bin: Some("crictl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlInfoTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crictl info"), "cmd: {cmd}");
        assert!(cmd.contains("-o 'json'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_info_yaml_output() {
        let args = SshCrictlInfoArgs {
            host: "s1".into(),
            output: Some("yaml".into()),
            crictl_bin: Some("crictl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlInfoTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crictl info"), "cmd: {cmd}");
        assert!(cmd.contains("-o 'yaml'"), "cmd: {cmd}");
    }
}
