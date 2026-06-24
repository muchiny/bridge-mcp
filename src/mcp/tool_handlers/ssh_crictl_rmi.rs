//! crictl rmi Tool Handler — remove a CRI container image from a K3s node.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::crictl::CrictlCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_crictl_rmi` tool.
#[derive(Debug, Deserialize)]
pub struct SshCrictlRmiArgs {
    host: String,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    prune: bool,
    #[serde(default)]
    crictl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshCrictlRmiArgs);

/// Handler marker for `ssh_crictl_rmi`.
#[mcp_standard_tool(name = "ssh_crictl_rmi", group = "cri", annotation = "destructive")]
pub struct CrictlRmiTool;

impl StandardTool for CrictlRmiTool {
    type Args = SshCrictlRmiArgs;
    const NAME: &'static str = "ssh_crictl_rmi";
    const DESCRIPTION: &'static str = "Remove a container image (or prune all unused images) from a K3s node via \
        `crictl rmi`. DESTRUCTIVE: image deletion is irreversible and cannot be rolled back \
        without a fresh pull. Specify exactly one of `image` (a specific image ref) or \
        `prune=true` (remove all unused images).";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml (use ssh_status to list hosts)"},
            "image": {"type": "string", "description": "Image reference to remove (e.g. 'ubuntu:22.04', 'registry.io/app:v1.0'). Mutually exclusive with prune."},
            "prune": {"type": "boolean", "description": "Remove ALL unused images (crictl rmi --prune). Mutually exclusive with image. Default false."},
            "crictl_bin": {"type": "string", "description": "Custom crictl binary/prefix (default: auto-detect 'k3s crictl')"},
            "timeout_seconds": {"type": "integer", "description": "Optional timeout in seconds (default: from config)", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit). Truncated output yields an output_id for ssh_output_fetch.", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a local file on the MCP server."}
        },
        "required": ["host"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshCrictlRmiArgs, _host_config: &HostConfig) -> Result<String> {
        CrictlCommandBuilder::build_rmi_command(
            args.crictl_bin.as_deref(),
            args.image.as_deref(),
            args.prune,
        )
    }
}

/// Handler for `ssh_crictl_rmi`.
pub type SshCrictlRmiHandler = StandardToolHandler<CrictlRmiTool>;

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
        let handler = SshCrictlRmiHandler::new();
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
        let handler = SshCrictlRmiHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "image": "ubuntu:latest"})),
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
        let handler = SshCrictlRmiHandler::new();
        assert_eq!(handler.name(), "ssh_crictl_rmi");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_crictl_rmi");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k3s-node",
            "image": "ubuntu:22.04",
            "prune": false,
            "crictl_bin": "crictl",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshCrictlRmiArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.image, Some("ubuntu:22.04".to_string()));
        assert!(!args.prune);
        assert_eq!(args.crictl_bin, Some("crictl".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k3s-node"});
        let args: SshCrictlRmiArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert!(args.image.is_none());
        assert!(!args.prune);
        assert!(args.crictl_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCrictlRmiHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("image"));
        assert!(properties.contains_key("prune"));
        assert!(properties.contains_key("crictl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k3s-node", "prune": true});
        let args: SshCrictlRmiArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCrictlRmiArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCrictlRmiHandler::new();
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
    fn test_build_command_rmi_with_image() {
        let args = SshCrictlRmiArgs {
            host: "s1".into(),
            image: Some("ubuntu:22.04".into()),
            prune: false,
            crictl_bin: Some("crictl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlRmiTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crictl rmi"), "cmd: {cmd}");
        assert!(cmd.contains("'ubuntu:22.04'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rmi_prune() {
        let args = SshCrictlRmiArgs {
            host: "s1".into(),
            image: None,
            prune: true,
            crictl_bin: Some("crictl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlRmiTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crictl rmi --prune"), "cmd: {cmd}");
    }
}
