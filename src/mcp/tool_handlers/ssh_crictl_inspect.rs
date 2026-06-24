//! crictl inspect Tool Handler — inspect a CRI container, pod, or image.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::crictl::{
    CrictlCommandBuilder, validate_container_id, validate_inspect_kind,
};
use crate::error::{BridgeError, Result};
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_crictl_inspect` tool.
#[derive(Debug, Deserialize)]
pub struct SshCrictlInspectArgs {
    host: String,
    kind: String,
    id: String,
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

impl_common_args!(SshCrictlInspectArgs);

/// Handler marker for `ssh_crictl_inspect`.
#[mcp_standard_tool(name = "ssh_crictl_inspect", group = "cri", annotation = "read_only")]
pub struct CrictlInspectTool;

impl StandardTool for CrictlInspectTool {
    type Args = SshCrictlInspectArgs;
    const NAME: &'static str = "ssh_crictl_inspect";
    const DESCRIPTION: &'static str = "Inspect a CRI object (container, pod sandbox, or image) on a K3s node. \
        Maps `kind` to the correct crictl sub-command: `container` → `crictl inspect`, \
        `pod` → `crictl inspectp`, `image` → `crictl inspecti`. \
        Defaults to JSON output for jq_filter reduction.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml (use ssh_status to list hosts)"},
            "kind": {"type": "string", "description": "Object type to inspect: container, pod, or image"},
            "id": {"type": "string", "description": "Container/pod/image ID to inspect"},
            "output": {"type": "string", "description": "Output format: json (default), yaml, go-template"},
            "crictl_bin": {"type": "string", "description": "Custom crictl binary/prefix (default: auto-detect 'k3s crictl')"},
            "timeout_seconds": {"type": "integer", "description": "Optional timeout in seconds (default: from config)", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit). Truncated output yields an output_id for ssh_output_fetch.", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a local file on the MCP server."}
        },
        "required": ["host", "kind", "id"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshCrictlInspectArgs, _host_config: &HostConfig) -> Result<String> {
        if args.kind.is_empty() {
            return Err(BridgeError::McpMissingParam {
                param: "kind".to_string(),
            });
        }
        if args.id.is_empty() {
            return Err(BridgeError::McpMissingParam {
                param: "id".to_string(),
            });
        }
        validate_inspect_kind(&args.kind)?;
        validate_container_id(&args.id)?;
        Ok(CrictlCommandBuilder::build_inspect_command(
            args.crictl_bin.as_deref(),
            &args.kind,
            &args.id,
            args.output.as_deref(),
        ))
    }
}

/// Handler for `ssh_crictl_inspect`.
pub type SshCrictlInspectHandler = StandardToolHandler<CrictlInspectTool>;

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
        let handler = SshCrictlInspectHandler::new();
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
        let handler = SshCrictlInspectHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "kind": "container", "id": "abc123"})),
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
        let handler = SshCrictlInspectHandler::new();
        assert_eq!(handler.name(), "ssh_crictl_inspect");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_crictl_inspect");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("kind")));
        assert!(required.contains(&json!("id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k3s-node",
            "kind": "container",
            "id": "abc123def456",
            "output": "json",
            "crictl_bin": "crictl",
            "timeout_seconds": 30,
            "max_output": 50000
        });
        let args: SshCrictlInspectArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.kind, "container");
        assert_eq!(args.id, "abc123def456");
        assert_eq!(args.output, Some("json".to_string()));
        assert_eq!(args.crictl_bin, Some("crictl".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(50000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k3s-node", "kind": "pod", "id": "pod123"});
        let args: SshCrictlInspectArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.kind, "pod");
        assert_eq!(args.id, "pod123");
        assert!(args.output.is_none());
        assert!(args.crictl_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCrictlInspectHandler::new();
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
        let json = json!({"host": "k3s-node", "kind": "image", "id": "ubuntu"});
        let args: SshCrictlInspectArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCrictlInspectArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCrictlInspectHandler::new();
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
    fn test_build_command_inspect_container() {
        let args = SshCrictlInspectArgs {
            host: "s1".into(),
            kind: "container".into(),
            id: "abc123".into(),
            output: None,
            crictl_bin: Some("crictl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlInspectTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crictl inspect"), "cmd: {cmd}");
        assert!(cmd.contains("'abc123'"), "cmd: {cmd}");
        assert!(cmd.contains("-o 'json'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_inspect_pod() {
        let args = SshCrictlInspectArgs {
            host: "s1".into(),
            kind: "pod".into(),
            id: "pod456".into(),
            output: Some("yaml".into()),
            crictl_bin: Some("crictl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlInspectTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crictl inspectp"), "cmd: {cmd}");
        assert!(cmd.contains("'pod456'"), "cmd: {cmd}");
        assert!(cmd.contains("-o 'yaml'"), "cmd: {cmd}");
    }
}
