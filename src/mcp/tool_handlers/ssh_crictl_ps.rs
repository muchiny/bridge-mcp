//! crictl ps Tool Handler — list CRI containers on a K3s node.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::crictl::CrictlCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_crictl_ps` tool.
#[derive(Debug, Deserialize)]
pub struct SshCrictlPsArgs {
    host: String,
    #[serde(default)]
    all: bool,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    label: Option<String>,
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

impl_common_args!(SshCrictlPsArgs);

/// Handler marker for `ssh_crictl_ps`.
#[mcp_standard_tool(name = "ssh_crictl_ps", group = "cri", annotation = "read_only")]
pub struct CrictlPsTool;

impl StandardTool for CrictlPsTool {
    type Args = SshCrictlPsArgs;
    const NAME: &'static str = "ssh_crictl_ps";
    const DESCRIPTION: &'static str = "List CRI containers on a K3s node via `crictl ps` \
        (embedded containerd — works when the apiserver is down, unlike ssh_k8s_get). \
        Defaults to JSON output for jq_filter reduction. Filter with `state`/`name`/`label`; \
        `all=true` includes exited containers.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml (use ssh_status to list hosts)"},
            "all": {"type": "boolean", "description": "Include non-running containers (crictl ps -a). Default false."},
            "state": {"type": "string", "description": "Filter by state: created, running, exited, unknown"},
            "name": {"type": "string", "description": "Filter by container name substring"},
            "label": {"type": "string", "description": "Filter by label key=value"},
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

    fn build_command(args: &SshCrictlPsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(CrictlCommandBuilder::build_ps_command(
            args.crictl_bin.as_deref(),
            args.all,
            args.state.as_deref(),
            args.name.as_deref(),
            args.label.as_deref(),
            args.output.as_deref(),
        ))
    }
}

/// Handler for `ssh_crictl_ps`.
pub type SshCrictlPsHandler = StandardToolHandler<CrictlPsTool>;

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
        let handler = SshCrictlPsHandler::new();
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
        let handler = SshCrictlPsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent"
                })),
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
        let handler = SshCrictlPsHandler::new();
        assert_eq!(handler.name(), "ssh_crictl_ps");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_crictl_ps");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k3s-node",
            "all": true,
            "state": "running",
            "name": "nginx",
            "label": "app=frontend",
            "output": "json",
            "crictl_bin": "crictl",
            "timeout_seconds": 30,
            "max_output": 50000
        });
        let args: SshCrictlPsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert!(args.all);
        assert_eq!(args.state, Some("running".to_string()));
        assert_eq!(args.name, Some("nginx".to_string()));
        assert_eq!(args.label, Some("app=frontend".to_string()));
        assert_eq!(args.output, Some("json".to_string()));
        assert_eq!(args.crictl_bin, Some("crictl".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(50000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "k3s-node"
        });
        let args: SshCrictlPsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert!(!args.all);
        assert!(args.state.is_none());
        assert!(args.name.is_none());
        assert!(args.label.is_none());
        assert!(args.output.is_none());
        assert!(args.crictl_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshCrictlPsHandler::new();
        let ctx = create_test_context();
        // host field missing — all other fields are optional
        let result = handler.execute(Some(json!({"all": true})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCrictlPsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("all"));
        assert!(properties.contains_key("state"));
        assert!(properties.contains_key("name"));
        assert!(properties.contains_key("label"));
        assert!(properties.contains_key("output"));
        assert!(properties.contains_key("crictl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "k3s-node"
        });
        let args: SshCrictlPsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCrictlPsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCrictlPsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": 123
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    #[test]
    fn test_build_command_ps_filters() {
        let args = SshCrictlPsArgs {
            host: "s1".into(),
            all: true,
            state: Some("running".into()),
            name: None,
            label: None,
            output: None,
            crictl_bin: Some("crictl".into()), // explicit bin dodges &>/dev/null blacklist
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlPsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crictl ps -a"), "cmd: {cmd}");
        assert!(cmd.contains("--state 'running'"), "cmd: {cmd}");
        assert!(cmd.contains("-o 'json'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_ps_minimal() {
        let args = SshCrictlPsArgs {
            host: "s1".into(),
            all: false,
            state: None,
            name: None,
            label: None,
            output: None,
            crictl_bin: Some("crictl".into()), // explicit bin dodges &>/dev/null blacklist
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CrictlPsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crictl ps"), "cmd: {cmd}");
        assert!(!cmd.contains("-a"), "no -a flag when all=false: {cmd}");
        assert!(cmd.contains("-o 'json'"), "defaults to json output: {cmd}");
    }
}
