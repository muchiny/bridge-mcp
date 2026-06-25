//! K3s uninstall — removes k3s server or agent from the node.
//! DESTRUCTIVE: permanently removes the k3s installation.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::k3s::K3sCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_uninstall` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sUninstallArgs {
    host: String,
    #[serde(default)]
    agent: bool,
    #[serde(default)]
    script_path: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK3sUninstallArgs);

/// Handler marker for the `ssh_k3s_uninstall` tool.
#[mcp_standard_tool(name = "ssh_k3s_uninstall", group = "k3s", annotation = "destructive")]
pub struct K3sUninstallTool;

impl StandardTool for K3sUninstallTool {
    type Args = SshK3sUninstallArgs;
    const NAME: &'static str = "ssh_k3s_uninstall";
    const DESCRIPTION: &'static str = "Uninstall K3s from the node by running the \
        official uninstall script. \
        **DESTRUCTIVE and IRREVERSIBLE**: permanently removes the k3s binary, \
        systemd units, config files, data directories, and all cluster state \
        from the node. \
        Set `agent=true` to run `k3s-agent-uninstall.sh` (for agent nodes) \
        instead of `k3s-uninstall.sh` (for server nodes, the default). \
        Run `ssh_k3s_killall` first to stop all k3s processes before uninstalling.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml"},
            "agent": {"type": "boolean", "description": "Uninstall an agent node (runs k3s-agent-uninstall.sh). Default false = server node (k3s-uninstall.sh).", "default": false},
            "script_path": {"type": "string", "description": "Absolute path to the uninstall script. Overrides default. Must be k3s-uninstall.sh or k3s-agent-uninstall.sh."},
            "timeout_seconds": {"type": "integer", "description": "Timeout in seconds", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit)", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a file on the MCP server"}
        },
        "required": ["host"]
    }"#;

    fn build_command(args: &SshK3sUninstallArgs, _host_config: &HostConfig) -> Result<String> {
        K3sCommandBuilder::build_uninstall_command(args.agent, args.script_path.as_deref())
    }
}

/// Handler for the `ssh_k3s_uninstall` tool.
pub type SshK3sUninstallHandler = StandardToolHandler<K3sUninstallTool>;

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
        let handler = SshK3sUninstallHandler::new();
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
        let handler = SshK3sUninstallHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": "nohost"})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nohost"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK3sUninstallHandler::new();
        assert_eq!(handler.name(), "ssh_k3s_uninstall");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(!required.contains(&json!("agent")));
    }

    #[test]
    fn test_args_deserialization() {
        let args: SshK3sUninstallArgs = serde_json::from_value(json!({
            "host": "k3s-node",
            "agent": true
        }))
        .unwrap();
        assert_eq!(args.host, "k3s-node");
        assert!(args.agent);
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let args: SshK3sUninstallArgs =
            serde_json::from_value(json!({"host": "k3s-node"})).unwrap();
        assert!(!args.agent);
        assert!(args.script_path.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sUninstallHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("agent"));
        assert!(props.contains_key("script_path"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let args: SshK3sUninstallArgs =
            serde_json::from_value(json!({"host": "k3s-node"})).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK3sUninstallArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK3sUninstallHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_server_default() {
        let args = SshK3sUninstallArgs {
            host: "s1".into(),
            agent: false,
            script_path: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sUninstallTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.starts_with("sudo "), "cmd: {cmd}");
        assert!(cmd.contains("k3s-uninstall.sh"), "cmd: {cmd}");
        assert!(!cmd.contains("agent"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_agent_flag() {
        let args = SshK3sUninstallArgs {
            host: "s1".into(),
            agent: true,
            script_path: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sUninstallTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("k3s-agent-uninstall.sh"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_invalid_script_rejected() {
        let args = SshK3sUninstallArgs {
            host: "s1".into(),
            agent: false,
            script_path: Some("/tmp/evil.sh".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K3sUninstallTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
