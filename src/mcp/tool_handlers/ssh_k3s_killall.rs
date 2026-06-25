//! K3s killall — kills all k3s processes, containers, and network namespaces.
//! DESTRUCTIVE: stops ALL k3s-related processes on the node immediately.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::k3s::{K3sCommandBuilder, validate_script_path};
use crate::error::{BridgeError, Result};
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_killall` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sKillallArgs {
    host: String,
    #[serde(default)]
    script_path: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK3sKillallArgs);

/// Handler marker for the `ssh_k3s_killall` tool.
#[mcp_standard_tool(name = "ssh_k3s_killall", group = "k3s", annotation = "destructive")]
pub struct K3sKillallTool;

impl StandardTool for K3sKillallTool {
    type Args = SshK3sKillallArgs;
    const NAME: &'static str = "ssh_k3s_killall";
    const DESCRIPTION: &'static str = "Run the k3s killall script \
        (`/usr/local/bin/k3s-killall.sh` by default). \
        **DESTRUCTIVE**: kills ALL k3s processes, containers, and cleans up \
        network namespaces and interfaces on the node immediately. \
        This is a hard stop — unlike `ssh_service_stop`, it also forcibly \
        removes containerd-shims and CNI state. Use before uninstalling k3s \
        or for emergency node recovery. \
        If `script_path` is specified it must be an absolute path to `k3s-killall.sh`.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml"},
            "script_path": {"type": "string", "description": "Absolute path to k3s-killall.sh (default: /usr/local/bin/k3s-killall.sh). Must be an absolute path and basename must be k3s-killall.sh."},
            "timeout_seconds": {"type": "integer", "description": "Timeout in seconds", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit)", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a file on the MCP server"}
        },
        "required": ["host"]
    }"#;

    fn build_command(args: &SshK3sKillallArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(p) = args.script_path.as_deref() {
            validate_script_path(p)?;
            // Extra check: basename must be k3s-killall.sh specifically
            let basename = p.split('/').next_back().unwrap_or("");
            if basename != "k3s-killall.sh" {
                return Err(BridgeError::CommandDenied {
                    reason: format!("script basename must be 'k3s-killall.sh', got '{basename}'"),
                });
            }
        }
        Ok(K3sCommandBuilder::build_killall_command(
            args.script_path.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k3s_killall` tool.
pub type SshK3sKillallHandler = StandardToolHandler<K3sKillallTool>;

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
        let handler = SshK3sKillallHandler::new();
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
        let handler = SshK3sKillallHandler::new();
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
        let handler = SshK3sKillallHandler::new();
        assert_eq!(handler.name(), "ssh_k3s_killall");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(!required.contains(&json!("script_path")));
    }

    #[test]
    fn test_args_deserialization() {
        let args: SshK3sKillallArgs = serde_json::from_value(json!({
            "host": "k3s-node",
            "script_path": "/usr/local/bin/k3s-killall.sh"
        }))
        .unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(
            args.script_path,
            Some("/usr/local/bin/k3s-killall.sh".to_string())
        );
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let args: SshK3sKillallArgs = serde_json::from_value(json!({"host": "k3s-node"})).unwrap();
        assert!(args.script_path.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sKillallHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("script_path"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let args: SshK3sKillallArgs = serde_json::from_value(json!({"host": "k3s-node"})).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK3sKillallArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK3sKillallHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_default_path() {
        let args = SshK3sKillallArgs {
            host: "s1".into(),
            script_path: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sKillallTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.starts_with("sudo "), "cmd: {cmd}");
        assert!(cmd.contains("k3s-killall.sh"), "cmd: {cmd}");
        assert!(cmd.contains("/usr/local/bin/k3s-killall.sh"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_custom_valid_path() {
        let args = SshK3sKillallArgs {
            host: "s1".into(),
            script_path: Some("/opt/k3s/k3s-killall.sh".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sKillallTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("/opt/k3s/k3s-killall.sh"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_wrong_basename_rejected() {
        let args = SshK3sKillallArgs {
            host: "s1".into(),
            script_path: Some("/usr/local/bin/k3s-uninstall.sh".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K3sKillallTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_invalid_path_rejected() {
        let args = SshK3sKillallArgs {
            host: "s1".into(),
            script_path: Some("relative/k3s-killall.sh".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K3sKillallTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
