//! `ssh_k3s_kubeconfig_get` Tool Handler — retrieve the k3s kubeconfig file.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::k3s::{K3sCommandBuilder, validate_path, validate_server_ip};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_kubeconfig_get` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sKubeconfigGetArgs {
    host: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    server_ip: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshK3sKubeconfigGetArgs);

/// Handler marker for `ssh_k3s_kubeconfig_get`.
#[mcp_standard_tool(
    name = "ssh_k3s_kubeconfig_get",
    group = "k3s",
    annotation = "read_only"
)]
pub struct SshK3sKubeconfigGetTool;

impl StandardTool for SshK3sKubeconfigGetTool {
    type Args = SshK3sKubeconfigGetArgs;
    const NAME: &'static str = "ssh_k3s_kubeconfig_get";
    const DESCRIPTION: &'static str = "Retrieve the k3s kubeconfig file (`/etc/rancher/k3s/k3s.yaml`). \
        Optionally rewrite the server address with `server_ip` so the file \
        is usable from outside the node (replaces 127.0.0.1 and 0.0.0.0). \
        Use `save_output` to write it directly to the MCP server.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml (use ssh_status to list hosts)"},
            "path": {"type": "string", "description": "Absolute path to the kubeconfig file (default: /etc/rancher/k3s/k3s.yaml)."},
            "server_ip": {"type": "string", "description": "Replace the server address (127.0.0.1/0.0.0.0) with this IP or hostname. Charset: [A-Za-z0-9.-] only."},
            "timeout_seconds": {"type": "integer", "description": "Optional timeout in seconds (default: from config).", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit).", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a local file on the MCP server."}
        },
        "required": ["host"]
    }"#;

    fn build_command(args: &SshK3sKubeconfigGetArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(p) = &args.path {
            validate_path(p)?;
        }
        if let Some(ip) = &args.server_ip {
            validate_server_ip(ip)?;
        }
        Ok(K3sCommandBuilder::build_kubeconfig_get_command(
            args.path.as_deref(),
            args.server_ip.as_deref(),
        ))
    }
}

/// Handler for `ssh_k3s_kubeconfig_get`.
pub type SshK3sKubeconfigGetHandler = StandardToolHandler<SshK3sKubeconfigGetTool>;

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
        let handler = SshK3sKubeconfigGetHandler::new();
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
        let handler = SshK3sKubeconfigGetHandler::new();
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
        let handler = SshK3sKubeconfigGetHandler::new();
        assert_eq!(handler.name(), "ssh_k3s_kubeconfig_get");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k3s_kubeconfig_get");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k3s-node",
            "path": "/etc/rancher/k3s/k3s.yaml",
            "server_ip": "192.168.1.100",
            "timeout_seconds": 30,
            "max_output": 50000
        });
        let args: SshK3sKubeconfigGetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.path, Some("/etc/rancher/k3s/k3s.yaml".to_string()));
        assert_eq!(args.server_ip, Some("192.168.1.100".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k3s-node"});
        let args: SshK3sKubeconfigGetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert!(args.path.is_none());
        assert!(args.server_ip.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sKubeconfigGetHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("path"));
        assert!(properties.contains_key("server_ip"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k3s-node"});
        let args: SshK3sKubeconfigGetArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK3sKubeconfigGetArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK3sKubeconfigGetHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ── build_command tests ───────────────────────────────────────────────────

    #[test]
    fn test_build_command_default() {
        let args = SshK3sKubeconfigGetArgs {
            host: "k3s".into(),
            path: None,
            server_ip: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SshK3sKubeconfigGetTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.contains("sudo cat '/etc/rancher/k3s/k3s.yaml'"),
            "cmd: {cmd}"
        );
        assert!(!cmd.contains("sed"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_with_server_ip() {
        let args = SshK3sKubeconfigGetArgs {
            host: "k3s".into(),
            path: None,
            server_ip: Some("192.168.1.100".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SshK3sKubeconfigGetTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("sed"), "cmd: {cmd}");
        assert!(cmd.contains("192.168.1.100:6443"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_invalid_server_ip_rejected() {
        let args = SshK3sKubeconfigGetArgs {
            host: "k3s".into(),
            path: None,
            server_ip: Some("192.168.1.1;rm -rf /".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(SshK3sKubeconfigGetTool::build_command(&args, &test_host_config()).is_err());
    }
}
