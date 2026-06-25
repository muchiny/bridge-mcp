//! `ssh_k3s_status` Tool Handler — composite k3s cluster status check.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::k3s::K3sCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_status` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sStatusArgs {
    host: String,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshK3sStatusArgs);

/// Handler marker for `ssh_k3s_status`.
#[mcp_standard_tool(name = "ssh_k3s_status", group = "k3s", annotation = "read_only")]
pub struct SshK3sStatusTool;

impl StandardTool for SshK3sStatusTool {
    type Args = SshK3sStatusArgs;
    const NAME: &'static str = "ssh_k3s_status";
    const DESCRIPTION: &'static str = "Composite k3s cluster status: systemd unit state, node list, \
        `/readyz` endpoint, and containerd version. \
        Covers both server and agent roles automatically.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml (use ssh_status to list hosts)"},
            "kubectl_bin": {"type": "string", "description": "Custom kubectl binary path (default: auto-detect 'kubectl')."},
            "timeout_seconds": {"type": "integer", "description": "Optional timeout in seconds (default: from config).", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit).", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a local file on the MCP server."}
        },
        "required": ["host"]
    }"#;

    fn build_command(args: &SshK3sStatusArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(K3sCommandBuilder::build_k3s_status_command(
            args.kubectl_bin.as_deref(),
        ))
    }
}

/// Handler for `ssh_k3s_status`.
pub type SshK3sStatusHandler = StandardToolHandler<SshK3sStatusTool>;

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
        let handler = SshK3sStatusHandler::new();
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
        let handler = SshK3sStatusHandler::new();
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
        let handler = SshK3sStatusHandler::new();
        assert_eq!(handler.name(), "ssh_k3s_status");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k3s_status");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k3s-node",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 30,
            "max_output": 50000
        });
        let args: SshK3sStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.kubectl_bin, Some("kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k3s-node"});
        let args: SshK3sStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert!(args.kubectl_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sStatusHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k3s-node"});
        let args: SshK3sStatusArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK3sStatusArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK3sStatusHandler::new();
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
    fn test_build_command_contains_sections() {
        let args = SshK3sStatusArgs {
            host: "k3s".into(),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SshK3sStatusTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("== systemd =="), "cmd: {cmd}");
        assert!(cmd.contains("== nodes =="), "cmd: {cmd}");
        assert!(cmd.contains("== readyz =="), "cmd: {cmd}");
        assert!(cmd.contains("== containerd =="), "cmd: {cmd}");
        assert!(cmd.contains("kubectl get nodes"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_custom_kubectl_bin() {
        let args = SshK3sStatusArgs {
            host: "k3s".into(),
            kubectl_bin: Some("/usr/local/bin/kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SshK3sStatusTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.contains("/usr/local/bin/kubectl get nodes"),
            "cmd: {cmd}"
        );
    }
}
