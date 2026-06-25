//! K8s Local-Path Inspect Tool Handler
//!
//! Shows PV hostPath/local.path, runs du/df/ls on the host dir, and tails
//! local-path-provisioner logs filtered to that directory.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{KubernetesCommandBuilder, validate_context};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_localpath_inspect` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sLocalpathInspectArgs {
    host: String,
    pv: String,
    #[serde(default)]
    provisioner_log_lines: Option<u64>,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sLocalpathInspectArgs);

/// Handler marker for the `ssh_k8s_localpath_inspect` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_localpath_inspect",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sLocalpathInspectTool;

impl StandardTool for K8sLocalpathInspectTool {
    type Args = SshK8sLocalpathInspectArgs;
    const NAME: &'static str = "ssh_k8s_localpath_inspect";
    const DESCRIPTION: &'static str = "Inspect a K3s local-path PersistentVolume: shows \
        hostPath / local.path + nodeAffinity, runs du/df/ls on the host directory, \
        and tails local-path-provisioner logs filtered to that directory. \
        Useful for debugging disk pressure, orphaned data, and provisioning failures.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "pv": {
                "type": "string",
                "description": "Name of the PersistentVolume to inspect"
            },
            "provisioner_log_lines": {
                "type": "integer",
                "description": "Number of local-path-provisioner log lines to tail (1-1000, default 50)",
                "minimum": 1,
                "maximum": 1000
            },
            "context": {
                "type": "string",
                "description": "kubectl context for multi-cluster targeting"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Custom kubectl binary path (default: auto-detect)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (0 = no limit)",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a file on the MCP server"
            }
        },
        "required": ["host", "pv"]
    }"#;

    fn build_command(
        args: &SshK8sLocalpathInspectArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        if let Some(ctx) = args.context.as_deref() {
            validate_context(ctx)?;
        }
        let log_lines = args.provisioner_log_lines.unwrap_or(50).clamp(1, 1000);
        Ok(KubernetesCommandBuilder::build_localpath_inspect_command(
            args.kubectl_bin.as_deref(),
            &args.pv,
            args.context.as_deref(),
            log_lines,
        ))
    }
}

/// Handler for the `ssh_k8s_localpath_inspect` tool.
pub type SshK8sLocalpathInspectHandler = StandardToolHandler<K8sLocalpathInspectTool>;

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
        let handler = SshK8sLocalpathInspectHandler::new();
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
        let handler = SshK8sLocalpathInspectHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "pv": "pvc-abc"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK8sLocalpathInspectHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_localpath_inspect");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_localpath_inspect");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("pv")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "pv": "pvc-abc123",
            "provisioner_log_lines": 100,
            "context": "prod",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60
        });
        let args: SshK8sLocalpathInspectArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pv, "pvc-abc123");
        assert_eq!(args.provisioner_log_lines, Some(100));
        assert_eq!(args.context, Some("prod".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "pv": "pvc-abc123"});
        let args: SshK8sLocalpathInspectArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pv, "pvc-abc123");
        assert!(args.provisioner_log_lines.is_none());
        assert!(args.context.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sLocalpathInspectHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("provisioner_log_lines"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "pv": "pvc-abc"});
        let args: SshK8sLocalpathInspectArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sLocalpathInspectArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sLocalpathInspectHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "pv": "pvc-abc"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_basic() {
        let args = SshK8sLocalpathInspectArgs {
            host: "s1".into(),
            pv: "pvc-abc123".into(),
            provisioner_log_lines: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sLocalpathInspectTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("get pv"), "cmd: {cmd}");
        assert!(cmd.contains("'pvc-abc123'"), "cmd: {cmd}");
        assert!(cmd.contains("local-path-provisioner"), "cmd: {cmd}");
        assert!(cmd.contains("--tail=50"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_invalid_context() {
        let args = SshK8sLocalpathInspectArgs {
            host: "s1".into(),
            pv: "pvc-abc".into(),
            provisioner_log_lines: None,
            context: Some("--bad-ctx".into()),
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(K8sLocalpathInspectTool::build_command(&args, &test_host_config()).is_err());
    }
}
