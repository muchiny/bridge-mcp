//! K8s PVC Status Tool Handler
//!
//! Shows PVC phase, bound PV details, and provisioning events.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{KubernetesCommandBuilder, validate_context};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_pvc_status` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sPvcStatusArgs {
    host: String,
    pvc: String,
    #[serde(default)]
    namespace: Option<String>,
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

impl_common_args!(SshK8sPvcStatusArgs);

/// Handler marker for the `ssh_k8s_pvc_status` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_pvc_status",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sPvcStatusTool;

impl StandardTool for K8sPvcStatusTool {
    type Args = SshK8sPvcStatusArgs;
    const NAME: &'static str = "ssh_k8s_pvc_status";
    const DESCRIPTION: &'static str = "Show PVC phase, bound PV details (hostPath / local.path / \
        nodeAffinity / reclaim policy), and the last 25 provisioning events for a given PVC. \
        Composite read-only view — no cluster state is modified.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "pvc": {
                "type": "string",
                "description": "Name of the PersistentVolumeClaim to inspect"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (default: current context namespace)"
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
        "required": ["host", "pvc"]
    }"#;

    fn build_command(args: &SshK8sPvcStatusArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(ctx) = args.context.as_deref() {
            validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_pvc_status_command(
            args.kubectl_bin.as_deref(),
            &args.pvc,
            args.namespace.as_deref(),
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_pvc_status` tool.
pub type SshK8sPvcStatusHandler = StandardToolHandler<K8sPvcStatusTool>;

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
        let handler = SshK8sPvcStatusHandler::new();
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
        let handler = SshK8sPvcStatusHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "pvc": "my-pvc"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK8sPvcStatusHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_pvc_status");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_pvc_status");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("pvc")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "pvc": "data-pvc",
            "namespace": "default",
            "context": "prod",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60,
            "max_output": 50000
        });
        let args: SshK8sPvcStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pvc, "data-pvc");
        assert_eq!(args.namespace, Some("default".to_string()));
        assert_eq!(args.context, Some("prod".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "pvc": "my-pvc"});
        let args: SshK8sPvcStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pvc, "my-pvc");
        assert!(args.namespace.is_none());
        assert!(args.context.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sPvcStatusHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "pvc": "my-pvc"});
        let args: SshK8sPvcStatusArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sPvcStatusArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sPvcStatusHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "pvc": "my-pvc"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_basic() {
        let args = SshK8sPvcStatusArgs {
            host: "s1".into(),
            pvc: "data-pvc".into(),
            namespace: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sPvcStatusTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("get pvc"), "cmd: {cmd}");
        assert!(cmd.contains("'data-pvc'"), "cmd: {cmd}");
        assert!(cmd.contains("=== PVC ==="), "cmd: {cmd}");
        assert!(cmd.contains("=== PV ==="), "cmd: {cmd}");
        assert!(cmd.contains("=== Provisioning Events ==="), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_invalid_namespace() {
        let args = SshK8sPvcStatusArgs {
            host: "s1".into(),
            pvc: "my-pvc".into(),
            namespace: Some("--bad-ns".into()),
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(K8sPvcStatusTool::build_command(&args, &test_host_config()).is_err());
    }
}
