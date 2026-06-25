//! K8s PVC Usage Tool Handler
//!
//! Scrapes `kubelet_volume_stats` metrics per node or falls back to du over
//! the K3s local-path storage root.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{KubernetesCommandBuilder, validate_context};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_pvc_usage` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sPvcUsageArgs {
    host: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    all_namespaces: Option<bool>,
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

impl_common_args!(SshK8sPvcUsageArgs);

/// Handler marker for the `ssh_k8s_pvc_usage` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_pvc_usage",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sPvcUsageTool;

impl StandardTool for K8sPvcUsageTool {
    type Args = SshK8sPvcUsageArgs;
    const NAME: &'static str = "ssh_k8s_pvc_usage";
    const DESCRIPTION: &'static str = "Show actual disk usage for PersistentVolumeClaims. \
        Primary: scrapes kubelet_volume_stats_{used,capacity,available}_bytes from each node's \
        /metrics proxy endpoint. Fallback (when metrics-server absent): lists bound PVCs and \
        runs du -sh over /var/lib/rancher/k3s/storage/. K3s-aware.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace to filter PVCs (default: current context namespace)"
            },
            "all_namespaces": {
                "type": "boolean",
                "description": "Show PVCs from all namespaces (overrides namespace)"
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
        "required": ["host"]
    }"#;

    fn build_command(args: &SshK8sPvcUsageArgs, _host_config: &HostConfig) -> Result<String> {
        let all_ns = args.all_namespaces.unwrap_or(false);
        if !all_ns && let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(ctx) = args.context.as_deref() {
            validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_pvc_usage_command(
            args.kubectl_bin.as_deref(),
            args.namespace.as_deref(),
            all_ns,
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_pvc_usage` tool.
pub type SshK8sPvcUsageHandler = StandardToolHandler<K8sPvcUsageTool>;

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
        let handler = SshK8sPvcUsageHandler::new();
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
        let handler = SshK8sPvcUsageHandler::new();
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
        let handler = SshK8sPvcUsageHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_pvc_usage");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_pvc_usage");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "namespace": "default",
            "all_namespaces": true,
            "context": "prod",
            "kubectl_bin": "kubectl"
        });
        let args: SshK8sPvcUsageArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.namespace, Some("default".to_string()));
        assert_eq!(args.all_namespaces, Some(true));
        assert_eq!(args.context, Some("prod".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshK8sPvcUsageArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.namespace.is_none());
        assert!(args.all_namespaces.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sPvcUsageHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("all_namespaces"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshK8sPvcUsageArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sPvcUsageArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sPvcUsageHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_basic() {
        let args = SshK8sPvcUsageArgs {
            host: "s1".into(),
            namespace: None,
            all_namespaces: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sPvcUsageTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("kubelet_volume_stats"), "cmd: {cmd}");
        assert!(cmd.contains("rancher/k3s/storage"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_all_namespaces() {
        let args = SshK8sPvcUsageArgs {
            host: "s1".into(),
            namespace: None,
            all_namespaces: Some(true),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sPvcUsageTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains(" -A"), "cmd: {cmd}");
    }
}
