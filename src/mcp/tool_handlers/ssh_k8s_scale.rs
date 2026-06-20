//! SSH Kubernetes Scale Tool Handler
//!
//! Scales a Kubernetes resource via `kubectl` on a remote host.
//! Changes the replica count for deployments, statefulsets, and replicasets.
//! Auto-detects `kubectl` binary (k8s, k3s, microk8s).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshK8sScaleArgs {
    host: String,
    resource: String,
    replicas: u64,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sScaleArgs);

#[mcp_standard_tool(name = "ssh_k8s_scale", group = "kubernetes", annotation = "mutating")]
pub struct K8sScaleTool;

impl StandardTool for K8sScaleTool {
    type Args = SshK8sScaleArgs;

    const NAME: &'static str = "ssh_k8s_scale";

    const DESCRIPTION: &'static str = "Scale a Kubernetes deployment, statefulset, or replicaset via kubectl on a remote \
        host. Changes the replica count (set to 0 to scale down completely). Resource format: \
        'deployment/myapp'. Use ssh_k8s_get first to check current replicas. To do a rolling \
        restart without changing replica count, use ssh_k8s_rollout with action='restart' \
        instead. Auto-detects kubectl binary (k8s, k3s, microk8s).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "resource": {
                "type": "string",
                "description": "Resource path e.g. deployment/myapp"
            },
            "replicas": {
                "type": "integer",
                "minimum": 0,
                "description": "Target replica count"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Custom kubectl binary path (default: auto-detect kubectl, k3s kubectl, microk8s kubectl)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            }
        },
        "required": ["host", "resource", "replicas"]
    }"#;

    fn build_command(args: &SshK8sScaleArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(KubernetesCommandBuilder::build_scale_command(
            args.kubectl_bin.as_deref(),
            &args.resource,
            args.replicas,
            args.namespace.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_scale` tool.
pub type SshK8sScaleHandler = StandardToolHandler<K8sScaleTool>;

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
        let handler = SshK8sScaleHandler::new();
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshK8sScaleHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "resource": "deployment/myapp",
                    "replicas": 3
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "nonexistent");
            }
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK8sScaleHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_scale");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_scale");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("resource")));
        assert!(required.contains(&json!("replicas")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "resource": "deployment/myapp",
            "replicas": 5,
            "namespace": "production",
            "kubectl_bin": "k3s kubectl",
            "timeout_seconds": 60,
            "max_output": 10000
        });

        let args: SshK8sScaleArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "deployment/myapp");
        assert_eq!(args.replicas, 5);
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.kubectl_bin, Some("k3s kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "resource": "deployment/myapp",
            "replicas": 3
        });

        let args: SshK8sScaleArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "deployment/myapp");
        assert_eq!(args.replicas, 3);
        assert!(args.namespace.is_none());
        assert!(args.kubectl_bin.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sScaleHandler::new();
        let ctx = create_test_context();

        // Missing replicas field
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "resource": "deployment/myapp"
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

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sScaleHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "resource": "deployment/myapp", "replicas": 3});
        let args: SshK8sScaleArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sScaleArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sScaleHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host
        let result = handler
            .execute(
                Some(json!({"host": 123, "resource": "deployment/myapp", "replicas": 3})),
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
    fn test_build_command_defaults() {
        let args = SshK8sScaleArgs {
            host: "server1".to_string(),
            resource: "deployment/myapp".to_string(),
            replicas: 3,
            namespace: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sScaleTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "kubectl scale 'deployment/myapp' --replicas=3");
    }

    #[test]
    fn test_build_command_with_namespace() {
        let args = SshK8sScaleArgs {
            host: "server1".to_string(),
            resource: "deployment/myapp".to_string(),
            replicas: 5,
            namespace: Some("production".to_string()),
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sScaleTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("--replicas=5"));
        assert!(cmd.contains("-n 'production'"));
    }

    #[test]
    fn test_build_command_custom_bin() {
        let args = SshK8sScaleArgs {
            host: "server1".to_string(),
            resource: "statefulset/redis".to_string(),
            replicas: 0,
            namespace: None,
            kubectl_bin: Some("k3s kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sScaleTool::build_command(&args, &host_config).unwrap();
        // "k3s kubectl" has a space so is_valid_binary_path rejects it; falls back to auto-detect
        assert!(cmd.contains("scale 'statefulset/redis'"));
        assert!(cmd.contains("--replicas=0"));
    }
}
