//! K8s Wait Tool Handler
//!
//! Blocks until a Kubernetes resource meets a condition (kubectl wait) via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_wait` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sWaitArgs {
    host: String,
    resource: String,
    #[serde(default)]
    name: Option<String>,
    condition: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    all_namespaces: Option<bool>,
    #[serde(default)]
    label_selector: Option<String>,
    #[serde(default)]
    timeout: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sWaitArgs);

/// Handler marker for the `ssh_k8s_wait` tool.
#[mcp_standard_tool(name = "ssh_k8s_wait", group = "kubernetes", annotation = "read_only")]
pub struct K8sWaitTool;

impl StandardTool for K8sWaitTool {
    type Args = SshK8sWaitArgs;

    const NAME: &'static str = "ssh_k8s_wait";

    const DESCRIPTION: &'static str = "Block until a Kubernetes resource meets a condition (kubectl wait --for). \
        condition e.g. condition=Ready, condition=Available, delete, \
        jsonpath='{.status.phase}'=Running. Set timeout (e.g. 60s) BELOW \
        timeout_seconds or SSH kills it first. Read-only.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "resource": {
                "type": "string",
                "description": "Kubernetes resource type or type/name (e.g. pod, deployment, job)"
            },
            "name": {
                "type": "string",
                "description": "Specific resource name to wait on (omit to use label_selector)"
            },
            "condition": {
                "type": "string",
                "description": "Condition to wait for (e.g. condition=Ready, condition=Available, delete, jsonpath='{.status.phase}'=Running)"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (default: current context namespace)"
            },
            "all_namespaces": {
                "type": "boolean",
                "description": "Wait across all namespaces (-A flag)"
            },
            "label_selector": {
                "type": "string",
                "description": "Filter by label selector (e.g. app=nginx, tier in (frontend,backend))"
            },
            "timeout": {
                "type": "string",
                "description": "kubectl wait budget e.g. 60s; keep < timeout_seconds or SSH kills it first"
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
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "resource", "condition"]
    }"#;

    fn build_command(args: &SshK8sWaitArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(KubernetesCommandBuilder::build_wait_command(
            args.kubectl_bin.as_deref(),
            &args.resource,
            args.name.as_deref(),
            &args.condition,
            args.namespace.as_deref(),
            args.all_namespaces.unwrap_or(false),
            args.label_selector.as_deref(),
            args.timeout.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_wait` tool.
pub type SshK8sWaitHandler = StandardToolHandler<K8sWaitTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshK8sWaitHandler::new();
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
        let handler = SshK8sWaitHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "resource": "pod", "condition": "condition=Ready"})),
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
        let handler = SshK8sWaitHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_wait");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_wait");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("resource")));
        assert!(required.contains(&json!("condition")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "resource": "pod",
            "name": "my-pod",
            "condition": "condition=Ready",
            "namespace": "default",
            "all_namespaces": false,
            "label_selector": "app=nginx",
            "timeout": "60s",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 120,
            "max_output": 10000
        });
        let args: SshK8sWaitArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "pod");
        assert_eq!(args.name, Some("my-pod".to_string()));
        assert_eq!(args.condition, "condition=Ready");
        assert_eq!(args.namespace, Some("default".to_string()));
        assert_eq!(args.all_namespaces, Some(false));
        assert_eq!(args.label_selector, Some("app=nginx".to_string()));
        assert_eq!(args.timeout, Some("60s".to_string()));
        assert_eq!(args.kubectl_bin, Some("kubectl".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "resource": "pod", "condition": "condition=Ready"});
        let args: SshK8sWaitArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "pod");
        assert_eq!(args.condition, "condition=Ready");
        assert!(args.name.is_none());
        assert!(args.namespace.is_none());
        assert!(args.all_namespaces.is_none());
        assert!(args.timeout.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field_condition() {
        let handler = SshK8sWaitHandler::new();
        let ctx = create_test_context();
        // Missing condition
        let result = handler
            .execute(Some(json!({"host": "server1", "resource": "pod"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_missing_required_field_resource() {
        let handler = SshK8sWaitHandler::new();
        let ctx = create_test_context();
        // Missing resource
        let result = handler
            .execute(
                Some(json!({"host": "server1", "condition": "condition=Ready"})),
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
        let handler = SshK8sWaitHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("name"));
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("all_namespaces"));
        assert!(properties.contains_key("label_selector"));
        assert!(properties.contains_key("timeout"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "resource": "pod", "condition": "condition=Ready"});
        let args: SshK8sWaitArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sWaitArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sWaitHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host
        let result = handler
            .execute(
                Some(json!({"host": 123, "resource": "pod", "condition": "condition=Ready"})),
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

    #[test]
    fn test_build_command_defaults() {
        let args = SshK8sWaitArgs {
            host: "server1".to_string(),
            resource: "pod".to_string(),
            name: None,
            condition: "condition=Ready".to_string(),
            namespace: None,
            all_namespaces: None,
            label_selector: None,
            timeout: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sWaitTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "kubectl wait 'pod' --for='condition=Ready'");
    }

    #[test]
    fn test_build_command_with_name_namespace_timeout() {
        let args = SshK8sWaitArgs {
            host: "server1".to_string(),
            resource: "pod".to_string(),
            name: Some("my-pod".to_string()),
            condition: "condition=Ready".to_string(),
            namespace: Some("default".to_string()),
            all_namespaces: None,
            label_selector: None,
            timeout: Some("60s".to_string()),
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sWaitTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("wait 'pod' 'my-pod'"), "cmd={cmd}");
        assert!(cmd.contains("--for='condition=Ready'"), "cmd={cmd}");
        assert!(cmd.contains("-n 'default'"), "cmd={cmd}");
        assert!(cmd.contains("--timeout='60s'"), "cmd={cmd}");
    }

    #[test]
    fn test_build_command_with_selector() {
        let args = SshK8sWaitArgs {
            host: "server1".to_string(),
            resource: "pod".to_string(),
            name: None,
            condition: "condition=Ready".to_string(),
            namespace: None,
            all_namespaces: None,
            label_selector: Some("app=web".to_string()),
            timeout: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sWaitTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("wait 'pod'"), "cmd={cmd}");
        assert!(cmd.contains("--for='condition=Ready'"), "cmd={cmd}");
        assert!(cmd.contains("-l 'app=web'"), "cmd={cmd}");
        assert!(!cmd.contains("-n "), "should not have namespace: cmd={cmd}");
    }

    #[test]
    fn test_build_command_rejects_flag_like_namespace() {
        let args = SshK8sWaitArgs {
            host: "server1".to_string(),
            resource: "pod".to_string(),
            name: None,
            condition: "condition=Ready".to_string(),
            namespace: Some("--all-namespaces".to_string()),
            all_namespaces: None,
            label_selector: None,
            timeout: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let result = K8sWaitTool::build_command(&args, &host_config);
        assert!(
            result.is_err(),
            "expected rejection for flag-like namespace"
        );
    }
}
