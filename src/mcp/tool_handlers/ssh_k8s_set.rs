//! K8s Set Tool Handler
//!
//! Surgically mutates a live Kubernetes resource via `kubectl set`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::{BridgeError, Result};
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_set` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sSetArgs {
    host: String,
    subcommand: String,
    target: String,
    assignments: Vec<String>,
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

impl_common_args!(SshK8sSetArgs);

/// Handler marker for the `ssh_k8s_set` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_set",
    group = "kubernetes",
    annotation = "mutating_idempotent"
)]
pub struct K8sSetTool;

impl StandardTool for K8sSetTool {
    type Args = SshK8sSetArgs;
    const NAME: &'static str = "ssh_k8s_set";
    const DESCRIPTION: &'static str = "Surgical mutation of a live Kubernetes resource via \
        `kubectl set <subcommand>` (image|env|resources). \
        Example: set image deployment/api app=nginx:1.27. \
        Mutating but idempotent — re-setting the same value converges. \
        Use `context` for multi-cluster targeting.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "subcommand": {
                "type": "string",
                "description": "kubectl set subcommand: 'image' (update container images), 'env' (set environment variables), or 'resources' (update resource requests/limits)"
            },
            "target": {
                "type": "string",
                "description": "Resource target, e.g. 'deployment/api' or 'pod/mypod'"
            },
            "assignments": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Assignment expressions, e.g. ['app=nginx:1.27'] for image or ['FOO=bar'] for env"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace"
            },
            "context": {
                "type": "string",
                "description": "kubectl context for multi-cluster targeting (e.g. 'east', 'prod-us-east-1')"
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
        "required": ["host", "subcommand", "target", "assignments"]
    }"#;

    fn build_command(args: &SshK8sSetArgs, _host_config: &HostConfig) -> Result<String> {
        if !matches!(args.subcommand.as_str(), "image" | "env" | "resources") {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "subcommand must be image|env|resources, got {}",
                    args.subcommand
                ),
            });
        }
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(ctx) = args.context.as_deref() {
            crate::domain::use_cases::kubernetes::validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_set_command(
            args.kubectl_bin.as_deref(),
            &args.subcommand,
            &args.target,
            &args.assignments,
            args.namespace.as_deref(),
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_set` tool.
pub type SshK8sSetHandler = StandardToolHandler<K8sSetTool>;

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
        let handler = SshK8sSetHandler::new();
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
        let handler = SshK8sSetHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "subcommand": "image",
                    "target": "deployment/api",
                    "assignments": ["app=nginx:1.27"]
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
        let handler = SshK8sSetHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_set");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_set");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("subcommand")));
        assert!(required.contains(&json!("target")));
        assert!(required.contains(&json!("assignments")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "subcommand": "image",
            "target": "deployment/api",
            "assignments": ["app=nginx:1.27"],
            "namespace": "default",
            "kubectl_bin": "k3s kubectl",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshK8sSetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.subcommand, "image");
        assert_eq!(args.target, "deployment/api");
        assert_eq!(args.assignments, vec!["app=nginx:1.27"]);
        assert_eq!(args.namespace, Some("default".to_string()));
        assert_eq!(args.kubectl_bin, Some("k3s kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "subcommand": "image",
            "target": "deployment/api",
            "assignments": ["app=nginx:1.27"]
        });
        let args: SshK8sSetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.subcommand, "image");
        assert_eq!(args.target, "deployment/api");
        assert_eq!(args.assignments, vec!["app=nginx:1.27"]);
        assert!(args.namespace.is_none());
        assert!(args.kubectl_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sSetHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sSetHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "subcommand": "image",
            "target": "deployment/api",
            "assignments": ["app=nginx:1.27"]
        });
        let args: SshK8sSetArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sSetArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sSetHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": 123,
                    "subcommand": "image",
                    "target": "deployment/api",
                    "assignments": ["app=nginx:1.27"]
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
    fn test_build_command_set_image_with_context() {
        let args = SshK8sSetArgs {
            host: "s1".into(),
            subcommand: "image".into(),
            target: "deployment/api".into(),
            assignments: vec!["app=nginx:1.27".into()],
            namespace: Some("prod".into()),
            context: Some("east".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sSetTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.contains("set 'image' 'deployment/api' 'app=nginx:1.27'"),
            "cmd: {cmd}"
        );
        assert!(cmd.contains("--context=east"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_bad_subcommand() {
        let args = SshK8sSetArgs {
            host: "s1".into(),
            subcommand: "delete".into(),
            target: "deployment/api".into(),
            assignments: vec!["app=x".into()],
            namespace: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(K8sSetTool::build_command(&args, &test_host_config()).is_err());
    }
}
