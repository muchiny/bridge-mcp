//! K8s Patch Tool Handler
//!
//! Applies a strategic, merge, or JSON patch to a live Kubernetes resource
//! via `kubectl patch`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::{BridgeError, Result};
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_patch` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sPatchArgs {
    host: String,
    target: String,
    patch: String,
    patch_type: String,
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

impl_common_args!(SshK8sPatchArgs);

/// Handler marker for the `ssh_k8s_patch` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_patch",
    group = "kubernetes",
    annotation = "mutating_idempotent"
)]
pub struct K8sPatchTool;

impl StandardTool for K8sPatchTool {
    type Args = SshK8sPatchArgs;
    const NAME: &'static str = "ssh_k8s_patch";
    const DESCRIPTION: &'static str = "Apply a strategic, merge, or JSON patch to a live \
        Kubernetes resource via `kubectl patch`. \
        Mutating but idempotent — re-applying the same patch converges to the same state. \
        Supports `patch_type` values: strategic (default K8s), merge (RFC 7386), \
        json (RFC 6902). Use `context` for multi-cluster targeting.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "target": {
                "type": "string",
                "description": "Resource target, e.g. 'deployment/api' or 'pod/mypod'"
            },
            "patch": {
                "type": "string",
                "description": "Patch document, e.g. '{\"spec\":{\"replicas\":3}}'"
            },
            "patch_type": {
                "type": "string",
                "description": "Patch strategy: 'strategic' (Kubernetes strategic merge patch), 'merge' (RFC 7386 JSON merge patch), or 'json' (RFC 6902 JSON Patch)"
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
        "required": ["host", "target", "patch", "patch_type"]
    }"#;

    fn build_command(args: &SshK8sPatchArgs, _host_config: &HostConfig) -> Result<String> {
        if !matches!(args.patch_type.as_str(), "strategic" | "merge" | "json") {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "patch_type must be strategic|merge|json, got {}",
                    args.patch_type
                ),
            });
        }
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(ctx) = args.context.as_deref() {
            crate::domain::use_cases::kubernetes::validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_patch_command(
            args.kubectl_bin.as_deref(),
            &args.target,
            &args.patch,
            &args.patch_type,
            args.namespace.as_deref(),
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_patch` tool.
pub type SshK8sPatchHandler = StandardToolHandler<K8sPatchTool>;

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
        let handler = SshK8sPatchHandler::new();
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
        let handler = SshK8sPatchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "target": "deployment/api",
                    "patch": "{\"spec\":{\"replicas\":3}}",
                    "patch_type": "merge"
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
        let handler = SshK8sPatchHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_patch");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_patch");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("target")));
        assert!(required.contains(&json!("patch")));
        assert!(required.contains(&json!("patch_type")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "target": "deployment/api",
            "patch": "{\"spec\":{\"replicas\":3}}",
            "patch_type": "merge",
            "namespace": "prod",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshK8sPatchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.target, "deployment/api");
        assert_eq!(args.patch, "{\"spec\":{\"replicas\":3}}");
        assert_eq!(args.patch_type, "merge");
        assert_eq!(args.namespace, Some("prod".to_string()));
        assert_eq!(args.kubectl_bin, Some("kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "target": "deployment/api",
            "patch": "{\"spec\":{\"replicas\":3}}",
            "patch_type": "merge"
        });
        let args: SshK8sPatchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.target, "deployment/api");
        assert_eq!(args.patch, "{\"spec\":{\"replicas\":3}}");
        assert_eq!(args.patch_type, "merge");
        assert!(args.namespace.is_none());
        assert!(args.kubectl_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sPatchHandler::new();
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
        let handler = SshK8sPatchHandler::new();
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
            "target": "deployment/api",
            "patch": "{\"spec\":{\"replicas\":3}}",
            "patch_type": "merge"
        });
        let args: SshK8sPatchArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sPatchArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sPatchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": 123,
                    "target": "deployment/api",
                    "patch": "{\"spec\":{\"replicas\":3}}",
                    "patch_type": "merge"
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
    fn test_build_command_patch_merge_with_context() {
        let args = SshK8sPatchArgs {
            host: "s1".into(),
            target: "deployment/api".into(),
            patch: r#"{"spec":{"replicas":3}}"#.into(),
            patch_type: "merge".into(),
            namespace: Some("prod".into()),
            context: Some("east".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sPatchTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.contains("patch 'deployment/api' --type='merge' -p"),
            "cmd: {cmd}"
        );
        assert!(cmd.contains("--context=east"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_bad_patch_type() {
        let args = SshK8sPatchArgs {
            host: "s1".into(),
            target: "deployment/api".into(),
            patch: "{}".into(),
            patch_type: "evil".into(),
            namespace: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(K8sPatchTool::build_command(&args, &test_host_config()).is_err());
    }
}
