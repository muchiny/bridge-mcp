//! K8s Auth Can-I Tool Handler
//!
//! RBAC preflight — check whether an identity can perform a verb on a resource
//! via `kubectl auth can-i`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_auth_can_i` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sAuthCanIArgs {
    host: String,
    verb: String,
    resource: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    as_user: Option<String>,
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

impl_common_args!(SshK8sAuthCanIArgs);

/// Handler marker for the `ssh_k8s_auth_can_i` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_auth_can_i",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sAuthCanITool;

impl StandardTool for K8sAuthCanITool {
    type Args = SshK8sAuthCanIArgs;
    const NAME: &'static str = "ssh_k8s_auth_can_i";
    const DESCRIPTION: &'static str = "RBAC preflight — check whether the current (or \
        impersonated via `as_user`) identity can perform `<verb>` on `<resource>` via \
        `kubectl auth can-i`. Read-only; run before a mutating change to fail fast on \
        permissions. Use `context` for multi-cluster targeting.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "verb": {
                "type": "string",
                "description": "The action to check, e.g. 'create', 'delete', 'get', 'list', 'update', 'patch', 'watch'"
            },
            "resource": {
                "type": "string",
                "description": "The resource type to check, e.g. 'deployments', 'pods', 'services', 'secrets'"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace to scope the check (omit for cluster-scoped resources)"
            },
            "as_user": {
                "type": "string",
                "description": "Impersonate a user or service account (maps to kubectl --as), e.g. 'system:serviceaccount:ci:deployer'"
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
        "required": ["host", "verb", "resource"]
    }"#;

    fn build_command(args: &SshK8sAuthCanIArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(ctx) = args.context.as_deref() {
            crate::domain::use_cases::kubernetes::validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_auth_can_i_command(
            args.kubectl_bin.as_deref(),
            &args.verb,
            &args.resource,
            args.namespace.as_deref(),
            args.as_user.as_deref(),
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_auth_can_i` tool.
pub type SshK8sAuthCanIHandler = StandardToolHandler<K8sAuthCanITool>;

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
        let handler = SshK8sAuthCanIHandler::new();
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
        let handler = SshK8sAuthCanIHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "verb": "create",
                    "resource": "deployments"
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
        let handler = SshK8sAuthCanIHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_auth_can_i");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_auth_can_i");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("verb")));
        assert!(required.contains(&json!("resource")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "verb": "create",
            "resource": "deployments",
            "namespace": "prod",
            "as_user": "system:serviceaccount:ci:deployer",
            "context": "east",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshK8sAuthCanIArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.verb, "create");
        assert_eq!(args.resource, "deployments");
        assert_eq!(args.namespace, Some("prod".to_string()));
        assert_eq!(
            args.as_user,
            Some("system:serviceaccount:ci:deployer".to_string())
        );
        assert_eq!(args.context, Some("east".to_string()));
        assert_eq!(args.kubectl_bin, Some("kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "verb": "get",
            "resource": "pods"
        });
        let args: SshK8sAuthCanIArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.verb, "get");
        assert_eq!(args.resource, "pods");
        assert!(args.namespace.is_none());
        assert!(args.as_user.is_none());
        assert!(args.context.is_none());
        assert!(args.kubectl_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sAuthCanIHandler::new();
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
        let handler = SshK8sAuthCanIHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("as_user"));
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
            "verb": "create",
            "resource": "deployments"
        });
        let args: SshK8sAuthCanIArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sAuthCanIArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sAuthCanIHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": 123,
                    "verb": "create",
                    "resource": "deployments"
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
    fn test_build_command_auth_can_i_full() {
        let args = SshK8sAuthCanIArgs {
            host: "s1".into(),
            verb: "create".into(),
            resource: "deployments".into(),
            namespace: Some("prod".into()),
            as_user: Some("system:serviceaccount:ci:deployer".into()),
            context: Some("east".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sAuthCanITool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.contains("auth can-i 'create' 'deployments'"),
            "cmd: {cmd}"
        );
        assert!(cmd.contains("-n 'prod'"), "cmd: {cmd}");
        assert!(
            cmd.contains("--as 'system:serviceaccount:ci:deployer'"),
            "cmd: {cmd}"
        );
        assert!(cmd.contains("--context=east"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_auth_can_i_minimal() {
        let args = SshK8sAuthCanIArgs {
            host: "s1".into(),
            verb: "get".into(),
            resource: "pods".into(),
            namespace: None,
            as_user: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sAuthCanITool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("auth can-i 'get' 'pods'"), "cmd: {cmd}");
        assert!(
            !cmd.contains("--as"),
            "no impersonation when as_user None: {cmd}"
        );
        assert!(!cmd.contains("-n "), "no namespace flag when None: {cmd}");
    }
}
