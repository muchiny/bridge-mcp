//! K8s Create Token Tool Handler
//!
//! Create a short-lived token for a Kubernetes service account via
//! `kubectl create token`. The output contains a bearer token — treat as
//! sensitive. Mutating (creates a token object in the API server).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{
    KubernetesCommandBuilder, validate_duration, validate_rbac_kind, validate_sa_name,
};
use crate::error::{BridgeError, Result};
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_create_token` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sCreateTokenArgs {
    host: String,
    service_account: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    duration: Option<String>,
    #[serde(default)]
    audiences: Option<Vec<String>>,
    #[serde(default)]
    bound_object_kind: Option<String>,
    #[serde(default)]
    bound_object_name: Option<String>,
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

impl_common_args!(SshK8sCreateTokenArgs);

/// Handler marker for the `ssh_k8s_create_token` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_create_token",
    group = "kubernetes",
    annotation = "mutating"
)]
pub struct K8sCreateTokenTool;

impl StandardTool for K8sCreateTokenTool {
    type Args = SshK8sCreateTokenArgs;
    const NAME: &'static str = "ssh_k8s_create_token";
    const DESCRIPTION: &'static str = "Create a short-lived bearer token for a Kubernetes \
        service account via `kubectl create token`. The resulting token is printed to stdout — \
        treat it as sensitive and do not log it. Use `duration` to control token lifetime \
        (e.g. '1h', '30m'). Use `bound_object_kind` + `bound_object_name` to bind the \
        token to a specific Pod or Secret. Mutating (creates a TokenRequest in the API server).";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "service_account": {
                "type": "string",
                "description": "Name of the service account to create a token for"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace of the service account (default: current namespace)"
            },
            "duration": {
                "type": "string",
                "description": "Token lifetime, e.g. '3600s', '1h', '30m' (default: server default, usually 1h)"
            },
            "audiences": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Intended audiences for the token (default: API server audience)"
            },
            "bound_object_kind": {
                "type": "string",
                "description": "Bind token to this object kind: 'Pod' or 'Secret'",
                "enum": ["Pod", "Secret"]
            },
            "bound_object_name": {
                "type": "string",
                "description": "Name of the object to bind the token to (required when bound_object_kind is set)"
            },
            "context": {
                "type": "string",
                "description": "kubectl context for multi-cluster targeting"
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
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit).",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server)."
            }
        },
        "required": ["host", "service_account"]
    }"#;

    fn build_command(args: &SshK8sCreateTokenArgs, _host_config: &HostConfig) -> Result<String> {
        validate_sa_name(&args.service_account)?;
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(dur) = args.duration.as_deref() {
            validate_duration(dur)?;
        }
        if let Some(kind) = args.bound_object_kind.as_deref() {
            validate_rbac_kind(kind, &["Pod", "Secret"])?;
        }
        if args.bound_object_name.is_some() && args.bound_object_kind.is_none() {
            return Err(BridgeError::CommandDenied {
                reason: "bound_object_name requires bound_object_kind to be set".to_string(),
            });
        }
        if let Some(ctx) = args.context.as_deref() {
            crate::domain::use_cases::kubernetes::validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_create_token_command(
            args.kubectl_bin.as_deref(),
            &args.service_account,
            args.namespace.as_deref(),
            args.duration.as_deref(),
            args.audiences.as_deref(),
            args.bound_object_kind.as_deref(),
            args.bound_object_name.as_deref(),
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_create_token` tool.
pub type SshK8sCreateTokenHandler = StandardToolHandler<K8sCreateTokenTool>;

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
        let handler = SshK8sCreateTokenHandler::new();
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
        let handler = SshK8sCreateTokenHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "service_account": "default"})),
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
        let handler = SshK8sCreateTokenHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_create_token");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_create_token");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("service_account")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "service_account": "my-sa",
            "namespace": "prod",
            "duration": "1h",
            "audiences": ["https://api.example.com"],
            "bound_object_kind": "Pod",
            "bound_object_name": "my-pod",
            "context": "east",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshK8sCreateTokenArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.service_account, "my-sa");
        assert_eq!(args.namespace, Some("prod".to_string()));
        assert_eq!(args.duration, Some("1h".to_string()));
        assert_eq!(args.audiences, Some(vec!["https://api.example.com".to_string()]));
        assert_eq!(args.bound_object_kind, Some("Pod".to_string()));
        assert_eq!(args.bound_object_name, Some("my-pod".to_string()));
        assert_eq!(args.context, Some("east".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "service_account": "default"});
        let args: SshK8sCreateTokenArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.service_account, "default");
        assert!(args.namespace.is_none());
        assert!(args.duration.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sCreateTokenHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("duration"));
        assert!(properties.contains_key("audiences"));
        assert!(properties.contains_key("bound_object_kind"));
        assert!(properties.contains_key("bound_object_name"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let args: SshK8sCreateTokenArgs = serde_json::from_value(json!({
            "host": "server1",
            "service_account": "default"
        })).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sCreateTokenArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sCreateTokenHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "service_account": "default"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_create_token_basic() {
        let args = SshK8sCreateTokenArgs {
            host: "s1".into(),
            service_account: "my-sa".into(),
            namespace: Some("prod".into()),
            duration: Some("1h".into()),
            audiences: None,
            bound_object_kind: None,
            bound_object_name: None,
            context: Some("east".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sCreateTokenTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("create token"), "cmd: {cmd}");
        assert!(cmd.contains("my-sa"), "cmd: {cmd}");
        assert!(cmd.contains("-n"), "cmd: {cmd}");
        assert!(cmd.contains("prod"), "cmd: {cmd}");
        assert!(cmd.contains("--duration"), "cmd: {cmd}");
        assert!(cmd.contains("1h"), "cmd: {cmd}");
        assert!(cmd.contains("--context=east"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_create_token_with_audiences() {
        let args = SshK8sCreateTokenArgs {
            host: "s1".into(),
            service_account: "ci-deployer".into(),
            namespace: None,
            duration: None,
            audiences: Some(vec!["https://api.example.com".to_string()]),
            bound_object_kind: None,
            bound_object_name: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sCreateTokenTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("create token"), "cmd: {cmd}");
        assert!(cmd.contains("--audience"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_bound_object_name_without_kind_fails() {
        let args = SshK8sCreateTokenArgs {
            host: "s1".into(),
            service_account: "my-sa".into(),
            namespace: None,
            duration: None,
            audiences: None,
            bound_object_kind: None,
            bound_object_name: Some("my-pod".into()),
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sCreateTokenTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bound_object_name"), "reason: {reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_invalid_duration() {
        let args = SshK8sCreateTokenArgs {
            host: "s1".into(),
            service_account: "my-sa".into(),
            namespace: None,
            duration: Some("1d".into()), // invalid: 'd' not allowed
            audiences: None,
            bound_object_kind: None,
            bound_object_name: None,
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sCreateTokenTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
