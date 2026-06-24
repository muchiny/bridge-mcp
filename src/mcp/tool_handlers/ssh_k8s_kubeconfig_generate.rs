//! K8s Kubeconfig Generate Tool Handler
//!
//! Composite tool that generates a service-account-scoped kubeconfig
//! by assembling cluster CA, server URL, and a fresh bearer token.
//! Mutating (calls kubectl create token).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{
    KubernetesCommandBuilder, validate_duration, validate_sa_name, validate_url,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_kubeconfig_generate` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sKubeconfigGenerateArgs {
    host: String,
    service_account: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    server_url: Option<String>,
    #[serde(default)]
    cluster_name: Option<String>,
    #[serde(default)]
    duration: Option<String>,
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

impl_common_args!(SshK8sKubeconfigGenerateArgs);

/// Handler marker for the `ssh_k8s_kubeconfig_generate` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_kubeconfig_generate",
    group = "kubernetes",
    annotation = "mutating"
)]
pub struct K8sKubeconfigGenerateTool;

impl StandardTool for K8sKubeconfigGenerateTool {
    type Args = SshK8sKubeconfigGenerateArgs;
    const NAME: &'static str = "ssh_k8s_kubeconfig_generate";
    const DESCRIPTION: &'static str = "Generate a service-account-scoped kubeconfig YAML by \
        assembling the cluster CA certificate, server URL, and a freshly created bearer token \
        via `kubectl create token`. The output is a complete, standalone kubeconfig — \
        pass it to `save_output` to write it directly to a file on the bridge host. \
        Mutating (creates a TokenRequest). \
        If `server_url` is omitted, the current kubeconfig's cluster server is used. \
        Use `duration` to control token lifetime (e.g. '24h').";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "service_account": {
                "type": "string",
                "description": "Name of the service account to generate a kubeconfig for"
            },
            "namespace": {
                "type": "string",
                "description": "Namespace of the service account (default: 'default')"
            },
            "server_url": {
                "type": "string",
                "description": "API server URL (e.g. 'https://k8s.example.com:6443'). Defaults to current kubeconfig cluster server."
            },
            "cluster_name": {
                "type": "string",
                "description": "Cluster name to embed in the kubeconfig (default: 'gen-cluster')"
            },
            "duration": {
                "type": "string",
                "description": "Token lifetime, e.g. '24h', '7200s' (default: server default, usually 1h)"
            },
            "context": {
                "type": "string",
                "description": "kubectl context for multi-cluster targeting"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Custom kubectl binary path"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save generated kubeconfig to a local file on the MCP server"
            }
        },
        "required": ["host", "service_account"]
    }"#;

    fn build_command(
        args: &SshK8sKubeconfigGenerateArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        validate_sa_name(&args.service_account)?;
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(dur) = args.duration.as_deref() {
            validate_duration(dur)?;
        }
        if let Some(url) = args.server_url.as_deref() {
            validate_url(url)?;
        }
        if let Some(ctx) = args.context.as_deref() {
            crate::domain::use_cases::kubernetes::validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_kubeconfig_generate_command(
            args.kubectl_bin.as_deref(),
            &args.service_account,
            args.namespace.as_deref(),
            args.server_url.as_deref(),
            args.cluster_name.as_deref(),
            args.duration.as_deref(),
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_kubeconfig_generate` tool.
pub type SshK8sKubeconfigGenerateHandler = StandardToolHandler<K8sKubeconfigGenerateTool>;

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
        let handler = SshK8sKubeconfigGenerateHandler::new();
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
        let handler = SshK8sKubeconfigGenerateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "service_account": "my-sa"})),
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
        let handler = SshK8sKubeconfigGenerateHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_kubeconfig_generate");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_kubeconfig_generate");
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
            "service_account": "ci-deployer",
            "namespace": "ci",
            "server_url": "https://k8s.example.com:6443",
            "cluster_name": "prod-cluster",
            "duration": "24h",
            "context": "east",
            "kubectl_bin": "kubectl"
        });
        let args: SshK8sKubeconfigGenerateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.service_account, "ci-deployer");
        assert_eq!(args.namespace, Some("ci".to_string()));
        assert_eq!(args.server_url, Some("https://k8s.example.com:6443".to_string()));
        assert_eq!(args.cluster_name, Some("prod-cluster".to_string()));
        assert_eq!(args.duration, Some("24h".to_string()));
        assert_eq!(args.context, Some("east".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "service_account": "default"});
        let args: SshK8sKubeconfigGenerateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.service_account, "default");
        assert!(args.namespace.is_none());
        assert!(args.server_url.is_none());
        assert!(args.duration.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sKubeconfigGenerateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("server_url"));
        assert!(properties.contains_key("cluster_name"));
        assert!(properties.contains_key("duration"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let args: SshK8sKubeconfigGenerateArgs = serde_json::from_value(json!({
            "host": "server1", "service_account": "default"
        }))
        .unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sKubeconfigGenerateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sKubeconfigGenerateHandler::new();
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
    fn test_build_command_kubeconfig_with_all_params() {
        let args = SshK8sKubeconfigGenerateArgs {
            host: "s1".into(),
            service_account: "ci-deployer".into(),
            namespace: Some("ci".into()),
            server_url: Some("https://k8s.example.com:6443".into()),
            cluster_name: Some("prod-cluster".into()),
            duration: Some("24h".into()),
            context: Some("east".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sKubeconfigGenerateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("create token"), "cmd: {cmd}");
        assert!(cmd.contains("apiVersion: v1"), "cmd: {cmd}");
        assert!(cmd.contains("kind: Config"), "cmd: {cmd}");
        assert!(cmd.contains("ci-deployer"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_kubeconfig_minimal() {
        let args = SshK8sKubeconfigGenerateArgs {
            host: "s1".into(),
            service_account: "my-sa".into(),
            namespace: None,
            server_url: None,
            cluster_name: None,
            duration: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sKubeconfigGenerateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("create token"), "cmd: {cmd}");
        // Should derive server from config view
        assert!(cmd.contains("config view"), "should derive server from config view: {cmd}");
    }

    #[test]
    fn test_build_command_invalid_server_url() {
        let args = SshK8sKubeconfigGenerateArgs {
            host: "s1".into(),
            service_account: "my-sa".into(),
            namespace: None,
            server_url: Some("http://insecure.example.com".into()), // http, not https
            cluster_name: None,
            duration: None,
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sKubeconfigGenerateTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("https://"), "reason: {reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_invalid_duration() {
        let args = SshK8sKubeconfigGenerateArgs {
            host: "s1".into(),
            service_account: "my-sa".into(),
            namespace: None,
            server_url: None,
            cluster_name: None,
            duration: Some("1d".into()), // 'd' not allowed
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sKubeconfigGenerateTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
