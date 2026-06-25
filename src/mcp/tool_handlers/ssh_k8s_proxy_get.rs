//! SSH Kubernetes Proxy Get Tool Handler
//!
//! Proxies an HTTP request through the Kubernetes API server to a service
//! or pod using `kubectl get --raw '/api/v1/namespaces/<ns>/<resource>/<name>/proxy<path>'`.
//! The proxy path is strictly validated to prevent injection.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_proxy_get` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sProxyGetArgs {
    host: String,
    /// Resource type: `services` or `pods`.
    resource: String,
    /// Resource name (e.g. service or pod name).
    name: String,
    /// Proxy path (must start with `/`, e.g. `/healthz`, `/metrics`).
    proxy_path: String,
    /// Optional named port or port number to include in the API path.
    #[serde(default)]
    port: Option<u16>,
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
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshK8sProxyGetArgs);

/// Handler marker for the `ssh_k8s_proxy_get` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_proxy_get",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sProxyGet;

impl StandardTool for K8sProxyGet {
    type Args = SshK8sProxyGetArgs;
    const NAME: &'static str = "ssh_k8s_proxy_get";
    const DESCRIPTION: &'static str = "Proxy an HTTP GET request through the Kubernetes API server to a service or pod \
        using `kubectl get --raw`. Useful for reaching /healthz, /metrics, or other HTTP \
        endpoints exposed by pods without requiring direct network access. \
        resource must be 'services' or 'pods'; proxy_path must start with '/'.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "resource": {
                "type": "string",
                "description": "Resource type: 'services' or 'pods'",
                "enum": ["services", "pods"]
            },
            "name": {
                "type": "string",
                "description": "Name of the service or pod to proxy to"
            },
            "proxy_path": {
                "type": "string",
                "description": "HTTP path to proxy to (must start with '/', e.g. /healthz, /metrics)"
            },
            "port": {
                "type": "integer",
                "description": "Port number to include in the API path (optional)",
                "minimum": 1,
                "maximum": 65535
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (default: 'default')"
            },
            "context": {
                "type": "string",
                "description": "kubectl context for multi-cluster targeting"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Custom kubectl binary path (default: auto-detect kubectl/k3s/microk8s)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "SSH command timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (0 = no limit). Truncated output yields an output_id for ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a file on the MCP server."
            }
        },
        "required": ["host", "resource", "name", "proxy_path"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshK8sProxyGetArgs, _host_config: &HostConfig) -> Result<String> {
        KubernetesCommandBuilder::build_proxy_get_command(
            args.kubectl_bin.as_deref(),
            &args.resource,
            &args.name,
            &args.proxy_path,
            args.port,
            args.namespace.as_deref(),
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_k8s_proxy_get` tool.
pub type SshK8sProxyGetHandler = StandardToolHandler<K8sProxyGet>;

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

    #[test]
    fn test_args_full_deserialization() {
        let json = json!({
            "host": "k8s-host",
            "resource": "services",
            "name": "myservice",
            "proxy_path": "/healthz",
            "port": 9090,
            "namespace": "monitoring",
            "context": "prod",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 30,
            "max_output": 40000
        });
        let args: SshK8sProxyGetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s-host");
        assert_eq!(args.resource, "services");
        assert_eq!(args.name, "myservice");
        assert_eq!(args.proxy_path, "/healthz");
        assert_eq!(args.port, Some(9090));
        assert_eq!(args.namespace, Some("monitoring".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "k8s",
            "resource": "services",
            "name": "web",
            "proxy_path": "/healthz"
        });
        let args: SshK8sProxyGetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s");
        assert!(args.port.is_none());
        assert!(args.namespace.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json =
            json!({"host": "k8s", "resource": "services", "name": "web", "proxy_path": "/healthz"});
        let args: SshK8sProxyGetArgs = serde_json::from_value(json).unwrap();
        let s = format!("{args:?}");
        assert!(s.contains("SshK8sProxyGetArgs"));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sProxyGetHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("port"));
        assert!(props.contains_key("namespace"));
        assert!(props.contains_key("context"));
        assert!(props.contains_key("kubectl_bin"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sProxyGetHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "resource": "services", "name": "web", "proxy_path": "/healthz"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_basic() {
        let args = SshK8sProxyGetArgs {
            host: "k8s".into(),
            resource: "services".into(),
            name: "myservice".into(),
            proxy_path: "/healthz".into(),
            port: None,
            namespace: Some("default".into()),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sProxyGet::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("get --raw"), "cmd: {cmd}");
        assert!(
            cmd.contains("/api/v1/namespaces/default/services/myservice/proxy/healthz"),
            "cmd: {cmd}"
        );
    }

    #[test]
    fn test_build_command_with_port() {
        let args = SshK8sProxyGetArgs {
            host: "k8s".into(),
            resource: "services".into(),
            name: "myservice".into(),
            proxy_path: "/metrics".into(),
            port: Some(9090),
            namespace: Some("monitoring".into()),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sProxyGet::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.contains("/api/v1/namespaces/monitoring/services/myservice:9090/proxy/metrics"),
            "cmd: {cmd}"
        );
    }

    #[test]
    fn test_build_command_rejects_invalid_proxy_path() {
        let args = SshK8sProxyGetArgs {
            host: "k8s".into(),
            resource: "services".into(),
            name: "myservice".into(),
            proxy_path: "/../etc/passwd".into(),
            port: None,
            namespace: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sProxyGet::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_rejects_bad_resource_type() {
        let args = SshK8sProxyGetArgs {
            host: "k8s".into(),
            resource: "deployments".into(),
            name: "myapp".into(),
            proxy_path: "/healthz".into(),
            port: None,
            namespace: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sProxyGet::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_with_context() {
        let args = SshK8sProxyGetArgs {
            host: "k8s".into(),
            resource: "pods".into(),
            name: "mypod".into(),
            proxy_path: "/healthz".into(),
            port: None,
            namespace: None,
            context: Some("prod".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sProxyGet::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--context=prod"), "cmd: {cmd}");
    }
}
