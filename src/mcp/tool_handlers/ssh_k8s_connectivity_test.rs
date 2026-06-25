//! SSH Kubernetes Connectivity Test Tool Handler
//!
//! Runs an ephemeral pod using `nc -z` to test TCP connectivity from
//! within the cluster to a target host:port. Cleans up the pod via
//! both `--rm` and an explicit delete for safety.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_connectivity_test` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sConnectivityTestArgs {
    host: String,
    /// DNS name or IP to test connectivity to.
    target_host: String,
    /// TCP port to test (1–65535).
    target_port: u16,
    #[serde(default)]
    namespace: Option<String>,
    /// Container image for the probe pod (default: busybox:1.36).
    #[serde(default)]
    image: Option<String>,
    /// Wait duration in seconds before pod timeout (default: 15, max: 300).
    #[serde(default = "default_wait_secs")]
    wait_secs: u64,
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

fn default_wait_secs() -> u64 {
    15
}

impl_common_args!(SshK8sConnectivityTestArgs);

/// Handler marker for the `ssh_k8s_connectivity_test` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_connectivity_test",
    group = "kubernetes",
    annotation = "mutating_idempotent"
)]
pub struct K8sConnectivityTest;

impl StandardTool for K8sConnectivityTest {
    type Args = SshK8sConnectivityTestArgs;
    const NAME: &'static str = "ssh_k8s_connectivity_test";
    const DESCRIPTION: &'static str = "Test TCP connectivity from within the Kubernetes cluster \
        to a target host:port by running an ephemeral pod using nc -z. The pod is auto-cleaned \
        via --rm and an explicit delete. Returns REACHABLE or UNREACHABLE with exit code.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "target_host": {
                "type": "string",
                "description": "DNS name or IP address to test connectivity to"
            },
            "target_port": {
                "type": "integer",
                "description": "TCP port to test (1-65535)",
                "minimum": 1,
                "maximum": 65535
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace to run the probe pod in (default: 'default')"
            },
            "image": {
                "type": "string",
                "description": "Container image for the probe pod (default: busybox:1.36)"
            },
            "wait_secs": {
                "type": "integer",
                "description": "Timeout in seconds for the probe pod (default: 15, max: 300)",
                "minimum": 1,
                "maximum": 300
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
        "required": ["host", "target_host", "target_port"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(
        args: &SshK8sConnectivityTestArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        KubernetesCommandBuilder::build_connectivity_test_command(
            args.kubectl_bin.as_deref(),
            &args.target_host,
            args.target_port,
            args.namespace.as_deref(),
            args.image.as_deref(),
            args.wait_secs,
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_k8s_connectivity_test` tool.
pub type SshK8sConnectivityTestHandler = StandardToolHandler<K8sConnectivityTest>;

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
            "target_host": "my-service",
            "target_port": 8080,
            "namespace": "production",
            "image": "busybox:1.36",
            "wait_secs": 20,
            "context": "prod",
            "kubectl_bin": "kubectl"
        });
        let args: SshK8sConnectivityTestArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s-host");
        assert_eq!(args.target_host, "my-service");
        assert_eq!(args.target_port, 8080);
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.wait_secs, 20);
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k8s", "target_host": "redis", "target_port": 6379});
        let args: SshK8sConnectivityTestArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s");
        assert_eq!(args.target_host, "redis");
        assert_eq!(args.target_port, 6379);
        assert_eq!(args.wait_secs, 15); // default
        assert!(args.namespace.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k8s", "target_host": "redis", "target_port": 6379});
        let args: SshK8sConnectivityTestArgs = serde_json::from_value(json).unwrap();
        let s = format!("{args:?}");
        assert!(s.contains("SshK8sConnectivityTestArgs"));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sConnectivityTestHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("namespace"));
        assert!(props.contains_key("image"));
        assert!(props.contains_key("wait_secs"));
        assert!(props.contains_key("context"));
        assert!(props.contains_key("kubectl_bin"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sConnectivityTestHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "target_host": "redis", "target_port": 6379})),
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
        let args = SshK8sConnectivityTestArgs {
            host: "k8s".into(),
            target_host: "my-service".into(),
            target_port: 8080,
            namespace: Some("default".into()),
            image: None,
            wait_secs: 15,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sConnectivityTest::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("conn-probe-$$"), "cmd: {cmd}");
        assert!(cmd.contains("'my-service'"), "cmd: {cmd}");
        assert!(cmd.contains("nc -z -w 5"), "cmd: {cmd}");
        assert!(cmd.contains("--rm"), "cmd: {cmd}");
        assert!(cmd.contains("delete pod"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_invalid_host() {
        let args = SshK8sConnectivityTestArgs {
            host: "k8s".into(),
            target_host: "BadHost".into(),
            target_port: 80,
            namespace: None,
            image: None,
            wait_secs: 15,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sConnectivityTest::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_rejects_invalid_namespace() {
        let args = SshK8sConnectivityTestArgs {
            host: "k8s".into(),
            target_host: "redis".into(),
            target_port: 6379,
            namespace: Some("--all-namespaces".into()),
            image: None,
            wait_secs: 15,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sConnectivityTest::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_with_context() {
        let args = SshK8sConnectivityTestArgs {
            host: "k8s".into(),
            target_host: "postgres".into(),
            target_port: 5432,
            namespace: None,
            image: None,
            wait_secs: 15,
            context: Some("prod".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sConnectivityTest::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--context=prod"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_includes_kubectl_prefix() {
        let args = SshK8sConnectivityTestArgs {
            host: "k8s".into(),
            target_host: "redis".into(),
            target_port: 6379,
            namespace: None,
            image: None,
            wait_secs: 15,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sConnectivityTest::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("K='kubectl'"), "cmd: {cmd}");
    }
}
