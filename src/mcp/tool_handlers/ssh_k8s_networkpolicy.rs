//! SSH Kubernetes `NetworkPolicy` Tool Handler
//!
//! Shows a `NetworkPolicy`'s YAML, the pods matched by its `podSelector`,
//! and a CNI enforcement caveat for flannel-based K3s clusters.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_networkpolicy` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sNetworkpolicyArgs {
    host: String,
    /// Name of the `NetworkPolicy` resource.
    policy: String,
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

impl_common_args!(SshK8sNetworkpolicyArgs);

/// Handler marker for the `ssh_k8s_networkpolicy` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_networkpolicy",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sNetworkpolicy;

impl StandardTool for K8sNetworkpolicy {
    type Args = SshK8sNetworkpolicyArgs;
    const NAME: &'static str = "ssh_k8s_networkpolicy";
    const DESCRIPTION: &'static str = "Inspect a Kubernetes NetworkPolicy: shows the policy YAML, the pods matched by its \
        podSelector (with IP and phase), and a CNI enforcement caveat for flannel-based K3s \
        clusters. IMPORTANT: flannel (default K3s CNI) does NOT enforce NetworkPolicy; \
        install Calico, Cilium, or use --flannel-backend=none for enforcement.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "policy": {
                "type": "string",
                "description": "Name of the NetworkPolicy resource"
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
        "required": ["host", "policy"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshK8sNetworkpolicyArgs, _host_config: &HostConfig) -> Result<String> {
        KubernetesCommandBuilder::build_networkpolicy_command(
            args.kubectl_bin.as_deref(),
            &args.policy,
            args.namespace.as_deref(),
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_k8s_networkpolicy` tool.
pub type SshK8sNetworkpolicyHandler = StandardToolHandler<K8sNetworkpolicy>;

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
            "policy": "allow-web",
            "namespace": "production",
            "context": "prod",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60,
            "max_output": 40000
        });
        let args: SshK8sNetworkpolicyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s-host");
        assert_eq!(args.policy, "allow-web");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.context, Some("prod".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k8s", "policy": "deny-all"});
        let args: SshK8sNetworkpolicyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s");
        assert_eq!(args.policy, "deny-all");
        assert!(args.namespace.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k8s", "policy": "allow-web"});
        let args: SshK8sNetworkpolicyArgs = serde_json::from_value(json).unwrap();
        let s = format!("{args:?}");
        assert!(s.contains("SshK8sNetworkpolicyArgs"));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sNetworkpolicyHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("namespace"));
        assert!(props.contains_key("context"));
        assert!(props.contains_key("kubectl_bin"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sNetworkpolicyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "policy": "allow-web"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_basic() {
        let args = SshK8sNetworkpolicyArgs {
            host: "k8s".into(),
            policy: "allow-web".into(),
            namespace: Some("default".into()),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sNetworkpolicy::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("networkpolicy"), "cmd: {cmd}");
        assert!(cmd.contains("'allow-web'"), "cmd: {cmd}");
        assert!(cmd.contains("flannel"), "cmd: {cmd}");
        assert!(cmd.contains("podSelector"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_invalid_policy_name() {
        let args = SshK8sNetworkpolicyArgs {
            host: "k8s".into(),
            policy: "Bad Policy".into(),
            namespace: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sNetworkpolicy::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_rejects_invalid_namespace() {
        let args = SshK8sNetworkpolicyArgs {
            host: "k8s".into(),
            policy: "allow-web".into(),
            namespace: Some("--bad".into()),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sNetworkpolicy::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_with_context() {
        let args = SshK8sNetworkpolicyArgs {
            host: "k8s".into(),
            policy: "allow-web".into(),
            namespace: None,
            context: Some("prod".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sNetworkpolicy::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--context=prod"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_includes_cni_caveat() {
        let args = SshK8sNetworkpolicyArgs {
            host: "k8s".into(),
            policy: "deny-all".into(),
            namespace: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sNetworkpolicy::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("flannel"), "cmd should mention flannel: {cmd}");
        assert!(cmd.contains("NetworkPolicy"), "cmd: {cmd}");
    }
}
