//! SSH K3s ServiceLB Status Tool Handler
//!
//! Shows all `type=LoadBalancer` services cluster-wide, klipper svclb
//! daemonsets, and svclb pods with their node/hostPort mappings.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_servicelb_status` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sServicelbStatusArgs {
    host: String,
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

impl_common_args!(SshK3sServicelbStatusArgs);

/// Handler marker for the `ssh_k3s_servicelb_status` tool.
#[mcp_standard_tool(
    name = "ssh_k3s_servicelb_status",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K3sServicelbStatus;

impl StandardTool for K3sServicelbStatus {
    type Args = SshK3sServicelbStatusArgs;
    const NAME: &'static str = "ssh_k3s_servicelb_status";
    const DESCRIPTION: &'static str = "Show K3s ServiceLB (klipper) status: lists all type=LoadBalancer \
        services cluster-wide with external IPs, klipper svclb daemonsets, and svclb pods with their \
        node and hostPort mappings. Essential for diagnosing K3s LoadBalancer provisioning issues.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace filter for LoadBalancer services (optional; daemonsets/pods always use kube-system)"
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
        "required": ["host"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(
        args: &SshK3sServicelbStatusArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        KubernetesCommandBuilder::build_servicelb_status_command(
            args.kubectl_bin.as_deref(),
            args.namespace.as_deref(),
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_k3s_servicelb_status` tool.
pub type SshK3sServicelbStatusHandler = StandardToolHandler<K3sServicelbStatus>;

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
            "namespace": "production",
            "context": "prod",
            "kubectl_bin": "kubectl"
        });
        let args: SshK3sServicelbStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s-host");
        assert_eq!(args.namespace, Some("production".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k8s"});
        let args: SshK3sServicelbStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s");
        assert!(args.namespace.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k8s"});
        let args: SshK3sServicelbStatusArgs = serde_json::from_value(json).unwrap();
        let s = format!("{args:?}");
        assert!(s.contains("SshK3sServicelbStatusArgs"));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sServicelbStatusHandler::new();
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
        let handler = SshK3sServicelbStatusHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_basic() {
        let args = SshK3sServicelbStatusArgs {
            host: "k8s".into(),
            namespace: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sServicelbStatus::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("type=LoadBalancer"), "cmd: {cmd}");
        assert!(cmd.contains("klipper svclb"), "cmd: {cmd}");
        assert!(cmd.contains("svclb pods"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_invalid_namespace() {
        let args = SshK3sServicelbStatusArgs {
            host: "k8s".into(),
            namespace: Some("--all-namespaces".into()),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K3sServicelbStatus::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_with_context() {
        let args = SshK3sServicelbStatusArgs {
            host: "k8s".into(),
            namespace: None,
            context: Some("prod".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sServicelbStatus::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--context=prod"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_includes_kubectl_prefix() {
        let args = SshK3sServicelbStatusArgs {
            host: "k8s".into(),
            namespace: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sServicelbStatus::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.starts_with("K='kubectl'"), "cmd: {cmd}");
    }
}
