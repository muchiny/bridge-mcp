//! SSH K3s Addon Manifests Tool Handler
//!
//! Lists the K3s auto-deploy manifests directory, HelmChart CRDs,
//! HelmChart job status, and helm-install jobs in kube-system.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_addon_manifests` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sAddonManifestsArgs {
    host: String,
    /// Path to the K3s auto-deploy manifests directory (default: /var/lib/rancher/k3s/server/manifests).
    #[serde(default)]
    manifests_dir: Option<String>,
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

impl_common_args!(SshK3sAddonManifestsArgs);

/// Handler marker for the `ssh_k3s_addon_manifests` tool.
#[mcp_standard_tool(
    name = "ssh_k3s_addon_manifests",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K3sAddonManifests;

impl StandardTool for K3sAddonManifests {
    type Args = SshK3sAddonManifestsArgs;
    const NAME: &'static str = "ssh_k3s_addon_manifests";
    const DESCRIPTION: &'static str = "Inspect K3s addon manifests: lists the auto-deploy manifests \
        directory, HelmChart CRDs (k3s addon installs via helm-controller), HelmChart job status, \
        and helm-install jobs in kube-system. Useful for understanding what addons K3s has deployed \
        or is managing via the built-in Helm controller.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "manifests_dir": {
                "type": "string",
                "description": "Path to the K3s auto-deploy manifests directory (default: /var/lib/rancher/k3s/server/manifests)"
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

    fn build_command(args: &SshK3sAddonManifestsArgs, _host_config: &HostConfig) -> Result<String> {
        KubernetesCommandBuilder::build_addon_manifests_command(
            args.kubectl_bin.as_deref(),
            args.manifests_dir.as_deref(),
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_k3s_addon_manifests` tool.
pub type SshK3sAddonManifestsHandler = StandardToolHandler<K3sAddonManifests>;

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
            "manifests_dir": "/custom/manifests",
            "context": "prod",
            "kubectl_bin": "kubectl"
        });
        let args: SshK3sAddonManifestsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s-host");
        assert_eq!(args.manifests_dir, Some("/custom/manifests".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k8s"});
        let args: SshK3sAddonManifestsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s");
        assert!(args.manifests_dir.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k8s"});
        let args: SshK3sAddonManifestsArgs = serde_json::from_value(json).unwrap();
        let s = format!("{args:?}");
        assert!(s.contains("SshK3sAddonManifestsArgs"));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sAddonManifestsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("manifests_dir"));
        assert!(props.contains_key("context"));
        assert!(props.contains_key("kubectl_bin"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK3sAddonManifestsHandler::new();
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
        let args = SshK3sAddonManifestsArgs {
            host: "k8s".into(),
            manifests_dir: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sAddonManifests::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("rancher/k3s/server/manifests"), "cmd: {cmd}");
        assert!(cmd.contains("HelmChart CRDs"), "cmd: {cmd}");
        assert!(cmd.contains("helm-install jobs"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_relative_dir() {
        let args = SshK3sAddonManifestsArgs {
            host: "k8s".into(),
            manifests_dir: Some("relative/path".into()),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K3sAddonManifests::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_rejects_invalid_namespace() {
        // No namespace for this tool; context injection check (starts with '-' = flag)
        let args = SshK3sAddonManifestsArgs {
            host: "k8s".into(),
            manifests_dir: None,
            context: Some("-injected-flag".into()), // starts with '-' = invalid
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K3sAddonManifests::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_with_context() {
        let args = SshK3sAddonManifestsArgs {
            host: "k8s".into(),
            manifests_dir: None,
            context: Some("prod".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sAddonManifests::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--context=prod"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_includes_kubectl_prefix() {
        let args = SshK3sAddonManifestsArgs {
            host: "k8s".into(),
            manifests_dir: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sAddonManifests::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("K='kubectl'"), "cmd: {cmd}");
    }
}
