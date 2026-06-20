//! SSH Kubernetes Apply Tool Handler
//!
//! Applies a Kubernetes manifest via `kubectl` on a remote host.
//! Supports file paths and inline YAML, with dry-run and server-side apply options.
//! Auto-detects `kubectl` binary (k8s, k3s, microk8s).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshK8sApplyArgs {
    host: String,
    manifest: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    dry_run: Option<String>,
    #[serde(default)]
    force: Option<bool>,
    #[serde(default)]
    server_side: Option<bool>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sApplyArgs);

#[mcp_standard_tool(
    name = "ssh_k8s_apply",
    group = "kubernetes",
    annotation = "mutating_idempotent"
)]
pub struct K8sApplyTool;

impl StandardTool for K8sApplyTool {
    type Args = SshK8sApplyArgs;

    const NAME: &'static str = "ssh_k8s_apply";

    const DESCRIPTION: &'static str = "Apply a Kubernetes manifest via kubectl on a remote host. The manifest parameter can \
        be a file path on the remote host or inline YAML content. Supports dry-run \
        (client/server) to validate before applying. Use ssh_k8s_rollout after applying to \
        check deployment status. Auto-detects kubectl binary (k8s, k3s, microk8s).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "manifest": {
                "type": "string",
                "description": "Path to manifest file on the remote host (must start with '/', './', or '~') or raw inline YAML content. Strings that start with any of those prefixes are treated as file paths; everything else is piped as inline YAML."
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace"
            },
            "dry_run": {
                "type": "string",
                "enum": ["none", "client", "server"],
                "description": "Dry-run mode: none (actually apply), client (local validation), server (server-side validation)"
            },
            "force": {
                "type": "boolean",
                "description": "Force apply even if there are conflicts"
            },
            "server_side": {
                "type": "boolean",
                "description": "Use server-side apply (--server-side flag)"
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
            }
        },
        "required": ["host", "manifest"]
    }"#;

    fn build_command(args: &SshK8sApplyArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(KubernetesCommandBuilder::build_apply_command(
            args.kubectl_bin.as_deref(),
            &args.manifest,
            args.namespace.as_deref(),
            args.dry_run.as_deref(),
            args.force.unwrap_or(false),
            args.server_side.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_k8s_apply` tool.
pub type SshK8sApplyHandler = StandardToolHandler<K8sApplyTool>;

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
        let handler = SshK8sApplyHandler::new();
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshK8sApplyHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "manifest": "/tmp/deployment.yaml"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "nonexistent");
            }
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK8sApplyHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_apply");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_apply");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("manifest")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "manifest": "/tmp/deployment.yaml",
            "namespace": "production",
            "dry_run": "server",
            "force": true,
            "server_side": true,
            "kubectl_bin": "k3s kubectl",
            "timeout_seconds": 120,
            "max_output": 10000
        });

        let args: SshK8sApplyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.manifest, "/tmp/deployment.yaml");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.dry_run, Some("server".to_string()));
        assert_eq!(args.force, Some(true));
        assert_eq!(args.server_side, Some(true));
        assert_eq!(args.kubectl_bin, Some("k3s kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "manifest": "/tmp/deployment.yaml"
        });

        let args: SshK8sApplyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.manifest, "/tmp/deployment.yaml");
        assert!(args.namespace.is_none());
        assert!(args.dry_run.is_none());
        assert!(args.force.is_none());
        assert!(args.server_side.is_none());
        assert!(args.kubectl_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sApplyHandler::new();
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
        let handler = SshK8sApplyHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("dry_run"));
        assert!(properties.contains_key("force"));
        assert!(properties.contains_key("server_side"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "manifest": "/tmp/deployment.yaml"});
        let args: SshK8sApplyArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sApplyArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sApplyHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host
        let result = handler
            .execute(
                Some(json!({"host": 123, "manifest": "/tmp/deployment.yaml"})),
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
    fn test_build_command_from_file() {
        let args = SshK8sApplyArgs {
            host: "server1".to_string(),
            manifest: "/tmp/deployment.yaml".to_string(),
            namespace: None,
            dry_run: None,
            force: None,
            server_side: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sApplyTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.starts_with("kubectl apply -f '/tmp/deployment.yaml'"));
    }

    #[test]
    fn test_build_command_with_namespace() {
        let args = SshK8sApplyArgs {
            host: "server1".to_string(),
            manifest: "/tmp/service.yaml".to_string(),
            namespace: Some("production".to_string()),
            dry_run: None,
            force: None,
            server_side: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sApplyTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("kubectl apply -f"));
        assert!(cmd.contains("-n 'production'"));
    }

    #[test]
    fn test_build_command_dry_run() {
        let args = SshK8sApplyArgs {
            host: "server1".to_string(),
            manifest: "/tmp/deployment.yaml".to_string(),
            namespace: Some("staging".to_string()),
            dry_run: Some("server".to_string()),
            force: Some(true),
            server_side: Some(true),
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sApplyTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("-n 'staging'"));
        assert!(cmd.contains("--dry-run='server'"));
        assert!(cmd.contains("--force"));
        assert!(cmd.contains("--server-side"));
    }
}
