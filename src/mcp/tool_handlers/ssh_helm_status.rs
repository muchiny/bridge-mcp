//! SSH Helm Status Tool Handler
//!
//! Shows the status of a Helm release on a remote host via SSH.
//! Displays release info, resources, and notes.
//! Auto-detects helm binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{HelmCommandBuilder, KubernetesCommandBuilder};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshHelmStatusArgs {
    host: String,
    release: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    revision: Option<u64>,
    #[serde(default)]
    show_resources: Option<bool>,
    #[serde(default)]
    show_desc: Option<bool>,
    #[serde(default)]
    helm_bin: Option<String>,
    #[serde(default)]
    kubeconfig: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshHelmStatusArgs);

#[mcp_standard_tool(
    name = "ssh_helm_status",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct HelmStatusTool;

impl StandardTool for HelmStatusTool {
    type Args = SshHelmStatusArgs;

    const NAME: &'static str = "ssh_helm_status";

    const DESCRIPTION: &'static str = "Show the status of a Helm release on a remote host. Use ssh_helm_list first to find \
        release names. Returns release info, deployed resources, and chart notes. Use \
        ssh_helm_history to see revision history. Auto-detects helm binary.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "release": {
                "type": "string",
                "description": "Helm release name"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (default: current context namespace)"
            },
            "output": {
                "type": "string",
                "enum": ["table", "json", "yaml"],
                "description": "Output format (default: table)"
            },
            "revision": {
                "type": "integer",
                "description": "Show status for specific revision"
            },
            "show_resources": {
                "type": "boolean",
                "description": "Show the resources in the release"
            },
            "show_desc": {
                "type": "boolean",
                "description": "Show the description of the release"
            },
            "helm_bin": {
                "type": "string",
                "description": "Custom helm binary path (default: auto-detect)"
            },
            "kubeconfig": {
                "type": "string",
                "description": "Path to kubeconfig file (e.g., /etc/rancher/k3s/k3s.yaml for K3s)"
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
        "required": ["host", "release"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshHelmStatusArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(HelmCommandBuilder::build_status_command(
            args.helm_bin.as_deref(),
            args.kubeconfig.as_deref(),
            &args.release,
            args.namespace.as_deref(),
            args.output.as_deref(),
            args.revision,
            args.show_resources.unwrap_or(false),
            args.show_desc.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_helm_status` tool.
pub type SshHelmStatusHandler = StandardToolHandler<HelmStatusTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmStatusHandler::new();
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
        let handler = SshHelmStatusHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "release": "my-app"})),
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
        let handler = SshHelmStatusHandler::new();
        assert_eq!(handler.name(), "ssh_helm_status");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_status");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("release")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "release": "my-app",
            "namespace": "production",
            "output": "json",
            "revision": 3,
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });

        let args: SshHelmStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "my-app");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.output, Some("json".to_string()));
        assert_eq!(args.revision, Some(3));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "release": "my-app"});

        let args: SshHelmStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "my-app");
        assert!(args.namespace.is_none());
        assert!(args.output.is_none());
        assert!(args.revision.is_none());
        assert!(args.helm_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHelmStatusHandler::new();
        let ctx = create_test_context();

        // Missing release field
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
        let handler = SshHelmStatusHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("output"));
        assert!(properties.contains_key("revision"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "release": "my-app"});
        let args: SshHelmStatusArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmStatusArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmStatusHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "release": "my-app"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    use crate::config::{HostKeyVerification, OsType};

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
    fn test_build_command_defaults() {
        let args = SshHelmStatusArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            namespace: None,
            output: None,
            revision: None,
            show_resources: None,
            show_desc: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmStatusTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm status"));
        assert!(cmd.contains("'my-app'"));
    }

    #[test]
    fn test_build_command_with_namespace() {
        let args = SshHelmStatusArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            namespace: Some("production".to_string()),
            output: None,
            revision: None,
            show_resources: None,
            show_desc: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmStatusTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-n 'production'"));
    }

    #[test]
    fn test_build_command_with_output() {
        let args = SshHelmStatusArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            namespace: None,
            output: Some("json".to_string()),
            revision: Some(3),
            show_resources: None,
            show_desc: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmStatusTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-o 'json'"));
        assert!(cmd.contains("--revision 3"));
    }

    #[test]
    fn test_build_command_show_resources_show_desc() {
        let args = SshHelmStatusArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            namespace: None,
            output: None,
            revision: None,
            show_resources: Some(true),
            show_desc: Some(true),
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmStatusTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--show-resources"), "cmd={cmd}");
        assert!(cmd.contains("--show-desc"), "cmd={cmd}");
    }
}
