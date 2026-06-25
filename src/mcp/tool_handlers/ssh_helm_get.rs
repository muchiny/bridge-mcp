//! Helm Get Tool Handler
//!
//! Inspects a deployed Helm release's values/manifest/hooks/notes via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{HelmCommandBuilder, KubernetesCommandBuilder};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_helm_get` tool.
#[derive(Debug, Deserialize)]
pub struct SshHelmGetArgs {
    host: String,
    subcommand: String,
    release: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    revision: Option<u64>,
    #[serde(default)]
    output: Option<String>,
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

impl_common_args!(SshHelmGetArgs);

/// Handler marker for the `ssh_helm_get` tool.
#[mcp_standard_tool(name = "ssh_helm_get", group = "kubernetes", annotation = "read_only")]
pub struct HelmGetTool;

impl StandardTool for HelmGetTool {
    type Args = SshHelmGetArgs;

    const NAME: &'static str = "ssh_helm_get";

    const DESCRIPTION: &'static str = "Inspect a deployed Helm release. subcommand: all | values | manifest | hooks | notes. \
        Use revision to inspect a prior release version. Read-only — the evidence base for \
        drift/rollback decisions.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "subcommand": {
                "type": "string",
                "enum": ["all", "values", "manifest", "hooks", "notes", "metadata"],
                "description": "What to fetch: all | values | manifest | hooks | notes | metadata"
            },
            "release": {
                "type": "string",
                "description": "Helm release name"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (default: current context namespace)"
            },
            "revision": {
                "type": "integer",
                "description": "Inspect a specific release revision",
                "minimum": 1
            },
            "output": {
                "type": "string",
                "enum": ["json", "yaml"],
                "description": "Output format (json or yaml)"
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
        "required": ["host", "subcommand", "release"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshHelmGetArgs, _host_config: &HostConfig) -> Result<String> {
        KubernetesCommandBuilder::validate_helm_get_subcommand(&args.subcommand)?;
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(HelmCommandBuilder::build_get_command(
            args.helm_bin.as_deref(),
            args.kubeconfig.as_deref(),
            &args.subcommand,
            &args.release,
            args.namespace.as_deref(),
            args.revision,
            args.output.as_deref(),
        ))
    }
}

/// Handler for the `ssh_helm_get` tool.
pub type SshHelmGetHandler = StandardToolHandler<HelmGetTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmGetHandler::new();
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
        let handler = SshHelmGetHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "subcommand": "values", "release": "my-app"})),
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
        let handler = SshHelmGetHandler::new();
        assert_eq!(handler.name(), "ssh_helm_get");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_get");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("subcommand")));
        assert!(required.contains(&json!("release")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "subcommand": "values",
            "release": "my-app",
            "namespace": "production",
            "revision": 3,
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });

        let args: SshHelmGetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.subcommand, "values");
        assert_eq!(args.release, "my-app");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.revision, Some(3));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "subcommand": "manifest", "release": "my-app"});

        let args: SshHelmGetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.subcommand, "manifest");
        assert_eq!(args.release, "my-app");
        assert!(args.namespace.is_none());
        assert!(args.revision.is_none());
        assert!(args.helm_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHelmGetHandler::new();
        let ctx = create_test_context();

        // Missing subcommand field
        let result = handler
            .execute(Some(json!({"host": "server1", "release": "my-app"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_missing_required_field_release() {
        let handler = SshHelmGetHandler::new();
        let ctx = create_test_context();

        // Missing release field
        let result = handler
            .execute(
                Some(json!({"host": "server1", "subcommand": "values"})),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmGetHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("revision"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("kubeconfig"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "subcommand": "notes", "release": "my-app"});
        let args: SshHelmGetArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmGetArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmGetHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "subcommand": "values", "release": "my-app"})),
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
        let args = SshHelmGetArgs {
            host: "server1".to_string(),
            subcommand: "values".to_string(),
            release: "rel".to_string(),
            namespace: None,
            revision: None,
            output: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmGetTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("get 'values' 'rel'"), "cmd={cmd}");
    }

    #[test]
    fn test_build_command_with_revision_and_namespace() {
        let args = SshHelmGetArgs {
            host: "server1".to_string(),
            subcommand: "manifest".to_string(),
            release: "my-release".to_string(),
            namespace: Some("staging".to_string()),
            revision: Some(5),
            output: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmGetTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("get 'manifest' 'my-release'"), "cmd={cmd}");
        assert!(cmd.contains("-n 'staging'"), "cmd={cmd}");
        assert!(cmd.contains("--revision 5"), "cmd={cmd}");
    }

    #[test]
    fn test_build_command_invalid_subcommand() {
        let args = SshHelmGetArgs {
            host: "server1".to_string(),
            subcommand: "delete".to_string(),
            release: "rel".to_string(),
            namespace: None,
            revision: None,
            output: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let result = HelmGetTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("delete"), "reason={reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_with_output() {
        let args = SshHelmGetArgs {
            host: "server1".to_string(),
            subcommand: "values".to_string(),
            release: "rel".to_string(),
            namespace: None,
            revision: None,
            output: Some("json".to_string()),
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmGetTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-o 'json'"), "cmd={cmd}");
    }

    #[test]
    fn test_build_command_metadata_subcommand() {
        let args = SshHelmGetArgs {
            host: "server1".to_string(),
            subcommand: "metadata".to_string(),
            release: "rel".to_string(),
            namespace: None,
            revision: None,
            output: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmGetTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("get 'metadata' 'rel'"), "cmd={cmd}");
    }
}
