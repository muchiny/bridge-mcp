//! Helm Template Tool Handler
//!
//! Renders a chart's manifests client-side (helm template) via SSH — no cluster mutation.

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{HelmCommandBuilder, KubernetesCommandBuilder};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_helm_template` tool.
#[derive(Debug, Deserialize)]
pub struct SshHelmTemplateArgs {
    host: String,
    release: String,
    chart: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    set_values: Option<HashMap<String, String>>,
    #[serde(default)]
    values_files: Option<Vec<String>>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    show_only: Option<Vec<String>>,
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

impl_common_args!(SshHelmTemplateArgs);

/// Handler marker for the `ssh_helm_template` tool.
#[mcp_standard_tool(
    name = "ssh_helm_template",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct HelmTemplateTool;

impl StandardTool for HelmTemplateTool {
    type Args = SshHelmTemplateArgs;

    const NAME: &'static str = "ssh_helm_template";

    const DESCRIPTION: &'static str = "Render a Helm chart's Kubernetes manifests locally (helm template) without touching the \
        cluster. Validate image tags/limits/securityContext before an install/upgrade. Use \
        show_only to render a single template.";

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
            "chart": {
                "type": "string",
                "description": "Chart reference (repo/chart or local path)"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (default: current context namespace)"
            },
            "set_values": {
                "type": "object",
                "description": "Key-value pairs for --set",
                "additionalProperties": { "type": "string" }
            },
            "values_files": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Paths to values YAML files on the remote host"
            },
            "version": {
                "type": "string",
                "description": "Chart version constraint"
            },
            "show_only": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Only render listed templates, e.g. templates/deployment.yaml"
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
        "required": ["host", "release", "chart"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Yaml;

    fn build_command(args: &SshHelmTemplateArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(HelmCommandBuilder::build_template_command(
            args.helm_bin.as_deref(),
            args.kubeconfig.as_deref(),
            &args.release,
            &args.chart,
            args.namespace.as_deref(),
            args.set_values.as_ref(),
            args.values_files.as_deref(),
            args.version.as_deref(),
            args.show_only.as_deref(),
        ))
    }
}

/// Handler for the `ssh_helm_template` tool.
pub type SshHelmTemplateHandler = StandardToolHandler<HelmTemplateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmTemplateHandler::new();
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
        let handler = SshHelmTemplateHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "release": "rel",
                    "chart": "repo/chart"
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
        let handler = SshHelmTemplateHandler::new();
        assert_eq!(handler.name(), "ssh_helm_template");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_template");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("release")));
        assert!(required.contains(&json!("chart")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "release": "rel",
            "chart": "repo/chart",
            "namespace": "production",
            "set_values": {"image.tag": "v2", "replicaCount": "3"},
            "values_files": ["/tmp/values.yaml", "/tmp/overrides.yaml"],
            "version": "1.2.3",
            "show_only": ["templates/deployment.yaml"],
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });

        let args: SshHelmTemplateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "rel");
        assert_eq!(args.chart, "repo/chart");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert!(args.set_values.is_some());
        let sv = args.set_values.unwrap();
        assert_eq!(sv.get("image.tag"), Some(&"v2".to_string()));
        assert_eq!(sv.get("replicaCount"), Some(&"3".to_string()));
        assert_eq!(
            args.values_files,
            Some(vec![
                "/tmp/values.yaml".to_string(),
                "/tmp/overrides.yaml".to_string()
            ])
        );
        assert_eq!(args.version, Some("1.2.3".to_string()));
        assert_eq!(
            args.show_only,
            Some(vec!["templates/deployment.yaml".to_string()])
        );
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "release": "rel", "chart": "repo/chart"});

        let args: SshHelmTemplateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "rel");
        assert_eq!(args.chart, "repo/chart");
        assert!(args.namespace.is_none());
        assert!(args.set_values.is_none());
        assert!(args.values_files.is_none());
        assert!(args.version.is_none());
        assert!(args.show_only.is_none());
        assert!(args.helm_bin.is_none());
        assert!(args.kubeconfig.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHelmTemplateHandler::new();
        let ctx = create_test_context();

        // Missing chart field
        let result = handler
            .execute(Some(json!({"host": "server1", "release": "rel"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }

        // Missing release field
        let result2 = handler
            .execute(
                Some(json!({"host": "server1", "chart": "repo/chart"})),
                &ctx,
            )
            .await;

        assert!(result2.is_err());
        match result2.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmTemplateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("set_values"));
        assert!(properties.contains_key("values_files"));
        assert!(properties.contains_key("version"));
        assert!(properties.contains_key("show_only"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "release": "rel", "chart": "repo/chart"});
        let args: SshHelmTemplateArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmTemplateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmTemplateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "release": "rel", "chart": "repo/chart"})),
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
        let args = SshHelmTemplateArgs {
            host: "server1".to_string(),
            release: "rel".to_string(),
            chart: "repo/chart".to_string(),
            namespace: None,
            set_values: None,
            values_files: None,
            version: None,
            show_only: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmTemplateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("template 'rel' 'repo/chart'"), "cmd={cmd}");
    }

    #[test]
    fn test_build_command_with_set_and_values() {
        let mut set_values = HashMap::new();
        set_values.insert("image.tag".to_string(), "v2".to_string());

        let args = SshHelmTemplateArgs {
            host: "server1".to_string(),
            release: "rel".to_string(),
            chart: "repo/chart".to_string(),
            namespace: Some("staging".to_string()),
            set_values: Some(set_values),
            values_files: Some(vec!["/tmp/v.yaml".to_string()]),
            version: None,
            show_only: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmTemplateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("template 'rel' 'repo/chart'"), "cmd={cmd}");
        assert!(cmd.contains("-n 'staging'"), "cmd={cmd}");
        assert!(cmd.contains("--set 'image.tag'='v2'"), "cmd={cmd}");
        assert!(cmd.contains("-f '/tmp/v.yaml'"), "cmd={cmd}");
    }

    #[test]
    fn test_build_command_show_only_and_version() {
        let args = SshHelmTemplateArgs {
            host: "server1".to_string(),
            release: "rel".to_string(),
            chart: "repo/chart".to_string(),
            namespace: None,
            set_values: None,
            values_files: None,
            version: Some("1.2.3".to_string()),
            show_only: Some(vec!["templates/deployment.yaml".to_string()]),
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmTemplateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--version '1.2.3'"), "cmd={cmd}");
        assert!(
            cmd.contains("--show-only 'templates/deployment.yaml'"),
            "cmd={cmd}"
        );
    }
}
