//! K8s Diff Tool Handler
//!
//! Previews changes a manifest would make (kubectl diff) via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_diff` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sDiffArgs {
    host: String,
    manifest: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sDiffArgs);

/// Handler marker for the `ssh_k8s_diff` tool.
#[mcp_standard_tool(name = "ssh_k8s_diff", group = "kubernetes", annotation = "read_only")]
pub struct K8sDiffTool;

impl StandardTool for K8sDiffTool {
    type Args = SshK8sDiffArgs;
    const NAME: &'static str = "ssh_k8s_diff";
    const DESCRIPTION: &'static str = "Preview the changes a manifest would make against the live cluster (kubectl diff -f). \
        manifest is a remote file path (starts with /, ./, ~) or inline YAML. \
        Read-only — use before ssh_k8s_apply.";
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
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "manifest"]
    }"#;

    fn build_command(args: &SshK8sDiffArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(KubernetesCommandBuilder::build_diff_command(
            args.kubectl_bin.as_deref(),
            &args.manifest,
            args.namespace.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_diff` tool.
pub type SshK8sDiffHandler = StandardToolHandler<K8sDiffTool>;

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
        let handler = SshK8sDiffHandler::new();
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
        let handler = SshK8sDiffHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "manifest": "/tmp/d.yaml"})),
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
        let handler = SshK8sDiffHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_diff");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_diff");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("manifest")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "manifest": "/tmp/d.yaml",
            "namespace": "default",
            "kubectl_bin": "k3s kubectl",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshK8sDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.manifest, "/tmp/d.yaml");
        assert_eq!(args.namespace, Some("default".to_string()));
        assert_eq!(args.kubectl_bin, Some("k3s kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "manifest": "/tmp/d.yaml"});
        let args: SshK8sDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.manifest, "/tmp/d.yaml");
        assert!(args.namespace.is_none());
        assert!(args.kubectl_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sDiffHandler::new();
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
        let handler = SshK8sDiffHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "manifest": "/tmp/d.yaml"});
        let args: SshK8sDiffArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sDiffArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sDiffHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "manifest": "/tmp/d.yaml"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    #[test]
    fn test_build_command_file_path() {
        let args = SshK8sDiffArgs {
            host: "server1".to_string(),
            manifest: "/tmp/d.yaml".to_string(),
            namespace: Some("default".to_string()),
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sDiffTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("diff -f '/tmp/d.yaml'"), "cmd: {cmd}");
        assert!(cmd.contains("-n 'default'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_inline_yaml() {
        let args = SshK8sDiffArgs {
            host: "server1".to_string(),
            manifest: "apiVersion: v1".to_string(),
            namespace: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sDiffTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("| "), "cmd: {cmd}");
        assert!(cmd.contains("diff -f -"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_with_namespace() {
        let args = SshK8sDiffArgs {
            host: "server1".to_string(),
            manifest: "/tmp/d.yaml".to_string(),
            namespace: Some("production".to_string()),
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sDiffTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("diff -f '/tmp/d.yaml'"), "cmd: {cmd}");
        assert!(cmd.contains("-n 'production'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_flag_like_namespace() {
        let args = SshK8sDiffArgs {
            host: "server1".to_string(),
            manifest: "/tmp/d.yaml".to_string(),
            namespace: Some("--all-namespaces".to_string()),
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let result = K8sDiffTool::build_command(&args, &host_config);
        assert!(
            result.is_err(),
            "expected rejection for flag-like namespace"
        );
    }
}
