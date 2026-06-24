//! K8s Cluster Info Tool Handler
//!
//! Cluster endpoint summary via `kubectl cluster-info`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{KubernetesCommandBuilder, validate_context};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_cluster_info` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sClusterInfoArgs {
    host: String,
    #[serde(default)]
    dump: Option<bool>,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sClusterInfoArgs);

/// Handler marker for the `ssh_k8s_cluster_info` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_cluster_info",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sClusterInfoTool;

impl StandardTool for K8sClusterInfoTool {
    type Args = SshK8sClusterInfoArgs;
    const NAME: &'static str = "ssh_k8s_cluster_info";
    const DESCRIPTION: &'static str = "Print cluster endpoint summary via `kubectl cluster-info`. \
        Without `dump`: shows control-plane and CoreDNS addresses (fast). \
        With `dump=true`: verbose diagnostic dump of cluster state (large output, \
        use `save_output` to avoid truncation). \
        Use `context` for multi-cluster targeting.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "dump": {
                "type": "boolean",
                "description": "Set to true for verbose diagnostic dump (kubectl cluster-info dump). Default: false."
            },
            "context": {
                "type": "string",
                "description": "kubectl context for multi-cluster targeting (e.g. 'east', 'prod-us-east-1')"
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
        "required": ["host"]
    }"#;

    fn build_command(args: &SshK8sClusterInfoArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ctx) = args.context.as_deref() {
            validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_cluster_info_command(
            args.kubectl_bin.as_deref(),
            args.dump.unwrap_or(false),
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_cluster_info` tool.
pub type SshK8sClusterInfoHandler = StandardToolHandler<K8sClusterInfoTool>;

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
        let handler = SshK8sClusterInfoHandler::new();
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
        let handler = SshK8sClusterInfoHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK8sClusterInfoHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_cluster_info");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_cluster_info");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "dump": true,
            "context": "east",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60,
            "max_output": 50000
        });
        let args: SshK8sClusterInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.dump, Some(true));
        assert_eq!(args.context, Some("east".to_string()));
        assert_eq!(args.kubectl_bin, Some("kubectl".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshK8sClusterInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.dump.is_none());
        assert!(args.context.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sClusterInfoHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("dump"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshK8sClusterInfoArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sClusterInfoArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sClusterInfoHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_no_dump() {
        let args = SshK8sClusterInfoArgs {
            host: "s1".into(),
            dump: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sClusterInfoTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("cluster-info"), "cmd: {cmd}");
        assert!(!cmd.contains("dump"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_with_dump() {
        let args = SshK8sClusterInfoArgs {
            host: "s1".into(),
            dump: Some(true),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sClusterInfoTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("cluster-info dump"), "cmd: {cmd}");
    }
}
