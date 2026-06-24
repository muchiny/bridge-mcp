//! K8s Drain Tool Handler
//!
//! Evicts all pods from a Kubernetes node via `kubectl drain`.
//!
//! **DESTRUCTIVE** — draining evicts running workloads from the node. This
//! disrupts any pods that do not have a replica set / controller able to
//! reschedule them elsewhere. The operation is not automatically reversed
//! when the node returns to service; an explicit `kubectl uncordon` is
//! required. Use `ssh_k8s_cordon` first to mark the node unschedulable
//! before draining.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Default value `true` for `ignore_daemonsets`.
///
/// `DaemonSet` pods cannot be evicted by kubectl drain; without this flag
/// the command aborts. The flag must default to `true` so that a plain
/// `{"host":"…","node":"…"}` invocation succeeds.
fn default_true() -> bool {
    true
}

/// Arguments for the `ssh_k8s_drain` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sDrainArgs {
    host: String,
    node: String,
    /// Skip DaemonSet-managed pods (required for drain to succeed; default true).
    #[serde(default = "default_true")]
    ignore_daemonsets: bool,
    /// Delete local data in emptyDir volumes (permanent data loss; default false).
    #[serde(default)]
    delete_emptydir: bool,
    /// Force deletion of pods not managed by a controller (data loss; default false).
    #[serde(default)]
    force: bool,
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

impl_common_args!(SshK8sDrainArgs);

/// Handler marker for the `ssh_k8s_drain` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_drain",
    group = "kubernetes",
    annotation = "destructive"
)]
pub struct K8sDrainTool;

impl StandardTool for K8sDrainTool {
    type Args = SshK8sDrainArgs;
    const NAME: &'static str = "ssh_k8s_drain";
    const DESCRIPTION: &'static str = "Evict all pods from a Kubernetes node via `kubectl drain`. \
        **DESTRUCTIVE** — this disrupts running workloads and is not \
        automatically reversed; run `ssh_k8s_uncordon` afterwards to \
        return the node to service. \
        Flags: `ignore_daemonsets` (default true — required, DaemonSet pods \
        cannot be evicted), `delete_emptydir` (default false — deletes \
        emptyDir volume data permanently), `force` (default false — deletes \
        bare pods that have no controller, causing permanent data loss). \
        Use `context` for multi-cluster targeting.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "node": {
                "type": "string",
                "description": "Name of the Kubernetes node to drain, e.g. 'node-1'"
            },
            "ignore_daemonsets": {
                "type": "boolean",
                "description": "Skip DaemonSet-managed pods — required for drain to proceed (default true)",
                "default": true
            },
            "delete_emptydir": {
                "type": "boolean",
                "description": "Delete local data in emptyDir volumes — permanent data loss (default false)",
                "default": false
            },
            "force": {
                "type": "boolean",
                "description": "Force deletion of unmanaged (bare) pods — permanent pod loss (default false)",
                "default": false
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
        "required": ["host", "node"]
    }"#;

    fn build_command(args: &SshK8sDrainArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ctx) = args.context.as_deref() {
            crate::domain::use_cases::kubernetes::validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_drain_command(
            args.kubectl_bin.as_deref(),
            &args.node,
            args.ignore_daemonsets,
            args.delete_emptydir,
            args.force,
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_drain` tool.
pub type SshK8sDrainHandler = StandardToolHandler<K8sDrainTool>;

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
        let handler = SshK8sDrainHandler::new();
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
        let handler = SshK8sDrainHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "node": "node-1"
                })),
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
        let handler = SshK8sDrainHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_drain");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_drain");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("node")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "node": "node-1",
            "ignore_daemonsets": true,
            "delete_emptydir": true,
            "force": false,
            "context": "east",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshK8sDrainArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.node, "node-1");
        assert!(args.ignore_daemonsets);
        assert!(args.delete_emptydir);
        assert!(!args.force);
        assert_eq!(args.context, Some("east".to_string()));
        assert_eq!(args.kubectl_bin, Some("kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "node": "node-1"
        });
        let args: SshK8sDrainArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.node, "node-1");
        assert!(args.context.is_none());
        assert!(args.kubectl_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sDrainHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("ignore_daemonsets"));
        assert!(properties.contains_key("delete_emptydir"));
        assert!(properties.contains_key("force"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "node": "node-1"
        });
        let args: SshK8sDrainArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sDrainArgs"));
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sDrainHandler::new();
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

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sDrainHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": 123,
                    "node": "node-1"
                })),
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
    fn test_build_command_drain_with_flags() {
        let args = SshK8sDrainArgs {
            host: "s1".into(),
            node: "node-1".into(),
            ignore_daemonsets: true,
            delete_emptydir: false,
            force: false,
            context: Some("east".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sDrainTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("drain 'node-1'"), "cmd: {cmd}");
        assert!(cmd.contains("--ignore-daemonsets"), "cmd: {cmd}");
        assert!(!cmd.contains("--delete-emptydir-data"), "cmd: {cmd}");
        assert!(!cmd.contains("--force"), "cmd: {cmd}");
        assert!(cmd.contains("--context=east"), "cmd: {cmd}");
    }

    #[test]
    fn test_args_default_ignore_daemonsets_true() {
        let args: SshK8sDrainArgs =
            serde_json::from_value(json!({"host": "s1", "node": "node-1"})).unwrap();
        assert!(
            args.ignore_daemonsets,
            "ignore_daemonsets must default true"
        );
        assert!(!args.delete_emptydir);
        assert!(!args.force);
    }
}
