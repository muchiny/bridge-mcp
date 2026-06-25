//! K8s Local-Path GC Tool Handler
//!
//! Finds and optionally removes orphaned local-path-provisioner directories —
//! on-disk subdirectories under the storage root that are no longer referenced
//! by any `PersistentVolume`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{
    KubernetesCommandBuilder, validate_context, validate_storage_root,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

const DEFAULT_STORAGE_ROOT: &str = "/var/lib/rancher/k3s/storage";

/// Arguments for the `ssh_k8s_localpath_gc` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sLocalpathGcArgs {
    host: String,
    #[serde(default)]
    storage_root: Option<String>,
    #[serde(default)]
    apply: Option<bool>,
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

impl_common_args!(SshK8sLocalpathGcArgs);

/// Handler marker for the `ssh_k8s_localpath_gc` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_localpath_gc",
    group = "kubernetes",
    annotation = "destructive"
)]
pub struct K8sLocalpathGcTool;

impl StandardTool for K8sLocalpathGcTool {
    type Args = SshK8sLocalpathGcArgs;
    const NAME: &'static str = "ssh_k8s_localpath_gc";
    const DESCRIPTION: &'static str = "Garbage-collect orphaned local-path-provisioner \
        directories. Compares on-disk subdirectories under `storage_root` against live PV \
        host paths; reports orphans. With `apply=true`, removes orphans via `rm -rf` \
        (guarded: only paths inside `storage_root` are deleted). Default is dry-run. \
        DESTRUCTIVE when `apply=true` — data cannot be recovered.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "storage_root": {
                "type": "string",
                "description": "Storage root directory (default: /var/lib/rancher/k3s/storage)"
            },
            "apply": {
                "type": "boolean",
                "description": "Set to true to actually delete orphans (default: false = dry-run)"
            },
            "context": {
                "type": "string",
                "description": "kubectl context for multi-cluster targeting"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Custom kubectl binary path (default: auto-detect)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (0 = no limit)",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a file on the MCP server"
            }
        },
        "required": ["host"]
    }"#;

    fn build_command(args: &SshK8sLocalpathGcArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ctx) = args.context.as_deref() {
            validate_context(ctx)?;
        }
        let root = args.storage_root.as_deref().unwrap_or(DEFAULT_STORAGE_ROOT);
        validate_storage_root(root)?;
        Ok(KubernetesCommandBuilder::build_localpath_gc_command(
            args.kubectl_bin.as_deref(),
            root,
            args.context.as_deref(),
            args.apply.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_k8s_localpath_gc` tool.
pub type SshK8sLocalpathGcHandler = StandardToolHandler<K8sLocalpathGcTool>;

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
        let handler = SshK8sLocalpathGcHandler::new();
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
        let handler = SshK8sLocalpathGcHandler::new();
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
        let handler = SshK8sLocalpathGcHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_localpath_gc");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_localpath_gc");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "storage_root": "/var/lib/rancher/k3s/storage",
            "apply": true,
            "context": "prod",
            "kubectl_bin": "kubectl"
        });
        let args: SshK8sLocalpathGcArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(
            args.storage_root,
            Some("/var/lib/rancher/k3s/storage".to_string())
        );
        assert_eq!(args.apply, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshK8sLocalpathGcArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.storage_root.is_none());
        assert!(args.apply.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sLocalpathGcHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("storage_root"));
        assert!(properties.contains_key("apply"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshK8sLocalpathGcArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sLocalpathGcArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sLocalpathGcHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_dry_run_default() {
        let args = SshK8sLocalpathGcArgs {
            host: "s1".into(),
            storage_root: None,
            apply: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sLocalpathGcTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("dry-run"), "cmd: {cmd}");
        assert!(cmd.contains("APPLY=false"), "cmd: {cmd}");
        assert!(cmd.contains("rancher/k3s/storage"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_shallow_root() {
        let args = SshK8sLocalpathGcArgs {
            host: "s1".into(),
            storage_root: Some("/var".into()),
            apply: None,
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(K8sLocalpathGcTool::build_command(&args, &test_host_config()).is_err());
    }
}
