//! K8s Auth Reconcile Tool Handler
//!
//! Reconcile cluster RBAC objects from a manifest via `kubectl auth reconcile`.
//! Idempotent — repeated calls converge the cluster to the declared state.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_auth_reconcile` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sAuthReconcileArgs {
    host: String,
    manifest: String,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    remove_extra_permissions: bool,
    #[serde(default)]
    remove_extra_subjects: bool,
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

impl_common_args!(SshK8sAuthReconcileArgs);

/// Handler marker for the `ssh_k8s_auth_reconcile` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_auth_reconcile",
    group = "kubernetes",
    annotation = "mutating_idempotent"
)]
pub struct K8sAuthReconcileTool;

impl StandardTool for K8sAuthReconcileTool {
    type Args = SshK8sAuthReconcileArgs;
    const NAME: &'static str = "ssh_k8s_auth_reconcile";
    const DESCRIPTION: &'static str = "Reconcile Kubernetes RBAC objects from a manifest via \
        `kubectl auth reconcile -f`. Unlike `kubectl apply`, this command merges rules — \
        existing permissions not mentioned in the manifest are preserved unless \
        `remove_extra_permissions=true` or `remove_extra_subjects=true`. \
        Idempotent — running it twice converges to the same state. \
        `manifest` may be a file path (starting with `/`, `./`, or `~`) \
        or inline YAML/JSON content.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "manifest": {
                "type": "string",
                "description": "File path (starting with '/', './', or '~') or inline YAML/JSON content for the RBAC manifest"
            },
            "dry_run": {
                "type": "boolean",
                "description": "Preview changes without applying (--dry-run=client)",
                "default": false
            },
            "remove_extra_permissions": {
                "type": "boolean",
                "description": "Remove permissions from roles not present in the manifest (--remove-extra-permissions)",
                "default": false
            },
            "remove_extra_subjects": {
                "type": "boolean",
                "description": "Remove subjects from bindings not present in the manifest (--remove-extra-subjects)",
                "default": false
            },
            "context": {
                "type": "string",
                "description": "kubectl context for multi-cluster targeting"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Custom kubectl binary path"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file"
            }
        },
        "required": ["host", "manifest"]
    }"#;

    fn build_command(args: &SshK8sAuthReconcileArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ctx) = args.context.as_deref() {
            crate::domain::use_cases::kubernetes::validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_auth_reconcile_command(
            args.kubectl_bin.as_deref(),
            &args.manifest,
            args.dry_run,
            args.remove_extra_permissions,
            args.remove_extra_subjects,
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_auth_reconcile` tool.
pub type SshK8sAuthReconcileHandler = StandardToolHandler<K8sAuthReconcileTool>;

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
        let handler = SshK8sAuthReconcileHandler::new();
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
        let handler = SshK8sAuthReconcileHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "manifest": "/tmp/rbac.yaml"})),
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
        let handler = SshK8sAuthReconcileHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_auth_reconcile");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_auth_reconcile");
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
            "manifest": "/etc/k8s/rbac.yaml",
            "dry_run": true,
            "remove_extra_permissions": true,
            "remove_extra_subjects": false,
            "context": "east",
            "kubectl_bin": "kubectl"
        });
        let args: SshK8sAuthReconcileArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.manifest, "/etc/k8s/rbac.yaml");
        assert!(args.dry_run);
        assert!(args.remove_extra_permissions);
        assert!(!args.remove_extra_subjects);
        assert_eq!(args.context, Some("east".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "manifest": "/tmp/rbac.yaml"});
        let args: SshK8sAuthReconcileArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.manifest, "/tmp/rbac.yaml");
        assert!(!args.dry_run);
        assert!(!args.remove_extra_permissions);
        assert!(!args.remove_extra_subjects);
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sAuthReconcileHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("dry_run"));
        assert!(properties.contains_key("remove_extra_permissions"));
        assert!(properties.contains_key("remove_extra_subjects"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let args: SshK8sAuthReconcileArgs = serde_json::from_value(json!({
            "host": "server1",
            "manifest": "/tmp/rbac.yaml"
        }))
        .unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sAuthReconcileArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sAuthReconcileHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "manifest": "/tmp/rbac.yaml"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_reconcile_file_path() {
        let args = SshK8sAuthReconcileArgs {
            host: "s1".into(),
            manifest: "/etc/k8s/rbac.yaml".into(),
            dry_run: false,
            remove_extra_permissions: false,
            remove_extra_subjects: false,
            context: Some("east".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sAuthReconcileTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("auth reconcile"), "cmd: {cmd}");
        assert!(cmd.contains("-f"), "cmd: {cmd}");
        assert!(cmd.contains("/etc/k8s/rbac.yaml"), "cmd: {cmd}");
        assert!(cmd.contains("--context=east"), "cmd: {cmd}");
        assert!(!cmd.contains("echo"), "should be file path, not inline: {cmd}");
    }

    #[test]
    fn test_build_command_reconcile_inline_manifest() {
        let args = SshK8sAuthReconcileArgs {
            host: "s1".into(),
            manifest: "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role".into(),
            dry_run: true,
            remove_extra_permissions: true,
            remove_extra_subjects: true,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sAuthReconcileTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("echo"), "should be inline: {cmd}");
        assert!(cmd.contains("auth reconcile -f -"), "cmd: {cmd}");
        assert!(cmd.contains("--dry-run=client"), "cmd: {cmd}");
        assert!(cmd.contains("--remove-extra-permissions"), "cmd: {cmd}");
        assert!(cmd.contains("--remove-extra-subjects"), "cmd: {cmd}");
    }
}
