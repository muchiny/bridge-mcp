//! SSH Helm Uninstall Tool Handler
//!
//! Uninstalls a Helm release from a remote host via SSH.
//! Optionally keeps release history.
//! Auto-detects helm binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{HelmCommandBuilder, KubernetesCommandBuilder};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshHelmUninstallArgs {
    host: String,
    release: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    keep_history: Option<bool>,
    #[serde(default)]
    no_hooks: Option<bool>,
    #[serde(default)]
    wait: Option<bool>,
    #[serde(default)]
    cascade: Option<String>,
    #[serde(default)]
    timeout: Option<String>,
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

impl_common_args!(SshHelmUninstallArgs);

#[mcp_standard_tool(
    name = "ssh_helm_uninstall",
    group = "kubernetes",
    annotation = "destructive"
)]
pub struct HelmUninstallTool;

impl StandardTool for HelmUninstallTool {
    type Args = SshHelmUninstallArgs;

    const NAME: &'static str = "ssh_helm_uninstall";

    const DESCRIPTION: &'static str = "Uninstall a Helm release from a remote host, removing all associated Kubernetes \
        resources. Use ssh_helm_list first to find the release name. Set keep_history=true to \
        retain history for potential reinstall. Supports dry_run to preview before removing. \
        Auto-detects helm binary.";

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
            "dry_run": {
                "type": "boolean",
                "description": "Simulate uninstall without actually removing the release"
            },
            "keep_history": {
                "type": "boolean",
                "description": "Retain release history after uninstall"
            },
            "no_hooks": {
                "type": "boolean",
                "description": "Prevent hooks from running during uninstall"
            },
            "wait": {
                "type": "boolean",
                "description": "Wait for all resources to be deleted before returning"
            },
            "cascade": {
                "type": "string",
                "enum": ["background", "orphan", "foreground"],
                "description": "Cascade deletion strategy: background | orphan | foreground"
            },
            "timeout": {
                "type": "string",
                "description": "Helm --timeout: Go duration to wait for Kubernetes operations (e.g. '5m0s', '10m')"
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

    fn build_command(args: &SshHelmUninstallArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(c) = args.cascade.as_deref() {
            HelmCommandBuilder::validate_cascade(c)?;
        }
        Ok(HelmCommandBuilder::build_uninstall_command(
            args.helm_bin.as_deref(),
            args.kubeconfig.as_deref(),
            &args.release,
            args.namespace.as_deref(),
            args.dry_run.unwrap_or(false),
            args.keep_history.unwrap_or(false),
            args.no_hooks.unwrap_or(false),
            args.wait.unwrap_or(false),
            args.cascade.as_deref(),
            args.timeout.as_deref(),
        ))
    }

    /// Confirm destructive operation via `elicitation/create` before
    /// running the underlying command. Falls back to a no-op when the
    /// client does not advertise the elicitation capability — the
    /// global `security.require_elicitation_on_destructive` gate still
    /// applies in that case.
    async fn pre_execute(args: &Self::Args, ctx: &ToolContext) -> Result<Option<ToolCallResult>> {
        let summary = format!(
            "Uninstall helm release `{}` (namespace=`{}`) on host `{}`",
            args.release,
            args.namespace.as_deref().unwrap_or("default"),
            args.host,
        );
        match ctx.elicit_confirm(Self::NAME, &summary).await? {
            Some(false) => Ok(Some(ToolCallResult::error(
                "User declined destructive operation".to_string(),
            ))),
            _ => Ok(None),
        }
    }
}

/// Handler for the `ssh_helm_uninstall` tool.
pub type SshHelmUninstallHandler = StandardToolHandler<HelmUninstallTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmUninstallHandler::new();
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
        let handler = SshHelmUninstallHandler::new();
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
        let handler = SshHelmUninstallHandler::new();
        assert_eq!(handler.name(), "ssh_helm_uninstall");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_uninstall");

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
            "dry_run": true,
            "keep_history": true,
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });

        let args: SshHelmUninstallArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "my-app");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.dry_run, Some(true));
        assert_eq!(args.keep_history, Some(true));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "release": "my-app"});

        let args: SshHelmUninstallArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "my-app");
        assert!(args.namespace.is_none());
        assert!(args.dry_run.is_none());
        assert!(args.keep_history.is_none());
        assert!(args.helm_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHelmUninstallHandler::new();
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
        let handler = SshHelmUninstallHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("dry_run"));
        assert!(properties.contains_key("keep_history"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "release": "my-app"});
        let args: SshHelmUninstallArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmUninstallArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmUninstallHandler::new();
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
        let args = SshHelmUninstallArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            namespace: None,
            dry_run: None,
            keep_history: None,
            no_hooks: None,
            wait: None,
            cascade: None,
            timeout: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmUninstallTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm uninstall"));
        assert!(cmd.contains("'my-app'"));
    }

    #[test]
    fn test_build_command_with_namespace() {
        let args = SshHelmUninstallArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            namespace: Some("production".to_string()),
            dry_run: None,
            keep_history: None,
            no_hooks: None,
            wait: None,
            cascade: None,
            timeout: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmUninstallTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-n 'production'"));
    }

    #[test]
    fn test_build_command_dry_run() {
        let args = SshHelmUninstallArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            namespace: None,
            dry_run: Some(true),
            keep_history: Some(true),
            no_hooks: None,
            wait: None,
            cascade: None,
            timeout: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmUninstallTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--dry-run"));
        assert!(cmd.contains("--keep-history"));
    }

    #[test]
    fn test_build_command_no_hooks_wait_cascade_timeout() {
        let args = SshHelmUninstallArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            namespace: None,
            dry_run: None,
            keep_history: None,
            no_hooks: Some(true),
            wait: Some(true),
            cascade: Some("foreground".to_string()),
            timeout: Some("5m".to_string()),
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmUninstallTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--no-hooks"), "cmd={cmd}");
        assert!(cmd.contains("--wait"), "cmd={cmd}");
        assert!(cmd.contains("--cascade 'foreground'"), "cmd={cmd}");
        assert!(cmd.contains("--timeout '5m'"), "cmd={cmd}");
    }

    #[test]
    fn test_build_command_cascade_invalid_rejected() {
        let args = SshHelmUninstallArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            namespace: None,
            dry_run: None,
            keep_history: None,
            no_hooks: None,
            wait: None,
            cascade: Some("--evil".to_string()),
            timeout: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let result = HelmUninstallTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
