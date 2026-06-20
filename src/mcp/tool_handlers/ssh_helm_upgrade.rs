//! SSH Helm Upgrade Tool Handler
//!
//! Upgrades a Helm release on a remote host via SSH.
//! Supports set values, values files, dry-run, wait, and install-if-not-exists.
//! Auto-detects helm binary.

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{HelmCommandBuilder, KubernetesCommandBuilder};
use crate::error::Result;
use crate::mcp::protocol::LogLevel;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshHelmUpgradeArgs {
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
    dry_run: Option<String>,
    #[serde(default)]
    wait: Option<bool>,
    #[serde(default)]
    timeout: Option<String>,
    #[serde(default)]
    install: Option<bool>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    create_namespace: Option<bool>,
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

impl_common_args!(SshHelmUpgradeArgs);

#[mcp_standard_tool(
    name = "ssh_helm_upgrade",
    group = "kubernetes",
    annotation = "mutating"
)]
pub struct HelmUpgradeTool;

impl StandardTool for HelmUpgradeTool {
    type Args = SshHelmUpgradeArgs;

    const NAME: &'static str = "ssh_helm_upgrade";

    const DESCRIPTION: &'static str = "Upgrade an existing Helm release on a remote host. For new installations, use \
        ssh_helm_install or set install=true to install if not present. Supports custom \
        values, dry-run, wait for readiness, and version constraints. Use ssh_helm_history to \
        check revision history after upgrade. Auto-detects helm binary.";

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
            "dry_run": {
                "type": "string",
                "enum": ["none", "client", "server"],
                "description": "Dry-run mode: none (actually apply), client (local validation), server (server-side validation)"
            },
            "wait": {
                "type": "boolean",
                "description": "Wait for resources to be ready before marking release as successful"
            },
            "timeout": {
                "type": "string",
                "description": "Helm --timeout: Go duration Helm waits for Kubernetes operations to complete (e.g. '5m0s', '10m'). Only meaningful when wait=true. Distinct from timeout_seconds which is the SSH/bridge-level connection timeout."
            },
            "install": {
                "type": "boolean",
                "description": "Install if release doesn't exist (--install flag)"
            },
            "version": {
                "type": "string",
                "description": "Chart version constraint"
            },
            "create_namespace": {
                "type": "boolean",
                "description": "Create namespace if it doesn't exist"
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
                "description": "SSH/bridge-level connection timeout in seconds (default: from config). Controls how long the bridge waits for the SSH command to complete, not how long Helm waits for Kubernetes. Use 'timeout' for Helm's own operation timeout.",
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

    fn build_command(args: &SshHelmUpgradeArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(HelmCommandBuilder::build_upgrade_command(
            args.helm_bin.as_deref(),
            args.kubeconfig.as_deref(),
            &args.release,
            &args.chart,
            args.namespace.as_deref(),
            args.set_values.as_ref(),
            args.values_files.as_deref(),
            args.dry_run.as_deref(),
            args.wait.unwrap_or(false),
            args.timeout.as_deref(),
            args.install.unwrap_or(false),
            args.version.as_deref(),
            args.create_namespace.unwrap_or(false),
        ))
    }

    /// Parse the helm upgrade output and emit one structured log per
    /// key field (Release, Status, Revision, Namespace, Last Deployed,
    /// Notes). The raw result is returned unchanged — this hook only
    /// adds observability for clients that subscribed to
    /// `notifications/message`.
    async fn enrich(
        result: ToolCallResult,
        args: &Self::Args,
        output: &str,
        ctx: &ToolContext,
    ) -> Result<ToolCallResult> {
        let Some(logger) = ctx.mcp_logger.as_ref() else {
            return Ok(result);
        };
        // Header event so the client knows the upgrade started even if
        // the command produced no parseable status lines.
        logger.log(
            LogLevel::Info,
            "ssh_helm_upgrade",
            serde_json::json!({
                "phase": "start",
                "release": args.release,
                "chart": args.chart,
                "namespace": args.namespace.clone().unwrap_or_else(|| "default".to_string()),
                "dry_run": args.dry_run.is_some(),
            }),
        );
        for line in output.lines() {
            let trimmed = line.trim_start();
            // helm-upgrade prints `KEY: value` lines for status/version/etc.
            if let Some((key, value)) = trimmed.split_once(": ") {
                let lower = key.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "release"
                        | "status"
                        | "revision"
                        | "namespace"
                        | "last deployed"
                        | "chart"
                        | "version"
                ) {
                    logger.log(
                        LogLevel::Info,
                        "ssh_helm_upgrade",
                        serde_json::json!({
                            "phase": "field",
                            "key": lower,
                            "value": value.trim(),
                        }),
                    );
                }
            } else if trimmed.starts_with("Error:") || trimmed.starts_with("error:") {
                logger.log(
                    LogLevel::Error,
                    "ssh_helm_upgrade",
                    serde_json::json!({"phase": "error", "line": trimmed}),
                );
            }
        }
        Ok(result)
    }
}

/// Handler for the `ssh_helm_upgrade` tool.
pub type SshHelmUpgradeHandler = StandardToolHandler<HelmUpgradeTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmUpgradeHandler::new();
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
        let handler = SshHelmUpgradeHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "release": "my-app",
                    "chart": "stable/nginx"
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
        let handler = SshHelmUpgradeHandler::new();
        assert_eq!(handler.name(), "ssh_helm_upgrade");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_upgrade");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("release")));
        assert!(required.contains(&json!("chart")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "release": "my-app",
            "chart": "stable/nginx",
            "namespace": "production",
            "set_values": {"replicaCount": "3", "image.tag": "v2.0"},
            "values_files": ["/tmp/values.yaml", "/tmp/overrides.yaml"],
            "dry_run": "server",
            "wait": true,
            "timeout": "5m0s",
            "install": true,
            "version": "1.2.3",
            "create_namespace": true,
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 120,
            "max_output": 10000
        });

        let args: SshHelmUpgradeArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "my-app");
        assert_eq!(args.chart, "stable/nginx");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert!(args.set_values.is_some());
        let sv = args.set_values.unwrap();
        assert_eq!(sv.get("replicaCount"), Some(&"3".to_string()));
        assert_eq!(sv.get("image.tag"), Some(&"v2.0".to_string()));
        assert_eq!(
            args.values_files,
            Some(vec![
                "/tmp/values.yaml".to_string(),
                "/tmp/overrides.yaml".to_string()
            ])
        );
        assert_eq!(args.dry_run, Some("server".to_string()));
        assert_eq!(args.wait, Some(true));
        assert_eq!(args.timeout, Some("5m0s".to_string()));
        assert_eq!(args.install, Some(true));
        assert_eq!(args.version, Some("1.2.3".to_string()));
        assert_eq!(args.create_namespace, Some(true));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "release": "my-app",
            "chart": "stable/nginx"
        });

        let args: SshHelmUpgradeArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "my-app");
        assert_eq!(args.chart, "stable/nginx");
        assert!(args.namespace.is_none());
        assert!(args.set_values.is_none());
        assert!(args.values_files.is_none());
        assert!(args.dry_run.is_none());
        assert!(args.wait.is_none());
        assert!(args.timeout.is_none());
        assert!(args.install.is_none());
        assert!(args.version.is_none());
        assert!(args.create_namespace.is_none());
        assert!(args.helm_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHelmUpgradeHandler::new();
        let ctx = create_test_context();

        // Missing chart field
        let result = handler
            .execute(Some(json!({"host": "server1", "release": "my-app"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmUpgradeHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("set_values"));
        assert!(properties.contains_key("values_files"));
        assert!(properties.contains_key("dry_run"));
        assert!(properties.contains_key("wait"));
        assert!(properties.contains_key("timeout"));
        assert!(properties.contains_key("install"));
        assert!(properties.contains_key("version"));
        assert!(properties.contains_key("create_namespace"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "release": "my-app", "chart": "stable/nginx"});
        let args: SshHelmUpgradeArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmUpgradeArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmUpgradeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "release": "my-app", "chart": "stable/nginx"})),
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
        let args = SshHelmUpgradeArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            chart: "stable/nginx".to_string(),
            namespace: None,
            set_values: None,
            values_files: None,
            dry_run: None,
            wait: None,
            timeout: None,
            install: None,
            version: None,
            create_namespace: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmUpgradeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm upgrade"));
        assert!(cmd.contains("'my-app'"));
        assert!(cmd.contains("'stable/nginx'"));
    }

    #[test]
    fn test_build_command_with_set_values() {
        let mut set_values = HashMap::new();
        set_values.insert("replicaCount".to_string(), "3".to_string());

        let args = SshHelmUpgradeArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            chart: "stable/nginx".to_string(),
            namespace: None,
            set_values: Some(set_values),
            values_files: None,
            dry_run: None,
            wait: None,
            timeout: None,
            install: None,
            version: None,
            create_namespace: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmUpgradeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--set 'replicaCount'='3'"));
    }

    #[test]
    fn test_build_command_dry_run() {
        let args = SshHelmUpgradeArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            chart: "stable/nginx".to_string(),
            namespace: None,
            set_values: None,
            values_files: None,
            dry_run: Some("server".to_string()),
            wait: None,
            timeout: None,
            install: None,
            version: None,
            create_namespace: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmUpgradeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--dry-run='server'"));
    }

    #[test]
    fn test_build_command_all_opts() {
        let mut set_values = HashMap::new();
        set_values.insert("image.tag".to_string(), "v2.0".to_string());

        let args = SshHelmUpgradeArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            chart: "stable/nginx".to_string(),
            namespace: Some("production".to_string()),
            set_values: Some(set_values),
            values_files: Some(vec!["/tmp/values.yaml".to_string()]),
            dry_run: Some("client".to_string()),
            wait: Some(true),
            timeout: Some("5m0s".to_string()),
            install: Some(true),
            version: Some("1.2.3".to_string()),
            create_namespace: Some(true),
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmUpgradeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-n 'production'"));
        assert!(cmd.contains("--set 'image.tag'='v2.0'"));
        assert!(cmd.contains("-f '/tmp/values.yaml'"));
        assert!(cmd.contains("--dry-run='client'"));
        assert!(cmd.contains("--wait"));
        assert!(cmd.contains("--timeout '5m0s'"));
        assert!(cmd.contains("--install"));
        assert!(cmd.contains("--version '1.2.3'"));
        assert!(cmd.contains("--create-namespace"));
    }
}
