//! SSH Helm Rollback Tool Handler
//!
//! Rolls back a Helm release to a previous revision on a remote host via SSH.
//! Auto-detects helm binary.

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
pub struct SshHelmRollbackArgs {
    host: String,
    release: String,
    #[serde(default)]
    revision: Option<u64>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    dry_run: Option<String>,
    #[serde(default)]
    wait: Option<bool>,
    #[serde(default)]
    cleanup_on_fail: Option<bool>,
    #[serde(default)]
    wait_for_jobs: Option<bool>,
    #[serde(default)]
    timeout: Option<String>,
    #[serde(default)]
    force: Option<bool>,
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

impl_common_args!(SshHelmRollbackArgs);

#[mcp_standard_tool(
    name = "ssh_helm_rollback",
    group = "kubernetes",
    annotation = "destructive"
)]
pub struct HelmRollbackTool;

impl StandardTool for HelmRollbackTool {
    type Args = SshHelmRollbackArgs;

    const NAME: &'static str = "ssh_helm_rollback";

    const DESCRIPTION: &'static str = "Rollback a Helm release to a previous revision on a remote host. Use ssh_helm_history \
        first to find the target revision number. Supports dry-run to preview the rollback \
        safely. Omit revision to roll back to the immediately previous version. Auto-detects \
        helm binary.";

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
            "revision": {
                "type": "integer",
                "description": "Target revision, default: previous"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (default: current context namespace)"
            },
            "dry_run": {
                "type": "string",
                "enum": ["none", "client", "server"],
                "description": "Dry-run mode: none (actually apply), client (local validation), server (server-side validation)"
            },
            "wait": {
                "type": "boolean",
                "description": "Wait for resources to be ready before marking rollback as successful"
            },
            "cleanup_on_fail": {
                "type": "boolean",
                "description": "Allow deletion of new resources created during rollback when it fails"
            },
            "wait_for_jobs": {
                "type": "boolean",
                "description": "Wait for Jobs to complete before marking rollback as successful"
            },
            "timeout": {
                "type": "string",
                "description": "Helm --timeout: Go duration to wait for Kubernetes operations (e.g. '5m0s', '10m')"
            },
            "force": {
                "type": "boolean",
                "description": "Force resource update through delete/recreate if needed"
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

    fn build_command(args: &SshHelmRollbackArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(HelmCommandBuilder::build_rollback_command(
            args.helm_bin.as_deref(),
            args.kubeconfig.as_deref(),
            &args.release,
            args.revision,
            args.namespace.as_deref(),
            args.dry_run.as_deref(),
            args.wait.unwrap_or(false),
            args.cleanup_on_fail.unwrap_or(false),
            args.wait_for_jobs.unwrap_or(false),
            args.timeout.as_deref(),
            args.force.unwrap_or(false),
        ))
    }

    /// Mirror of `ssh_helm_upgrade::enrich`: surface the rollback as
    /// a synthetic `phase=start` event then one log per helm status
    /// field. Errors surface at `LogLevel::Error`.
    async fn enrich(
        result: ToolCallResult,
        args: &Self::Args,
        output: &str,
        ctx: &ToolContext,
    ) -> Result<ToolCallResult> {
        let Some(logger) = ctx.mcp_logger.as_ref() else {
            return Ok(result);
        };
        logger.log(
            LogLevel::Info,
            "ssh_helm_rollback",
            serde_json::json!({
                "phase": "start",
                "release": args.release,
                "revision": args.revision,
                "namespace": args.namespace.clone().unwrap_or_else(|| "default".to_string()),
                "dry_run": args.dry_run.is_some(),
            }),
        );
        for line in output.lines() {
            let trimmed = line.trim_start();
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
                        "ssh_helm_rollback",
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
                    "ssh_helm_rollback",
                    serde_json::json!({"phase": "error", "line": trimmed}),
                );
            }
        }
        Ok(result)
    }
}

/// Handler for the `ssh_helm_rollback` tool.
pub type SshHelmRollbackHandler = StandardToolHandler<HelmRollbackTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmRollbackHandler::new();
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
        let handler = SshHelmRollbackHandler::new();
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
        let handler = SshHelmRollbackHandler::new();
        assert_eq!(handler.name(), "ssh_helm_rollback");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_rollback");

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
            "revision": 3,
            "namespace": "production",
            "dry_run": "server",
            "wait": true,
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });

        let args: SshHelmRollbackArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "my-app");
        assert_eq!(args.revision, Some(3));
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.dry_run, Some("server".to_string()));
        assert_eq!(args.wait, Some(true));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "release": "my-app"});

        let args: SshHelmRollbackArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "my-app");
        assert!(args.revision.is_none());
        assert!(args.namespace.is_none());
        assert!(args.dry_run.is_none());
        assert!(args.wait.is_none());
        assert!(args.helm_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHelmRollbackHandler::new();
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
        let handler = SshHelmRollbackHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("revision"));
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("dry_run"));
        assert!(properties.contains_key("wait"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "release": "my-app"});
        let args: SshHelmRollbackArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmRollbackArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmRollbackHandler::new();
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
        let args = SshHelmRollbackArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            revision: None,
            namespace: None,
            dry_run: None,
            wait: None,
            cleanup_on_fail: None,
            wait_for_jobs: None,
            timeout: None,
            force: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmRollbackTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm rollback"));
        assert!(cmd.contains("'my-app'"));
    }

    #[test]
    fn test_build_command_with_revision() {
        let args = SshHelmRollbackArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            revision: Some(3),
            namespace: None,
            dry_run: None,
            wait: None,
            cleanup_on_fail: None,
            wait_for_jobs: None,
            timeout: None,
            force: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmRollbackTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains(" 3"));
    }

    #[test]
    fn test_build_command_all_opts() {
        let args = SshHelmRollbackArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            revision: Some(5),
            namespace: Some("production".to_string()),
            dry_run: Some("server".to_string()),
            wait: Some(true),
            cleanup_on_fail: None,
            wait_for_jobs: None,
            timeout: None,
            force: None,
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmRollbackTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-n 'production'"));
        assert!(cmd.contains("--dry-run='server'"));
        assert!(cmd.contains("--wait"));
    }

    #[test]
    fn test_build_command_cleanup_wait_for_jobs_force_timeout() {
        let args = SshHelmRollbackArgs {
            host: "server1".to_string(),
            release: "my-app".to_string(),
            revision: None,
            namespace: None,
            dry_run: None,
            wait: None,
            cleanup_on_fail: Some(true),
            wait_for_jobs: Some(true),
            timeout: Some("10m".to_string()),
            force: Some(true),
            helm_bin: Some("helm".to_string()),
            kubeconfig: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = HelmRollbackTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--cleanup-on-fail"), "cmd={cmd}");
        assert!(cmd.contains("--wait-for-jobs"), "cmd={cmd}");
        assert!(cmd.contains("--timeout '10m'"), "cmd={cmd}");
        assert!(cmd.contains("--force"), "cmd={cmd}");
    }
}
