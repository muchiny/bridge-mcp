//! SSH Helm Dependency Tool Handler
//!
//! Manages Helm chart dependencies on a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::HelmCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshHelmDependencyArgs {
    host: String,
    subcommand: String,
    chart_path: String,
    #[serde(default)]
    skip_refresh: Option<bool>,
    #[serde(default)]
    verify: Option<bool>,
    #[serde(default)]
    helm_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshHelmDependencyArgs);

#[mcp_standard_tool(
    name = "ssh_helm_dependency",
    group = "kubernetes",
    annotation = "mutating_idempotent"
)]
pub struct HelmDependencyTool;

impl StandardTool for HelmDependencyTool {
    type Args = SshHelmDependencyArgs;

    const NAME: &'static str = "ssh_helm_dependency";

    const DESCRIPTION: &'static str = "Manage Helm chart dependencies on a remote host. \
        subcommand: build | update | list. \
        Use build to rebuild the charts/ directory from Chart.lock. \
        Use update to update and rebuild charts/ from Chart.yaml. \
        Use list to list all chart dependencies. Auto-detects helm binary.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "subcommand": {
                "type": "string",
                "enum": ["build", "update", "list"],
                "description": "Dependency action: build | update | list"
            },
            "chart_path": {
                "type": "string",
                "description": "Path to the chart directory on the remote host"
            },
            "skip_refresh": {
                "type": "boolean",
                "description": "Do not refresh the local repository cache (build/update only)"
            },
            "verify": {
                "type": "boolean",
                "description": "Verify the packages against signatures"
            },
            "helm_bin": {
                "type": "string",
                "description": "Custom helm binary path (default: auto-detect)"
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
        "required": ["host", "subcommand", "chart_path"]
    }"#;

    fn build_command(args: &SshHelmDependencyArgs, _host_config: &HostConfig) -> Result<String> {
        HelmCommandBuilder::validate_dependency_subcommand(&args.subcommand)?;
        Ok(HelmCommandBuilder::build_dependency_command(
            args.helm_bin.as_deref(),
            &args.subcommand,
            &args.chart_path,
            args.skip_refresh.unwrap_or(false),
            args.verify.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_helm_dependency` tool.
pub type SshHelmDependencyHandler = StandardToolHandler<HelmDependencyTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmDependencyHandler::new();
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
        let handler = SshHelmDependencyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "subcommand": "build", "chart_path": "/path"})),
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
        let handler = SshHelmDependencyHandler::new();
        assert_eq!(handler.name(), "ssh_helm_dependency");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_dependency");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("subcommand")));
        assert!(required.contains(&json!("chart_path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json_val = json!({
            "host": "server1",
            "subcommand": "build",
            "chart_path": "/opt/charts/myapp",
            "skip_refresh": true,
            "verify": false,
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshHelmDependencyArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.subcommand, "build");
        assert_eq!(args.chart_path, "/opt/charts/myapp");
        assert_eq!(args.skip_refresh, Some(true));
        assert_eq!(args.verify, Some(false));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json_val =
            json!({"host": "server1", "subcommand": "list", "chart_path": "/opt/charts"});
        let args: SshHelmDependencyArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.subcommand, "list");
        assert_eq!(args.chart_path, "/opt/charts");
        assert!(args.skip_refresh.is_none());
        assert!(args.verify.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmDependencyHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("skip_refresh"));
        assert!(properties.contains_key("verify"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json_val =
            json!({"host": "server1", "subcommand": "build", "chart_path": "/opt/charts"});
        let args: SshHelmDependencyArgs = serde_json::from_value(json_val).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmDependencyArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmDependencyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "subcommand": "build", "chart_path": "/path"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

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
    fn test_build_command_build() {
        let args = SshHelmDependencyArgs {
            host: "server1".to_string(),
            subcommand: "build".to_string(),
            chart_path: "/opt/charts/myapp".to_string(),
            skip_refresh: None,
            verify: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmDependencyTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm dependency 'build' '/opt/charts/myapp'"));
    }

    #[test]
    fn test_build_command_with_skip_refresh() {
        let args = SshHelmDependencyArgs {
            host: "server1".to_string(),
            subcommand: "update".to_string(),
            chart_path: "/opt/charts/myapp".to_string(),
            skip_refresh: Some(true),
            verify: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmDependencyTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--skip-refresh"));
    }

    #[test]
    fn test_build_command_invalid_subcommand() {
        let args = SshHelmDependencyArgs {
            host: "server1".to_string(),
            subcommand: "invalid".to_string(),
            chart_path: "/opt/charts/myapp".to_string(),
            skip_refresh: None,
            verify: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = HelmDependencyTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
