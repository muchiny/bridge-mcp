//! SSH Helm Pull Tool Handler
//!
//! Downloads Helm charts to a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::HelmCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshHelmPullArgs {
    host: String,
    chart: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    untar: Option<bool>,
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    devel: Option<bool>,
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

impl_common_args!(SshHelmPullArgs);

#[mcp_standard_tool(
    name = "ssh_helm_pull",
    group = "kubernetes",
    annotation = "mutating_idempotent"
)]
pub struct HelmPullTool;

impl StandardTool for HelmPullTool {
    type Args = SshHelmPullArgs;

    const NAME: &'static str = "ssh_helm_pull";

    const DESCRIPTION: &'static str = "Download a Helm chart to a remote host. \
        Pulls the chart archive (.tgz) from a repository and saves it locally on the host. \
        Use untar to extract after download. Use destination to specify download directory. \
        Auto-detects helm binary.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "chart": {
                "type": "string",
                "description": "Chart name (e.g. bitnami/nginx) or OCI reference (oci://registry/chart)"
            },
            "version": {
                "type": "string",
                "description": "Chart version to pull (default: latest)"
            },
            "repo": {
                "type": "string",
                "description": "Chart repository URL"
            },
            "untar": {
                "type": "boolean",
                "description": "Extract the chart after downloading"
            },
            "destination": {
                "type": "string",
                "description": "Directory to save the chart (default: current directory)"
            },
            "devel": {
                "type": "boolean",
                "description": "Include development versions (alpha, beta, rc)"
            },
            "verify": {
                "type": "boolean",
                "description": "Verify the chart before pulling"
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
        "required": ["host", "chart"]
    }"#;

    fn build_command(args: &SshHelmPullArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(r) = args.repo.as_deref() {
            HelmCommandBuilder::validate_repo_url(r)?;
        }
        Ok(HelmCommandBuilder::build_pull_command(
            args.helm_bin.as_deref(),
            &args.chart,
            args.version.as_deref(),
            args.repo.as_deref(),
            args.untar.unwrap_or(false),
            args.destination.as_deref(),
            args.devel.unwrap_or(false),
            args.verify.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_helm_pull` tool.
pub type SshHelmPullHandler = StandardToolHandler<HelmPullTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmPullHandler::new();
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
        let handler = SshHelmPullHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "chart": "bitnami/nginx"})),
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
        let handler = SshHelmPullHandler::new();
        assert_eq!(handler.name(), "ssh_helm_pull");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_pull");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("chart")));
    }

    #[test]
    fn test_args_deserialization() {
        let json_val = json!({
            "host": "server1",
            "chart": "bitnami/nginx",
            "version": "1.0.0",
            "repo": "https://charts.bitnami.com/bitnami",
            "untar": true,
            "destination": "/tmp/charts",
            "devel": false,
            "verify": true,
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshHelmPullArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.chart, "bitnami/nginx");
        assert_eq!(args.version, Some("1.0.0".to_string()));
        assert_eq!(
            args.repo,
            Some("https://charts.bitnami.com/bitnami".to_string())
        );
        assert_eq!(args.untar, Some(true));
        assert_eq!(args.destination, Some("/tmp/charts".to_string()));
        assert_eq!(args.devel, Some(false));
        assert_eq!(args.verify, Some(true));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json_val = json!({"host": "server1", "chart": "bitnami/nginx"});
        let args: SshHelmPullArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.chart, "bitnami/nginx");
        assert!(args.version.is_none());
        assert!(args.repo.is_none());
        assert!(args.untar.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmPullHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("version"));
        assert!(properties.contains_key("repo"));
        assert!(properties.contains_key("untar"));
        assert!(properties.contains_key("destination"));
        assert!(properties.contains_key("devel"));
        assert!(properties.contains_key("verify"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json_val = json!({"host": "server1", "chart": "bitnami/nginx"});
        let args: SshHelmPullArgs = serde_json::from_value(json_val).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmPullArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmPullHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "chart": "nginx"})), &ctx)
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
    fn test_build_command_basic() {
        let args = SshHelmPullArgs {
            host: "server1".to_string(),
            chart: "bitnami/nginx".to_string(),
            version: None,
            repo: None,
            untar: None,
            destination: None,
            devel: None,
            verify: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmPullTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm pull 'bitnami/nginx'"));
    }

    #[test]
    fn test_build_command_with_options() {
        let args = SshHelmPullArgs {
            host: "server1".to_string(),
            chart: "bitnami/nginx".to_string(),
            version: Some("1.0.0".to_string()),
            repo: None,
            untar: Some(true),
            destination: Some("/tmp/charts".to_string()),
            devel: None,
            verify: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmPullTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--version '1.0.0'"));
        assert!(cmd.contains("--untar"));
        assert!(cmd.contains("--destination '/tmp/charts'"));
    }

    #[test]
    fn test_build_command_rejects_bad_repo_url() {
        let args = SshHelmPullArgs {
            host: "server1".to_string(),
            chart: "nginx".to_string(),
            version: None,
            repo: Some("http://x.com|evil".to_string()),
            untar: None,
            destination: None,
            devel: None,
            verify: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = HelmPullTool::build_command(&args, &test_host_config());
        assert!(
            result.is_err(),
            "expected error for repo URL with shell metachar"
        );
    }
}
