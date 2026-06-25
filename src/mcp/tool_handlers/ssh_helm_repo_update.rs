//! SSH Helm Repo Update Tool Handler
//!
//! Updates Helm chart repositories on a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::HelmCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshHelmRepoUpdateArgs {
    host: String,
    #[serde(default)]
    repos: Option<Vec<String>>,
    #[serde(default)]
    helm_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshHelmRepoUpdateArgs);

#[mcp_standard_tool(
    name = "ssh_helm_repo_update",
    group = "kubernetes",
    annotation = "mutating_idempotent"
)]
pub struct HelmRepoUpdateTool;

impl StandardTool for HelmRepoUpdateTool {
    type Args = SshHelmRepoUpdateArgs;

    const NAME: &'static str = "ssh_helm_repo_update";

    const DESCRIPTION: &'static str = "Update Helm chart repository indexes on a remote host. Refreshes the local \
        cache of chart information from all configured repos (or specific repos if named). \
        Run this before searching or installing to get the latest chart versions. \
        Auto-detects helm binary.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "repos": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific repo names to update (default: update all repos)"
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
        "required": ["host"]
    }"#;

    fn build_command(args: &SshHelmRepoUpdateArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(repos) = args.repos.as_deref() {
            for r in repos {
                HelmCommandBuilder::validate_repo_name(r)?;
            }
        }
        Ok(HelmCommandBuilder::build_repo_update_command(
            args.helm_bin.as_deref(),
            args.repos.as_deref(),
        ))
    }
}

/// Handler for the `ssh_helm_repo_update` tool.
pub type SshHelmRepoUpdateHandler = StandardToolHandler<HelmRepoUpdateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmRepoUpdateHandler::new();
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
        let handler = SshHelmRepoUpdateHandler::new();
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
        let handler = SshHelmRepoUpdateHandler::new();
        assert_eq!(handler.name(), "ssh_helm_repo_update");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_repo_update");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json_val = json!({
            "host": "server1",
            "repos": ["stable", "bitnami"],
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshHelmRepoUpdateArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(
            args.repos,
            Some(vec!["stable".to_string(), "bitnami".to_string()])
        );
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json_val = json!({"host": "server1"});
        let args: SshHelmRepoUpdateArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.repos.is_none());
        assert!(args.helm_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmRepoUpdateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("repos"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json_val = json!({"host": "server1"});
        let args: SshHelmRepoUpdateArgs = serde_json::from_value(json_val).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmRepoUpdateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmRepoUpdateHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
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
    fn test_build_command_all_repos() {
        let args = SshHelmRepoUpdateArgs {
            host: "server1".to_string(),
            repos: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmRepoUpdateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm repo update"));
    }

    #[test]
    fn test_build_command_specific_repos() {
        let args = SshHelmRepoUpdateArgs {
            host: "server1".to_string(),
            repos: Some(vec!["stable".to_string(), "bitnami".to_string()]),
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmRepoUpdateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm repo update"));
        assert!(cmd.contains("'stable'"));
        assert!(cmd.contains("'bitnami'"));
    }
}
