//! SSH Helm Repo List Tool Handler
//!
//! Lists configured Helm chart repositories on a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::HelmCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshHelmRepoListArgs {
    host: String,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    helm_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshHelmRepoListArgs);

#[mcp_standard_tool(
    name = "ssh_helm_repo_list",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct HelmRepoListTool;

impl StandardTool for HelmRepoListTool {
    type Args = SshHelmRepoListArgs;

    const NAME: &'static str = "ssh_helm_repo_list";

    const DESCRIPTION: &'static str = "List configured Helm chart repositories on a remote host. \
        Shows name and URL for each configured repo. Run ssh_helm_repo_update afterwards \
        to refresh the index. Output as table, JSON, or YAML. Auto-detects helm binary.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "output": {
                "type": "string",
                "enum": ["table", "json", "yaml"],
                "description": "Output format (default: table)"
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

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshHelmRepoListArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(out) = args.output.as_deref() {
            HelmCommandBuilder::validate_helm_output(out)?;
        }
        Ok(HelmCommandBuilder::build_repo_list_command(
            args.helm_bin.as_deref(),
            args.output.as_deref(),
        ))
    }
}

/// Handler for the `ssh_helm_repo_list` tool.
pub type SshHelmRepoListHandler = StandardToolHandler<HelmRepoListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmRepoListHandler::new();
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
        let handler = SshHelmRepoListHandler::new();
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
        let handler = SshHelmRepoListHandler::new();
        assert_eq!(handler.name(), "ssh_helm_repo_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_repo_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json_val = json!({
            "host": "server1",
            "output": "json",
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshHelmRepoListArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.output, Some("json".to_string()));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json_val = json!({"host": "server1"});
        let args: SshHelmRepoListArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.output.is_none());
        assert!(args.helm_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmRepoListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("output"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json_val = json!({"host": "server1"});
        let args: SshHelmRepoListArgs = serde_json::from_value(json_val).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmRepoListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmRepoListHandler::new();
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
    fn test_build_command_defaults() {
        let args = SshHelmRepoListArgs {
            host: "server1".to_string(),
            output: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmRepoListTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm repo list"));
    }

    #[test]
    fn test_build_command_with_output() {
        let args = SshHelmRepoListArgs {
            host: "server1".to_string(),
            output: Some("json".to_string()),
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmRepoListTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-o 'json'"));
    }

    #[test]
    fn test_build_command_invalid_output() {
        let args = SshHelmRepoListArgs {
            host: "server1".to_string(),
            output: Some("xml".to_string()),
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = HelmRepoListTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
