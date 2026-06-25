//! SSH Helm Diff Tool Handler
//!
//! Shows diff of Helm releases using the helm-diff plugin on a remote host via SSH.

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::HelmCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshHelmDiffArgs {
    host: String,
    subcommand: String,
    release: String,
    #[serde(default)]
    chart: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    values_files: Option<Vec<String>>,
    #[serde(default)]
    set_values: Option<HashMap<String, String>>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    detailed_exitcode: Option<bool>,
    #[serde(default)]
    helm_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshHelmDiffArgs);

#[mcp_standard_tool(name = "ssh_helm_diff", group = "kubernetes", annotation = "read_only")]
pub struct HelmDiffTool;

impl StandardTool for HelmDiffTool {
    type Args = SshHelmDiffArgs;

    const NAME: &'static str = "ssh_helm_diff";

    const DESCRIPTION: &'static str = "Show diff of Helm changes using the helm-diff plugin on a remote host. \
        Requires the helm-diff plugin to be installed (helm plugin install https://github.com/databus23/helm-diff). \
        subcommand: upgrade | rollback | release | revision. \
        Use upgrade to preview changes before helm upgrade. Use rollback to see what a rollback would do. \
        Auto-detects helm binary. Exits with code 4 if helm-diff plugin is not installed.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "subcommand": {
                "type": "string",
                "enum": ["upgrade", "rollback", "release", "revision"],
                "description": "Diff subcommand: upgrade | rollback | release | revision"
            },
            "release": {
                "type": "string",
                "description": "Helm release name"
            },
            "chart": {
                "type": "string",
                "description": "Chart name or path (required for upgrade subcommand)"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace"
            },
            "values_files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Value files to use during diff (-f flag for each)"
            },
            "set_values": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": "Key-value pairs to pass as --set overrides"
            },
            "version": {
                "type": "string",
                "description": "Chart version to diff against"
            },
            "detailed_exitcode": {
                "type": "boolean",
                "description": "Exit with 2 if there are changes, 0 if no changes"
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
        "required": ["host", "subcommand", "release"]
    }"#;

    fn build_command(args: &SshHelmDiffArgs, _host_config: &HostConfig) -> Result<String> {
        HelmCommandBuilder::validate_diff_subcommand(&args.subcommand)?;
        Ok(HelmCommandBuilder::build_diff_command(
            args.helm_bin.as_deref(),
            &args.subcommand,
            &args.release,
            args.chart.as_deref(),
            args.namespace.as_deref(),
            args.values_files.as_deref(),
            args.set_values.as_ref(),
            args.version.as_deref(),
            args.detailed_exitcode.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_helm_diff` tool.
pub type SshHelmDiffHandler = StandardToolHandler<HelmDiffTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmDiffHandler::new();
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
        let handler = SshHelmDiffHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "subcommand": "upgrade", "release": "myapp"})),
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
        let handler = SshHelmDiffHandler::new();
        assert_eq!(handler.name(), "ssh_helm_diff");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_diff");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("subcommand")));
        assert!(required.contains(&json!("release")));
    }

    #[test]
    fn test_args_deserialization() {
        let json_val = json!({
            "host": "server1",
            "subcommand": "upgrade",
            "release": "myapp",
            "chart": "bitnami/nginx",
            "namespace": "production",
            "values_files": ["/opt/values.yaml"],
            "set_values": {"key": "val"},
            "version": "1.0.0",
            "detailed_exitcode": true,
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshHelmDiffArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.subcommand, "upgrade");
        assert_eq!(args.release, "myapp");
        assert_eq!(args.chart, Some("bitnami/nginx".to_string()));
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(
            args.values_files,
            Some(vec!["/opt/values.yaml".to_string()])
        );
        assert!(args.set_values.is_some());
        assert_eq!(args.version, Some("1.0.0".to_string()));
        assert_eq!(args.detailed_exitcode, Some(true));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json_val = json!({"host": "server1", "subcommand": "release", "release": "myapp"});
        let args: SshHelmDiffArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.subcommand, "release");
        assert_eq!(args.release, "myapp");
        assert!(args.chart.is_none());
        assert!(args.namespace.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmDiffHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("chart"));
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("values_files"));
        assert!(properties.contains_key("set_values"));
        assert!(properties.contains_key("version"));
        assert!(properties.contains_key("detailed_exitcode"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json_val = json!({"host": "server1", "subcommand": "upgrade", "release": "myapp"});
        let args: SshHelmDiffArgs = serde_json::from_value(json_val).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmDiffArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmDiffHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "subcommand": "upgrade", "release": "myapp"})),
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
    fn test_build_command_basic() {
        let args = SshHelmDiffArgs {
            host: "server1".to_string(),
            subcommand: "upgrade".to_string(),
            release: "myapp".to_string(),
            chart: Some("bitnami/nginx".to_string()),
            namespace: None,
            values_files: None,
            set_values: None,
            version: None,
            detailed_exitcode: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmDiffTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm diff 'upgrade' 'myapp'"));
        assert!(cmd.contains("helm-diff plugin not installed"));
    }

    #[test]
    fn test_build_command_invalid_subcommand() {
        let args = SshHelmDiffArgs {
            host: "server1".to_string(),
            subcommand: "invalid".to_string(),
            release: "myapp".to_string(),
            chart: None,
            namespace: None,
            values_files: None,
            set_values: None,
            version: None,
            detailed_exitcode: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = HelmDiffTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
