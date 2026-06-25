//! SSH Helm Lint Tool Handler
//!
//! Lints Helm charts on a remote host via SSH.

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::HelmCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshHelmLintArgs {
    host: String,
    chart_path: String,
    #[serde(default)]
    strict: Option<bool>,
    #[serde(default)]
    values_files: Option<Vec<String>>,
    #[serde(default)]
    set_values: Option<HashMap<String, String>>,
    #[serde(default)]
    quiet: Option<bool>,
    #[serde(default)]
    helm_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshHelmLintArgs);

#[mcp_standard_tool(name = "ssh_helm_lint", group = "kubernetes", annotation = "read_only")]
pub struct HelmLintTool;

impl StandardTool for HelmLintTool {
    type Args = SshHelmLintArgs;

    const NAME: &'static str = "ssh_helm_lint";

    const DESCRIPTION: &'static str = "Lint a Helm chart on a remote host. Validates chart structure, \
        templates, and values. Use strict mode to treat warnings as errors. \
        Supply values files or --set overrides to lint with specific configuration. \
        Auto-detects helm binary.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "chart_path": {
                "type": "string",
                "description": "Path to the chart directory or archive on the remote host"
            },
            "strict": {
                "type": "boolean",
                "description": "Fail on lint warnings (not just errors)"
            },
            "values_files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Value files to use during linting (-f flag for each)"
            },
            "set_values": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": "Key-value pairs to pass as --set overrides"
            },
            "quiet": {
                "type": "boolean",
                "description": "Print only warnings and errors"
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
        "required": ["host", "chart_path"]
    }"#;

    fn build_command(args: &SshHelmLintArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(HelmCommandBuilder::build_lint_command(
            args.helm_bin.as_deref(),
            &args.chart_path,
            args.strict.unwrap_or(false),
            args.values_files.as_deref(),
            args.set_values.as_ref(),
            args.quiet.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_helm_lint` tool.
pub type SshHelmLintHandler = StandardToolHandler<HelmLintTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmLintHandler::new();
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
        let handler = SshHelmLintHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "chart_path": "/path/to/chart"})),
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
        let handler = SshHelmLintHandler::new();
        assert_eq!(handler.name(), "ssh_helm_lint");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_lint");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("chart_path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json_val = json!({
            "host": "server1",
            "chart_path": "/opt/charts/myapp",
            "strict": true,
            "values_files": ["/opt/values.yaml"],
            "set_values": {"key": "value"},
            "quiet": false,
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshHelmLintArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.chart_path, "/opt/charts/myapp");
        assert_eq!(args.strict, Some(true));
        assert_eq!(
            args.values_files,
            Some(vec!["/opt/values.yaml".to_string()])
        );
        assert!(args.set_values.is_some());
        assert_eq!(args.quiet, Some(false));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json_val = json!({"host": "server1", "chart_path": "/opt/charts/myapp"});
        let args: SshHelmLintArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.chart_path, "/opt/charts/myapp");
        assert!(args.strict.is_none());
        assert!(args.values_files.is_none());
        assert!(args.set_values.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmLintHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("strict"));
        assert!(properties.contains_key("values_files"));
        assert!(properties.contains_key("set_values"));
        assert!(properties.contains_key("quiet"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json_val = json!({"host": "server1", "chart_path": "/opt/charts/myapp"});
        let args: SshHelmLintArgs = serde_json::from_value(json_val).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmLintArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmLintHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "chart_path": "/path"})), &ctx)
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
        let args = SshHelmLintArgs {
            host: "server1".to_string(),
            chart_path: "/opt/charts/myapp".to_string(),
            strict: None,
            values_files: None,
            set_values: None,
            quiet: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmLintTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm lint '/opt/charts/myapp'"));
    }

    #[test]
    fn test_build_command_with_strict() {
        let args = SshHelmLintArgs {
            host: "server1".to_string(),
            chart_path: "/opt/charts/myapp".to_string(),
            strict: Some(true),
            values_files: Some(vec!["/opt/values.yaml".to_string()]),
            set_values: None,
            quiet: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmLintTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--strict"));
        assert!(cmd.contains("-f '/opt/values.yaml'"));
    }
}
