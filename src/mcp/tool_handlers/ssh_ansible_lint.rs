//! SSH Ansible Lint Tool Handler
//!
//! Runs `ansible-lint` on a remote host to validate playbooks, roles,
//! and collections against best practices.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshAnsibleLintArgs {
    host: String,
    target: String,
    #[serde(default)]
    output_format: Option<String>,
    #[serde(default)]
    parseable: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshAnsibleLintArgs);

#[mcp_standard_tool(name = "ssh_ansible_lint", group = "ansible", annotation = "read_only")]
pub struct AnsibleLintTool;

impl StandardTool for AnsibleLintTool {
    type Args = SshAnsibleLintArgs;

    const NAME: &'static str = "ssh_ansible_lint";

    const DESCRIPTION: &'static str = "Run ansible-lint on a remote host to validate playbooks, \
        roles, or collections against best practices. Use output_format='json' or \
        output_format='sarif' to get structured output (maps to ansible-lint's --format flag); \
        use parseable=true for grep-friendly single-line output (equivalent to -p). \
        Exit codes: 0 = no violations; 2 = violations found; 3 = invalid configuration; \
        5 = no Ansible files matched; 8 = all violations auto-fixed.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "target": {
                "type": "string",
                "description": "Path to playbook, role directory, or collection to lint"
            },
            "output_format": {
                "type": "string",
                "description": "ansible-lint native output format (--format flag). Use 'json' or 'sarif' for structured output compatible with jq_filter. Use 'pep8' for grep-friendly single-line output (similar to parseable=true). Default: human-readable.",
                "enum": ["json", "codeclimate", "sarif", "pep8", "brief"]
            },
            "parseable": {
                "type": "boolean",
                "description": "Use parseable output format (one violation per line)"
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
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "target"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshAnsibleLintArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(AnsibleCommandBuilder::build_lint_command(
            &args.target,
            args.output_format.as_deref(),
            args.parseable.unwrap_or(false),
        ))
    }

    fn validate(args: &SshAnsibleLintArgs, _host_config: &HostConfig) -> Result<()> {
        AnsibleCommandBuilder::validate_lint_target(&args.target)?;
        Ok(())
    }
}

/// Handler for the `ssh_ansible_lint` tool.
pub type SshAnsibleLintHandler = StandardToolHandler<AnsibleLintTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsibleLintHandler::new();
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshAnsibleLintHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "target": "site.yml"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "nonexistent");
            }
            e => panic!("Expected UnknownHost error, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshAnsibleLintHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_lint");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ansible_lint");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("target")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "target": "site.yml",
            "output_format": "json",
            "parseable": true,
            "timeout_seconds": 120,
            "max_output": 10000
        });

        let args: SshAnsibleLintArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.target, "site.yml");
        assert_eq!(args.output_format, Some("json".to_string()));
        assert_eq!(args.parseable, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "target": "roles/"
        });

        let args: SshAnsibleLintArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.target, "roles/");
        assert!(args.output_format.is_none());
        assert!(args.parseable.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsibleLintHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("output_format"));
        assert!(properties.contains_key("parseable"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "target": "site.yml"
        });
        let args: SshAnsibleLintArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAnsibleLintArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsibleLintHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "target": "site.yml"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_path_traversal_rejected() {
        let handler = SshAnsibleLintHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "target": "../../../etc/shadow"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Path traversal"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
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
    fn test_build_command_minimal() {
        let args = SshAnsibleLintArgs {
            host: "server1".to_string(),
            target: "site.yml".to_string(),
            output_format: None,
            parseable: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleLintTool::build_command(&args, &test_host_config()).unwrap();
        assert_eq!(cmd, "ansible-lint 'site.yml'");
    }

    #[test]
    fn test_build_command_with_format() {
        let args = SshAnsibleLintArgs {
            host: "server1".to_string(),
            target: "roles/".to_string(),
            output_format: Some("json".to_string()),
            parseable: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleLintTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ansible-lint 'roles/'"));
        assert!(cmd.contains("--format 'json'"));
        assert!(cmd.contains("-p"));
    }
}
