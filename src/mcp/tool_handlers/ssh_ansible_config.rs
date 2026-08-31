//! SSH Ansible Config Tool Handler
//!
//! Displays the current Ansible configuration via `ansible-config dump`.
//! Useful for checking which callback plugin, inventory, and settings are active.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshAnsibleConfigArgs {
    host: String,
    #[serde(default)]
    only_changed: Option<bool>,
    #[serde(default)]
    output_format: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshAnsibleConfigArgs);

#[mcp_standard_tool(
    name = "ssh_ansible_config",
    group = "ansible",
    annotation = "read_only"
)]
pub struct AnsibleConfigTool;

impl StandardTool for AnsibleConfigTool {
    type Args = SshAnsibleConfigArgs;

    const NAME: &'static str = "ssh_ansible_config";

    const DESCRIPTION: &'static str = "Show current Ansible configuration on a remote host. \
        Displays settings from ansible.cfg, environment variables, and defaults. \
        Use only_changed=true to show only non-default values (much shorter output). \
        Useful for checking which stdout callback, inventory, and connection settings are active.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "only_changed": {
                "type": "boolean",
                "description": "Only show settings that differ from defaults (recommended for shorter output)"
            },
            "output_format": {
                "type": "string",
                "description": "Output format: 'json' for structured output (enables jq_filter)",
                "enum": ["json"]
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 40000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshAnsibleConfigArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(AnsibleCommandBuilder::build_config_command(
            args.only_changed.unwrap_or(false),
            args.output_format.as_deref(),
        ))
    }
}

/// Handler for the `ssh_ansible_config` tool.
pub type SshAnsibleConfigHandler = StandardToolHandler<AnsibleConfigTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsibleConfigHandler::new();
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
        let handler = SshAnsibleConfigHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
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
        let handler = SshAnsibleConfigHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_config");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ansible_config");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "only_changed": true,
            "output_format": "json",
            "timeout_seconds": 30
        });

        let args: SshAnsibleConfigArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.only_changed, Some(true));
        assert_eq!(args.output_format, Some("json".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});

        let args: SshAnsibleConfigArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.only_changed.is_none());
        assert!(args.output_format.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsibleConfigHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("only_changed"));
        assert!(properties.contains_key("output_format"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshAnsibleConfigArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAnsibleConfigArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsibleConfigHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
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
        let args = SshAnsibleConfigArgs {
            host: "server1".to_string(),
            only_changed: None,
            output_format: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleConfigTool::build_command(&args, &test_host_config()).unwrap();
        assert_eq!(cmd, "ansible-config dump");
    }

    #[test]
    fn test_build_command_only_changed_json() {
        let args = SshAnsibleConfigArgs {
            host: "server1".to_string(),
            only_changed: Some(true),
            output_format: Some("json".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleConfigTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--only-changed"));
        assert!(cmd.contains("--format 'json'"));
    }
}
