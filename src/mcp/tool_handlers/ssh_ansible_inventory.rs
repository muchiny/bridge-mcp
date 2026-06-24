//! SSH Ansible Inventory Tool Handler
//!
//! Queries Ansible inventory on a remote host via SSH.
//! Supports list, graph, and host detail modes with YAML output option.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshAnsibleInventoryArgs {
    host: String,
    #[serde(default)]
    inventory: Option<String>,
    #[serde(default)]
    list: Option<bool>,
    #[serde(default)]
    graph: Option<bool>,
    #[serde(default)]
    host_pattern: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    yaml: Option<bool>,
    #[serde(default)]
    vars: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshAnsibleInventoryArgs);

#[mcp_standard_tool(
    name = "ssh_ansible_inventory",
    group = "ansible",
    annotation = "read_only"
)]
pub struct AnsibleInventoryTool;

impl StandardTool for AnsibleInventoryTool {
    type Args = SshAnsibleInventoryArgs;

    const NAME: &'static str = "ssh_ansible_inventory";

    const DESCRIPTION: &'static str = "Query Ansible inventory on a remote host. Start here to discover available hosts and \
        groups before running ssh_ansible_playbook or ssh_ansible_adhoc. Modes: list (full \
        JSON inventory — use with jq_filter), graph (plain-text ASCII tree — jq_filter does \
        not apply), or host_pattern (JSON details for a specific host). Only one mode applies \
        at a time (list > graph > host_pattern). Note: yaml=true is incompatible with \
        jq_filter (jq requires JSON output).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "inventory": {
                "type": "string",
                "description": "Inventory file path"
            },
            "list": {
                "type": "boolean",
                "description": "Output full inventory as JSON"
            },
            "graph": {
                "type": "boolean",
                "description": "Output inventory as a plain-text ASCII group tree (not JSON — jq_filter does not apply; use list=true for JSON output)"
            },
            "host_pattern": {
                "type": "string",
                "description": "Show info for a specific host"
            },
            "group": {
                "type": "string",
                "description": "Group name for graph mode"
            },
            "yaml": {
                "type": "boolean",
                "description": "Use YAML output format"
            },
            "vars": {
                "type": "boolean",
                "description": "Show variables in graph mode"
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
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool. Recommended for large dynamic inventories."
            }
        },
        "required": ["host"]
    }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Json;

    fn build_command(args: &SshAnsibleInventoryArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(AnsibleCommandBuilder::build_inventory_command(
            args.inventory.as_deref(),
            args.list.unwrap_or(false),
            args.graph.unwrap_or(false),
            args.host_pattern.as_deref(),
            args.group.as_deref(),
            args.yaml.unwrap_or(false),
            args.vars.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_ansible_inventory` tool.
pub type SshAnsibleInventoryHandler = StandardToolHandler<AnsibleInventoryTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsibleInventoryHandler::new();
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
        let handler = SshAnsibleInventoryHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent"
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
        let handler = SshAnsibleInventoryHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_inventory");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ansible_inventory");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "inventory": "/etc/ansible/hosts",
            "list": true,
            "graph": false,
            "host_pattern": "webserver01",
            "group": "webservers",
            "yaml": true,
            "vars": true,
            "timeout_seconds": 60,
            "max_output": 20000
        });

        let args: SshAnsibleInventoryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.inventory, Some("/etc/ansible/hosts".to_string()));
        assert_eq!(args.list, Some(true));
        assert_eq!(args.graph, Some(false));
        assert_eq!(args.host_pattern, Some("webserver01".to_string()));
        assert_eq!(args.group, Some("webservers".to_string()));
        assert_eq!(args.yaml, Some(true));
        assert_eq!(args.vars, Some(true));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(20000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1"
        });

        let args: SshAnsibleInventoryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.inventory.is_none());
        assert!(args.list.is_none());
        assert!(args.graph.is_none());
        assert!(args.host_pattern.is_none());
        assert!(args.group.is_none());
        assert!(args.yaml.is_none());
        assert!(args.vars.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshAnsibleInventoryHandler::new();
        let ctx = create_test_context();

        // Missing host field
        let result = handler
            .execute(
                Some(json!({
                    "inventory": "/etc/ansible/hosts"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsibleInventoryHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("inventory"));
        assert!(properties.contains_key("list"));
        assert!(properties.contains_key("graph"));
        assert!(properties.contains_key("host_pattern"));
        assert!(properties.contains_key("group"));
        assert!(properties.contains_key("yaml"));
        assert!(properties.contains_key("vars"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1"
        });
        let args: SshAnsibleInventoryArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAnsibleInventoryArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsibleInventoryHandler::new();
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
        let args = SshAnsibleInventoryArgs {
            host: "server1".to_string(),
            inventory: None,
            list: None,
            graph: None,
            host_pattern: None,
            group: None,
            yaml: None,
            vars: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleInventoryTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ansible-inventory"));
    }

    #[test]
    fn test_build_command_with_inventory() {
        let args = SshAnsibleInventoryArgs {
            host: "server1".to_string(),
            inventory: Some("/etc/ansible/hosts".to_string()),
            list: Some(true),
            graph: None,
            host_pattern: None,
            group: None,
            yaml: None,
            vars: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleInventoryTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-i '/etc/ansible/hosts'"));
        assert!(cmd.contains("--list"));
    }

    #[test]
    fn test_build_command_with_host_limit() {
        let args = SshAnsibleInventoryArgs {
            host: "server1".to_string(),
            inventory: None,
            list: None,
            graph: Some(true),
            host_pattern: None,
            group: Some("webservers".to_string()),
            yaml: Some(true),
            vars: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleInventoryTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--graph 'webservers'"));
        assert!(cmd.contains("--yaml"));
        assert!(cmd.contains("--vars"));
    }
}
