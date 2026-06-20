//! SSH Ansible Facts Tool Handler
//!
//! Gathers Ansible facts from remote hosts via `ansible -m setup`.
//! Supports fact filtering to reduce output (e.g., `filter=ansible_distribution*`).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshAnsibleFactsArgs {
    host: String,
    pattern: String,
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    inventory: Option<String>,
    #[serde(default, rename = "become")]
    use_become: Option<bool>,
    #[serde(default)]
    become_user: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshAnsibleFactsArgs);

#[mcp_standard_tool(
    name = "ssh_ansible_facts",
    group = "ansible",
    annotation = "read_only"
)]
pub struct AnsibleFactsTool;

impl StandardTool for AnsibleFactsTool {
    type Args = SshAnsibleFactsArgs;

    const NAME: &'static str = "ssh_ansible_facts";

    const DESCRIPTION: &'static str = "Gather Ansible facts from remote hosts via SSH. Uses \
        `ansible -m setup` to collect system information. Use filter parameter to reduce \
        output (e.g., 'ansible_distribution*' for OS info, 'ansible_memory*' for RAM, \
        'ansible_default_ipv4*' for network). Without filter, returns ALL facts (~50K chars). \
        Returns JSON output compatible with jq_filter for further extraction.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "pattern": {
                "type": "string",
                "description": "Host or group pattern to gather facts from (e.g., 'all', 'webservers', 'host1')"
            },
            "filter": {
                "type": "string",
                "description": "Fact filter glob pattern passed to the setup module (-a filter=...). Supports wildcards (e.g., 'ansible_distribution*') and comma-separated patterns (e.g., 'ansible_eth*,ansible_memory*' on Ansible 2.9+). Strongly recommended to reduce output — without filter, ALL facts (~50K chars) are returned."
            },
            "inventory": {
                "type": "string",
                "description": "Inventory file or comma-separated host list"
            },
            "become": {
                "type": "boolean",
                "description": "Escalate privileges with sudo"
            },
            "become_user": {
                "type": "string",
                "description": "User to become"
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
        "required": ["host", "pattern"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Json;

    fn build_command(args: &SshAnsibleFactsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(AnsibleCommandBuilder::build_facts_command(
            &args.pattern,
            args.filter.as_deref(),
            args.inventory.as_deref(),
            args.use_become.unwrap_or(false),
            args.become_user.as_deref(),
        ))
    }
}

/// Handler for the `ssh_ansible_facts` tool.
pub type SshAnsibleFactsHandler = StandardToolHandler<AnsibleFactsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsibleFactsHandler::new();
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
        let handler = SshAnsibleFactsHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "pattern": "all"
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
        let handler = SshAnsibleFactsHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_facts");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ansible_facts");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("pattern")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "pattern": "webservers",
            "filter": "ansible_distribution*",
            "inventory": "hosts.ini",
            "become": true,
            "become_user": "root",
            "timeout_seconds": 120,
            "max_output": 10000
        });

        let args: SshAnsibleFactsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pattern, "webservers");
        assert_eq!(args.filter, Some("ansible_distribution*".to_string()));
        assert_eq!(args.inventory, Some("hosts.ini".to_string()));
        assert_eq!(args.use_become, Some(true));
        assert_eq!(args.become_user, Some("root".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "pattern": "all"
        });

        let args: SshAnsibleFactsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pattern, "all");
        assert!(args.filter.is_none());
        assert!(args.inventory.is_none());
        assert!(args.use_become.is_none());
        assert!(args.become_user.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsibleFactsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("filter"));
        assert!(properties.contains_key("inventory"));
        assert!(properties.contains_key("become"));
        assert!(properties.contains_key("become_user"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "pattern": "all"
        });
        let args: SshAnsibleFactsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAnsibleFactsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsibleFactsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "pattern": "all"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshAnsibleFactsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(result.is_err());
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
        let args = SshAnsibleFactsArgs {
            host: "server1".to_string(),
            pattern: "all".to_string(),
            filter: None,
            inventory: None,
            use_become: None,
            become_user: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleFactsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ansible 'all' -m setup"));
    }

    #[test]
    fn test_build_command_with_filter() {
        let args = SshAnsibleFactsArgs {
            host: "server1".to_string(),
            pattern: "webservers".to_string(),
            filter: Some("ansible_distribution*".to_string()),
            inventory: Some("hosts.ini".to_string()),
            use_become: Some(true),
            become_user: Some("root".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleFactsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ansible 'webservers' -m setup"));
        assert!(cmd.contains("filter="));
        assert!(cmd.contains("ansible_distribution"));
        assert!(cmd.contains("-i 'hosts.ini'"));
        assert!(cmd.contains(" -b"));
        assert!(cmd.contains("--become-user 'root'"));
    }
}
