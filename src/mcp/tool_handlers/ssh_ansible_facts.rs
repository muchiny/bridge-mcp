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
#[serde(deny_unknown_fields)]
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
                "description": "Fact-name glob passed to the setup module (-a filter=...): letters, digits, '_', '*', '?', ',' and [...] classes only (e.g., 'ansible_distribution*'; comma-separated patterns such as 'ansible_eth*,ansible_memory*' on Ansible 2.9+). Spaces, '=' and Jinja are refused. Strongly recommended to reduce output — without filter, ALL facts (~50K chars) are returned."
            },
            "inventory": {
                "type": "string",
                "description": "Inventory file, directory or comma-separated host list. Read as data (host list, YAML, INI, TOML), never executed; must not start with '-'"
            },
            "become": {
                "type": "boolean",
                "description": "Escalate privileges with sudo"
            },
            "become_user": {
                "type": "string",
                "description": "User to become (letters, digits, '_', '.', '@', '-'; max 64; no leading '-'; optional DOMAIN\\ prefix and trailing '$')"
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

    fn validate(args: &SshAnsibleFactsArgs, _host_config: &HostConfig) -> Result<()> {
        AnsibleCommandBuilder::validate_pattern(&args.pattern)?;
        AnsibleCommandBuilder::refuse_jinja_in(&[
            ("pattern", Some(args.pattern.as_str())),
            ("inventory", args.inventory.as_deref()),
        ])?;
        if let Some(inventory) = args.inventory.as_deref() {
            AnsibleCommandBuilder::validate_inventory(inventory)?;
        }
        if let Some(filter) = args.filter.as_deref() {
            AnsibleCommandBuilder::validate_facts_filter(filter)?;
        }
        // `become_user` ends up unquoted in a shell line on the targets.
        if let Some(user) = args.become_user.as_deref() {
            AnsibleCommandBuilder::validate_user_name("become_user", user)?;
        }
        Ok(())
    }
}

/// Handler for the `ssh_ansible_facts` tool.
pub type SshAnsibleFactsHandler = StandardToolHandler<AnsibleFactsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
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
        assert_ne!(handler.description(), "");

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

    #[tokio::test]
    async fn test_option_like_pattern_refused() {
        let handler = SshAnsibleFactsHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(Some(json!({"host":"server1","pattern":"-ZQXdash"})), &ctx)
            .await;
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("pattern"), "{reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_filter_with_jinja_is_refused() {
        let handler = SshAnsibleFactsHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "pattern": "localhost",
                    "filter": "{{ lookup('pipe','id') }}"
                })),
                &ctx,
            )
            .await;
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("filter"), "{reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_filter_with_a_second_parameter_is_refused() {
        let handler = SshAnsibleFactsHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "pattern": "localhost",
                    "filter": "* fact_path=/var/tmp/d"
                })),
                &ctx,
            )
            .await;
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("filter"), "{reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_become_user_with_jinja_is_refused() {
        let handler = SshAnsibleFactsHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "pattern": "all",
                    "become_user": "{{ lookup('pipe','id') }}"
                })),
                &ctx,
            )
            .await;
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("become_user"), "{reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_fact_glob_filters_still_pass_validation() {
        let json = json!({
            "host": "server1",
            "pattern": "all",
            "filter": "ansible_eth*,ansible_memory*",
            "become_user": "root"
        });
        let args: SshAnsibleFactsArgs = serde_json::from_value(json).unwrap();
        assert!(AnsibleFactsTool::validate(&args, &test_host_config()).is_ok());
    }

    #[test]
    fn test_become_user_with_shell_syntax_is_refused() {
        for user in [
            "root; id",
            "root && id",
            "root id",
            "$(id)",
            "`id`",
            "-root",
            "",
            "root|id",
            "root\nid",
        ] {
            let args: SshAnsibleFactsArgs = serde_json::from_value(
                json!({"host":"server1","pattern":"all","become_user":user}),
            )
            .unwrap();
            let err = AnsibleFactsTool::validate(&args, &test_host_config()).expect_err(user);
            match err {
                BridgeError::CommandDenied { reason } => {
                    assert!(reason.contains("become_user"), "{reason}");
                }
                e => panic!("Expected CommandDenied, got: {e:?}"),
            }
        }
    }

    #[test]
    fn test_become_user_names_still_pass() {
        for user in ["root", "deploy", "_svc", "ops.team", "j.doe@corp", "a-b_c9"] {
            let args: SshAnsibleFactsArgs = serde_json::from_value(
                json!({"host":"server1","pattern":"all","become_user":user}),
            )
            .unwrap();
            assert!(
                AnsibleFactsTool::validate(&args, &test_host_config()).is_ok(),
                "{user}"
            );
        }
    }

    #[test]
    fn test_jinja_in_pattern_and_inventory_is_refused() {
        for field in ["pattern", "inventory"] {
            let mut value = json!({"host":"server1","pattern":"all"});
            value[field] = json!("{{ lookup('pipe','id') }}");
            let args: SshAnsibleFactsArgs = serde_json::from_value(value).unwrap();
            match AnsibleFactsTool::validate(&args, &test_host_config()) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains(field), "{field}: {reason}");
                }
                other => panic!("{field}: expected CommandDenied, got {other:?}"),
            }
        }
        let ok: SshAnsibleFactsArgs = serde_json::from_value(
            json!({"host":"server1","pattern":"web*:!db1","inventory":"hosts.ini"}),
        )
        .unwrap();
        assert!(AnsibleFactsTool::validate(&ok, &test_host_config()).is_ok());
    }

    #[test]
    fn test_inventory_is_read_as_data() {
        let with: SshAnsibleFactsArgs = serde_json::from_value(
            json!({"host":"server1","pattern":"all","inventory":"/tmp/inv"}),
        )
        .unwrap();
        let cmd = AnsibleFactsTool::build_command(&with, &test_host_config()).unwrap();
        assert_eq!(
            cmd,
            "ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml ansible 'all' -m setup -i '/tmp/inv'"
        );
        let without: SshAnsibleFactsArgs =
            serde_json::from_value(json!({"host":"server1","pattern":"all"})).unwrap();
        let cmd = AnsibleFactsTool::build_command(&without, &test_host_config()).unwrap();
        assert_eq!(cmd, "ansible 'all' -m setup");
    }

    #[test]
    fn test_dashed_inventory_is_refused() {
        let bad: SshAnsibleFactsArgs = serde_json::from_value(
            json!({"host":"server1","pattern":"all","inventory":"-ZQXdash"}),
        )
        .unwrap();
        match AnsibleFactsTool::validate(&bad, &test_host_config()) {
            Err(BridgeError::CommandDenied { reason }) => {
                assert!(reason.contains("inventory"), "{reason}");
            }
            other => panic!("expected CommandDenied, got {other:?}"),
        }
        let ok: SshAnsibleFactsArgs = serde_json::from_value(
            json!({"host":"server1","pattern":"all","inventory":"./-hosts,"}),
        )
        .unwrap();
        assert!(AnsibleFactsTool::validate(&ok, &test_host_config()).is_ok());
    }

    #[test]
    fn test_windows_domain_and_gmsa_become_users() {
        for user in ["CORP\\svc", "svc$"] {
            let ok: SshAnsibleFactsArgs = serde_json::from_value(
                json!({"host":"server1","pattern":"all","become_user":user}),
            )
            .unwrap();
            assert!(
                AnsibleFactsTool::validate(&ok, &test_host_config()).is_ok(),
                "{user}"
            );
        }
        let bad: SshAnsibleFactsArgs = serde_json::from_value(
            json!({"host":"server1","pattern":"all","become_user":"CORP\\"}),
        )
        .unwrap();
        assert!(AnsibleFactsTool::validate(&bad, &test_host_config()).is_err());
    }
}
