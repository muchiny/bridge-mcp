//! SSH Ansible Ad-Hoc Tool Handler
//!
//! Runs an Ansible ad-hoc command on a remote host via SSH.
//! Executes single modules against target hosts without a playbook.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshAnsibleAdhocArgs {
    host: String,
    pattern: String,
    module: String,
    #[serde(default)]
    args: Option<String>,
    #[serde(default)]
    inventory: Option<String>,
    #[serde(default, rename = "become")]
    use_become: Option<bool>,
    #[serde(default)]
    become_user: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    forks: Option<u32>,
    #[serde(default)]
    verbose: Option<u8>,
    #[serde(default)]
    check: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshAnsibleAdhocArgs);

#[mcp_standard_tool(name = "ssh_ansible_adhoc", group = "ansible", annotation = "destructive")]
pub struct AnsibleAdhocTool;

impl StandardTool for AnsibleAdhocTool {
    type Args = SshAnsibleAdhocArgs;

    const NAME: &'static str = "ssh_ansible_adhoc";

    const DESCRIPTION: &'static str = "Run an Ansible ad-hoc command on a remote host without a playbook. Execute a single \
        module (e.g., ping, shell, copy, service) against target hosts. Use \
        ssh_ansible_inventory first to discover hosts. For complex multi-task automation, use \
        ssh_ansible_playbook instead. Supports check mode for dry-run.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "pattern": {
                "type": "string",
                "description": "Host or group pattern e.g. 'all', 'webservers'"
            },
            "module": {
                "type": "string",
                "description": "Ansible module name e.g. ping, shell, copy, service"
            },
            "args": {
                "type": "string",
                "description": "Module arguments"
            },
            "inventory": {
                "type": "string",
                "description": "Inventory file or comma-separated host list"
            },
            "become": {
                "type": "boolean",
                "description": "Escalate with sudo"
            },
            "become_user": {
                "type": "string",
                "description": "User to become"
            },
            "user": {
                "type": "string",
                "description": "Remote SSH user"
            },
            "forks": {
                "type": "integer",
                "description": "Number of parallel processes",
                "minimum": 1
            },
            "verbose": {
                "type": "integer",
                "description": "Verbosity level 0-4",
                "minimum": 0,
                "maximum": 4
            },
            "check": {
                "type": "boolean",
                "description": "Check mode"
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
        "required": ["host", "pattern", "module"]
    }"#;

    fn build_command(args: &SshAnsibleAdhocArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(AnsibleCommandBuilder::build_adhoc_command(
            &args.pattern,
            &args.module,
            args.args.as_deref(),
            args.inventory.as_deref(),
            args.use_become.unwrap_or(false),
            args.become_user.as_deref(),
            args.user.as_deref(),
            args.forks,
            args.verbose,
            args.check.unwrap_or(false),
        ))
    }

    fn validate(args: &SshAnsibleAdhocArgs, _host_config: &HostConfig) -> Result<()> {
        AnsibleCommandBuilder::validate_adhoc_module(&args.module, args.args.as_deref())?;
        Ok(())
    }
}

/// Handler for the `ssh_ansible_adhoc` tool.
pub type SshAnsibleAdhocHandler = StandardToolHandler<AnsibleAdhocTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsibleAdhocHandler::new();
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
        let handler = SshAnsibleAdhocHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "pattern": "all",
                    "module": "ping"
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
        let handler = SshAnsibleAdhocHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_adhoc");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ansible_adhoc");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("pattern")));
        assert!(required.contains(&json!("module")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "pattern": "webservers",
            "module": "shell",
            "args": "uptime",
            "inventory": "hosts.ini",
            "become": true,
            "become_user": "root",
            "user": "deploy",
            "forks": 5,
            "verbose": 2,
            "check": false,
            "timeout_seconds": 120,
            "max_output": 10000
        });

        let args: SshAnsibleAdhocArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pattern, "webservers");
        assert_eq!(args.module, "shell");
        assert_eq!(args.args, Some("uptime".to_string()));
        assert_eq!(args.inventory, Some("hosts.ini".to_string()));
        assert_eq!(args.use_become, Some(true));
        assert_eq!(args.become_user, Some("root".to_string()));
        assert_eq!(args.user, Some("deploy".to_string()));
        assert_eq!(args.forks, Some(5));
        assert_eq!(args.verbose, Some(2));
        assert_eq!(args.check, Some(false));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "pattern": "all",
            "module": "ping"
        });

        let args: SshAnsibleAdhocArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pattern, "all");
        assert_eq!(args.module, "ping");
        assert!(args.args.is_none());
        assert!(args.inventory.is_none());
        assert!(args.use_become.is_none());
        assert!(args.become_user.is_none());
        assert!(args.user.is_none());
        assert!(args.forks.is_none());
        assert!(args.verbose.is_none());
        assert!(args.check.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshAnsibleAdhocHandler::new();
        let ctx = create_test_context();

        // Missing module field
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "pattern": "all"
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

    #[tokio::test]
    async fn test_dangerous_module_rejected() {
        let handler = SshAnsibleAdhocHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "pattern": "all",
                    "module": "raw",
                    "args": "rm -rf /"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("rm -rf"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsibleAdhocHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("args"));
        assert!(properties.contains_key("inventory"));
        assert!(properties.contains_key("become"));
        assert!(properties.contains_key("become_user"));
        assert!(properties.contains_key("user"));
        assert!(properties.contains_key("forks"));
        assert!(properties.contains_key("verbose"));
        assert!(properties.contains_key("check"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "pattern": "all",
            "module": "ping"
        });
        let args: SshAnsibleAdhocArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAnsibleAdhocArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsibleAdhocHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "pattern": "all", "module": "ping"})),
                &ctx,
            )
            .await;
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
        let args = SshAnsibleAdhocArgs {
            host: "server1".to_string(),
            pattern: "all".to_string(),
            module: "ping".to_string(),
            args: None,
            inventory: None,
            use_become: None,
            become_user: None,
            user: None,
            forks: None,
            verbose: None,
            check: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleAdhocTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ansible 'all' -m 'ping'"));
    }

    #[test]
    fn test_build_command_with_module_args() {
        let args = SshAnsibleAdhocArgs {
            host: "server1".to_string(),
            pattern: "webservers".to_string(),
            module: "shell".to_string(),
            args: Some("uptime".to_string()),
            inventory: Some("hosts.ini".to_string()),
            use_become: None,
            become_user: None,
            user: None,
            forks: None,
            verbose: None,
            check: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleAdhocTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-a 'uptime'"));
        assert!(cmd.contains("-i 'hosts.ini'"));
    }

    #[test]
    fn test_build_command_with_become() {
        let args = SshAnsibleAdhocArgs {
            host: "server1".to_string(),
            pattern: "all".to_string(),
            module: "service".to_string(),
            args: Some("name=nginx state=restarted".to_string()),
            inventory: None,
            use_become: Some(true),
            become_user: Some("root".to_string()),
            user: Some("deploy".to_string()),
            forks: Some(5),
            verbose: None,
            check: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleAdhocTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains(" -b"));
        assert!(cmd.contains("--become-user 'root'"));
        assert!(cmd.contains("-u 'deploy'"));
        assert!(cmd.contains(" -C"));
    }
}
