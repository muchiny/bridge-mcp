//! SSH Ansible Recap Tool Handler
//!
//! Runs an Ansible playbook with the `dense` callback and filters output to
//! show only the PLAY RECAP, FAILED, and CHANGED lines. Produces ultra-compact
//! output (~100-200 tokens vs ~5000+ for full stdout).

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshAnsibleRecapArgs {
    host: String,
    playbook: String,
    #[serde(default)]
    inventory: Option<String>,
    #[serde(default)]
    limit: Option<String>,
    #[serde(default)]
    tags: Option<String>,
    #[serde(default)]
    skip_tags: Option<String>,
    #[serde(default)]
    extra_vars: Option<HashMap<String, String>>,
    #[serde(default)]
    check: Option<bool>,
    #[serde(default)]
    diff: Option<bool>,
    #[serde(default)]
    forks: Option<u32>,
    #[serde(default, rename = "become")]
    use_become: Option<bool>,
    #[serde(default)]
    become_user: Option<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    vault_password_file: Option<String>,
    #[serde(default)]
    vault_id: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshAnsibleRecapArgs);

#[mcp_standard_tool(name = "ssh_ansible_recap", group = "ansible", annotation = "mutating")]
pub struct AnsibleRecapTool;

impl StandardTool for AnsibleRecapTool {
    type Args = SshAnsibleRecapArgs;

    const NAME: &'static str = "ssh_ansible_recap";

    const DESCRIPTION: &'static str = "Run an Ansible playbook and return only the compact \
        summary (PLAY RECAP + failures + changes). Uses the 'dense' callback for 1-line-per-task \
        output filtered to key events. Produces ~100-200 tokens vs ~5000+ for full stdout. \
        Ideal for quick status checks. For full output, use ssh_ansible_playbook instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "playbook": {
                "type": "string",
                "description": "Path to the Ansible playbook YAML file on the remote host"
            },
            "inventory": {
                "type": "string",
                "description": "Inventory file or comma-separated host list"
            },
            "limit": {
                "type": "string",
                "description": "Limit to subset of hosts"
            },
            "tags": {
                "type": "string",
                "description": "Only run plays/tasks matching these tags"
            },
            "skip_tags": {
                "type": "string",
                "description": "Skip plays/tasks matching these tags"
            },
            "extra_vars": {
                "type": "object",
                "description": "Extra variables as key-value pairs"
            },
            "check": {
                "type": "boolean",
                "description": "Dry-run mode"
            },
            "diff": {
                "type": "boolean",
                "description": "Show file change diffs"
            },
            "forks": {
                "type": "integer",
                "description": "Number of parallel processes",
                "minimum": 1
            },
            "become": {
                "type": "boolean",
                "description": "Escalate privileges with sudo"
            },
            "become_user": {
                "type": "string",
                "description": "User to become"
            },
            "working_dir": {
                "type": "string",
                "description": "Directory to cd into before running"
            },
            "vault_password_file": {
                "type": "string",
                "description": "Path to an ansible-vault password file on the remote host (--vault-password-file)"
            },
            "vault_id": {
                "type": "string",
                "description": "ansible-vault identity, e.g. 'prod@/etc/ansible/prod-pass' (--vault-id)"
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
        "required": ["host", "playbook"]
    }"#;

    fn build_command(args: &SshAnsibleRecapArgs, _host_config: &HostConfig) -> Result<String> {
        // Use dense callback + grep to extract only key lines
        let playbook_cmd = AnsibleCommandBuilder::build_playbook_command(
            &args.playbook,
            args.inventory.as_deref(),
            args.limit.as_deref(),
            args.tags.as_deref(),
            args.skip_tags.as_deref(),
            args.extra_vars.as_ref(),
            args.check.unwrap_or(false),
            args.diff.unwrap_or(false),
            None, // no extra verbose for recap
            args.forks,
            args.use_become.unwrap_or(false),
            args.become_user.as_deref(),
            args.working_dir.as_deref(),
            Some("dense"),
            args.vault_password_file.as_deref(),
            args.vault_id.as_deref(),
        );
        // Pipe through grep to keep only FAILED, CHANGED, PLAY RECAP, and fatal lines.
        // Use `; true` to ignore grep's non-zero exit when no matches (all OK run).
        Ok(format!(
            "{playbook_cmd} 2>&1 | grep -E '(FAILED|CHANGED|PLAY RECAP|fatal|unreachable)'; true"
        ))
    }

    fn validate(args: &SshAnsibleRecapArgs, _host_config: &HostConfig) -> Result<()> {
        AnsibleCommandBuilder::validate_playbook_path(&args.playbook)?;
        Ok(())
    }
}

/// Handler for the `ssh_ansible_recap` tool.
pub type SshAnsibleRecapHandler = StandardToolHandler<AnsibleRecapTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsibleRecapHandler::new();
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
        let handler = SshAnsibleRecapHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "playbook": "site.yml"
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
        let handler = SshAnsibleRecapHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_recap");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ansible_recap");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("playbook")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "playbook": "site.yml",
            "inventory": "hosts.ini",
            "limit": "webservers",
            "tags": "deploy",
            "check": true,
            "become": true,
            "become_user": "root"
        });

        let args: SshAnsibleRecapArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert_eq!(args.inventory, Some("hosts.ini".to_string()));
        assert_eq!(args.limit, Some("webservers".to_string()));
        assert_eq!(args.use_become, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "playbook": "site.yml"
        });

        let args: SshAnsibleRecapArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert!(args.inventory.is_none());
        assert!(args.limit.is_none());
        assert!(args.tags.is_none());
        assert!(args.check.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsibleRecapHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("inventory"));
        assert!(properties.contains_key("limit"));
        assert!(properties.contains_key("tags"));
        assert!(properties.contains_key("check"));
        assert!(properties.contains_key("become"));
        assert!(properties.contains_key("vault_password_file"));
        assert!(properties.contains_key("vault_id"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "playbook": "site.yml"
        });
        let args: SshAnsibleRecapArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAnsibleRecapArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsibleRecapHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "playbook": "site.yml"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_playbook_path_traversal_rejected() {
        let handler = SshAnsibleRecapHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "playbook": "../../../etc/shadow"
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
    fn test_build_command_uses_dense_callback() {
        let args = SshAnsibleRecapArgs {
            host: "server1".to_string(),
            playbook: "site.yml".to_string(),
            inventory: None,
            limit: None,
            tags: None,
            skip_tags: None,
            extra_vars: None,
            check: None,
            diff: None,
            forks: None,
            use_become: None,
            become_user: None,
            working_dir: None,
            vault_password_file: None,
            vault_id: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleRecapTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ANSIBLE_STDOUT_CALLBACK='dense'"));
        assert!(cmd.contains("ansible-playbook 'site.yml'"));
        assert!(cmd.contains("grep -E"));
        assert!(cmd.contains("PLAY RECAP"));
        assert!(cmd.contains("FAILED"));
        assert!(cmd.contains("CHANGED"));
    }

    #[test]
    fn test_build_command_with_options() {
        let args = SshAnsibleRecapArgs {
            host: "server1".to_string(),
            playbook: "deploy.yml".to_string(),
            inventory: Some("hosts.ini".to_string()),
            limit: Some("webservers".to_string()),
            tags: None,
            skip_tags: None,
            extra_vars: None,
            check: Some(true),
            diff: None,
            forks: Some(10),
            use_become: Some(true),
            become_user: None,
            working_dir: None,
            vault_password_file: None,
            vault_id: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsibleRecapTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ANSIBLE_STDOUT_CALLBACK='dense'"));
        assert!(cmd.contains("-i 'hosts.ini'"));
        assert!(cmd.contains("--limit 'webservers'"));
        assert!(cmd.contains("--check"));
        assert!(cmd.contains("-f 10"));
        assert!(cmd.contains(" -b"));
    }
}
