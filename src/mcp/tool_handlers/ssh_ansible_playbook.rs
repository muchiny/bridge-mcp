//! SSH Ansible Playbook Tool Handler
//!
//! Runs an Ansible playbook on a remote host via SSH.
//! Supports inventory, tags, extra variables, check mode, and verbosity control.

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::protocol::LogLevel;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshAnsiblePlaybookArgs {
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
    verbose: Option<u8>,
    #[serde(default)]
    forks: Option<u32>,
    #[serde(default, rename = "become")]
    use_become: Option<bool>,
    #[serde(default)]
    become_user: Option<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    callback: Option<String>,
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

impl_common_args!(SshAnsiblePlaybookArgs);

#[mcp_standard_tool(
    name = "ssh_ansible_playbook",
    group = "ansible",
    annotation = "destructive"
)]
pub struct AnsiblePlaybookTool;

impl StandardTool for AnsiblePlaybookTool {
    type Args = SshAnsiblePlaybookArgs;

    const NAME: &'static str = "ssh_ansible_playbook";

    const DESCRIPTION: &'static str = "Run an Ansible playbook on a remote host via SSH. The playbook file must exist on the \
        remote host. Use check=true for dry-run mode to preview changes without applying. Use \
        ssh_ansible_inventory first to discover available hosts and groups. For quick \
        single-module tasks, prefer ssh_ansible_adhoc instead. Set callback='json' for \
        structured JSON output (works with jq_filter for token-efficient extraction). \
        Set callback='dense' for ultra-compact 1-line-per-task output. Returns \
        ansible-playbook output in the selected format.";

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
                "description": "Inventory file, directory or comma-separated host list. Read as data (host list, YAML, INI, TOML), never executed; must not start with '-'. Must be listed in hosts.<host>.ansible.inventories in config.yaml (exact match); leave it out to use the inventory set in ansible.cfg"
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
            "verbose": {
                "type": "integer",
                "description": "Verbosity level 0-4",
                "minimum": 0,
                "maximum": 4
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
                "description": "User to become (letters, digits, '_', '.', '@', '-'; max 64; no leading '-'; optional DOMAIN\\ prefix and trailing '$')"
            },
            "working_dir": {
                "type": "string",
                "description": "Directory to cd into before running. Must be listed in hosts.<host>.ansible.working_dirs in config.yaml (exact match), because an ansible.cfg there sets the inventory, the remote user and the keys; leave it out to use absolute paths"
            },
            "callback": {
                "type": "string",
                "description": "Ansible stdout callback plugin. Use 'json' for structured JSON output (enables jq_filter), 'dense' for compact 1-line-per-task, 'yaml' for YAML format, 'minimal' for minimal output. Default: Ansible default. Note: 'oneline' was removed from Ansible core >= 2.8 — use 'minimal' instead on modern installs.",
                "enum": ["json", "yaml", "dense", "minimal", "tree", "default", "oneline", "debug", "null"]
            },
            "vault_password_file": {
                "type": "string",
                "description": "Path to an ansible-vault password file on the remote host (--vault-password-file). Must be a plain file without execute permission (Ansible runs an executable one); the call stops with exit status 2 otherwise"
            },
            "vault_id": {
                "type": "string",
                "description": "ansible-vault identity, e.g. 'prod@/etc/ansible/prod-pass' (--vault-id). The file after the first '@' (the whole value without one) must be a plain file without execute permission; 'prompt' and 'prompt_ask_vault_pass' are not files"
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
        "required": ["host", "playbook"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshAnsiblePlaybookArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(AnsibleCommandBuilder::build_playbook_command(
            &args.playbook,
            args.inventory.as_deref(),
            args.limit.as_deref(),
            args.tags.as_deref(),
            args.skip_tags.as_deref(),
            args.extra_vars.as_ref(),
            args.check.unwrap_or(false),
            args.diff.unwrap_or(false),
            args.verbose,
            args.forks,
            args.use_become.unwrap_or(false),
            args.become_user.as_deref(),
            args.working_dir.as_deref(),
            args.callback.as_deref(),
            args.vault_password_file.as_deref(),
            args.vault_id.as_deref(),
        ))
    }

    /// Parse the ansible-playbook output and emit a structured
    /// `notifications/message` per `PLAY [...]` and `TASK [...]` line so
    /// the client can render a live timeline of the run. Failed tasks
    /// (`fatal:` prefix) are logged at Error; others at Info. The raw
    /// result is returned unchanged — this hook is purely additive
    /// observability.
    fn enrich(
        result: ToolCallResult,
        _args: &Self::Args,
        output: &str,
        ctx: &ToolContext,
    ) -> impl std::future::Future<Output = Result<ToolCallResult>> + Send {
        let Some(logger) = ctx.mcp_logger.as_ref() else {
            return std::future::ready(Ok(result));
        };
        for line in output.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("PLAY [") || trimmed.starts_with("PLAY RECAP") {
                logger.log(
                    LogLevel::Info,
                    "ssh_ansible_playbook",
                    serde_json::json!({"phase": "play", "line": trimmed}),
                );
            } else if trimmed.starts_with("TASK [") {
                logger.log(
                    LogLevel::Info,
                    "ssh_ansible_playbook",
                    serde_json::json!({"phase": "task", "line": trimmed}),
                );
            } else if trimmed.starts_with("fatal:") || trimmed.starts_with("FAILED!") {
                logger.log(
                    LogLevel::Error,
                    "ssh_ansible_playbook",
                    serde_json::json!({"phase": "fatal", "line": trimmed}),
                );
            } else if trimmed.starts_with("changed:") {
                logger.log(
                    LogLevel::Info,
                    "ssh_ansible_playbook",
                    serde_json::json!({"phase": "changed", "line": trimmed}),
                );
            }
        }
        std::future::ready(Ok(result))
    }

    fn validate(args: &SshAnsiblePlaybookArgs, host_config: &HostConfig) -> Result<()> {
        AnsibleCommandBuilder::validate_playbook_path(&args.playbook)?;
        AnsibleCommandBuilder::refuse_jinja_in(&[
            ("inventory", args.inventory.as_deref()),
            ("limit", args.limit.as_deref()),
            ("tags", args.tags.as_deref()),
            ("skip_tags", args.skip_tags.as_deref()),
        ])?;
        if let Some(inventory) = args.inventory.as_deref() {
            AnsibleCommandBuilder::validate_inventory(inventory)?;
            AnsibleCommandBuilder::validate_inventory_choice(
                &args.host,
                inventory,
                host_config.ansible_inventories(),
            )?;
        }
        if let Some(dir) = args.working_dir.as_deref() {
            AnsibleCommandBuilder::validate_working_dir_choice(
                &args.host,
                dir,
                host_config.ansible_working_dirs(),
            )?;
        }
        AnsibleCommandBuilder::validate_vault_args(
            args.vault_password_file.as_deref(),
            args.vault_id.as_deref(),
        )?;
        // `become_user` ends up unquoted in a shell line on the targets.
        if let Some(user) = args.become_user.as_deref() {
            AnsibleCommandBuilder::validate_user_name("become_user", user)?;
        }
        if let Some(ref vars) = args.extra_vars {
            AnsibleCommandBuilder::validate_extra_vars(vars)?;
        }
        if let Some(ref cb) = args.callback {
            AnsibleCommandBuilder::validate_callback(cb)?;
        }
        Ok(())
    }
}

/// Handler for the `ssh_ansible_playbook` tool.
pub type SshAnsiblePlaybookHandler = StandardToolHandler<AnsiblePlaybookTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsiblePlaybookHandler::new();
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
        let handler = SshAnsiblePlaybookHandler::new();
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
        let handler = SshAnsiblePlaybookHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_playbook");
        assert_ne!(handler.description(), "");

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ansible_playbook");

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
            "skip_tags": "debug",
            "extra_vars": {"env": "production", "version": "1.2.3"},
            "check": true,
            "diff": true,
            "verbose": 2,
            "forks": 10,
            "become": true,
            "become_user": "root",
            "working_dir": "/opt/ansible",
            "callback": "json",
            "timeout_seconds": 600,
            "max_output": 15000
        });

        let args: SshAnsiblePlaybookArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert_eq!(args.inventory, Some("hosts.ini".to_string()));
        assert_eq!(args.limit, Some("webservers".to_string()));
        assert_eq!(args.tags, Some("deploy".to_string()));
        assert_eq!(args.skip_tags, Some("debug".to_string()));
        let extra_vars = args.extra_vars.unwrap();
        assert_eq!(extra_vars.get("env"), Some(&"production".to_string()));
        assert_eq!(extra_vars.get("version"), Some(&"1.2.3".to_string()));
        assert_eq!(args.check, Some(true));
        assert_eq!(args.diff, Some(true));
        assert_eq!(args.verbose, Some(2));
        assert_eq!(args.forks, Some(10));
        assert_eq!(args.use_become, Some(true));
        assert_eq!(args.become_user, Some("root".to_string()));
        assert_eq!(args.working_dir, Some("/opt/ansible".to_string()));
        assert_eq!(args.callback, Some("json".to_string()));
        assert_eq!(args.timeout_seconds, Some(600));
        assert_eq!(args.max_output, Some(15000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "playbook": "site.yml"
        });

        let args: SshAnsiblePlaybookArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert!(args.inventory.is_none());
        assert!(args.limit.is_none());
        assert!(args.tags.is_none());
        assert!(args.skip_tags.is_none());
        assert!(args.extra_vars.is_none());
        assert!(args.check.is_none());
        assert!(args.diff.is_none());
        assert!(args.verbose.is_none());
        assert!(args.forks.is_none());
        assert!(args.use_become.is_none());
        assert!(args.become_user.is_none());
        assert!(args.working_dir.is_none());
        assert!(args.callback.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context();

        // Missing playbook field
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1"
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
    async fn test_playbook_path_traversal_rejected() {
        let handler = SshAnsiblePlaybookHandler::new();
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

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsiblePlaybookHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("inventory"));
        assert!(properties.contains_key("limit"));
        assert!(properties.contains_key("tags"));
        assert!(properties.contains_key("skip_tags"));
        assert!(properties.contains_key("extra_vars"));
        assert!(properties.contains_key("check"));
        assert!(properties.contains_key("diff"));
        assert!(properties.contains_key("verbose"));
        assert!(properties.contains_key("forks"));
        assert!(properties.contains_key("become"));
        assert!(properties.contains_key("become_user"));
        assert!(properties.contains_key("working_dir"));
        assert!(properties.contains_key("callback"));
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
        let args: SshAnsiblePlaybookArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAnsiblePlaybookArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsiblePlaybookHandler::new();
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
            ansible: None,
        }
    }

    /// `test_host_config()` with the inventories and directory the tests name.
    fn listed_host_config() -> HostConfig {
        HostConfig {
            ansible: Some(crate::config::AnsibleHostConfig {
                inventories: vec!["hosts.ini".to_string(), "/tmp/inv".to_string()],
                working_dirs: vec!["/opt/a".to_string()],
                ..Default::default()
            }),
            ..test_host_config()
        }
    }

    #[test]
    fn test_build_command_defaults() {
        let args = SshAnsiblePlaybookArgs {
            host: "server1".to_string(),
            playbook: "site.yml".to_string(),
            inventory: None,
            limit: None,
            tags: None,
            skip_tags: None,
            extra_vars: None,
            check: None,
            diff: None,
            verbose: None,
            forks: None,
            use_become: None,
            become_user: None,
            working_dir: None,
            callback: None,
            vault_password_file: None,
            vault_id: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsiblePlaybookTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ansible-playbook"));
        assert!(cmd.contains("'site.yml'"));
    }

    #[test]
    fn test_build_command_with_inventory_limit() {
        let args = SshAnsiblePlaybookArgs {
            host: "server1".to_string(),
            playbook: "site.yml".to_string(),
            inventory: Some("hosts.ini".to_string()),
            limit: Some("webservers".to_string()),
            tags: None,
            skip_tags: None,
            extra_vars: None,
            check: None,
            diff: None,
            verbose: None,
            forks: None,
            use_become: None,
            become_user: None,
            working_dir: None,
            callback: None,
            vault_password_file: None,
            vault_id: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsiblePlaybookTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-i 'hosts.ini'"));
        assert!(cmd.contains("--limit 'webservers'"));
    }

    #[test]
    fn test_build_command_with_extra_vars() {
        let mut extra_vars = HashMap::new();
        extra_vars.insert("env".to_string(), "production".to_string());

        let args = SshAnsiblePlaybookArgs {
            host: "server1".to_string(),
            playbook: "site.yml".to_string(),
            inventory: None,
            limit: None,
            tags: None,
            skip_tags: None,
            extra_vars: Some(extra_vars),
            check: Some(true),
            diff: None,
            verbose: None,
            forks: None,
            use_become: None,
            become_user: None,
            working_dir: None,
            callback: None,
            vault_password_file: None,
            vault_id: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsiblePlaybookTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains(r#"-e '{"env":"production"}'"#));
        assert!(cmd.contains("--check"));
    }

    #[test]
    fn test_build_command_all_opts() {
        let mut extra_vars = HashMap::new();
        extra_vars.insert("version".to_string(), "1.2.3".to_string());

        let args = SshAnsiblePlaybookArgs {
            host: "server1".to_string(),
            playbook: "deploy.yml".to_string(),
            inventory: Some("hosts.ini".to_string()),
            limit: Some("webservers".to_string()),
            tags: Some("deploy".to_string()),
            skip_tags: Some("debug".to_string()),
            extra_vars: Some(extra_vars),
            check: Some(true),
            diff: Some(true),
            verbose: Some(2),
            forks: Some(10),
            use_become: Some(true),
            become_user: Some("root".to_string()),
            working_dir: Some("/opt/ansible".to_string()),
            callback: None,
            vault_password_file: None,
            vault_id: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsiblePlaybookTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("cd -- '/opt/ansible' &&"));
        assert!(cmd.contains("ansible-playbook"));
        assert!(cmd.contains("-i 'hosts.ini'"));
        assert!(cmd.contains("--limit 'webservers'"));
        assert!(cmd.contains("--tags 'deploy'"));
        assert!(cmd.contains("--skip-tags 'debug'"));
        assert!(cmd.contains("--check"));
        assert!(cmd.contains("--diff"));
        assert!(cmd.contains("-b"));
        assert!(cmd.contains("--become-user 'root'"));
    }

    /// `limit` here is `ansible-playbook --limit`, a host pattern. The reduction
    /// used to strip it, so the playbook ran on every host of the inventory.
    #[tokio::test]
    async fn the_host_pattern_reaches_the_command_that_runs() {
        let hosts = create_test_context_with_host().config.hosts.clone();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            hosts,
            crate::ssh::CommandOutput {
                exit_code: 0,
                stdout: "ok".to_string(),
                stderr: String::new(),
                duration_ms: 1,
            },
        );
        SshAnsiblePlaybookHandler::new()
            .execute(
                Some(json!({"host": "server1", "playbook": "site.yml", "limit": "web01:web02"})),
                &ctx,
            )
            .await
            .expect("the handler must run");
        let recorded = ctx.history.recent(1);
        let command = &recorded.first().expect("one history entry").command;
        assert!(
            command.contains("--limit") && command.contains("web01:web02"),
            "the host pattern must reach ansible-playbook: {command}"
        );
    }

    #[tokio::test]
    async fn test_option_like_playbook_refused() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(Some(json!({"host":"server1","playbook":"-ZQXdash"})), &ctx)
            .await;
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("playbook"), "{reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_connection_extra_vars_refused() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(Some(json!({"host":"server1","playbook":"site.yml","extra_vars":{"ansible_ssh_common_args":"x"}})), &ctx)
            .await;
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("extra_vars"), "{reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_become_user_with_jinja_is_refused() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host":"server1","playbook":"site.yml","become_user":"{{ lookup('pipe','id') }}"})),
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
    fn test_plain_become_user_still_validates() {
        let args: SshAnsiblePlaybookArgs = serde_json::from_value(
            json!({"host":"server1","playbook":"site.yml","become_user":"deploy"}),
        )
        .unwrap();
        assert!(AnsiblePlaybookTool::validate(&args, &test_host_config()).is_ok());
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
            let args: SshAnsiblePlaybookArgs = serde_json::from_value(
                json!({"host":"server1","playbook":"site.yml","become_user":user}),
            )
            .unwrap();
            let err = AnsiblePlaybookTool::validate(&args, &test_host_config()).expect_err(user);
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
            let args: SshAnsiblePlaybookArgs = serde_json::from_value(
                json!({"host":"server1","playbook":"site.yml","become_user":user}),
            )
            .unwrap();
            assert!(
                AnsiblePlaybookTool::validate(&args, &test_host_config()).is_ok(),
                "{user}"
            );
        }
    }

    #[test]
    fn test_jinja_in_play_selectors_is_refused() {
        for field in ["inventory", "limit", "tags", "skip_tags"] {
            for text in ["{{ x }}", "a{% if 1 %}", "{# c #}"] {
                let mut value = json!({"host":"server1","playbook":"site.yml"});
                value[field] = json!(text);
                let args: SshAnsiblePlaybookArgs = serde_json::from_value(value).unwrap();
                match AnsiblePlaybookTool::validate(&args, &test_host_config()) {
                    Err(BridgeError::CommandDenied { reason }) => {
                        assert!(reason.contains(field), "{field}: {reason}");
                    }
                    other => panic!("{field} {text}: expected CommandDenied, got {other:?}"),
                }
            }
        }
        let ok: SshAnsiblePlaybookArgs = serde_json::from_value(json!({
            "host":"server1","playbook":"site.yml","inventory":"hosts.ini","limit":"web*:!db1","tags":"a,b","skip_tags":"slow"
        }))
        .unwrap();
        assert!(AnsiblePlaybookTool::validate(&ok, &listed_host_config()).is_ok());
    }

    fn playbook_args(value: serde_json::Value) -> SshAnsiblePlaybookArgs {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn test_inventory_is_read_as_data() {
        let args = playbook_args(json!({
            "host": "server1", "playbook": "site.yml", "inventory": "/tmp/inv",
            "working_dir": "/opt/a", "callback": "json"
        }));
        let cmd = AnsiblePlaybookTool::build_command(&args, &test_host_config()).unwrap();
        assert_eq!(
            cmd,
            "cd -- '/opt/a' && ANSIBLE_STDOUT_CALLBACK='json' \
             ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml \
             ansible-playbook 'site.yml' -i '/tmp/inv'"
        );
        let none = playbook_args(json!({"host": "server1", "playbook": "site.yml"}));
        let cmd = AnsiblePlaybookTool::build_command(&none, &test_host_config()).unwrap();
        assert_eq!(cmd, "ansible-playbook 'site.yml'");
    }

    #[test]
    fn test_vault_files_are_guarded_after_cd_and_before_ansible() {
        let args = playbook_args(json!({
            "host": "server1", "playbook": "site.yml", "working_dir": "/opt/a",
            "vault_password_file": "pass.txt", "vault_id": "prod@keys/prod-pass"
        }));
        assert!(AnsiblePlaybookTool::validate(&args, &listed_host_config()).is_ok());
        let cmd = AnsiblePlaybookTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.starts_with(
                "cd -- '/opt/a' && if [ -f 'pass.txt' ] && [ -n \"$(find -L 'pass.txt' -prune "
            ),
            "{cmd}"
        );
        assert!(
            cmd.contains(
                "; fi && if [ -f 'keys/prod-pass' ] && [ -n \"$(find -L 'keys/prod-pass' -prune "
            ),
            "{cmd}"
        );
        assert!(
            cmd.contains("; exit 2; fi && ansible-playbook 'site.yml'"),
            "{cmd}"
        );
        assert!(
            cmd.contains("vault password file pass.txt must be a plain file"),
            "{cmd}"
        );
    }

    #[test]
    fn test_no_guard_without_a_vault_file() {
        for extra in [
            json!({}),
            json!({"vault_id": "prompt"}),
            json!({"vault_id": "a@prompt"}),
        ] {
            let mut value = json!({"host": "server1", "playbook": "site.yml"});
            if let Some(id) = extra.get("vault_id") {
                value["vault_id"] = id.clone();
            }
            let cmd =
                AnsiblePlaybookTool::build_command(&playbook_args(value), &test_host_config())
                    .unwrap();
            assert!(!cmd.contains("find -L"), "{cmd}");
            assert!(!cmd.contains("exit 2"), "{cmd}");
        }
    }

    #[test]
    fn test_dashed_inventory_and_bad_vault_arguments_are_refused() {
        for (field, value) in [
            ("inventory", "-ZQXdash"),
            ("vault_password_file", "-x"),
            ("vault_password_file", "a{%b"),
            ("vault_id", "-x"),
            ("vault_id", "p@-x"),
            ("vault_id", "p@/a\tb"),
        ] {
            let mut v = json!({"host": "server1", "playbook": "site.yml"});
            v[field] = json!(value);
            match AnsiblePlaybookTool::validate(&playbook_args(v), &test_host_config()) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains(field), "{field}: {reason}");
                }
                other => panic!("{field} {value}: expected CommandDenied, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_windows_domain_and_gmsa_become_users() {
        for user in ["CORP\\svc", "svc$"] {
            let args = playbook_args(
                json!({"host": "server1", "playbook": "site.yml", "become_user": user}),
            );
            assert!(
                AnsiblePlaybookTool::validate(&args, &test_host_config()).is_ok(),
                "{user}"
            );
        }
        let bad = playbook_args(
            json!({"host": "server1", "playbook": "site.yml", "become_user": "CORP\\"}),
        );
        assert!(AnsiblePlaybookTool::validate(&bad, &test_host_config()).is_err());
    }

    #[test]
    fn test_unlisted_inventory_is_refused_with_the_allowed_values() {
        let args = playbook_args(json!({
            "host": "server1", "playbook": "site.yml", "inventory": "evil.example.com,"
        }));
        match AnsiblePlaybookTool::validate(&args, &listed_host_config()) {
            Err(BridgeError::CommandDenied { reason }) => assert_eq!(
                reason,
                "Invalid 'inventory': 'evil.example.com,' is not one of \
                 hosts.server1.ansible.inventories ('hosts.ini', '/tmp/inv'). Ansible connects \
                 to every host the inventory names, with the SSH credentials of the account on \
                 this control host. Add it to hosts.server1.ansible.inventories in config.yaml, \
                 or leave 'inventory' out to use the inventory set in ansible.cfg."
            ),
            other => panic!("expected CommandDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_inventory_needs_an_exact_match() {
        for value in [
            "HOSTS.INI",
            "hosts.ini ",
            " hosts.ini",
            "./hosts.ini",
            "hosts.ini,x,",
        ] {
            let args = playbook_args(
                json!({"host": "server1", "playbook": "site.yml", "inventory": value}),
            );
            assert!(
                matches!(
                    AnsiblePlaybookTool::validate(&args, &listed_host_config()),
                    Err(BridgeError::CommandDenied { .. })
                ),
                "{value:?}"
            );
        }
    }

    #[test]
    fn test_inventory_and_working_dir_are_refused_without_an_ansible_section() {
        let inventory = playbook_args(
            json!({"host": "server1", "playbook": "site.yml", "inventory": "hosts.ini"}),
        );
        match AnsiblePlaybookTool::validate(&inventory, &test_host_config()) {
            Err(BridgeError::CommandDenied { reason }) => assert_eq!(
                reason,
                "Invalid 'inventory': 'hosts.ini' cannot be used: no inventory is configured for \
                 host 'server1' (hosts.server1.ansible.inventories is absent or empty), so a \
                 call cannot name one. Ansible connects to every host the inventory names, with \
                 the SSH credentials of the account on this control host. Add it to \
                 hosts.server1.ansible.inventories in config.yaml, or leave 'inventory' out to \
                 use the inventory set in ansible.cfg."
            ),
            other => panic!("expected CommandDenied, got {other:?}"),
        }
        let dir = playbook_args(
            json!({"host": "server1", "playbook": "site.yml", "working_dir": "/opt/a"}),
        );
        match AnsiblePlaybookTool::validate(&dir, &test_host_config()) {
            Err(BridgeError::CommandDenied { reason }) => {
                assert!(
                    reason.contains("hosts.server1.ansible.working_dirs"),
                    "{reason}"
                );
                assert!(reason.contains("absent or empty"), "{reason}");
            }
            other => panic!("expected CommandDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_empty_lists_refuse_every_value() {
        let config = HostConfig {
            ansible: Some(crate::config::AnsibleHostConfig::default()),
            ..test_host_config()
        };
        for field in ["inventory", "working_dir"] {
            let mut value = json!({"host": "server1", "playbook": "site.yml"});
            value[field] = json!("/opt/a");
            assert!(
                matches!(
                    AnsiblePlaybookTool::validate(&playbook_args(value), &config),
                    Err(BridgeError::CommandDenied { .. })
                ),
                "{field}"
            );
        }
    }

    #[test]
    fn test_unlisted_working_dir_is_refused_with_the_allowed_values() {
        let args = playbook_args(json!({
            "host": "server1", "playbook": "site.yml", "working_dir": "/tmp/evil"
        }));
        match AnsiblePlaybookTool::validate(&args, &listed_host_config()) {
            Err(BridgeError::CommandDenied { reason }) => assert_eq!(
                reason,
                "Invalid 'working_dir': '/tmp/evil' is not one of \
                 hosts.server1.ansible.working_dirs ('/opt/a'). An ansible.cfg in that directory \
                 sets the inventory, the remote user, the key and the plugin paths. Add it to \
                 hosts.server1.ansible.working_dirs in config.yaml, or leave 'working_dir' out \
                 and use absolute paths."
            ),
            other => panic!("expected CommandDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_listed_values_and_calls_without_them_keep_the_7_0_0_command() {
        let listed = playbook_args(json!({
            "host": "server1", "playbook": "site.yml", "inventory": "/tmp/inv",
            "working_dir": "/opt/a", "callback": "json"
        }));
        assert!(AnsiblePlaybookTool::validate(&listed, &listed_host_config()).is_ok());
        assert_eq!(
            AnsiblePlaybookTool::build_command(&listed, &listed_host_config()).unwrap(),
            "cd -- '/opt/a' && ANSIBLE_STDOUT_CALLBACK='json' \
             ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml \
             ansible-playbook 'site.yml' -i '/tmp/inv'"
        );
        let bare = playbook_args(json!({"host": "server1", "playbook": "site.yml"}));
        assert!(AnsiblePlaybookTool::validate(&bare, &test_host_config()).is_ok());
        assert_eq!(
            AnsiblePlaybookTool::build_command(&bare, &test_host_config()).unwrap(),
            "ansible-playbook 'site.yml'"
        );
    }

    #[tokio::test]
    async fn test_unlisted_inventory_is_refused_through_the_handler() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "playbook": "site.yml", "inventory": "x,"})),
                &ctx,
            )
            .await;
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(
                    reason.contains("hosts.server1.ansible.inventories"),
                    "{reason}"
                );
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_working_dir_needs_an_exact_match() {
        let ok = playbook_args(
            json!({"host": "server1", "playbook": "site.yml", "working_dir": "/opt/a"}),
        );
        assert!(AnsiblePlaybookTool::validate(&ok, &listed_host_config()).is_ok());
        for value in [
            "/opt/a/",
            "/opt/a/.",
            "/opt/./a",
            "/opt/../opt/a",
            "/opt/a/../a",
            "//opt/a",
            "/opt//a",
            "/OPT/a",
            "/opt/A",
            "/opt/a ",
            " /opt/a",
            "opt/a",
            "./opt/a",
            "~/a",
            "$HOME/a",
            "/opt/a:/opt/b",
            "/opt/ab",
            "/opt",
        ] {
            let args = playbook_args(
                json!({"host": "server1", "playbook": "site.yml", "working_dir": value}),
            );
            assert!(
                matches!(
                    AnsiblePlaybookTool::validate(&args, &listed_host_config()),
                    Err(BridgeError::CommandDenied { .. })
                ),
                "{value:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_unlisted_working_dir_is_refused_through_the_handler() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1", "playbook": "site.yml", "working_dir": "/opt/a"
                })),
                &ctx,
            )
            .await;
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(
                    reason.contains("hosts.server1.ansible.working_dirs"),
                    "{reason}"
                );
                assert!(reason.contains("absent or empty"), "{reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_says_where_the_listed_values_live() {
        let schema: serde_json::Value = serde_json::from_str(AnsiblePlaybookTool::SCHEMA).unwrap();
        let text = |field: &str| schema["properties"][field]["description"].to_string();
        assert!(text("inventory").contains("hosts.<host>.ansible.inventories"));
        assert!(text("working_dir").contains("hosts.<host>.ansible.working_dirs"));
    }
}
