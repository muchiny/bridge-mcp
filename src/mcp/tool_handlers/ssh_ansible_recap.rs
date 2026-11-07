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
#[serde(deny_unknown_fields)]
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

#[mcp_standard_tool(
    name = "ssh_ansible_recap",
    group = "ansible",
    annotation = "destructive"
)]
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

    fn validate(args: &SshAnsibleRecapArgs, host_config: &HostConfig) -> Result<()> {
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
        assert_ne!(handler.description(), "");

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

    /// `limit` here is `--limit`, a host pattern. The reduction used to strip
    /// it, so the playbook ran on every host of the inventory.
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
        SshAnsibleRecapHandler::new()
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
            "the host pattern must reach ansible: {command}"
        );
    }

    #[tokio::test]
    async fn test_option_like_playbook_refused() {
        let handler = SshAnsibleRecapHandler::new();
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
        let handler = SshAnsibleRecapHandler::new();
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
        let handler = SshAnsibleRecapHandler::new();
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
        let args: SshAnsibleRecapArgs = serde_json::from_value(
            json!({"host":"server1","playbook":"site.yml","become_user":"deploy"}),
        )
        .unwrap();
        assert!(AnsibleRecapTool::validate(&args, &test_host_config()).is_ok());
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
            let args: SshAnsibleRecapArgs = serde_json::from_value(
                json!({"host":"server1","playbook":"site.yml","become_user":user}),
            )
            .unwrap();
            let err = AnsibleRecapTool::validate(&args, &test_host_config()).expect_err(user);
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
            let args: SshAnsibleRecapArgs = serde_json::from_value(
                json!({"host":"server1","playbook":"site.yml","become_user":user}),
            )
            .unwrap();
            assert!(
                AnsibleRecapTool::validate(&args, &test_host_config()).is_ok(),
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
                let args: SshAnsibleRecapArgs = serde_json::from_value(value).unwrap();
                match AnsibleRecapTool::validate(&args, &test_host_config()) {
                    Err(BridgeError::CommandDenied { reason }) => {
                        assert!(reason.contains(field), "{field}: {reason}");
                    }
                    other => panic!("{field} {text}: expected CommandDenied, got {other:?}"),
                }
            }
        }
        let ok: SshAnsibleRecapArgs = serde_json::from_value(json!({
            "host":"server1","playbook":"site.yml","inventory":"hosts.ini","limit":"web*:!db1","tags":"a,b","skip_tags":"slow"
        }))
        .unwrap();
        assert!(AnsibleRecapTool::validate(&ok, &listed_host_config()).is_ok());
    }

    fn recap_args(value: serde_json::Value) -> SshAnsibleRecapArgs {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn test_inventory_is_read_as_data() {
        let args = recap_args(json!({
            "host": "server1", "playbook": "site.yml", "inventory": "/tmp/inv",
            "working_dir": "/opt/a"
        }));
        let cmd = AnsibleRecapTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.starts_with(
                "cd -- '/opt/a' && ANSIBLE_STDOUT_CALLBACK='dense' \
                 ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml \
                 ansible-playbook 'site.yml' -i '/tmp/inv' 2>&1 | grep -E "
            ),
            "{cmd}"
        );
        let none = recap_args(json!({"host": "server1", "playbook": "site.yml"}));
        let cmd = AnsibleRecapTool::build_command(&none, &test_host_config()).unwrap();
        assert!(!cmd.contains("INVENTORY_ENABLED"), "{cmd}");
    }

    #[test]
    fn test_vault_files_are_guarded_before_the_pipeline() {
        let args = recap_args(json!({
            "host": "server1", "playbook": "site.yml", "working_dir": "/opt/a",
            "vault_password_file": "/etc/ansible/pass", "vault_id": "prod@/etc/ansible/prod-pass"
        }));
        assert!(AnsibleRecapTool::validate(&args, &listed_host_config()).is_ok());
        let cmd = AnsibleRecapTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.starts_with("cd -- '/opt/a' && if [ -f '/etc/ansible/pass' ] && [ -n \"$(find -L "),
            "{cmd}"
        );
        assert!(
            cmd.contains("; fi && if [ -f '/etc/ansible/prod-pass' ] && "),
            "{cmd}"
        );
        // The guards chain into the command; the pipe applies to ansible only.
        let guard_end = cmd.rfind("; exit 2; fi && ").expect("last guard");
        let pipe = cmd.find(" 2>&1 | grep -E ").expect("pipe");
        assert!(guard_end < pipe, "{cmd}");
        assert!(cmd.ends_with("; true"), "{cmd}");
    }

    #[test]
    fn test_no_guard_without_a_vault_file() {
        let args = recap_args(
            json!({"host": "server1", "playbook": "site.yml", "vault_id": "dev@prompt"}),
        );
        let cmd = AnsibleRecapTool::build_command(&args, &test_host_config()).unwrap();
        assert!(!cmd.contains("find -L"), "{cmd}");
        assert!(cmd.contains("--vault-id 'dev@prompt'"), "{cmd}");
    }

    #[test]
    fn test_dashed_inventory_and_bad_vault_arguments_are_refused() {
        for (field, value) in [
            ("inventory", "-ZQXdash"),
            ("vault_password_file", "-x"),
            ("vault_password_file", "{# x #}"),
            ("vault_id", "p@-x"),
            ("vault_id", "p@/a\rb"),
        ] {
            let mut v = json!({"host": "server1", "playbook": "site.yml"});
            v[field] = json!(value);
            match AnsibleRecapTool::validate(&recap_args(v), &test_host_config()) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains(field), "{field}: {reason}");
                }
                other => panic!("{field} {value}: expected CommandDenied, got {other:?}"),
            }
        }
        let ok = recap_args(json!({
            "host": "server1", "playbook": "site.yml", "become_user": "CORP\\svc$"
        }));
        assert!(AnsibleRecapTool::validate(&ok, &test_host_config()).is_ok());
    }

    #[test]
    fn test_unlisted_inventory_is_refused_with_the_allowed_values() {
        let args = recap_args(json!({
            "host": "server1", "playbook": "site.yml", "inventory": "evil.example.com,"
        }));
        match AnsibleRecapTool::validate(&args, &listed_host_config()) {
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
    fn test_unlisted_working_dir_is_refused_with_the_allowed_values() {
        let args = recap_args(json!({
            "host": "server1", "playbook": "site.yml", "working_dir": "/tmp/evil"
        }));
        match AnsibleRecapTool::validate(&args, &listed_host_config()) {
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
    fn test_inventory_and_working_dir_are_refused_without_an_ansible_section() {
        for (field, key) in [
            ("inventory", "inventories"),
            ("working_dir", "working_dirs"),
        ] {
            let mut value = json!({"host": "server1", "playbook": "site.yml"});
            value[field] = json!("/opt/a");
            match AnsibleRecapTool::validate(&recap_args(value), &test_host_config()) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(
                        reason.contains(&format!("hosts.server1.ansible.{key}")),
                        "{reason}"
                    );
                    assert!(reason.contains("absent or empty"), "{reason}");
                }
                other => panic!("{field}: expected CommandDenied, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_listed_values_and_calls_without_them_pass() {
        let listed = recap_args(json!({
            "host": "server1", "playbook": "site.yml", "inventory": "/tmp/inv",
            "working_dir": "/opt/a"
        }));
        assert!(AnsibleRecapTool::validate(&listed, &listed_host_config()).is_ok());
        let bare = recap_args(json!({"host": "server1", "playbook": "site.yml"}));
        assert!(AnsibleRecapTool::validate(&bare, &test_host_config()).is_ok());
    }

    #[tokio::test]
    async fn test_unlisted_inventory_is_refused_through_the_handler() {
        let handler = SshAnsibleRecapHandler::new();
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
        let ok =
            recap_args(json!({"host": "server1", "playbook": "site.yml", "working_dir": "/opt/a"}));
        assert!(AnsibleRecapTool::validate(&ok, &listed_host_config()).is_ok());
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
            let args = recap_args(
                json!({"host": "server1", "playbook": "site.yml", "working_dir": value}),
            );
            assert!(
                matches!(
                    AnsibleRecapTool::validate(&args, &listed_host_config()),
                    Err(BridgeError::CommandDenied { .. })
                ),
                "{value:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_unlisted_working_dir_is_refused_through_the_handler() {
        let handler = SshAnsibleRecapHandler::new();
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
        let schema: serde_json::Value = serde_json::from_str(AnsibleRecapTool::SCHEMA).unwrap();
        let text = |field: &str| schema["properties"][field]["description"].to_string();
        assert!(text("inventory").contains("hosts.<host>.ansible.inventories"));
        assert!(text("working_dir").contains("hosts.<host>.ansible.working_dirs"));
    }
}
