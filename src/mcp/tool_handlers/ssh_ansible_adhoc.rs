//! SSH Ansible Ad-Hoc Tool Handler
//!
//! Runs an Ansible ad-hoc command on a remote host via SSH.
//! Executes single modules against target hosts without a playbook.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::protocol::ToolCallResult;
use crate::mcp::standard_tool::{
    StandardTool, StandardToolHandler, impl_common_args, validate_free_form_command,
};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    vault_password_file: Option<String>,
    #[serde(default)]
    vault_id: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshAnsibleAdhocArgs);

#[mcp_standard_tool(
    name = "ssh_ansible_adhoc",
    group = "ansible",
    annotation = "destructive"
)]
pub struct AnsibleAdhocTool;

impl StandardTool for AnsibleAdhocTool {
    type Args = SshAnsibleAdhocArgs;

    const NAME: &'static str = "ssh_ansible_adhoc";

    const DESCRIPTION: &'static str = "Run an Ansible ad-hoc command on a remote host without a playbook. Execute a single \
        module (e.g., ping, shell, copy, service) against target hosts. In strict and standard \
        security mode only `ping` without arguments runs freely; any other module is checked \
        like an ssh_exec command and must match the whitelist: a module that runs a command \
        (command, shell, raw, script, ...) by its arguments, any other module as the text \
        `ansible-module <module> <args>` (`ansible-module <module>` without arguments). An \
        inventory file or directory is read as data (host list, YAML, INI or TOML), never \
        executed; a vault password file must be a plain file without execute permission. Use \
        ssh_ansible_inventory first to discover hosts. For complex multi-task automation, use \
        ssh_ansible_playbook instead. Supports check mode for dry-run. Requires Ansible \
        installed directly on the bridge host (not AWX/Tower — use ssh_awx_job_launch for \
        AWX-managed environments).";

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
                "description": "Module arguments as key=value text. For a module that runs a command (command, shell, raw, script, ...) they are checked like an ssh_exec command (whitelist); for any other module the text 'ansible-module <module> <args>' is (only 'ping' without arguments is exempt). Refused: Jinja ({{, {%, {#), the JSON form (starting with '{'), the escapes Ansible decodes (\\U and 8 hex digits, \\u and 4, \\x and 2, \\N{), the sequence \\=, a word starting with '=' that holds a backslash and, for a command module, a word starting with executable=, chdir= or stdin=. Other backslash sequences pass."
            },
            "inventory": {
                "type": "string",
                "description": "Inventory file, directory or comma-separated host list. Read as data (host list, YAML, INI, TOML), never executed; must not start with '-'"
            },
            "become": {
                "type": "boolean",
                "description": "Escalate with sudo"
            },
            "become_user": {
                "type": "string",
                "description": "User to become (letters, digits, '_', '.', '@', '-'; max 64; no leading '-'; optional DOMAIN\\ prefix and trailing '$')"
            },
            "user": {
                "type": "string",
                "description": "Remote SSH user (letters, digits, '_', '.', '@', '-'; max 64; no leading '-'; optional DOMAIN\\ prefix and trailing '$')"
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
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool. Useful for large host groups producing verbose output."
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
            args.vault_password_file.as_deref(),
            args.vault_id.as_deref(),
        ))
    }

    fn validate(args: &SshAnsibleAdhocArgs, _host_config: &HostConfig) -> Result<()> {
        AnsibleCommandBuilder::validate_pattern(&args.pattern)?;
        AnsibleCommandBuilder::validate_adhoc_module(&args.module, args.args.as_deref())?;
        // Ansible templates these on the control host (the SSH host): a
        // `{{ lookup('pipe', ...) }}` runs a command there, for any module.
        AnsibleCommandBuilder::refuse_jinja_in(&[
            ("pattern", Some(args.pattern.as_str())),
            ("module", Some(args.module.as_str())),
            ("inventory", args.inventory.as_deref()),
        ])?;
        if let Some(inventory) = args.inventory.as_deref() {
            AnsibleCommandBuilder::validate_inventory(inventory)?;
        }
        AnsibleCommandBuilder::validate_vault_args(
            args.vault_password_file.as_deref(),
            args.vault_id.as_deref(),
        )?;
        if let Some(a) = args.args.as_deref() {
            AnsibleCommandBuilder::validate_adhoc_args(&args.module, a)?;
        }
        // `become_user` and `user` end up unquoted in a shell line on the targets.
        if let Some(user) = args.become_user.as_deref() {
            AnsibleCommandBuilder::validate_user_name("become_user", user)?;
        }
        if let Some(user) = args.user.as_deref() {
            AnsibleCommandBuilder::validate_user_name("user", user)?;
        }
        Ok(())
    }

    /// Judge the module like an `ssh_exec` command, whitelist included.
    ///
    /// A module that runs a command line (`shell`, `command`, `raw`, `script`,
    /// ...) executes `args` as one, on the SSH host with the implicit
    /// `localhost`: `args` is judged. Every other module (`cron`, `pip`, `at`,
    /// ... can start any program) is judged as `"ansible-module {module}
    /// {args}"`, so in strict and standard mode it must be whitelisted
    /// explicitly, by a pattern that names `ansible-module`. `ping` without
    /// `args` is the one exemption.
    fn pre_execute(
        args: &SshAnsibleAdhocArgs,
        ctx: &ToolContext,
    ) -> impl std::future::Future<Output = Result<Option<ToolCallResult>>> + Send {
        let verdict =
            match AnsibleCommandBuilder::adhoc_policy_text(&args.module, args.args.as_deref()) {
                Some(text) => validate_free_form_command(ctx, Self::NAME, &args.host, &text),
                None => Ok(()),
            };
        std::future::ready(verdict.map(|()| None))
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
        assert_ne!(handler.description(), "");

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
        assert!(properties.contains_key("vault_password_file"));
        assert!(properties.contains_key("vault_id"));
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
            vault_password_file: None,
            vault_id: None,
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
            vault_password_file: None,
            vault_id: None,
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
            vault_password_file: None,
            vault_id: None,
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

    #[tokio::test]
    async fn test_option_like_pattern_refused() {
        let handler = SshAnsibleAdhocHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host":"server1","pattern":"-ZQXdash","module":"ping"})),
                &ctx,
            )
            .await;
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("pattern"), "{reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    fn adhoc_args(value: serde_json::Value) -> SshAnsibleAdhocArgs {
        serde_json::from_value(value).unwrap()
    }

    #[tokio::test]
    async fn test_shell_args_outside_the_whitelist_are_refused() {
        let ctx = crate::ports::mock::create_test_context_with_whitelist(&["^uptime$"]);
        for module in [
            "shell",
            "ansible.builtin.shell",
            "ansible.legacy.raw",
            "script",
        ] {
            let args = adhoc_args(json!({
                "host": "server1", "pattern": "localhost", "module": module, "args": "id > /tmp/x"
            }));
            let result = AnsibleAdhocTool::pre_execute(&args, &ctx).await;
            assert!(
                matches!(result, Err(BridgeError::CommandDenied { .. })),
                "{module}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_whitelisted_shell_args_and_bare_ping_pass() {
        let ctx = crate::ports::mock::create_test_context_with_whitelist(&["^uptime$"]);
        let shell = adhoc_args(json!({
            "host": "server1", "pattern": "all", "module": "ansible.builtin.shell",
            "args": "uptime"
        }));
        let result = AnsibleAdhocTool::pre_execute(&shell, &ctx).await;
        assert!(matches!(result, Ok(None)), "{result:?}");
        for module in ["ping", "ansible.builtin.ping", "PING"] {
            for extra in [json!({}), json!({"args": "  "})] {
                let mut value = json!({"host": "server1", "pattern": "all", "module": module});
                if let Some(a) = extra.get("args") {
                    value["args"] = a.clone();
                }
                let ping = adhoc_args(value);
                let result = AnsibleAdhocTool::pre_execute(&ping, &ctx).await;
                assert!(matches!(result, Ok(None)), "{module}: {result:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_other_modules_need_the_whitelist() {
        let ctx = crate::ports::mock::create_test_context_with_whitelist(&[
            "^uptime$",
            "^ansible-module service name=nginx state=restarted$",
            "^ansible-module setup$",
        ]);
        // Not whitelisted: refused, command-spawning ones included.
        for (module, text) in [
            (
                "ansible.builtin.cron",
                Some("name=x minute=* job=\"id > /tmp/x\""),
            ),
            (
                "ansible.builtin.pip",
                Some("virtualenv=/tmp/v virtualenv_command=\"sh -c id\""),
            ),
            ("debug", Some("var=lookup")),
            ("ping", Some("data=x")),
            ("service", Some("name=sshd state=stopped")),
            ("at", None),
        ] {
            let mut value = json!({"host": "server1", "pattern": "localhost", "module": module});
            if let Some(t) = text {
                value["args"] = json!(t);
            }
            let args = adhoc_args(value);
            let result = AnsibleAdhocTool::pre_execute(&args, &ctx).await;
            assert!(
                matches!(result, Err(BridgeError::CommandDenied { .. })),
                "{module}: {result:?}"
            );
        }
        // Whitelisted as "ansible-module <module> <args>" (or the bare module):
        // accepted.
        let service = adhoc_args(json!({
            "host": "server1", "pattern": "all", "module": "service",
            "args": "name=nginx state=restarted"
        }));
        let result = AnsibleAdhocTool::pre_execute(&service, &ctx).await;
        assert!(matches!(result, Ok(None)), "{result:?}");
        let setup = adhoc_args(json!({"host": "server1", "pattern": "all", "module": "setup"}));
        let result = AnsibleAdhocTool::pre_execute(&setup, &ctx).await;
        assert!(matches!(result, Ok(None)), "{result:?}");
    }

    #[tokio::test]
    async fn test_permissive_mode_still_runs_other_modules() {
        let base = create_test_context_with_host();
        let mut config = (*base.config).clone();
        config.security.mode = crate::config::SecurityMode::Permissive;
        let ctx = crate::ports::mock::create_test_context_with_config(config);
        let service = adhoc_args(json!({
            "host": "server1", "pattern": "all", "module": "service",
            "args": "name=nginx state=restarted"
        }));
        let result = AnsibleAdhocTool::pre_execute(&service, &ctx).await;
        assert!(matches!(result, Ok(None)), "{result:?}");
    }

    #[test]
    fn test_json_form_and_decoded_escapes_in_args_are_refused() {
        for text in [
            r#"{"msg": "\u007b\u007b lookup('pipe','id') \u007d\u007d"}"#,
            r#"  {"_raw_params": "id"}"#,
            r"msg=\x7b\x7b",
            r"msg=\u007b",
            r"msg=\U0000007b",
            r"msg=\N{LEFT CURLY BRACKET}",
            r"a\=b",
            r"msg=a =b\\n",
        ] {
            let args = adhoc_args(json!({
                "host": "server1", "pattern": "all", "module": "debug", "args": text
            }));
            match AnsibleAdhocTool::validate(&args, &test_host_config()) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains("args"), "{text}: {reason}");
                }
                other => panic!("{text}: expected CommandDenied, got {other:?}"),
            }
        }
        for text in [
            "name=nginx state=restarted",
            "msg='a b'",
            r"msg=line\nnext",
            r"path=C:\dir\file",
            r"msg=\173",
            r"msg=\0",
            r"dir C:\x\y",
            "uptime | grep up",
        ] {
            let args = adhoc_args(json!({
                "host": "server1", "pattern": "all", "module": "shell", "args": text
            }));
            assert!(
                AnsibleAdhocTool::validate(&args, &test_host_config()).is_ok(),
                "{text}"
            );
        }
    }

    #[test]
    fn test_users_with_shell_syntax_are_refused() {
        for field in ["become_user", "user"] {
            for name in [
                "root; id",
                "root && id",
                "root id",
                "$(id)",
                "-u",
                "",
                "a|b",
                "r\nx",
            ] {
                let mut value = json!({"host": "server1", "pattern": "all", "module": "ping"});
                value[field] = json!(name);
                let args = adhoc_args(value);
                match AnsibleAdhocTool::validate(&args, &test_host_config()) {
                    Err(BridgeError::CommandDenied { reason }) => {
                        assert!(reason.contains(field), "{field} {name}: {reason}");
                    }
                    other => panic!("{field} {name}: expected CommandDenied, got {other:?}"),
                }
            }
            let mut value = json!({"host": "server1", "pattern": "all", "module": "ping"});
            value[field] = json!("deploy.ops@corp-1");
            let ok = adhoc_args(value);
            assert!(AnsibleAdhocTool::validate(&ok, &test_host_config()).is_ok());
        }
    }

    #[test]
    fn test_jinja_in_play_strings_is_refused() {
        for field in ["pattern", "module", "inventory"] {
            let mut value = json!({"host": "server1", "pattern": "all", "module": "ping"});
            value[field] = json!("{{ lookup('pipe','id') }}");
            let args = adhoc_args(value);
            match AnsibleAdhocTool::validate(&args, &test_host_config()) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains(field), "{field}: {reason}");
                }
                other => panic!("{field}: expected CommandDenied, got {other:?}"),
            }
        }
        let ok = adhoc_args(json!({
            "host": "server1", "pattern": "web*:!db1", "module": "ansible.builtin.ping",
            "inventory": "hosts.ini"
        }));
        assert!(AnsibleAdhocTool::validate(&ok, &test_host_config()).is_ok());
    }

    #[tokio::test]
    async fn test_jinja_in_args_is_refused_for_every_module() {
        let handler = SshAnsibleAdhocHandler::new();
        let ctx = create_test_context_with_host();
        for (module, text) in [
            ("debug", "msg={{ lookup('pipe','id') }}"),
            ("ping", "data={% if 1 %}x{% endif %}"),
            ("ansible.builtin.shell", "{# c #}uptime"),
        ] {
            let result = handler
                .execute(
                    Some(json!({
                        "host": "server1", "pattern": "localhost",
                        "module": module, "args": text
                    })),
                    &ctx,
                )
                .await;
            match result.unwrap_err() {
                BridgeError::CommandDenied { reason } => {
                    assert!(reason.contains("args"), "{reason}");
                }
                e => panic!("Expected CommandDenied, got: {e:?}"),
            }
        }
    }

    #[test]
    fn test_jinja_in_users_is_refused_and_plain_values_pass() {
        let bad = adhoc_args(json!({
            "host": "server1", "pattern": "all", "module": "ping",
            "become_user": "{{ lookup('pipe','id') }}"
        }));
        assert!(AnsibleAdhocTool::validate(&bad, &test_host_config()).is_err());
        let bad = adhoc_args(json!({
            "host": "server1", "pattern": "all", "module": "ping", "user": "{{ x }}"
        }));
        assert!(AnsibleAdhocTool::validate(&bad, &test_host_config()).is_err());
        let ok = adhoc_args(json!({
            "host": "server1", "pattern": "all", "module": "service",
            "args": "name=nginx state=restarted", "become_user": "root", "user": "deploy"
        }));
        assert!(AnsibleAdhocTool::validate(&ok, &test_host_config()).is_ok());
    }

    #[tokio::test]
    async fn test_a_whitelist_for_the_bare_module_text_does_not_cover_the_module() {
        // The text a module is judged by starts with `ansible-module`, so a
        // pattern written for a shell command line does not let it through.
        let ctx = crate::ports::mock::create_test_context_with_whitelist(&[
            "^service name=nginx state=restarted$",
            "^setup$",
            "^ansible-module ansible.builtin.cron name=x$",
        ]);
        for (module, text) in [
            ("service", Some("name=nginx state=restarted")),
            ("setup", None),
            ("ansible.builtin.cron", Some("name=x job=id")),
        ] {
            let mut value = json!({"host": "server1", "pattern": "all", "module": module});
            if let Some(t) = text {
                value["args"] = json!(t);
            }
            let args = adhoc_args(value);
            let result = AnsibleAdhocTool::pre_execute(&args, &ctx).await;
            assert!(
                matches!(result, Err(BridgeError::CommandDenied { .. })),
                "{module}: {result:?}"
            );
        }
        let ok = adhoc_args(json!({
            "host": "server1", "pattern": "all", "module": "ansible.builtin.cron",
            "args": " name=x "
        }));
        let result = AnsibleAdhocTool::pre_execute(&ok, &ctx).await;
        assert!(matches!(result, Ok(None)), "{result:?}");
    }

    #[test]
    fn test_command_module_options_and_word_leading_equals_are_refused() {
        let denied = |module: &str, text: &str| {
            let args = adhoc_args(json!({
                "host": "server1", "pattern": "all", "module": module, "args": text
            }));
            AnsibleAdhocTool::validate(&args, &test_host_config())
        };
        for text in [
            "executable=/tmp/x echo hi",
            "echo hi chdir=/tmp",
            "stdin=x cat",
            "echo a\nexecutable=/bin/sh",
        ] {
            assert!(
                matches!(
                    denied("ansible.builtin.shell", text),
                    Err(BridgeError::CommandDenied { .. })
                ),
                "{text}"
            );
            // Other modules take `chdir`, `executable` and `stdin` as parameters.
            assert!(denied("copy", text).is_ok(), "{text}");
        }
        for text in [
            "creates=/tmp/x uptime",
            "removes=/tmp/x true",
            "warn=false id",
        ] {
            assert!(denied("shell", text).is_ok(), "{text}");
        }
        for module in ["shell", "copy"] {
            assert!(denied(module, "x =y\\n").is_err(), "{module}");
            assert!(denied(module, "=\\ty").is_err(), "{module}");
            assert!(denied(module, "[ a = b ]").is_ok(), "{module}");
            assert!(denied(module, "x\\=y").is_err(), "{module}");
        }
    }

    #[test]
    fn test_inventory_is_read_as_data_and_never_starts_with_a_dash() {
        let args = adhoc_args(json!({
            "host": "server1", "pattern": "all", "module": "ping", "inventory": "/tmp/inv"
        }));
        let cmd = AnsibleAdhocTool::build_command(&args, &test_host_config()).unwrap();
        assert_eq!(
            cmd,
            "ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml ansible 'all' -m 'ping' -i '/tmp/inv'"
        );
        let none = adhoc_args(json!({"host": "server1", "pattern": "all", "module": "ping"}));
        let cmd = AnsibleAdhocTool::build_command(&none, &test_host_config()).unwrap();
        assert_eq!(cmd, "ansible 'all' -m 'ping'");

        let dashed = adhoc_args(json!({
            "host": "server1", "pattern": "all", "module": "ping", "inventory": "-ZQXdash"
        }));
        match AnsibleAdhocTool::validate(&dashed, &test_host_config()) {
            Err(BridgeError::CommandDenied { reason }) => {
                assert!(reason.contains("inventory"), "{reason}");
            }
            other => panic!("expected CommandDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_vault_files_are_guarded_and_vault_arguments_checked() {
        let args = adhoc_args(json!({
            "host": "server1", "pattern": "all", "module": "ping",
            "vault_password_file": "/etc/ansible/pass",
            "vault_id": "prod@/etc/ansible/prod-pass"
        }));
        assert!(AnsibleAdhocTool::validate(&args, &test_host_config()).is_ok());
        let cmd = AnsibleAdhocTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.starts_with("if [ -f '/etc/ansible/pass' ] && [ -n \"$(find -L "),
            "{cmd}"
        );
        assert!(
            cmd.contains("; fi && if [ -f '/etc/ansible/prod-pass' ] && "),
            "{cmd}"
        );
        assert!(
            cmd.contains("; exit 2; fi && ansible 'all' -m 'ping'"),
            "{cmd}"
        );
        assert!(cmd.ends_with(
            "--vault-password-file '/etc/ansible/pass' --vault-id 'prod@/etc/ansible/prod-pass'"
        ));

        let prompt = adhoc_args(json!({
            "host": "server1", "pattern": "all", "module": "ping", "vault_id": "dev@prompt"
        }));
        let cmd = AnsibleAdhocTool::build_command(&prompt, &test_host_config()).unwrap();
        assert_eq!(cmd, "ansible 'all' -m 'ping' --vault-id 'dev@prompt'");

        for (field, value) in [
            ("vault_password_file", "-x"),
            ("vault_password_file", "{{ x }}"),
            ("vault_id", "p@-x"),
            ("vault_id", "p@/a\nb"),
        ] {
            let mut v = json!({"host": "server1", "pattern": "all", "module": "ping"});
            v[field] = json!(value);
            let bad = adhoc_args(v);
            match AnsibleAdhocTool::validate(&bad, &test_host_config()) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains(field), "{field}: {reason}");
                }
                other => panic!("{field} {value}: expected CommandDenied, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_windows_domain_and_gmsa_users_pass() {
        for field in ["become_user", "user"] {
            for name in ["CORP\\svc", "svc$", "corp.example.com\\gmsa-web$"] {
                let mut value = json!({"host": "server1", "pattern": "all", "module": "ping"});
                value[field] = json!(name);
                let ok = adhoc_args(value);
                assert!(
                    AnsibleAdhocTool::validate(&ok, &test_host_config()).is_ok(),
                    "{field} {name}"
                );
            }
            for name in ["CORP\\", "\\svc", "svc$x", "a\\b\\c", "CORP;x\\svc"] {
                let mut value = json!({"host": "server1", "pattern": "all", "module": "ping"});
                value[field] = json!(name);
                let bad = adhoc_args(value);
                assert!(
                    AnsibleAdhocTool::validate(&bad, &test_host_config()).is_err(),
                    "{field} {name}"
                );
            }
        }
    }
}
