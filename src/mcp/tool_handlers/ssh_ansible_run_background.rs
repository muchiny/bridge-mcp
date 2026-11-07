//! SSH Ansible Run Background Tool Handler
//!
//! Launches an Ansible playbook in the background via nohup with JSON callback,
//! returning a run ID and PID for later monitoring with `ssh_ansible_events`.

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshAnsibleRunBackgroundArgs {
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

impl_common_args!(SshAnsibleRunBackgroundArgs);

#[mcp_standard_tool(
    name = "ssh_ansible_run_background",
    group = "ansible",
    annotation = "destructive"
)]
pub struct AnsibleRunBackgroundTool;

impl StandardTool for AnsibleRunBackgroundTool {
    type Args = SshAnsibleRunBackgroundArgs;

    const NAME: &'static str = "ssh_ansible_run_background";

    const DESCRIPTION: &'static str = "Launch an Ansible playbook in the background with JSON \
        callback output. Returns a run_id and PID immediately. The playbook output is written \
        to /tmp/ansible-run-{run_id}.json on the remote host. Use ssh_ansible_events to monitor \
        progress and extract events. Use ssh_ansible_events with check_status=true and \
        pid=<pid> to check if the playbook is still running without a separate ssh_exec call.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
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
                "description": "Max output characters",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file"
            }
        },
        "required": ["host", "playbook"]
    }"#;

    fn build_command(
        args: &SshAnsibleRunBackgroundArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        let playbook_cmd = AnsibleCommandBuilder::build_playbook_command(
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
            Some("json"),
            args.vault_password_file.as_deref(),
            args.vault_id.as_deref(),
        );

        // The vault password file guards run first, in the foreground and in
        // `working_dir`, so the call itself reports a refused file (status 2,
        // message on stderr) instead of a `started` reply for a run that never
        // begins. The playbook command carries the same guards: they run again
        // right before `ansible-playbook` starts.
        let mut precheck = AnsibleCommandBuilder::vault_precheck(
            args.working_dir.as_deref(),
            args.vault_password_file.as_deref(),
            args.vault_id.as_deref(),
        );
        // Same for a host-list inventory whose name a path of the working
        // directory also has.
        precheck.push_str(&AnsibleCommandBuilder::host_list_precheck(
            args.working_dir.as_deref(),
            args.inventory.as_deref(),
        ));

        // A run ID from the date and the shell's PID. Only `nohup` goes to the
        // background: with `a && b && nohup … &` the whole list did, so the
        // `echo` saw no RUN_ID. OUTPUT_FILE is exported because the inner
        // `bash -c` expands it.
        Ok(format!(
            r#"{precheck}RUN_ID=$(date +%Y%m%d%H%M%S)_$$; export OUTPUT_FILE="/tmp/ansible-run-$RUN_ID.json"; nohup bash -c '{playbook_cmd} > "$OUTPUT_FILE" 2>&1' > /dev/null 2>&1 & PID=$!; echo '{{"run_id":"'$RUN_ID'","pid":'$PID',"output_file":"'$OUTPUT_FILE'","status":"started"}}'"#,
            playbook_cmd = playbook_cmd.replace('\'', "'\\''"),
        ))
    }

    fn validate(args: &SshAnsibleRunBackgroundArgs, host_config: &HostConfig) -> Result<()> {
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

/// Handler for the `ssh_ansible_run_background` tool.
pub type SshAnsibleRunBackgroundHandler = StandardToolHandler<AnsibleRunBackgroundTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsibleRunBackgroundHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshAnsibleRunBackgroundHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "playbook": "site.yml"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshAnsibleRunBackgroundHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_run_background");
        let schema = handler.schema();
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
            "check": true,
            "become": true
        });
        let args: SshAnsibleRunBackgroundArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert_eq!(args.check, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "playbook": "site.yml"});
        let args: SshAnsibleRunBackgroundArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert!(args.inventory.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsibleRunBackgroundHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("inventory"));
        assert!(properties.contains_key("tags"));
        assert!(properties.contains_key("become"));
        assert!(properties.contains_key("vault_password_file"));
        assert!(properties.contains_key("vault_id"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "s", "playbook": "p.yml"});
        let args: SshAnsibleRunBackgroundArgs = serde_json::from_value(json).unwrap();
        assert!(format!("{args:?}").contains("SshAnsibleRunBackgroundArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsibleRunBackgroundHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "playbook": "s"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_path_traversal_rejected() {
        let handler = SshAnsibleRunBackgroundHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "playbook": "../../etc/shadow"})),
                &ctx,
            )
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
    fn test_build_command_uses_json_callback_and_nohup() {
        let args = SshAnsibleRunBackgroundArgs {
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
            vault_password_file: None,
            vault_id: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = AnsibleRunBackgroundTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("nohup"));
        // Only `nohup` runs in the background, and the inner shell sees the
        // output file.
        assert!(cmd.contains("_$$; export OUTPUT_FILE="), "{cmd}");
        assert!(cmd.contains("2>&1 & PID=$!; echo"), "{cmd}");
        assert!(cmd.contains("ANSIBLE_STDOUT_CALLBACK"));
        assert!(cmd.contains("json"));
        assert!(cmd.contains("ansible-run-"));
        assert!(cmd.contains("run_id"));
        assert!(cmd.contains("pid"));
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
        SshAnsibleRunBackgroundHandler::new()
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
        let handler = SshAnsibleRunBackgroundHandler::new();
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
        let handler = SshAnsibleRunBackgroundHandler::new();
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
        let handler = SshAnsibleRunBackgroundHandler::new();
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
        let args: SshAnsibleRunBackgroundArgs = serde_json::from_value(
            json!({"host":"server1","playbook":"site.yml","become_user":"deploy"}),
        )
        .unwrap();
        assert!(AnsibleRunBackgroundTool::validate(&args, &test_host_config()).is_ok());
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
            let args: SshAnsibleRunBackgroundArgs = serde_json::from_value(
                json!({"host":"server1","playbook":"site.yml","become_user":user}),
            )
            .unwrap();
            let err =
                AnsibleRunBackgroundTool::validate(&args, &test_host_config()).expect_err(user);
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
            let args: SshAnsibleRunBackgroundArgs = serde_json::from_value(
                json!({"host":"server1","playbook":"site.yml","become_user":user}),
            )
            .unwrap();
            assert!(
                AnsibleRunBackgroundTool::validate(&args, &test_host_config()).is_ok(),
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
                let args: SshAnsibleRunBackgroundArgs = serde_json::from_value(value).unwrap();
                match AnsibleRunBackgroundTool::validate(&args, &test_host_config()) {
                    Err(BridgeError::CommandDenied { reason }) => {
                        assert!(reason.contains(field), "{field}: {reason}");
                    }
                    other => panic!("{field} {text}: expected CommandDenied, got {other:?}"),
                }
            }
        }
        let ok: SshAnsibleRunBackgroundArgs = serde_json::from_value(json!({
            "host":"server1","playbook":"site.yml","inventory":"hosts.ini","limit":"web*:!db1","tags":"a,b","skip_tags":"slow"
        }))
        .unwrap();
        assert!(AnsibleRunBackgroundTool::validate(&ok, &listed_host_config()).is_ok());
    }

    fn run_background_args(value: serde_json::Value) -> SshAnsibleRunBackgroundArgs {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn test_inventory_is_read_as_data_inside_the_background_shell() {
        let args = run_background_args(json!({
            "host": "server1", "playbook": "site.yml", "inventory": "/tmp/inv",
            "working_dir": "/opt/a"
        }));
        let cmd = AnsibleRunBackgroundTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.contains(
                "nohup bash -c 'cd -- '\\''/opt/a'\\'' && ANSIBLE_STDOUT_CALLBACK='\\''json'\\'' \
                 ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml \
                 ansible-playbook '\\''site.yml'\\'' -i '\\''/tmp/inv'\\'' > \"$OUTPUT_FILE\" 2>&1'"
            ),
            "{cmd}"
        );
        let none = run_background_args(json!({"host": "server1", "playbook": "site.yml"}));
        let cmd = AnsibleRunBackgroundTool::build_command(&none, &test_host_config()).unwrap();
        assert!(!cmd.contains("INVENTORY_ENABLED"), "{cmd}");
        assert!(cmd.starts_with("RUN_ID=$(date "), "{cmd}");
    }

    #[test]
    fn test_vault_guards_run_in_the_foreground_before_the_launch() {
        let args = run_background_args(json!({
            "host": "server1", "playbook": "site.yml", "working_dir": "/opt/a",
            "vault_password_file": "/etc/ansible/pass",
            "vault_id": "prod@/etc/ansible/prod-pass"
        }));
        let cmd = AnsibleRunBackgroundTool::build_command(&args, &test_host_config()).unwrap();
        // Foreground subshell in the working directory, ahead of everything.
        assert!(
            cmd.starts_with(
                "( cd -- '/opt/a' && if [ -f '/etc/ansible/pass' ] && [ -n \"$(find -L "
            ),
            "{cmd}"
        );
        let end = cmd
            .find("; fi ) || exit $?; RUN_ID=")
            .expect("precheck end");
        let launch = cmd.find("nohup bash -c '").expect("launch");
        assert!(end < launch, "{cmd}");
        assert!(
            cmd.get(..end)
                .is_some_and(|head| head.contains("; fi && if [ -f '/etc/ansible/prod-pass' ]")),
            "{cmd}"
        );
        // The same guards run again inside the background shell, quoted for it.
        assert!(
            cmd.contains(
                "nohup bash -c 'cd -- '\\''/opt/a'\\'' && if [ -f '\\''/etc/ansible/pass'\\'' ]"
            ),
            "{cmd}"
        );
        assert!(
            cmd.contains("--vault-password-file '\\''/etc/ansible/pass'\\''"),
            "{cmd}"
        );
    }

    #[test]
    fn test_vault_precheck_without_working_dir_and_without_vault_files() {
        let args = run_background_args(json!({
            "host": "server1", "playbook": "site.yml", "vault_id": "p@/v"
        }));
        let cmd = AnsibleRunBackgroundTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.starts_with("( if [ -f '/v' ] && [ -n \"$(find -L '/v' -prune "),
            "{cmd}"
        );
        assert!(cmd.contains("; fi ) || exit $?; RUN_ID=$(date "), "{cmd}");

        for vault in [
            json!({}),
            json!({"vault_id": "prompt"}),
            json!({"vault_id": "x@prompt_ask_vault_pass"}),
        ] {
            let mut value = json!({"host": "server1", "playbook": "site.yml"});
            if let Some(id) = vault.get("vault_id") {
                value["vault_id"] = id.clone();
            }
            let args = run_background_args(value);
            let cmd = AnsibleRunBackgroundTool::build_command(&args, &test_host_config()).unwrap();
            assert!(cmd.starts_with("RUN_ID=$(date "), "{cmd}");
            assert!(!cmd.contains("find -L"), "{cmd}");
        }
    }

    #[test]
    fn test_host_list_guard_runs_in_the_foreground_before_the_launch() {
        let args = run_background_args(json!({
            "host": "server1", "playbook": "site.yml",
            "inventory": "web1,web2,", "working_dir": "/opt/ansible"
        }));
        let cmd = AnsibleRunBackgroundTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.starts_with(
                "( cd -- '/opt/ansible' && if [ ! -e 'web1,web2,' ] && [ ! -L 'web1,web2,' ]; then"
            ),
            "{cmd}"
        );
        assert!(cmd.contains("; fi ) || exit $?; RUN_ID=$(date "), "{cmd}");

        let args = run_background_args(json!({
            "host": "server1", "playbook": "site.yml", "inventory": "/etc/ansible/hosts"
        }));
        let cmd = AnsibleRunBackgroundTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.starts_with("RUN_ID=$(date "), "{cmd}");
    }

    #[test]
    fn test_dashed_inventory_and_bad_vault_arguments_are_refused() {
        for (field, value) in [
            ("inventory", "-ZQXdash"),
            ("vault_password_file", "-x"),
            ("vault_password_file", "{{ x }}"),
            ("vault_id", "p@-x"),
            ("vault_id", "p@/a\nb"),
        ] {
            let mut v = json!({"host": "server1", "playbook": "site.yml"});
            v[field] = json!(value);
            let args = run_background_args(v);
            match AnsibleRunBackgroundTool::validate(&args, &test_host_config()) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains(field), "{field}: {reason}");
                }
                other => panic!("{field} {value}: expected CommandDenied, got {other:?}"),
            }
        }
        let ok = run_background_args(json!({
            "host": "server1", "playbook": "site.yml", "inventory": "hosts.ini",
            "vault_password_file": "/etc/ansible/pass", "vault_id": "prod@/etc/ansible/prod-pass",
            "become_user": "CORP\\svc"
        }));
        assert!(AnsibleRunBackgroundTool::validate(&ok, &listed_host_config()).is_ok());
    }

    #[test]
    fn test_unlisted_inventory_is_refused_with_the_allowed_values() {
        let args = run_background_args(json!({
            "host": "server1", "playbook": "site.yml", "inventory": "evil.example.com,"
        }));
        match AnsibleRunBackgroundTool::validate(&args, &listed_host_config()) {
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
        let args = run_background_args(json!({
            "host": "server1", "playbook": "site.yml", "working_dir": "/tmp/evil"
        }));
        match AnsibleRunBackgroundTool::validate(&args, &listed_host_config()) {
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
            let args = run_background_args(value);
            match AnsibleRunBackgroundTool::validate(&args, &test_host_config()) {
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
        let listed = run_background_args(json!({
            "host": "server1", "playbook": "site.yml", "inventory": "/tmp/inv",
            "working_dir": "/opt/a"
        }));
        assert!(AnsibleRunBackgroundTool::validate(&listed, &listed_host_config()).is_ok());
        let bare = run_background_args(json!({"host": "server1", "playbook": "site.yml"}));
        assert!(AnsibleRunBackgroundTool::validate(&bare, &test_host_config()).is_ok());
    }

    #[tokio::test]
    async fn test_unlisted_inventory_is_refused_through_the_handler() {
        let handler = SshAnsibleRunBackgroundHandler::new();
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
        let ok = run_background_args(
            json!({"host": "server1", "playbook": "site.yml", "working_dir": "/opt/a"}),
        );
        assert!(AnsibleRunBackgroundTool::validate(&ok, &listed_host_config()).is_ok());
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
            let args = run_background_args(
                json!({"host": "server1", "playbook": "site.yml", "working_dir": value}),
            );
            assert!(
                matches!(
                    AnsibleRunBackgroundTool::validate(&args, &listed_host_config()),
                    Err(BridgeError::CommandDenied { .. })
                ),
                "{value:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_unlisted_working_dir_is_refused_through_the_handler() {
        let handler = SshAnsibleRunBackgroundHandler::new();
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
        let schema: serde_json::Value =
            serde_json::from_str(AnsibleRunBackgroundTool::SCHEMA).unwrap();
        let text = |field: &str| schema["properties"][field]["description"].to_string();
        assert!(text("inventory").contains("hosts.<host>.ansible.inventories"));
        assert!(text("working_dir").contains("hosts.<host>.ansible.working_dirs"));
    }
}
