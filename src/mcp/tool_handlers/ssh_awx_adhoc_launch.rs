//! Handler for the `ssh_awx_adhoc_launch` tool.
//!
//! Launches an AWX ad-hoc command against an inventory by building a `curl`
//! POST command and relaying it via SSH to the configured AWX host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_adhoc_launch` tool.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshAwxAdhocLaunchArgs {
    /// Inventory ID to run the ad-hoc command against.
    inventory: u64,
    /// Credential ID to authenticate against the target hosts.
    credential: u64,
    /// Ansible module to run (e.g. `command`, `shell`, `ping`).
    #[serde(default = "default_module_name")]
    module_name: String,
    /// Arguments passed to the module (sent in the JSON body, never the shell).
    module_args: String,
    /// Limit pattern restricting the host subset.
    #[serde(default)]
    limit: Option<String>,
    /// Verbosity level (0-5).
    #[serde(default)]
    verbosity: Option<u8>,
    /// Whether to run the command with privilege escalation.
    #[serde(default)]
    become_enabled: Option<bool>,
}

/// Whether an Ansible module executes its arguments as a command line: the
/// same list `ssh_ansible_adhoc` checks.
#[cfg(test)]
fn runs_a_command(module_name: &str) -> bool {
    crate::domain::use_cases::ansible::AnsibleCommandBuilder::runs_a_command(module_name)
}

/// Default Ansible module for an ad-hoc command.
fn default_module_name() -> String {
    "command".to_string()
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "inventory": {
            "type": "integer",
            "description": "Inventory ID to run the ad-hoc command against",
            "minimum": 1
        },
        "credential": {
            "type": "integer",
            "description": "Credential ID to authenticate against the target hosts",
            "minimum": 1
        },
        "module_name": {
            "type": "string",
            "description": "Ansible module to run (e.g. command, shell, ping)",
            "default": "command"
        },
        "module_args": {
            "type": "string",
            "description": "Arguments passed to the module (sent in the JSON body, never the shell). Refused, as in ssh_ansible_adhoc: Jinja ({{, {%, {#), the JSON form (starting with '{'), the escapes Ansible decodes (\\U and 8 hex digits, \\u and 4, \\x and 2, \\N{), the sequence \\=, a word starting with '=' that holds a backslash and, for a command module, a word starting with executable=, chdir= or stdin=."
        },
        "limit": {
            "type": "string",
            "description": "Ansible host pattern restricting the host subset (no Jinja, no leading '-')"
        },
        "verbosity": {
            "type": "integer",
            "description": "Verbosity level (0-5)",
            "minimum": 0,
            "maximum": 5
        },
        "become_enabled": {
            "type": "boolean",
            "description": "Whether to run the command with privilege escalation"
        }
    },
    "required": ["inventory", "credential", "module_args"]
}"#;

/// Handler for launching AWX ad-hoc commands.
#[mcp_tool(
    name = "ssh_awx_adhoc_launch",
    group = "awx",
    annotation = "destructive"
)]
pub struct SshAwxAdhocLaunchHandler;

impl Default for SshAwxAdhocLaunchHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxAdhocLaunchHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "execute validates, builds the AWX body and the call in one flow"
)]
#[async_trait]
impl ToolHandler for SshAwxAdhocLaunchHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_adhoc_launch"
    }

    fn description(&self) -> &'static str {
        "Launch an AWX ad-hoc command (Ansible module) against an inventory. \
         Returns the ad-hoc command ID and initial status. \
         module_args is sent in the JSON body, never interpolated into the shell; the \
         text Ansible would decode or reinterpret (Jinja, the JSON form, \\x \\u \\U \\N \
         escapes, ...) is refused."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_adhoc_launch",
            description: self.description(),
            input_schema: SCHEMA,
        }
    }

    fn output_kind(&self) -> crate::domain::output_kind::OutputKind {
        crate::domain::output_kind::OutputKind::Json
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let mut raw = args.ok_or_else(|| BridgeError::McpMissingParam {
            param: "arguments".to_string(),
        })?;
        let dr = crate::domain::data_reduction::DataReductionArgs::extract_for(
            &mut raw,
            self.name(),
            self.output_kind(),
        )?;
        let args: SshAwxAdhocLaunchArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.inventory)?;
        AwxCommandBuilder::validate_id(args.credential)?;
        // AWX hands `module_args` to the same Ansible parser as
        // `ssh_ansible_adhoc` does, so the same text is refused.
        crate::domain::use_cases::ansible::AnsibleCommandBuilder::validate_adhoc_args(
            &args.module_name,
            &args.module_args,
        )?;
        crate::domain::use_cases::ansible::AnsibleCommandBuilder::validate_adhoc_module(
            &args.module_name,
            Some(&args.module_args),
        )?;
        // `limit` is the play's host pattern, which Ansible templates; the
        // module name is a plugin name.
        crate::domain::use_cases::ansible::AnsibleCommandBuilder::refuse_jinja_in(&[
            ("limit", args.limit.as_deref()),
            ("module_name", Some(args.module_name.as_str())),
        ])?;
        if let Some(limit) = args.limit.as_deref() {
            crate::domain::use_cases::shell::refuse_option_like("limit", limit)?;
        }

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        // Build JSON body with the required fields plus any present optional ones.
        let mut body_map = serde_json::Map::new();
        body_map.insert(
            "inventory".to_string(),
            serde_json::Value::Number(args.inventory.into()),
        );
        body_map.insert(
            "credential".to_string(),
            serde_json::Value::Number(args.credential.into()),
        );
        body_map.insert(
            "module_name".to_string(),
            serde_json::Value::String(args.module_name.clone()),
        );
        body_map.insert(
            "module_args".to_string(),
            serde_json::Value::String(args.module_args.clone()),
        );
        if let Some(ref limit) = args.limit {
            body_map.insert(
                "limit".to_string(),
                serde_json::Value::String(limit.clone()),
            );
        }
        if let Some(verbosity) = args.verbosity {
            body_map.insert(
                "verbosity".to_string(),
                serde_json::Value::Number(verbosity.into()),
            );
        }
        if let Some(become_enabled) = args.become_enabled {
            body_map.insert(
                "become_enabled".to_string(),
                serde_json::Value::Bool(become_enabled),
            );
        }

        let body_str = serde_json::Value::Object(body_map).to_string();

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            "/api/v2/ad_hoc_commands/",
            HttpMethod::Post,
            Some(&body_str),
            awx.verify_ssl,
            &[],
            awx.api_timeout,
        );

        let host = &awx.ssh_host;
        let host_config = ctx
            .config
            .hosts
            .get(host)
            .ok_or_else(|| BridgeError::UnknownHost { host: host.clone() })?;
        if let Some(reason) = crate::mcp::tool_handlers::utils::awx_host_refusal(host, host_config)
        {
            ctx.execute_use_case
                .log_denied(self.name(), host, "", &reason);
            return Ok(ToolCallResult::error(reason));
        }

        // The AWX server runs `module_args` as a command on the inventory hosts
        // when the module executes one, and any other module can start a
        // program too (a package, a service). Judged as `ssh_ansible_adhoc`
        // judges them: a command module's args alone, any other module as
        // `ansible-module MODULE ARGS`; only `ping` without args is exempt.
        if let Some(text) =
            crate::domain::use_cases::ansible::AnsibleCommandBuilder::adhoc_policy_text(
                &args.module_name,
                Some(&args.module_args),
            )
        {
            crate::mcp::standard_tool::validate_free_form_command(ctx, self.name(), host, &text)?;
        }

        let limits = ctx.config.limits.clone();
        let mut conn = ctx
            .connection_pool
            .get_connection_with_jump(host, host_config, &limits, None)
            .await?;
        let output = conn.exec(&cmd, &limits).await?;

        let raw = ctx
            .execute_use_case
            .process_success(self.name(), host, &cmd, &output.into(), &dr.used_params())
            .stdout;
        let mut stdout = AwxCommandBuilder::parse_checked_response(&raw)?;
        crate::mcp::standard_tool::apply_reduction_recorded(
            ctx,
            &mut stdout,
            &dr,
            crate::domain::output_kind::OutputKind::Json,
        )?;
        Ok(ToolCallResult::text(stdout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAwxAdhocLaunchHandler;
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshAwxAdhocLaunchHandler;
        assert_eq!(handler.name(), "ssh_awx_adhoc_launch");
        assert_ne!(handler.description(), "");
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_adhoc_launch");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("inventory")));
        assert!(required.contains(&json!("credential")));
        assert!(required.contains(&json!("module_args")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "inventory": 7,
            "credential": 3,
            "module_name": "shell",
            "module_args": "uptime",
            "limit": "webservers",
            "verbosity": 2,
            "become_enabled": true
        });
        let args: SshAwxAdhocLaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.inventory, 7);
        assert_eq!(args.credential, 3);
        assert_eq!(args.module_name, "shell");
        assert_eq!(args.module_args, "uptime");
        assert_eq!(args.limit.as_deref(), Some("webservers"));
        assert_eq!(args.verbosity, Some(2));
        assert_eq!(args.become_enabled, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"inventory": 1, "credential": 2, "module_args": "whoami"});
        let args: SshAwxAdhocLaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.inventory, 1);
        assert_eq!(args.credential, 2);
        // module_name defaults to "command".
        assert_eq!(args.module_name, "command");
        assert_eq!(args.module_args, "whoami");
        assert!(args.limit.is_none());
        assert!(args.verbosity.is_none());
        assert!(args.become_enabled.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let schema_json: serde_json::Value =
            serde_json::from_str(SshAwxAdhocLaunchHandler.schema().input_schema).unwrap();
        assert!(schema_json["properties"].is_object());
        assert!(schema_json["properties"]["limit"].is_object());
        assert!(schema_json["properties"]["verbosity"].is_object());
        assert!(schema_json["properties"]["become_enabled"].is_object());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"inventory": 1, "credential": 2, "module_args": "whoami"});
        let args: SshAwxAdhocLaunchArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxAdhocLaunchArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxAdhocLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "inventory": "not_a_number",
                    "credential": 2,
                    "module_args": "whoami"
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxAdhocLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"inventory": 7, "credential": 3, "module_args": "uptime"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("AWX not configured"),
            "Expected AWX not configured error, got: {err_msg}"
        );
    }

    // ============== Task 1.3 extra tests ==============

    #[test]
    fn test_body_contains_module_args() {
        // module_args must be carried in the JSON body as a string field, never
        // interpolated into the shell command.
        let body = serde_json::json!({
            "inventory": 7,
            "credential": 3,
            "module_name": "shell",
            "module_args": "rm -rf /tmp/foo && echo done",
        });
        let body_str = body.to_string();
        let cmd = AwxCommandBuilder::build_api_call_checked(
            "https://awx.internal",
            "tok",
            "/api/v2/ad_hoc_commands/",
            HttpMethod::Post,
            Some(&body_str),
            true,
            &[],
            30,
        );
        assert!(cmd.contains("-X POST"));
        assert!(cmd.contains("module_args"));
        assert!(cmd.contains("rm -rf /tmp/foo"));
    }

    #[tokio::test]
    async fn test_validate_inventory_zero() {
        let handler = SshAwxAdhocLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"inventory": 0, "credential": 3, "module_args": "uptime"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { .. } => {}
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    /// A standard-mode context with AWX on `server1` and a whitelist.
    fn awx_whitelist_ctx(whitelist: &[&str]) -> crate::ports::ToolContext {
        let mut config = (*crate::ports::mock::create_test_context_with_host().config).clone();
        config.security.mode = crate::config::SecurityMode::Standard;
        config.security.whitelist = whitelist.iter().map(|s| (*s).to_string()).collect();
        config.awx = Some(crate::config::AwxConfig {
            ssh_host: "server1".to_string(),
            url: "https://awx.test".to_string(),
            token: crate::config::RedactedSecret::from("awx-token"),
            api_timeout: 30,
            verify_ssl: true,
        });
        crate::ports::mock::create_test_context_with_config_and_mock_executor(
            config,
            crate::ssh::CommandOutput {
                exit_code: 0,
                stdout: "{}".to_string(),
                stderr: String::new(),
                duration_ms: 1,
            },
        )
    }

    /// Any module can start a program (a package's scripts, a service), so a
    /// module that is not a command module is judged as
    /// `ansible-module MODULE ARGS`, as `ssh_ansible_adhoc` judges it.
    #[tokio::test]
    async fn every_module_but_a_bare_ping_faces_the_whitelist() {
        let ctx = awx_whitelist_ctx(&[
            "^uptime$",
            "^ansible-module service name=nginx state=started$",
        ]);
        let call = |module: &str, margs: &str| json!({"inventory": 1, "credential": 1, "module_name": module, "module_args": margs});
        for (module, margs) in [
            ("apt", "deb=http://repo.internal/x.deb"),
            ("service", "name=evil state=started"),
            ("ping", "data=x"),
            ("shell", "id"),
        ] {
            let r = SshAwxAdhocLaunchHandler
                .execute(Some(call(module, margs)), &ctx)
                .await;
            assert!(r.is_err(), "{module} {margs}: {r:?}");
        }
        for (module, margs) in [
            ("command", "uptime"),
            ("service", "name=nginx state=started"),
            ("ping", ""),
        ] {
            let r = SshAwxAdhocLaunchHandler
                .execute(Some(call(module, margs)), &ctx)
                .await;
            assert!(r.is_ok(), "{module} {margs}: {r:?}");
        }
    }

    /// `limit` is the play's host pattern, which Ansible templates.
    #[tokio::test]
    async fn the_limit_refuses_jinja_and_a_leading_dash() {
        let ctx = awx_whitelist_ctx(&["^uptime$"]);
        for limit in ["all,{{ lookup('pipe','id') }}", "-x", "web{%x%}"] {
            let r = SshAwxAdhocLaunchHandler
                .execute(
                    Some(json!({
                        "inventory": 1, "credential": 1, "module_name": "command",
                        "module_args": "uptime", "limit": limit
                    })),
                    &ctx,
                )
                .await;
            assert!(
                matches!(r, Err(BridgeError::CommandDenied { .. })),
                "{limit}: {r:?}"
            );
        }
    }

    /// `limit` on this tool is an Ansible host pattern, not a row limit. The
    /// reduction used to strip the key before the tool read it, so the job ran
    /// on the whole inventory. Read what was RUN, from the history.
    #[tokio::test]
    async fn the_host_pattern_reaches_the_command_that_runs() {
        let mut config = (*crate::ports::mock::create_test_context_with_host().config).clone();
        // `command` runs `module_args`, which faces the whitelist like `ssh_exec`.
        config.security.mode = crate::config::SecurityMode::Permissive;
        config.awx = Some(crate::config::AwxConfig {
            ssh_host: "server1".to_string(),
            url: "https://awx.test".to_string(),
            token: crate::config::RedactedSecret::from("awx-token"),
            api_timeout: 30,
            verify_ssl: true,
        });
        let ctx = crate::ports::mock::create_test_context_with_config_and_mock_executor(
            config,
            crate::ssh::CommandOutput {
                exit_code: 0,
                stdout: "{}".to_string(),
                stderr: String::new(),
                duration_ms: 1,
            },
        );
        SshAwxAdhocLaunchHandler.execute(Some(json!({"inventory": 7, "credential": 3, "module_args": "uptime", "limit": "web01:web02"})), &ctx)
            .await
            .expect("the handler must run");
        let recorded = ctx.history.recent(1);
        let command = &recorded.first().expect("one history entry").command;
        assert!(
            command.contains("limit") && command.contains("web01:web02"),
            "the host pattern must reach the launched command: {command}"
        );
    }

    #[test]
    fn runs_a_command_matches_command_modules_only() {
        for m in [
            "command",
            "shell",
            "raw",
            "script",
            "ansible.builtin.shell",
            " Shell ",
            "ansible.windows.win_powershell",
        ] {
            assert!(runs_a_command(m), "{m}");
        }
        for m in ["ping", "copy", "setup", ""] {
            assert!(!runs_a_command(m), "{m}");
        }
    }

    #[tokio::test]
    async fn a_blacklisted_command_in_module_args_is_refused() {
        let mut config = (*create_test_context_with_host().config).clone();
        config.awx = Some(crate::config::AwxConfig {
            ssh_host: "server1".to_string(),
            url: "https://awx.test".to_string(),
            token: crate::config::RedactedSecret::from("awx-token"),
            api_timeout: 30,
            verify_ssl: true,
        });
        let ctx = crate::ports::mock::create_test_context_with_config_and_mock_executor(
            config,
            crate::ssh::CommandOutput {
                exit_code: 0,
                stdout: "{}".to_string(),
                stderr: String::new(),
                duration_ms: 1,
            },
        );
        let result = SshAwxAdhocLaunchHandler
            .execute(
                Some(
                    json!({"inventory": 1, "credential": 2, "module_name": "shell",
                    "module_args": "rm -rf /"}),
                ),
                &ctx,
            )
            .await;
        assert!(
            matches!(result, Err(BridgeError::CommandDenied { .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn test_module_args_ansible_would_reinterpret_are_refused() {
        let handler = SshAwxAdhocLaunchHandler;
        let ctx = create_test_context();
        for (module, text) in [
            ("shell", "{{ lookup('pipe','id') }}"),
            ("debug", "msg={% if 1 %}x{% endif %}"),
            ("shell", "{\"_raw_params\": \"id\"}"),
            ("command", "msg=\\x41"),
            ("command", "msg=\\u0041"),
            ("copy", "content=\\U00000041"),
            ("command", "\\N{LEFT CURLY BRACKET}"),
            ("command", "a\\=b"),
            ("command", "a =b\\n"),
            ("command", "=\\tb"),
            ("command", "executable=/tmp/x id"),
            ("shell", "id chdir=/tmp"),
            ("ansible.builtin.command", "stdin=x cat"),
        ] {
            let result = handler
                .execute(
                    Some(json!({
                        "inventory": 7, "credential": 3,
                        "module_name": module, "module_args": text
                    })),
                    &ctx,
                )
                .await;
            match result {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.contains("args"), "{module} {text}: {reason}");
                }
                other => panic!("{module} {text}: expected CommandDenied, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_legitimate_module_args_pass_the_parser_checks() {
        let handler = SshAwxAdhocLaunchHandler;
        // No AWX section in this context: a call that gets past the checks of
        // the arguments stops at "AWX not configured".
        let ctx = create_test_context();
        for (module, text) in [
            ("command", "uptime"),
            ("shell", "creates=/tmp/x removes=/tmp/y warn=false uptime"),
            ("shell", "dir C:\\Users\\Public"),
            ("shell", "echo \\0 \\173"),
            ("copy", "chdir=/tmp executable=x"),
            ("service", "name=nginx state=restarted"),
        ] {
            let result = handler
                .execute(
                    Some(json!({
                        "inventory": 7, "credential": 3,
                        "module_name": module, "module_args": text
                    })),
                    &ctx,
                )
                .await;
            let err = result.expect_err("no AWX section").to_string();
            assert!(err.contains("AWX not configured"), "{module} {text}: {err}");
        }
    }
}
