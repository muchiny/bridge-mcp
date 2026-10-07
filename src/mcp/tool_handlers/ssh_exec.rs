//! SSH Exec Tool Handler
//!
//! Executes commands on remote hosts via SSH.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};

use crate::domain::output_truncator::truncate_output_with_cache;
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::ssh::{is_retryable_error_for, with_retry_if};

use crate::config::ShellType;
use crate::domain::use_cases::shell;

/// Arguments for `ssh_exec` tool
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshExecArgs {
    host: String,
    command: String,
    timeout_seconds: Option<u64>,
    working_dir: Option<String>,
    #[serde(default)]
    max_output: Option<u64>,
    sudo: Option<bool>,
    sudo_user: Option<String>,
    save_output: Option<String>,
}

/// SSH Exec tool handler
#[mcp_tool(name = "ssh_exec", group = "core", annotation = "destructive")]
pub struct SshExecHandler;

impl SshExecHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "command": {
                "type": "string",
                "description": "The command to execute on the remote host"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "working_dir": {
                "type": "string",
                "description": "Optional working directory for the command"
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 40000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            },
            "sudo": {
                "type": "boolean",
                "description": "Run the command with sudo (default: false)"
            },
            "sudo_user": {
                "type": "string",
                "description": "User to run sudo as (default: root)"
            }
        },
        "required": ["host", "command"]
    }"#;
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl ToolHandler for SshExecHandler {
    fn name(&self) -> &'static str {
        "ssh_exec"
    }

    fn description(&self) -> &'static str {
        "Execute an arbitrary command on a remote host via SSH. Returns plain text with stdout, \
         stderr, and exit code. Use ssh_status first to discover available host aliases. \
         IMPORTANT: Prefer specialized tools over ssh_exec when available — they provide \
         structured output, safe parameter handling, and better error reporting: ssh_ls (list \
         files), ssh_find (search files), ssh_tail (read logs), ssh_process_list (ps), \
         ssh_service_status (systemd), ssh_docker_ps (containers), ssh_k8s_get (kubernetes), \
         ssh_metrics (system stats), ssh_git_status (git). Use ssh_exec only for ad-hoc \
         commands not covered by a specific tool. For multi-step workflows with shared state, \
         use ssh_session_create + ssh_session_exec. For parallel execution across hosts, \
         use ssh_exec_multi."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshExecArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        // Get host config
        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        // Validate command against whitelist/blacklist using the use case
        if let Err(e) = ctx.execute_use_case.validate(&args.command) {
            let reason = match &e {
                BridgeError::CommandDenied { reason } => reason.clone(),
                _ => e.to_string(),
            };
            ctx.execute_use_case
                .log_denied(self.name(), &args.host, &args.command, &reason);
            return Err(e);
        }

        // Check rate limit for this host
        if ctx.rate_limiter.check(&args.host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{}'. Please wait before sending more requests.",
                args.host
            )));
        }

        info!(
            host = %args.host,
            command = %args.command,
            "Executing SSH command"
        );

        // Build limits with optional timeout override
        let mut limits = ctx.config.limits.clone();
        if let Some(timeout) = args.timeout_seconds {
            limits.command_timeout_seconds = timeout;
        }

        // Derive effective shell for this host
        let effective_shell = host_config.effective_shell();

        // L'élévation est une décision du domaine : `privilege::elevate*`
        // enveloppe la ligne entière (`sudo -n bash -c '<tout>'`). La préfixer
        // ici n'élèverait que le premier processus — voir la documentation de
        // `domain::privilege::elevate`.
        let elevated = if effective_shell == ShellType::Posix {
            let privilege = crate::domain::privilege::PrivilegeArgs {
                sudo: args.sudo.unwrap_or(false),
                sudo_user: args.sudo_user.clone(),
            };
            // Only asked when elevation is: the helper warns on a non-SSH host,
            // and that must not fire on calls that never wanted sudo.
            let password = if privilege.sudo {
                host_config.sudo_password_for_exec(&args.host)
            } else {
                None
            };
            crate::domain::privilege::elevate_with_password(&args.command, &privilege, password)
        } else {
            // `sudo` n'a pas de sens hors POSIX. Avant, la ligne POSIX
            // échouait bruyamment ; l'ignorer en silence ferait réussir une
            // commande non élevée. Même intention que l'étape 5b de
            // `standard_tool.rs`, mais ni la condition ni le libellé ne sont
            // les siens : 5b teste l'OS (`os_type == Windows`), ici on teste
            // le shell effectif, qu'un `shell:` peut rendre non POSIX sur un
            // hôte Linux.
            if args.sudo.unwrap_or(false) {
                // Le shell effectif, pas l'OS : un hôte Linux avec `shell:`
                // non POSIX atteint aussi cette branche.
                return Ok(ToolCallResult::error(format!(
                    "'sudo' requires a POSIX shell; host '{}' uses '{}'.",
                    args.host,
                    format!("{effective_shell:?}").to_lowercase()
                )));
            }
            crate::domain::privilege::Elevated {
                command: args.command.clone(),
                stdin: None,
            }
        };
        // Le mot de passe sudo voyage sur le stdin du canal SSH, pas dans la
        // ligne de commande (qui devient l'argv du shell distant, lisible
        // avec `ps`). Emprunté, jamais cloné : `Zeroizing` l'efface au drop.
        let stdin_bytes: Option<&[u8]> = elevated.stdin.as_ref().map(|s| s.as_bytes());
        let command = &elevated.command;

        // Build the actual command (with optional cd, shell-aware)
        let full_command = args.working_dir.as_ref().map_or_else(
            || command.clone(),
            |dir| shell::cd_and_run(dir, command, effective_shell),
        );

        // Get retry config
        let retry_config = limits.retry_config();

        // Resolve jump host if configured
        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jump_config| (jump_name.as_str(), jump_config))
        });

        // Execute with retry logic
        let output = with_retry_if(
            &retry_config,
            "ssh_exec",
            async || {
                let mut conn = ctx
                    .connection_pool
                    .get_connection_with_jump(&args.host, host_config, &limits, jump_host)
                    .await?;

                match conn
                    .exec_with_stdin(&full_command, stdin_bytes, &limits)
                    .await
                {
                    Ok(output) => Ok(output),
                    Err(e) => {
                        // Mark connection as failed so it won't be returned to pool
                        conn.mark_failed();
                        Err(e)
                    }
                }
            },
            // `ssh_exec` runs an arbitrary caller-supplied command, so it is
            // never safe to replay. A timeout proves nothing about whether the
            // remote command ran — it may well still be running — and the plain
            // `is_retryable_error` treated one as retryable, silently running
            // the command up to three times. `StandardTool` already derives
            // this from annotations; this handler drives its own retry loop and
            // so escaped that.
            |e| is_retryable_error_for(e, false),
        )
        .await;

        let output = output.inspect_err(|e| {
            ctx.execute_use_case.log_failure(
                self.name(),
                &args.host,
                &args.command,
                &e.to_string(),
            );
        })?;

        // Process success using the use case (handles audit, history, formatting, sanitization)
        let response = ctx.execute_use_case.process_success(
            self.name(),
            &args.host,
            &args.command,
            &output.into(),
            &[],
        );

        if response.exit_code != 0 {
            warn!(
                host = %args.host,
                command = %args.command,
                exit_code = response.exit_code,
                "Command failed"
            );
        }

        // Apply smart truncation (head+tail) with optional caching
        #[allow(clippy::cast_possible_truncation)]
        let max_chars = args
            .max_output
            .map_or(ctx.config.limits.max_output_chars, |v| v as usize);
        let truncated_stdout = truncate_output_with_cache(
            &response.stdout,
            max_chars,
            ctx.output_cache.as_deref(),
            None,
        )
        .await;

        // Save full output to local file if requested
        let mut output_text = response.format_for_llm(&truncated_stdout);
        if let Some(ref save_path) = args.save_output {
            match super::utils::save_output_to_file(save_path, &response.output).await {
                Ok(msg) => output_text = format!("{output_text}\n{msg}"),
                Err(msg) => {
                    output_text = format!("{output_text}\nsave_output error: {msg}");
                }
            }
        }

        let result = ToolCallResult::text(output_text);

        // Le fait, pas le verdict. `ssh_exec` exécute la ligne que l'appelant
        // a écrite, et bien des lignes ordinaires sortent non nul *comme
        // réponse* : `grep` qui ne trouve rien, `diff` qui voit une
        // différence, `test` pour faux. Le code doit donc atteindre `$?` — un
        // script en `&& suite` doit s'arrêter — sans que `is_error` aille dire
        // à un client MCP que son propre `grep` a échoué. D'où
        // `with_remote_exit_code_only` et non `with_remote_exit_code`, qui
        // poserait le verdict par ricochet.
        //
        // Posé en dernier, dans le résultat final : `output_text` a déjà
        // absorbé la troncature et le `save_output`, et aucun de ces deux
        // chemins ne reconstruit le résultat.
        if response.exit_code != 0 {
            let code = i32::try_from(response.exit_code).unwrap_or(1);
            return Ok(result.with_remote_exit_code_only(code));
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    /// Contexte qui autorise n'importe quelle commande, avec une sortie
    /// distante simulée.
    ///
    /// Le mode par défaut est `Standard` avec une liste blanche vide, où
    /// `validator.rs` refuse **toute** commande : `ssh_exec` ferait demi-tour
    /// avant d'atteindre son propre code. La forme de config vient de
    /// `ssh_find.rs`, qui résout déjà le même problème.
    fn ctx_permissive_with_exit(exit_code: u32) -> crate::ports::ToolContext {
        use crate::config::{SecurityConfig, SecurityMode};

        // `HostConfig` n'implémente pas `Default` : on emprunte l'hôte
        // "server1" que le mock partagé fournit déjà.
        let mut config = (*create_test_context_with_host().config).clone();
        config.security = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: vec![],
            ..SecurityConfig::default()
        };
        crate::ports::mock::create_test_context_with_config_and_mock_executor(
            config,
            crate::ssh::CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code,
                duration_ms: 1,
            },
        )
    }

    #[tokio::test]
    async fn a_nonzero_exit_is_reported_as_a_fact_without_a_verdict() {
        // `false` rend 1. Le code doit atteindre l'appelant — mais `is_error`
        // doit rester absent : l'appelant a choisi cette commande, et un
        // `grep` qui ne trouve rien rend 1 sans avoir échoué.
        let ctx = ctx_permissive_with_exit(1);
        let result = SshExecHandler
            .execute(Some(json!({"host": "server1", "command": "false"})), &ctx)
            .await
            .expect("le handler doit rendre un résultat");
        assert_eq!(
            result.remote_exit_code,
            Some(1),
            "le fait remonte : {result:?}"
        );
        assert_eq!(
            result.is_error, None,
            "le verdict n'est pas posé : {result:?}"
        );
    }

    #[tokio::test]
    async fn sudo_on_a_windows_host_is_refused_not_silently_dropped() {
        let mut ctx = ctx_permissive_with_exit(0);
        let mut config = (*ctx.config).clone();
        config.hosts.get_mut("server1").expect("server1").os_type = crate::config::OsType::Windows;
        ctx.config = std::sync::Arc::new(config);
        let result = SshExecHandler
            .execute(
                Some(json!({"host": "server1", "command": "dir", "sudo": true})),
                &ctx,
            )
            .await
            .expect("le handler doit rendre un résultat");
        assert_eq!(result.is_error, Some(true), "refus attendu : {result:?}");
        let text = format!("{result:?}");
        assert!(
            text.contains("'sudo' requires a POSIX shell; host 'server1' uses 'cmd'."),
            "{text}"
        );
    }

    #[tokio::test]
    async fn sudo_on_a_linux_host_with_a_powershell_override_names_the_shell_not_the_os() {
        let mut ctx = ctx_permissive_with_exit(0);
        let mut config = (*ctx.config).clone();
        let host = config.hosts.get_mut("server1").expect("server1");
        host.os_type = crate::config::OsType::Linux;
        host.shell = Some(ShellType::PowerShell);
        ctx.config = std::sync::Arc::new(config);
        let result = SshExecHandler
            .execute(
                Some(json!({"host": "server1", "command": "id", "sudo": true})),
                &ctx,
            )
            .await
            .expect("le handler doit rendre un résultat");
        assert_eq!(result.is_error, Some(true), "refus attendu : {result:?}");
        let text = format!("{result:?}");
        assert!(
            text.contains("'sudo' requires a POSIX shell; host 'server1' uses 'powershell'."),
            "{text}"
        );
        assert!(
            !text.contains("Windows"),
            "un hôte Linux n'est pas un hôte Windows : {text}"
        );
    }

    #[tokio::test]
    async fn a_zero_exit_claims_nothing_at_all() {
        // Épingle le fait que la pose est CONDITIONNELLE. Sans la garde
        // `!= 0`, ce test verrait `Some(0)` : inoffensif pour `$?`, mais une
        // affirmation que rien dans l'arbre n'émet (voir la documentation des
        // trois états de `remote_exit_code`).
        let ctx = ctx_permissive_with_exit(0);
        let result = SshExecHandler
            .execute(Some(json!({"host": "server1", "command": "true"})), &ctx)
            .await
            .expect("le handler doit rendre un résultat");
        assert_eq!(
            result.remote_exit_code, None,
            "une commande qui réussit ne pose aucun code : {result:?}"
        );
        assert_eq!(result.is_error, None, "ni aucun verdict : {result:?}");
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshExecHandler;
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
    async fn test_invalid_arguments_missing_host() {
        let handler = SshExecHandler;
        let ctx = create_test_context();

        // Missing host field
        let result = handler.execute(Some(json!({"command": "ls"})), &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_arguments_missing_command() {
        let handler = SshExecHandler;
        let ctx = create_test_context();

        // Missing command field
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshExecHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "unknown_host",
                    "command": "ls -la"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "unknown_host");
            }
            e => panic!("Expected UnknownHost error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_command_denied_in_strict_mode() {
        let handler = SshExecHandler;
        let ctx = create_test_context_with_host();

        // In strict mode (default), commands not in whitelist are denied
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "command": "rm -rf /"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { .. } => {}
            e => panic!("Expected CommandDenied error, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshExecHandler;
        assert_eq!(handler.name(), "ssh_exec");
        assert_ne!(handler.description(), "");

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_exec");

        // Verify required fields are in schema
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshExecHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Verify optional fields exist
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("working_dir"));
    }

    #[test]
    fn test_schema_max_output_field() {
        let handler = SshExecHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Verify max_output field exists with correct type
        assert!(properties.contains_key("max_output"));
        assert_eq!(properties["max_output"]["type"], "integer");
    }

    #[test]
    fn test_ssh_exec_args_deserialization() {
        // Test that SshExecArgs deserializes correctly
        let json = json!({
            "host": "test-host",
            "command": "ls -la",
            "timeout_seconds": 60,
            "working_dir": "/tmp",
            "max_output": 10000
        });

        let args: SshExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "test-host");
        assert_eq!(args.command, "ls -la");
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.working_dir, Some("/tmp".to_string()));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_ssh_exec_args_minimal() {
        // Test with only required fields
        let json = json!({
            "host": "server",
            "command": "pwd"
        });

        let args: SshExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server");
        assert_eq!(args.command, "pwd");
        assert!(args.timeout_seconds.is_none());
        assert!(args.working_dir.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_ssh_exec_args_unicode_command() {
        let json = json!({
            "host": "server",
            "command": "echo '日本語'"
        });

        let args: SshExecArgs = serde_json::from_value(json).unwrap();
        assert!(args.command.contains("日本語"));
    }

    #[test]
    fn test_ssh_exec_args_special_chars() {
        let json = json!({
            "host": "server",
            "command": "grep 'pattern' file.txt | awk '{print $1}'"
        });

        let args: SshExecArgs = serde_json::from_value(json).unwrap();
        assert!(args.command.contains("grep"));
        assert!(args.command.contains("awk"));
    }

    #[test]
    fn test_ssh_exec_args_debug() {
        let json = json!({
            "host": "debug-host",
            "command": "debug-cmd"
        });

        let args: SshExecArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshExecArgs"));
        assert!(debug_str.contains("debug-host"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshExecHandler;
        let ctx = create_test_context();

        // Invalid type for host (number instead of string)
        let result = handler
            .execute(Some(json!({"host": 123, "command": "ls"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_empty_host_string() {
        let handler = SshExecHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"host": "", "command": "ls"})), &ctx)
            .await;

        // Empty host should result in UnknownHost error
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "");
            }
            e => panic!("Expected UnknownHost error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_empty_command_string() {
        let handler = SshExecHandler;
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(Some(json!({"host": "server1", "command": ""})), &ctx)
            .await;

        // Empty command should be denied in strict mode
        assert!(result.is_err());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_rate_limit_returns_error_result() {
        use crate::config::{
            AuditConfig, AuthConfig, Config, HostConfig, HostKeyVerification, HttpTransportConfig,
            LimitsConfig, OsType, SecurityConfig, SecurityMode, SessionConfig, SshConfigDiscovery,
            ToolGroupsConfig,
        };
        use crate::domain::history::HistoryConfig;
        use crate::domain::{ExecuteCommandUseCase, TunnelManager};
        use crate::mcp::CommandHistory;
        use crate::ports::ExecutorRouter;
        use crate::ports::ToolContext;
        use crate::ports::protocol::ToolContent;
        use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
        use crate::ssh::SessionManager;
        use std::collections::HashMap;
        use std::sync::Arc;

        // Need permissive mode so "ls -la" passes validation before hitting rate limiter
        let security = SecurityConfig {
            mode: SecurityMode::Permissive,
            ..SecurityConfig::default()
        };

        let mut hosts = HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
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
            },
        );

        let config = Config {
            hosts,
            security: security.clone(),
            limits: LimitsConfig::default(),
            // Test fixture: AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log).
            audit: AuditConfig {
                enabled: false,
                ..AuditConfig::default()
            },
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let validator = Arc::new(CommandValidator::new(&security));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        let rate_limiter = Arc::new(RateLimiter::new(1));
        // Exhaust the single token for server1
        assert!(rate_limiter.check("server1").is_ok());

        let ctx = ToolContext {
            mrtr: crate::ports::MrtrSlot::default(),
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::with_defaults()),
            execute_use_case,
            rate_limiter,
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        };

        let handler = SshExecHandler;
        let result = handler
            .execute(Some(json!({"host": "server1", "command": "ls -la"})), &ctx)
            .await;

        // Rate limit returns Ok with error content, not Err
        let result = result.unwrap();
        assert_eq!(result.is_error, Some(true));
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("Rate limit exceeded"));
                assert!(text.contains("server1"));
            }
            _ => panic!("Expected Text content"),
        }
    }
}
