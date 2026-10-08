//! SSH Exec Multi Tool Handler
//!
//! Executes the same command in parallel across multiple hosts,
//! aggregating results per host.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::config::{Config, ShellType};
use crate::domain::ExecuteCommandUseCase;
use crate::domain::OutputCache;
use crate::domain::output_truncator::truncate_output_with_cache;
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::ExecutorRouter;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::security::RateLimiter;
use crate::ssh::{is_retryable_error_for, with_retry_if};

use super::utils::shell_escape;

/// Arguments for `ssh_exec_multi` tool
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshExecMultiArgs {
    hosts: Vec<String>,
    command: String,
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    fail_fast: Option<bool>,
    working_dir: Option<String>,
    sudo: Option<bool>,
    sudo_user: Option<String>,
    save_output: Option<String>,
    /// Sprint 3 Phase B.7: enable multi-host output diffing.
    /// When `true`, the response additionally carries a `diff`
    /// section produced by [`crate::domain::diff::compute_multi_host_diff`]
    /// telling the caller which hosts match the baseline and
    /// which diverge, with a unified diff attached to each
    /// divergent host.
    #[serde(default)]
    diff: Option<bool>,
    /// Host to use as the diff baseline. Defaults to the first
    /// entry in `hosts`.
    #[serde(default)]
    diff_baseline: Option<String>,
    /// When `diff=true`, normalize volatile tokens (timestamps,
    /// PIDs, UUIDs) before comparing so hosts that differ only on
    /// runtime metadata still count as matching.
    #[serde(default)]
    normalize: Option<bool>,
}

/// Result for a single host execution
#[derive(Debug, Serialize)]
struct HostResult {
    host: String,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
}

/// Le code de sortie à remonter, ou `None` quand il n'a pas de référent unique.
///
/// Le garde compte les hôtes *demandés*, pas seulement les résultats : une
/// tâche qui panique fait perdre un `HostResult`, et deux hôtes dont un
/// panique donnent un seul résultat, qui n'est pas un appel mono-hôte.
fn single_host_exit(results: &[HostResult], requested_hosts: usize) -> Option<u32> {
    match results {
        [only] if requested_hosts == 1 => only.exit_code,
        _ => None,
    }
}

/// Aggregated results for all hosts
#[derive(Debug, Serialize)]
struct MultiExecResult {
    total_hosts: usize,
    succeeded: usize,
    failed: usize,
    results: Vec<HostResult>,
    /// Optional Sprint 3 Phase B.7 multi-host diff summary.
    /// Populated only when the caller passes `diff=true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<crate::domain::diff::MultiHostDiff>,
}

/// SSH Exec Multi tool handler
#[mcp_tool(name = "ssh_exec_multi", group = "core", annotation = "mutating")]
pub struct SshExecMultiHandler;

impl SshExecMultiHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "hosts": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Array of host aliases to execute on",
                "minItems": 1,
                "maxItems": 50
            },
            "command": {
                "type": "string",
                "description": "The command to execute on all hosts"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Per-host timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters per host (default: from server config, typically 40000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full JSON output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            },
            "fail_fast": {
                "type": "boolean",
                "description": "Stop remaining executions on first failure (default: false)",
                "default": false
            },
            "working_dir": {
                "type": "string",
                "description": "Optional working directory for the command"
            },
            "sudo": {
                "type": "boolean",
                "description": "Run the command with sudo (default: false)"
            },
            "sudo_user": {
                "type": "string",
                "description": "User to run sudo as (default: root)"
            },
            "diff": {
                "type": "boolean",
                "description": "Compute a multi-host diff of the results against a baseline host (default: false). The response gains a 'diff' section listing which hosts match the baseline and a unified diff for each divergent host. Useful for detecting config drift across a fleet.",
                "default": false
            },
            "diff_baseline": {
                "type": "string",
                "description": "Host name to use as the diff baseline (default: first host in 'hosts'). Only meaningful when diff=true."
            },
            "normalize": {
                "type": "boolean",
                "description": "Replaces common volatile patterns — ISO timestamps (2024-01-02T03:04:05Z), syslog timestamps (Jan  2 03:04:05), PID markers (pid=1234 or [1234]:), and lowercase-hex UUIDs — with placeholder tokens (<TIMESTAMP>, <PID>, <UUID>) before diffing. Does not normalize IP addresses or file paths. Only meaningful when diff=true. Default: false.",
                "default": false
            }
        },
        "required": ["hosts", "command"]
    }"#;
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl ToolHandler for SshExecMultiHandler {
    fn name(&self) -> &'static str {
        "ssh_exec_multi"
    }

    fn description(&self) -> &'static str {
        "Execute the same command in parallel across multiple hosts. Returns JSON with per-host \
         results (stdout, stderr, exit_code, duration). Use ssh_status first to discover \
         available host aliases. Use fail_fast to stop on first error, or let all hosts \
         complete independently. For a single host, prefer ssh_exec instead."
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
        let args: SshExecMultiArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        if args.hosts.is_empty() {
            return Err(BridgeError::McpInvalidRequest(
                "hosts array must not be empty".to_string(),
            ));
        }

        // Verify all hosts exist in config (before command validation)
        let mut unknown_hosts = Vec::new();
        for host in &args.hosts {
            if !ctx.config.hosts.contains_key(host) {
                unknown_hosts.push(host.clone());
            }
        }
        if !unknown_hosts.is_empty() {
            return Err(BridgeError::McpInvalidRequest(format!(
                "Unknown hosts: {}",
                unknown_hosts.join(", ")
            )));
        }

        // Validate command once (same rules for all hosts)
        ctx.execute_use_case.validate(&args.command)?;

        info!(
            hosts = ?args.hosts,
            command = %args.command,
            "Executing command on multiple hosts"
        );

        let use_sudo = args.sudo.unwrap_or(false);
        let sudo_user: Arc<str> = Arc::from(args.sudo_user.as_deref().unwrap_or("root"));

        #[allow(clippy::cast_possible_truncation)]
        let max_chars = args
            .max_output
            .map_or(ctx.config.limits.max_output_chars, |v| v as usize);

        let fail_fast = args.fail_fast.unwrap_or(false);
        let cancel_token = tokio_util::sync::CancellationToken::new();

        // Spawn parallel tasks
        let mut join_set = JoinSet::new();

        let config = Arc::clone(&ctx.config);
        let connection_pool = Arc::clone(&ctx.connection_pool);
        let execute_use_case = Arc::clone(&ctx.execute_use_case);
        let rate_limiter = Arc::clone(&ctx.rate_limiter);
        let output_cache = ctx.output_cache.clone();

        for host_name in &args.hosts {
            join_set.spawn(execute_on_host(
                host_name.clone(),
                args.command.clone(),
                args.working_dir.clone(),
                use_sudo,
                Arc::clone(&sudo_user),
                config.clone(),
                connection_pool.clone(),
                execute_use_case.clone(),
                rate_limiter.clone(),
                cancel_token.clone(),
                args.timeout_seconds,
                max_chars,
                fail_fast,
                output_cache.clone(),
            ));
        }

        // Collect results, reporting progress as each host completes.
        // The reporter is `None` if the client did not request progress;
        // calls then become a cheap no-op.
        let progress = ctx.progress_reporter(Some(args.hosts.len() as u64));
        let mut results = Vec::with_capacity(args.hosts.len());
        let mut completed: u64 = 0;
        while let Some(join_result) = join_set.join_next().await {
            match join_result {
                Ok(host_result) => {
                    completed += 1;
                    if let Some(reporter) = progress.as_ref() {
                        reporter.report(
                            completed,
                            Some(&format!(
                                "{} ({}/{})",
                                host_result.host,
                                completed,
                                args.hosts.len()
                            )),
                        );
                    }
                    results.push(host_result);
                }
                Err(e) => {
                    warn!("Task join error: {e}");
                }
            }
        }

        // Sort by original host order
        let host_order: std::collections::HashMap<&str, usize> = args
            .hosts
            .iter()
            .enumerate()
            .map(|(i, h)| (h.as_str(), i))
            .collect();
        results.sort_by_key(|r| {
            host_order
                .get(r.host.as_str())
                .copied()
                .unwrap_or(usize::MAX)
        });

        let succeeded = results.iter().filter(|r| r.success).count();
        let failed = results.len() - succeeded;

        // Le fait, pas le verdict — et seulement quand il a un référent unique.
        //
        // Un seul hôte : le code de sortie distant est celui-là, et il remonte
        // comme pour `ssh_exec`, et pour le même motif on ne pose PAS
        // `is_error` (l'appelant a choisi la ligne ; `grep` qui ne trouve rien
        // sort 1 sans avoir échoué).
        //
        // Plusieurs hôtes : rien n'est posé, délibérément. Le compteur `failed`
        // ci-dessus confond « la ligne a rendu non nul » et « l'hôte est
        // injoignable » — `HostResult::success` est faux dans les deux cas —
        // donc le mapper ferait dire au code 6 « le bridge n'a pas joint un
        // hôte », en re-confondant précisément ce que 6 existe pour séparer.
        // Le cas fan-out demeure donc ouvert plutôt que mal répondu.
        //
        // `exit_code` vaut `None` quand l'hôte n'a rien exécuté (annulation,
        // quota de débit, échec de connexion) : ce cas ne prétend alors rien
        // non plus.
        let single_host_exit = single_host_exit(&results, args.hosts.len());

        // Optional: compute a multi-host diff (Sprint 3 Phase B.7).
        // Runs against whatever succeeded — failed hosts still appear
        // in the diff with their error output, which is usually what
        // you want because "host fails while others succeed" IS the
        // kind of drift this feature is meant to surface.
        let diff_section = if args.diff.unwrap_or(false) {
            let diff_inputs: Vec<(String, String, i32)> = results
                .iter()
                .map(|r| {
                    let output = r
                        .output
                        .clone()
                        .or_else(|| r.error.clone())
                        .unwrap_or_default();
                    let exit = i32::try_from(r.exit_code.unwrap_or(0)).unwrap_or(0);
                    (r.host.clone(), output, exit)
                })
                .collect();

            let baseline = args
                .diff_baseline
                .clone()
                .unwrap_or_else(|| args.hosts[0].clone());
            let normalize = args.normalize.unwrap_or(false);

            match crate::domain::diff::compute_multi_host_diff(&baseline, &diff_inputs, normalize) {
                Ok(d) => Some(d),
                Err(e) => {
                    warn!(error = %e, "multi-host diff failed, skipping");
                    None
                }
            }
        } else {
            None
        };

        let multi_result = MultiExecResult {
            total_hosts: results.len(),
            succeeded,
            failed,
            results,
            diff: diff_section,
        };

        let mut json_output = serde_json::to_string(&multi_result)
            .unwrap_or_else(|e| format!("Error serializing results: {e}"));

        // Save full output to local file if requested
        if let Some(ref save_path) = args.save_output {
            match super::utils::save_output_to_file(save_path, &json_output).await {
                Ok(msg) => json_output = format!("{json_output}\n{msg}"),
                Err(msg) => {
                    json_output = format!("{json_output}\nsave_output error: {msg}");
                }
            }
        }

        let result = ToolCallResult::text(json_output);
        if let Some(code) = single_host_exit.filter(|c| *c != 0) {
            let code = i32::try_from(code).unwrap_or(1);
            return Ok(result.with_remote_exit_code_only(code));
        }

        Ok(result)
    }
}

/// Execute a command on a single host, returning a `HostResult`.
///
/// This is spawned as a parallel task by `SshExecMultiHandler::execute`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn execute_on_host(
    host_name: String,
    command: String,
    working_dir: Option<String>,
    use_sudo: bool,
    sudo_user: Arc<str>,
    config: Arc<Config>,
    connection_pool: Arc<ExecutorRouter>,
    execute_use_case: Arc<ExecuteCommandUseCase>,
    rate_limiter: Arc<RateLimiter>,
    cancel_token: tokio_util::sync::CancellationToken,
    timeout_seconds: Option<u64>,
    max_chars: usize,
    fail_fast: bool,
    output_cache: Option<Arc<OutputCache>>,
) -> HostResult {
    let start = Instant::now();

    // Check if cancelled by a previous fail_fast
    if cancel_token.is_cancelled() {
        return HostResult {
            host: host_name,
            success: false,
            exit_code: None,
            output: None,
            error: Some("Cancelled due to fail_fast".to_string()),
            duration_ms: None,
        };
    }

    // Check rate limit
    if rate_limiter.check(&host_name).is_err() {
        return HostResult {
            host: host_name,
            success: false,
            exit_code: None,
            output: None,
            error: Some("Rate limit exceeded".to_string()),
            duration_ms: Some(elapsed_ms(&start)),
        };
    }

    // Get host config (already validated in execute())
    let Some(host_config) = config.hosts.get(&host_name) else {
        return HostResult {
            host: host_name,
            success: false,
            exit_code: None,
            output: None,
            error: Some("Host config not found".to_string()),
            duration_ms: Some(elapsed_ms(&start)),
        };
    };

    // Wrap command with sudo if requested
    //
    // Elevation is a domain decision: `privilege::elevate*` wraps the whole
    // line (`sudo -n bash -c '<all>'`, or `sudo -S -p '' bash -c 'exec
    // 0</dev/null; <all>'` when the host has a `sudo_password` and the
    // transport is SSH). Prefixing it here would only elevate the first
    // process; see the docs of `domain::privilege::elevate`.
    //
    // Like `ssh_exec`: the POSIX sudo wrapper only makes sense on a POSIX host.
    // On a Windows host it failed, and the password still went into that
    // host's command line.
    if use_sudo && host_config.effective_shell() != ShellType::Posix {
        // Per-host refusal: the other hosts of the call still run. Ignoring
        // `sudo` silently would let an unelevated command report `success`.
        // Same intent as step 5b of `standard_tool.rs` (refuse rather than
        // silently downgrade the privilege), but neither the condition nor the
        // wording is its own: 5b tests the OS (`os_type == Windows`), this
        // tests the effective shell, which a `shell:` override can make
        // non-POSIX on a Linux host.
        if fail_fast {
            cancel_token.cancel();
        }
        return HostResult {
            host: host_name.clone(),
            success: false,
            exit_code: None,
            output: None,
            error: Some(format!(
                "'sudo' requires a POSIX shell; host '{host_name}' uses '{}'.",
                format!("{:?}", host_config.effective_shell()).to_lowercase()
            )),
            duration_ms: Some(elapsed_ms(&start)),
        };
    }
    let elevated = if use_sudo {
        let privilege = crate::domain::privilege::PrivilegeArgs {
            sudo: use_sudo,
            sudo_user: Some(sudo_user.to_string()),
        };
        crate::domain::privilege::elevate_with_password(
            &command,
            &privilege,
            host_config.sudo_password_for_exec(&host_name),
        )
    } else {
        crate::domain::privilege::Elevated {
            command: command.clone(),
            stdin: None,
        }
    };
    // The password travels on the channel's stdin, not in the remote argv.
    let stdin_bytes: Option<&[u8]> = elevated.stdin.as_ref().map(|s| s.as_bytes());
    let wrapped_command = &elevated.command;

    // Build the actual command (with optional cd)
    let full_command = working_dir.as_ref().map_or_else(
        || wrapped_command.clone(),
        |dir| format!("cd {} && {}", shell_escape(dir), wrapped_command),
    );

    // Build limits with optional timeout override
    let mut limits = config.limits.clone();
    if let Some(timeout) = timeout_seconds {
        limits.command_timeout_seconds = timeout;
    }
    let retry_config = limits.retry_config();

    // Resolve jump host
    let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
        config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    // Execute with retry
    let output = with_retry_if(
        &retry_config,
        "ssh_exec_multi",
        async || {
            let mut conn = connection_pool
                .get_connection_with_jump(&host_name, host_config, &limits, jump_host)
                .await?;

            match conn
                .exec_with_stdin(&full_command, stdin_bytes, &limits)
                .await
            {
                Ok(output) => Ok(output),
                Err(e) => {
                    conn.mark_failed();
                    Err(e)
                }
            }
        },
        // Like `ssh_exec`: the command is arbitrary and a timeout does not
        // prove it did not run. Replaying also replayed the password.
        |e| is_retryable_error_for(e, false),
    )
    .await;
    // The retry loop is done with the secret: wipe it now rather than at the
    // end of the function, across `process_success` and the truncation awaits.
    drop(elevated);

    let duration_ms = Some(elapsed_ms(&start));

    match output {
        Ok(output) => {
            // `&[]` is true here, not a placeholder: this tool declares no reduction
            // parameter (`deny_unknown_fields`, no `DataReductionArgs`), so none can have
            // acted on the output. `max_output` truncation is not a reduction parameter
            // either. Do not "fix" this by inventing a list.
            let response = execute_use_case.process_success(
                "ssh_exec_multi",
                &host_name,
                &command,
                &output.into(),
                &[],
            );
            let truncated = truncate_output_with_cache(
                &response.output,
                max_chars,
                output_cache.as_deref(),
                None,
            )
            .await;

            if response.exit_code != 0 && fail_fast {
                cancel_token.cancel();
            }

            HostResult {
                host: host_name,
                success: response.exit_code == 0,
                exit_code: Some(response.exit_code),
                output: Some(truncated),
                error: None,
                duration_ms,
            }
        }
        Err(e) => {
            execute_use_case.log_failure("ssh_exec_multi", &host_name, &command, &e.to_string());

            if fail_fast {
                cancel_token.cancel();
            }

            HostResult {
                host: host_name,
                success: false,
                exit_code: None,
                output: None,
                error: Some(e.to_string()),
                duration_ms,
            }
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
fn elapsed_ms(start: &Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
    use crate::ports::ToolContext;
    use crate::ports::mock::create_test_context;
    use serde_json::json;
    use std::collections::HashMap;

    fn host_result(exit_code: Option<u32>) -> HostResult {
        HostResult {
            host: "h".to_string(),
            success: exit_code == Some(0),
            exit_code,
            output: None,
            error: None,
            duration_ms: None,
        }
    }

    #[test]
    fn single_host_exit_reports_the_code_for_one_requested_host() {
        assert_eq!(single_host_exit(&[host_result(Some(1))], 1), Some(1));
    }

    #[test]
    fn single_host_exit_is_none_when_a_task_was_lost() {
        // Deux hôtes demandés, un seul résultat (JoinError) : pas mono-hôte.
        assert_eq!(single_host_exit(&[host_result(Some(1))], 2), None);
    }

    #[test]
    fn single_host_exit_is_none_for_several_results_or_no_code() {
        let two = [host_result(Some(1)), host_result(Some(2))];
        assert_eq!(single_host_exit(&two, 2), None);
        assert_eq!(single_host_exit(&[host_result(None)], 1), None);
    }

    fn create_test_context_with_hosts() -> ToolContext {
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
        hosts.insert(
            "server2".to_string(),
            HostConfig {
                hostname: "192.168.1.101".to_string(),
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
        hosts.insert(
            "server3".to_string(),
            HostConfig {
                hostname: "192.168.1.102".to_string(),
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
        crate::ports::mock::create_test_context_with_hosts(hosts)
    }

    /// Les mêmes trois hôtes, mais avec une sortie distante simulée et une
    /// config qui autorise la commande — en mode `Standard` par défaut la
    /// liste blanche est vide et `validator.rs` refuse tout, bien avant que le
    /// handler atteigne son propre code.
    fn ctx_permissive_with_exit(exit_code: u32) -> ToolContext {
        use crate::config::{SecurityConfig, SecurityMode};

        let mut config = (*create_test_context_with_hosts().config).clone();
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
    async fn a_single_host_nonzero_exit_is_a_fact_without_a_verdict() {
        let ctx = ctx_permissive_with_exit(1);
        let result = SshExecMultiHandler
            .execute(
                Some(json!({"hosts": ["server1"], "command": "false"})),
                &ctx,
            )
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
    async fn sudo_on_a_windows_host_fails_that_host_only() {
        let mut ctx = ctx_permissive_with_exit(0);
        let mut config = (*ctx.config).clone();
        config.hosts.get_mut("server1").expect("server1").os_type = crate::config::OsType::Windows;
        ctx.config = Arc::new(config);
        let result = SshExecMultiHandler
            .execute(
                Some(json!({
                    "hosts": ["server1", "server2"],
                    "command": "id",
                    "sudo": true
                })),
                &ctx,
            )
            .await
            .expect("le handler doit rendre un résultat");
        let text = match &result.content[0] {
            crate::mcp::protocol::ToolContent::Text { text } => text.clone(),
            other => panic!("contenu texte attendu, obtenu {other:?}"),
        };
        assert!(
            text.contains("'sudo' requires a POSIX shell; host 'server1' uses 'cmd'."),
            "{text}"
        );
        assert!(text.contains("\"failed\":1"), "{text}");
        assert!(text.contains("\"succeeded\":1"), "{text}");
    }

    #[tokio::test]
    async fn a_single_host_zero_exit_claims_nothing() {
        let ctx = ctx_permissive_with_exit(0);
        let result = SshExecMultiHandler
            .execute(Some(json!({"hosts": ["server1"], "command": "true"})), &ctx)
            .await
            .expect("le handler doit rendre un résultat");
        assert_eq!(
            result.remote_exit_code, None,
            "une commande qui réussit ne pose aucun code : {result:?}"
        );
    }

    #[tokio::test]
    async fn a_fan_out_claims_nothing_even_when_every_host_failed() {
        // Épingle l'abstention décrite au-dessus de `single_host_exit` : avec
        // plusieurs hôtes, `failed` vaut 2 et pourtant rien n'est posé, parce
        // que ce compteur ne distingue pas « la ligne a rendu non nul » de
        // « l'hôte est injoignable ». Mapper `failed > 0` ferait dire au code
        // 6 quelque chose qu'il a été créé pour ne PAS dire.
        let ctx = ctx_permissive_with_exit(1);
        let result = SshExecMultiHandler
            .execute(
                Some(json!({"hosts": ["server1", "server2"], "command": "false"})),
                &ctx,
            )
            .await
            .expect("le handler doit rendre un résultat");
        let text = match &result.content[0] {
            crate::mcp::protocol::ToolContent::Text { text } => text.clone(),
            other => panic!("contenu texte attendu, obtenu {other:?}"),
        };
        assert!(
            text.contains("\"failed\":2"),
            "les deux hôtes doivent avoir rendu non nul, sinon ce test \
             n'atteint pas le cas fan-out : {text}"
        );
        assert_eq!(
            result.remote_exit_code, None,
            "le fan-out s'abstient : {result:?}"
        );
    }

    #[test]
    fn test_schema() {
        let handler = SshExecMultiHandler;
        assert_eq!(handler.name(), "ssh_exec_multi");
        assert_ne!(handler.description(), "");

        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("hosts")));
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshExecMultiHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("fail_fast"));
        assert!(properties.contains_key("working_dir"));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshExecMultiHandler;
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
    async fn test_empty_hosts_array() {
        let handler = SshExecMultiHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "hosts": [],
                    "command": "ls"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("empty"));
            }
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_hosts_detected() {
        let handler = SshExecMultiHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "hosts": ["unknown1", "unknown2"],
                    "command": "ls"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("unknown1"));
                assert!(msg.contains("unknown2"));
            }
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_command_denied_in_strict_mode() {
        let handler = SshExecMultiHandler;
        let ctx = create_test_context_with_hosts();

        let result = handler
            .execute(
                Some(json!({
                    "hosts": ["server1", "server2"],
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

    // ============== Handler Trait Tests ==============

    #[test]
    fn test_handler_name() {
        let handler = SshExecMultiHandler;
        assert_eq!(handler.name(), "ssh_exec_multi");
    }

    #[test]
    fn test_handler_description_not_empty() {
        let handler = SshExecMultiHandler;
        assert_ne!(handler.description(), "");
        assert!(handler.description().contains("parallel"));
    }

    #[test]
    fn test_schema_properties() {
        let handler = SshExecMultiHandler;
        let schema = handler.schema();

        let parsed: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();

        // Check all properties exist
        let props = parsed["properties"].as_object().unwrap();
        assert!(props.contains_key("hosts"));
        assert!(props.contains_key("command"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("fail_fast"));
        assert!(props.contains_key("working_dir"));
    }

    #[test]
    fn test_schema_hosts_constraints() {
        let handler = SshExecMultiHandler;
        let schema = handler.schema();

        let parsed: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let hosts_prop = &parsed["properties"]["hosts"];

        assert_eq!(hosts_prop["type"], "array");
        assert_eq!(hosts_prop["minItems"], 1);
        assert_eq!(hosts_prop["maxItems"], 50);
    }

    #[test]
    fn test_schema_timeout_constraints() {
        let handler = SshExecMultiHandler;
        let schema = handler.schema();

        let parsed: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let timeout = &parsed["properties"]["timeout_seconds"];

        assert_eq!(timeout["minimum"], 1);
        assert_eq!(timeout["maximum"], 3600);
    }

    // ============== Invalid Input Tests ==============

    #[tokio::test]
    async fn test_invalid_json_arguments() {
        let handler = SshExecMultiHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "hosts": "not-an-array",
                    "command": "ls"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_missing_command() {
        let handler = SshExecMultiHandler;
        let ctx = create_test_context_with_hosts();

        let result = handler
            .execute(
                Some(json!({
                    "hosts": ["server1"]
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_missing_hosts() {
        let handler = SshExecMultiHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "command": "ls"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
    }

    // ============== HostResult Tests ==============

    #[test]
    fn test_host_result_success_serialization() {
        let result = HostResult {
            host: "server1".to_string(),
            success: true,
            exit_code: Some(0),
            output: Some("hello world".to_string()),
            error: None,
            duration_ms: Some(100),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("server1"));
        assert!(json.contains("true"));
        assert!(json.contains("hello world"));
        assert!(!json.contains("error")); // skip_serializing_if
    }

    #[test]
    fn test_host_result_failure_serialization() {
        let result = HostResult {
            host: "server2".to_string(),
            success: false,
            exit_code: None,
            output: None,
            error: Some("Connection refused".to_string()),
            duration_ms: Some(50),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("server2"));
        assert!(json.contains("false"));
        assert!(json.contains("Connection refused"));
        assert!(!json.contains("exit_code")); // skip_serializing_if
    }

    // ============== MultiExecResult Tests ==============

    #[test]
    fn test_multi_exec_result_serialization() {
        let result = MultiExecResult {
            total_hosts: 3,
            succeeded: 2,
            failed: 1,
            results: vec![
                HostResult {
                    host: "host1".to_string(),
                    success: true,
                    exit_code: Some(0),
                    output: Some("ok".to_string()),
                    error: None,
                    duration_ms: Some(100),
                },
                HostResult {
                    host: "host2".to_string(),
                    success: true,
                    exit_code: Some(0),
                    output: Some("ok".to_string()),
                    error: None,
                    duration_ms: Some(150),
                },
                HostResult {
                    host: "host3".to_string(),
                    success: false,
                    exit_code: None,
                    output: None,
                    error: Some("timeout".to_string()),
                    duration_ms: Some(30000),
                },
            ],
            diff: None,
        };

        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("total_hosts"));
        assert!(json.contains('3'));
        assert!(json.contains("succeeded"));
        assert!(json.contains('2'));
        assert!(json.contains("failed"));
        assert!(json.contains('1'));
        // diff section is skipped when None
        assert!(!json.contains("\"diff\""));
    }

    /// **Sprint 3 Phase B.7:** when `diff=true` is requested, the
    /// serialized `MultiExecResult` gains a `diff` section produced
    /// by `crate::domain::diff::compute_multi_host_diff`.
    #[test]
    fn test_multi_exec_result_with_diff_section_serializes() {
        use crate::domain::diff::compute_multi_host_diff;

        let diff_inputs: Vec<(String, String, i32)> = vec![
            ("web1".to_string(), "nginx/1.24.0\n".to_string(), 0),
            ("web2".to_string(), "nginx/1.24.0\n".to_string(), 0),
            ("web3".to_string(), "nginx/1.22.1\n".to_string(), 0),
        ];
        let diff = compute_multi_host_diff("web1", &diff_inputs, false).unwrap();

        let result = MultiExecResult {
            total_hosts: 3,
            succeeded: 3,
            failed: 0,
            results: vec![
                HostResult {
                    host: "web1".to_string(),
                    success: true,
                    exit_code: Some(0),
                    output: Some("nginx/1.24.0".to_string()),
                    error: None,
                    duration_ms: Some(50),
                },
                HostResult {
                    host: "web2".to_string(),
                    success: true,
                    exit_code: Some(0),
                    output: Some("nginx/1.24.0".to_string()),
                    error: None,
                    duration_ms: Some(60),
                },
                HostResult {
                    host: "web3".to_string(),
                    success: true,
                    exit_code: Some(0),
                    output: Some("nginx/1.22.1".to_string()),
                    error: None,
                    duration_ms: Some(70),
                },
            ],
            diff: Some(diff),
        };

        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(
            json.contains("\"diff\""),
            "diff section should be present when populated"
        );
        assert!(json.contains("baseline_host"));
        assert!(json.contains("web1"));
        assert!(
            json.contains("divergent_hosts"),
            "summary.divergent_hosts should serialize"
        );
        assert!(json.contains("web3"), "divergent host web3 should appear");
    }

    // ============== elapsed_ms Tests ==============

    #[test]
    fn test_elapsed_ms_immediate() {
        let start = std::time::Instant::now();
        let elapsed = elapsed_ms(&start);
        // Should be very small
        assert!(elapsed < 100);
    }

    // ============== SshExecMultiArgs Tests ==============

    #[test]
    fn test_args_deserialization_minimal() {
        let json = json!({
            "hosts": ["server1"],
            "command": "ls"
        });

        let args: SshExecMultiArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.hosts, vec!["server1"]);
        assert_eq!(args.command, "ls");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.fail_fast.is_none());
        assert!(args.working_dir.is_none());
    }

    #[test]
    fn test_args_deserialization_full() {
        let json = json!({
            "hosts": ["server1", "server2"],
            "command": "uptime",
            "timeout_seconds": 60,
            "max_output": 10000,
            "fail_fast": true,
            "working_dir": "/var/log"
        });

        let args: SshExecMultiArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.hosts.len(), 2);
        assert_eq!(args.command, "uptime");
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.fail_fast, Some(true));
        assert_eq!(args.working_dir, Some("/var/log".to_string()));
    }

    #[test]
    fn test_args_deserialization_empty_hosts() {
        let json = json!({
            "hosts": [],
            "command": "ls"
        });

        let args: SshExecMultiArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.hosts, [] as [std::string::String; 0]);
    }
}
