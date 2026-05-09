//! CLI runner functions
//!
//! These functions execute CLI commands by reusing the existing
//! domain logic and tool handlers.

use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use tracing::{info, warn};

use crate::config::{Config, ShellType};
use crate::domain::ExecuteCommandUseCase;
use crate::domain::use_cases::shell;
use crate::error::{BridgeError, Result};
use crate::mcp::CommandHistory;
use crate::mcp::history::HistoryConfig;
use crate::ports::ExecutorRouter;
use crate::ports::ToolContext;
use crate::security::{
    AuditEvent, AuditLogger, CommandResult, CommandValidator, RateLimiter, Sanitizer,
};
use crate::ssh::{
    SessionManager, SshClient, TransferMode, TransferOptions, TransferProgress, is_retryable_error,
    with_retry_if,
};

/// Try to forward a `tools/call` request to a running daemon over its
/// Unix socket.
///
/// Returns:
/// - `Ok(Some(response))` — daemon accepted and returned a JSON-RPC
///   response. The caller should print this and skip the in-process
///   path.
/// - `Ok(None)` — daemon is absent or refused the connection. Caller
///   falls back to the stateless in-process path.
/// - `Err(..)` — unexpected I/O failure during a reachable daemon call.
///
/// The function intentionally swallows `NotFound` and `ConnectionRefused`
/// errors: these indicate no daemon is running, not a fatal problem.
async fn try_forward_to_daemon(
    socket_path: &std::path::Path,
    tool_name: &str,
    arguments: serde_json::Value,
) -> Result<Option<serde_json::Value>> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let mut stream = match UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            tracing::debug!(
                path = %socket_path.display(),
                error = %e,
                "No daemon reachable, falling back to stateless path"
            );
            return Ok(None);
        }
        Err(e) => return Err(BridgeError::Io(e)),
    };

    let request_id = uuid::Uuid::new_v4().to_string();
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    });

    let body = serde_json::to_string(&request).map_err(BridgeError::Json)?;
    stream
        .write_all(body.as_bytes())
        .await
        .map_err(BridgeError::Io)?;
    stream.write_all(b"\n").await.map_err(BridgeError::Io)?;
    stream.flush().await.map_err(BridgeError::Io)?;

    // Read exactly one response line.
    let (reader, _writer) = stream.split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await.map_err(BridgeError::Io)?;

    let response: serde_json::Value =
        serde_json::from_str(line.trim()).map_err(BridgeError::Json)?;
    Ok(Some(response))
}

/// Print a JSON-RPC response from the daemon in the format the user
/// expects (JSON or text-pretty). Returns the appropriate exit code.
fn print_daemon_response(response: &serde_json::Value, json_output: bool) -> Result<i32> {
    // JSON-RPC error path.
    if let Some(err) = response.get("error") {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(response)
                    .map_err(|e| BridgeError::Config(e.to_string()))?
            );
        } else {
            eprintln!("Error: {err}");
        }
        return Ok(1);
    }

    let Some(result) = response.get("result") else {
        return Err(BridgeError::Config(
            "Daemon response has neither result nor error".to_string(),
        ));
    };

    let is_error = result
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let exit_code = i32::from(is_error);

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(result).map_err(|e| BridgeError::Config(e.to_string()))?
        );
    } else if let Some(content) = result.get("content").and_then(serde_json::Value::as_array) {
        for item in content {
            if let Some(text) = item.get("text").and_then(serde_json::Value::as_str) {
                println!("{text}");
            } else if let Ok(pretty) = serde_json::to_string_pretty(item) {
                println!("{pretty}");
            }
        }
    }

    Ok(exit_code)
}

/// Ergonomic CLI aliases for the universal data-reduction tool parameters.
///
/// These flags are syntactic sugar — `--jq '.foo'` is equivalent to passing
/// `jq_filter='.foo'` as a key=value tool argument. The underlying feature
/// is already exposed via [`crate::domain::data_reduction`] and
/// [`crate::mcp::registry::inject_reduction_schema`]; this struct just saves
/// users from typing the full param name each time.
///
/// Explicit `key=value` arguments always win — the flags only fill in fields
/// that the user did NOT set explicitly.
#[derive(Debug, Default, Clone)]
pub struct DataReductionFlags {
    /// jq expression to apply to JSON output (mapped to `jq_filter`).
    #[cfg(feature = "jq")]
    pub jq: Option<String>,
    /// Columns to keep in tabular output (mapped to `columns`).
    pub columns: Option<Vec<String>>,
    /// Max rows/entries to return (mapped to `limit`).
    pub limit: Option<usize>,
    /// Output format for jq/yq results: `json` (default) or `tsv` (mapped
    /// to `output_format`).
    #[cfg(feature = "jq")]
    pub output_format: Option<String>,
}

impl DataReductionFlags {
    /// Returns `true` if no flag is set — equivalent to
    /// `DataReductionFlags::default()`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "jq")]
        if self.jq.is_some() {
            return false;
        }
        #[cfg(feature = "jq")]
        if self.output_format.is_some() {
            return false;
        }
        self.columns.is_none() && self.limit.is_none()
    }
}

/// Merge [`DataReductionFlags`] into an existing tool arguments JSON value.
///
/// The flags only fill in fields that are NOT already present — explicit
/// `key=value` CLI arguments or `--json-args` entries win over the ergonomic
/// flags. This mirrors the policy documented on [`DataReductionFlags`].
fn merge_data_reduction(
    mut args: serde_json::Value,
    flags: &DataReductionFlags,
) -> serde_json::Value {
    if flags.is_empty() {
        return args;
    }
    // Ensure we have an object to write into.
    if !args.is_object() {
        args = serde_json::Value::Object(serde_json::Map::new());
    }
    let map = args.as_object_mut().expect("just ensured object");

    #[cfg(feature = "jq")]
    if let Some(expr) = flags.jq.as_deref()
        && !map.contains_key("jq_filter")
    {
        map.insert(
            "jq_filter".to_string(),
            serde_json::Value::String(expr.to_string()),
        );
    }
    if let Some(cols) = flags.columns.as_ref()
        && !map.contains_key("columns")
    {
        let as_json = serde_json::Value::Array(
            cols.iter()
                .map(|c| serde_json::Value::from(c.clone()))
                .collect(),
        );
        map.insert("columns".to_string(), as_json);
    }
    if let Some(n) = flags.limit
        && !map.contains_key("limit")
    {
        map.insert("limit".to_string(), serde_json::Value::from(n));
    }
    #[cfg(feature = "jq")]
    if let Some(fmt) = flags.output_format.as_deref()
        && !map.contains_key("output_format")
    {
        map.insert(
            "output_format".to_string(),
            serde_json::Value::String(fmt.to_string()),
        );
    }
    args
}

/// List all available MCP tools
pub async fn run_list_tools(
    config: Arc<Config>,
    group: Option<&str>,
    json_output: bool,
    groups_only: bool,
    search: Option<&str>,
) -> Result<()> {
    use crate::mcp::registry::{create_filtered_registry, tool_group};

    let registry = create_filtered_registry(&config.tool_groups);
    let mut tools = registry.list_tools();
    tools.sort_by(|a, b| a.name.cmp(&b.name));

    // Filter by group if specified
    if let Some(group_filter) = group {
        tools.retain(|t| tool_group(&t.name) == group_filter);
    }

    // Filter by search keyword (matches name or description, case-insensitive)
    if let Some(query) = search {
        let query_lower = query.to_lowercase();
        tools.retain(|t| {
            t.name.to_lowercase().contains(&query_lower)
                || t.description.to_lowercase().contains(&query_lower)
        });
    }

    // Groups-only mode: show just group names with tool counts
    if groups_only {
        let mut group_counts: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for tool in &tools {
            *group_counts.entry(tool_group(&tool.name)).or_insert(0) += 1;
        }

        if json_output {
            let map: std::collections::BTreeMap<&str, usize> = group_counts;
            let json = serde_json::to_string_pretty(&map)
                .map_err(|e| BridgeError::Config(e.to_string()))?;
            println!("{json}");
        } else {
            println!("{:<30} TOOLS", "GROUP");
            println!("{}", "-".repeat(40));
            for (group_name, count) in &group_counts {
                println!("{group_name:<30} {count}");
            }
            println!(
                "\nTotal: {} groups, {} tools",
                group_counts.len(),
                tools.len()
            );
        }
        return Ok(());
    }

    if json_output {
        // Enrich the JSON with an output_kind marker per tool so scripts can sort/filter.
        let enriched: Vec<serde_json::Value> = tools
            .iter()
            .map(|tool| {
                let kind_marker = registry
                    .get(&tool.name)
                    .map_or("—", |h| h.output_kind().short_marker());
                serde_json::json!({
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                    "annotations": tool.annotations,
                    "reduce": kind_marker,
                })
            })
            .collect();
        let json = serde_json::to_string_pretty(&enriched)
            .map_err(|e| BridgeError::Config(e.to_string()))?;
        println!("{json}");
    } else {
        println!("{:<40} {:<18} {:<7} DESCRIPTION", "TOOL", "GROUP", "REDUCE");
        let separator = "-".repeat(100);
        println!("{separator}");
        for tool in &tools {
            let group = tool_group(&tool.name);
            let reduce_marker = registry
                .get(&tool.name)
                .map_or("—", |h| h.output_kind().short_marker());
            // Truncate description to 55 chars (a bit tighter to fit the new column)
            let desc = if tool.description.len() > 55 {
                format!("{}...", &tool.description[..52])
            } else {
                tool.description.clone()
            };
            println!(
                "{:<40} {:<18} {:<7} {}",
                tool.name, group, reduce_marker, desc
            );
        }
        println!("\nTotal: {} tools", tools.len());
        println!(
            "\nReduce legend: jq+tsv=jq_filter+output_format  yq+tsv=yq_filter+output_format  \
             cols=columns+limit  *=any  —=none"
        );
        println!("Tip: run 'describe-tool <name>' to see the exact reduction params for a tool.");
    }

    Ok(())
}

/// Validate the configuration file and report issues
pub async fn run_validate(config: Arc<Config>) -> Result<()> {
    use crate::mcp::registry::create_filtered_registry;
    use crate::security::CommandValidator;

    let mut issues: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Check hosts
    if config.hosts.is_empty() {
        warnings.push(
            "No hosts configured. Use ssh_config auto-discovery or add hosts to config.yaml."
                .to_string(),
        );
    }

    for (name, host) in &config.hosts {
        if host.hostname.is_empty() {
            issues.push(format!("Host '{name}': hostname is empty"));
        }
        if host.user.is_empty() {
            issues.push(format!("Host '{name}': user is empty"));
        }
        if let crate::config::AuthConfig::Key { ref path, .. } = host.auth {
            let expanded = crate::path_utils::home_expand_or_input(path);
            if !std::path::Path::new(&expanded).exists() {
                warnings.push(format!("Host '{name}': key file '{path}' not found"));
            }
        }
    }

    // Check security config
    let validator = CommandValidator::new(&config.security);
    let test_commands = ["ls", "cat /etc/hostname", "docker ps"];
    for cmd in &test_commands {
        if validator.validate(cmd).is_err() {
            warnings.push(format!(
                "Security: common command '{cmd}' is denied by current config"
            ));
        }
    }

    // Check tool registry loads
    let registry = create_filtered_registry(&config.tool_groups);
    let tool_count = registry.len();

    // Report
    if issues.is_empty() && warnings.is_empty() {
        println!("Configuration is valid.");
        println!("  Hosts: {}", config.hosts.len());
        println!("  Tools: {tool_count}");
        println!("  Security mode: {:?}", config.security.mode);
    } else {
        if !issues.is_empty() {
            println!("ERRORS:");
            for issue in &issues {
                println!("  \u{2717} {issue}");
            }
        }
        if !warnings.is_empty() {
            println!("WARNINGS:");
            for warning in &warnings {
                println!("  \u{26a0} {warning}");
            }
        }
        println!("\n  Hosts: {}", config.hosts.len());
        println!("  Tools: {tool_count}");
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(BridgeError::Config(format!(
            "{} error(s) found",
            issues.len()
        )))
    }
}

/// Show differences between current and default configuration
pub async fn run_config_diff(config: Arc<Config>) -> Result<()> {
    use crate::config::{LimitsConfig, SecurityConfig};

    let default_security = SecurityConfig::default();
    let default_limits = LimitsConfig::default();

    println!("=== Configuration Differences (current vs default) ===\n");

    // Compare security mode
    if config.security.mode != default_security.mode {
        println!(
            "security.mode: {:?} (default: {:?})",
            config.security.mode, default_security.mode
        );
    }

    // Compare limits
    if config.limits.command_timeout_seconds != default_limits.command_timeout_seconds {
        println!(
            "limits.command_timeout_seconds: {} (default: {})",
            config.limits.command_timeout_seconds, default_limits.command_timeout_seconds
        );
    }
    if config.limits.max_concurrent_commands != default_limits.max_concurrent_commands {
        println!(
            "limits.max_concurrent_commands: {} (default: {})",
            config.limits.max_concurrent_commands, default_limits.max_concurrent_commands
        );
    }
    if config.limits.rate_limit_per_second != default_limits.rate_limit_per_second {
        println!(
            "limits.rate_limit_per_second: {} (default: {})",
            config.limits.rate_limit_per_second, default_limits.rate_limit_per_second
        );
    }
    if config.limits.max_output_chars != default_limits.max_output_chars {
        println!(
            "limits.max_output_chars: {} (default: {})",
            config.limits.max_output_chars, default_limits.max_output_chars
        );
    }

    // Compare hosts
    println!("\nhosts: {} configured", config.hosts.len());

    // Compare blacklist
    if config.security.blacklist.len() != default_security.blacklist.len() {
        println!(
            "security.blacklist: {} patterns (default: {} patterns)",
            config.security.blacklist.len(),
            default_security.blacklist.len()
        );
    }

    // Compare disabled tool groups
    let disabled: Vec<_> = config
        .tool_groups
        .groups
        .iter()
        .filter(|(_, enabled)| !**enabled)
        .map(|(name, _)| name.as_str())
        .collect();
    if !disabled.is_empty() {
        println!("tool_groups.disabled: {disabled:?}");
    }

    println!("\n(Only non-default values are shown)");

    Ok(())
}

/// Create a `ToolContext` from configuration
fn create_context(config: Arc<Config>) -> ToolContext {
    let validator = Arc::new(CommandValidator::new(&config.security));
    let sanitizer = Arc::new(Sanitizer::from_config_with_legacy(
        &config.security.sanitize,
        &config.security.sanitize_patterns,
    ));
    // For CLI mode, we don't spawn the audit writer task (short-lived process)
    let (audit_logger, _audit_task) =
        AuditLogger::new(&config.audit).unwrap_or_else(|_| (AuditLogger::disabled(), None));
    let audit_logger = Arc::new(audit_logger);
    let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
    let connection_pool = Arc::new(ExecutorRouter::with_defaults());
    let rate_limiter = Arc::new(RateLimiter::new(config.limits.rate_limit_per_second));

    let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
        Arc::clone(&validator),
        Arc::clone(&sanitizer),
        Arc::clone(&audit_logger),
        Arc::clone(&history),
    ));

    let session_manager = Arc::new(SessionManager::new(config.sessions.clone()));

    ToolContext::new(
        config,
        validator,
        sanitizer,
        audit_logger,
        history,
        connection_pool,
        execute_use_case,
        rate_limiter,
        session_manager,
    )
}

/// Execute a command on a remote host
///
/// # Errors
///
/// Returns an error if:
/// - The specified host is not found in the configuration
/// - The command is denied by security rules (whitelist/blacklist)
/// - SSH connection to the host fails
/// - Command execution fails or times out
pub async fn run_exec(
    config: Arc<Config>,
    host: &str,
    command: &str,
    timeout: u64,
    working_dir: Option<&str>,
) -> Result<()> {
    let ctx = create_context(Arc::clone(&config));

    // Get host config
    let host_config = config
        .hosts
        .get(host)
        .ok_or_else(|| BridgeError::UnknownHost {
            host: host.to_string(),
        })?;

    // Validate command
    if let Err(e) = ctx.execute_use_case.validate(command) {
        let reason = match &e {
            BridgeError::CommandDenied { reason } => reason.clone(),
            _ => e.to_string(),
        };
        ctx.execute_use_case.log_denied(host, command, &reason);
        return Err(e);
    }

    info!(host = %host, command = %command, "Executing SSH command");

    // Build limits with timeout override
    let mut limits = config.limits.clone();
    limits.command_timeout_seconds = timeout;

    // Build the actual command (with optional cd)
    let full_command = working_dir.map_or_else(
        || command.to_string(),
        |dir| format!("cd {} && {}", shell::escape(dir, ShellType::Posix), command),
    );

    // Get retry config
    let retry_config = limits.retry_config();

    // Resolve jump host if configured
    let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
        config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    // Execute with retry logic
    let output = with_retry_if(
        &retry_config,
        "cli_exec",
        async || {
            let mut conn = ctx
                .connection_pool
                .get_connection_with_jump(host, host_config, &limits, jump_host)
                .await?;

            match conn.exec(&full_command, &limits).await {
                Ok(output) => Ok(output),
                Err(e) => {
                    conn.mark_failed();
                    Err(e)
                }
            }
        },
        is_retryable_error,
    )
    .await;

    let output = output.inspect_err(|e| {
        ctx.execute_use_case
            .log_failure(host, command, &e.to_string());
    })?;

    // Process success
    let response = ctx
        .execute_use_case
        .process_success(host, command, &output.into());

    if response.exit_code != 0 {
        warn!(
            host = %host,
            command = %command,
            exit_code = response.exit_code,
            "Command failed"
        );
    }

    // Print the output
    println!("{}", response.output);

    // Propagate remote exit code to CLI exit code
    if response.exit_code != 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Show configured hosts and security settings
///
/// # Errors
///
/// This function is infallible in practice but returns `Result` for
/// consistency with other CLI commands.
pub async fn run_status(config: Arc<Config>) -> Result<()> {
    println!("MCP SSH Bridge Status");
    println!("=====================\n");

    // Security mode
    println!("Security Mode: {:?}", config.security.mode);

    if !config.security.whitelist.is_empty() {
        println!("\nWhitelist patterns:");
        for pattern in &config.security.whitelist {
            println!("  - {pattern}");
        }
    }

    if !config.security.blacklist.is_empty() {
        println!("\nBlacklist patterns:");
        for pattern in &config.security.blacklist {
            println!("  - {pattern}");
        }
    }

    // Hosts
    println!("\nConfigured Hosts ({}):", config.hosts.len());
    println!("{:-<60}", "");

    if config.hosts.is_empty() {
        println!("  (no hosts configured)");
    } else {
        for (alias, host) in &config.hosts {
            println!("\n  {alias}:");
            println!("    Hostname: {}:{}", host.hostname, host.port);
            println!("    User: {}", host.user);
            println!("    Auth: {:?}", auth_type_name(&host.auth));
            println!("    Host Key: {:?}", host.host_key_verification);
            if let Some(ref jump) = host.proxy_jump {
                println!("    Jump Host: {jump}");
            }
            if let Some(ref desc) = host.description {
                println!("    Description: {desc}");
            }
        }
    }

    // Limits
    println!("\nLimits:");
    println!(
        "  Command timeout: {}s",
        config.limits.command_timeout_seconds
    );
    println!(
        "  Connection timeout: {}s",
        config.limits.connection_timeout_seconds
    );
    println!("  Max output: {} bytes", config.limits.max_output_bytes);
    println!(
        "  Max concurrent: {}",
        config.limits.max_concurrent_commands
    );
    println!("  Retry attempts: {}", config.limits.retry_attempts);

    // Audit
    println!("\nAudit:");
    println!("  Enabled: {}", config.audit.enabled);
    if config.audit.enabled {
        println!("  Path: {}", config.audit.path.display());
    }

    Ok(())
}

fn auth_type_name(auth: &crate::config::AuthConfig) -> &'static str {
    match auth {
        crate::config::AuthConfig::Key { .. } => "SSH Key",
        crate::config::AuthConfig::Agent => "SSH Agent",
        crate::config::AuthConfig::Password { .. } => "Password",
        #[cfg(feature = "winrm")]
        crate::config::AuthConfig::Ntlm { .. } => "NTLM",
        #[cfg(feature = "winrm")]
        crate::config::AuthConfig::Certificate { .. } => "Certificate",
        #[cfg(feature = "winrm")]
        crate::config::AuthConfig::Kerberos => "Kerberos",
    }
}

/// Show command execution history
///
/// # Errors
///
/// This function is infallible in practice but returns `Result` for
/// consistency with other CLI commands.
pub async fn run_history(
    config: Arc<Config>,
    limit: usize,
    host_filter: Option<&str>,
) -> Result<()> {
    let ctx = create_context(config);

    let entries = if let Some(host) = host_filter {
        ctx.history.for_host(host, limit)
    } else {
        ctx.history.recent(limit)
    };

    if entries.is_empty() {
        println!("No command history available.");
        println!("\nNote: History is only available during a CLI session.");
        println!("For persistent history, check the audit log if enabled.");
        return Ok(());
    }

    println!("Command History (most recent first):");
    println!("{:-<80}", "");

    for entry in &entries {
        let status = if entry.success { "OK" } else { "FAIL" };
        let exit_info = if entry.exit_code == u32::MAX {
            "error".to_string()
        } else {
            format!("exit {}", entry.exit_code)
        };

        println!(
            "\n[{}] {} - {} ({})",
            entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
            entry.host,
            status,
            exit_info
        );
        println!("  Command: {}", entry.command);
        if entry.duration_ms > 0 {
            println!("  Duration: {}ms", entry.duration_ms);
        }
    }

    println!("\n{:-<80}", "");
    println!("Total: {} entries", entries.len());

    Ok(())
}

/// Upload a file to a remote host via SFTP
///
/// # Errors
///
/// Returns an error if:
/// - The specified host is not found in the configuration
/// - The transfer mode is invalid
/// - The local file does not exist or cannot be read
/// - SSH/SFTP connection fails
/// - The file transfer fails (permissions, disk space, network)
/// - Checksum verification fails (if enabled)
#[expect(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn run_upload(
    config: Arc<Config>,
    host: &str,
    local_path: &Path,
    remote_path: &str,
    mode: &str,
    chunk_size: u64,
    verify_checksum: bool,
    preserve_permissions: bool,
    show_progress: bool,
) -> Result<()> {
    let ctx = create_context(Arc::clone(&config));

    // Get host config
    let host_config = config
        .hosts
        .get(host)
        .ok_or_else(|| BridgeError::UnknownHost {
            host: host.to_string(),
        })?;

    // Parse transfer mode
    let transfer_mode = TransferMode::parse(mode).ok_or_else(|| BridgeError::FileTransfer {
        reason: format!(
            "Invalid transfer mode: {mode}. Valid modes: overwrite, append, resume, fail-if-exists"
        ),
    })?;

    // Expand and check local path (`~` -> home dir; pass-through otherwise).
    let local_path_str = local_path.to_string_lossy();
    let expanded_path = crate::path_utils::home_expand_or_input(&local_path_str);
    let local_path = Path::new(&expanded_path);

    if !local_path.exists() {
        return Err(BridgeError::FileTransfer {
            reason: format!("Local file not found: {}", local_path.display()),
        });
    }

    let metadata = std::fs::metadata(local_path).map_err(|e| BridgeError::FileTransfer {
        reason: format!("Cannot read file metadata: {e}"),
    })?;

    info!(
        host = %host,
        local = %local_path.display(),
        remote = %remote_path,
        size = metadata.len(),
        mode = %mode,
        "Uploading file via SFTP"
    );

    // Build transfer options
    let options = TransferOptions {
        mode: transfer_mode,
        chunk_size,
        verify_checksum,
        preserve_permissions,
    };

    // Resolve jump host if configured
    let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
        config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    // Connect to host (via jump host if configured)
    let client = if let Some((jump_name, jump_config)) = jump_host {
        SshClient::connect_via_jump(host, host_config, jump_name, jump_config, &config.limits)
            .await?
    } else {
        SshClient::connect(host, host_config, &config.limits).await?
    };

    // Create SFTP session
    let sftp = client.sftp_session().await?;

    // Progress callback (must be Send for future_not_send lint)
    let progress_callback: Option<Box<dyn FnMut(TransferProgress) + Send>> = if show_progress {
        Some(Box::new(|progress: TransferProgress| {
            print!(
                "\r  Progress: {:.1}% ({} / {} bytes)",
                progress.percentage, progress.bytes_transferred, progress.total_bytes
            );
            let _ = io::stdout().flush();
        }))
    } else {
        None
    };

    // Upload the file
    let result = sftp
        .upload_file(local_path, remote_path, &options, progress_callback)
        .await;

    // Log the result
    match &result {
        Ok(transfer_result) => {
            ctx.audit_logger.log(AuditEvent::new(
                host,
                &format!("SFTP_UPLOAD {} -> {}", local_path.display(), remote_path),
                CommandResult::Success {
                    exit_code: 0,
                    duration_ms: transfer_result.duration_ms,
                },
            ));
        }
        Err(e) => {
            ctx.audit_logger.log(AuditEvent::new(
                host,
                &format!("SFTP_UPLOAD {} -> {}", local_path.display(), remote_path),
                CommandResult::Error {
                    message: e.to_string(),
                },
            ));
        }
    }

    let transfer_result = result?;

    // Clear progress line if shown
    if show_progress {
        println!();
    }

    // Format output
    let mut output = String::new();
    let _ = writeln!(output, "File uploaded successfully:");
    let _ = writeln!(output, "  Host: {host}");
    let _ = writeln!(output, "  Local: {}", local_path.display());
    let _ = writeln!(output, "  Remote: {remote_path}");
    let _ = writeln!(
        output,
        "  Size: {} bytes",
        transfer_result.bytes_transferred
    );
    let _ = writeln!(output, "  Duration: {}ms", transfer_result.duration_ms);
    let _ = writeln!(
        output,
        "  Speed: {:.2} MB/s",
        transfer_result.bytes_per_second / 1_000_000.0
    );
    if let Some(checksum) = &transfer_result.checksum {
        let _ = writeln!(output, "  SHA256: {checksum}");
    }

    println!("{output}");

    Ok(())
}

/// Download a file from a remote host via SFTP
///
/// # Errors
///
/// Returns an error if:
/// - The specified host is not found in the configuration
/// - The transfer mode is invalid
/// - The local destination directory cannot be created
/// - SSH/SFTP connection fails
/// - The remote file does not exist or cannot be read
/// - The file transfer fails (permissions, disk space, network)
/// - Checksum verification fails (if enabled)
#[expect(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn run_download(
    config: Arc<Config>,
    host: &str,
    remote_path: &str,
    local_path: &Path,
    mode: &str,
    chunk_size: u64,
    verify_checksum: bool,
    preserve_permissions: bool,
    show_progress: bool,
) -> Result<()> {
    let ctx = create_context(Arc::clone(&config));

    // Get host config
    let host_config = config
        .hosts
        .get(host)
        .ok_or_else(|| BridgeError::UnknownHost {
            host: host.to_string(),
        })?;

    // Parse transfer mode
    let transfer_mode = TransferMode::parse(mode).ok_or_else(|| BridgeError::FileTransfer {
        reason: format!(
            "Invalid transfer mode: {mode}. Valid modes: overwrite, append, resume, fail-if-exists"
        ),
    })?;

    // Expand local path (`~` -> home dir; pass-through otherwise).
    let local_path_str = local_path.to_string_lossy();
    let expanded_path = crate::path_utils::home_expand_or_input(&local_path_str);
    let local_path = Path::new(&expanded_path);

    // Create parent directories if needed
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BridgeError::FileTransfer {
            reason: format!("Cannot create directory: {e}"),
        })?;
    }

    info!(
        host = %host,
        remote = %remote_path,
        local = %local_path.display(),
        mode = %mode,
        "Downloading file via SFTP"
    );

    // Build transfer options
    let options = TransferOptions {
        mode: transfer_mode,
        chunk_size,
        verify_checksum,
        preserve_permissions,
    };

    // Resolve jump host if configured
    let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
        config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    // Connect to host (via jump host if configured)
    let client = if let Some((jump_name, jump_config)) = jump_host {
        SshClient::connect_via_jump(host, host_config, jump_name, jump_config, &config.limits)
            .await?
    } else {
        SshClient::connect(host, host_config, &config.limits).await?
    };

    // Create SFTP session
    let sftp = client.sftp_session().await?;

    // Progress callback (must be Send for future_not_send lint)
    let progress_callback: Option<Box<dyn FnMut(TransferProgress) + Send>> = if show_progress {
        Some(Box::new(|progress: TransferProgress| {
            print!(
                "\r  Progress: {:.1}% ({} / {} bytes)",
                progress.percentage, progress.bytes_transferred, progress.total_bytes
            );
            let _ = io::stdout().flush();
        }))
    } else {
        None
    };

    // Download the file
    let result = sftp
        .download_file(remote_path, local_path, &options, progress_callback)
        .await;

    // Log the result
    match &result {
        Ok(transfer_result) => {
            ctx.audit_logger.log(AuditEvent::new(
                host,
                &format!("SFTP_DOWNLOAD {} -> {}", remote_path, local_path.display()),
                CommandResult::Success {
                    exit_code: 0,
                    duration_ms: transfer_result.duration_ms,
                },
            ));
        }
        Err(e) => {
            ctx.audit_logger.log(AuditEvent::new(
                host,
                &format!("SFTP_DOWNLOAD {} -> {}", remote_path, local_path.display()),
                CommandResult::Error {
                    message: e.to_string(),
                },
            ));
        }
    }

    let transfer_result = result?;

    // Clear progress line if shown
    if show_progress {
        println!();
    }

    // Format output
    let mut output = String::new();
    let _ = writeln!(output, "File downloaded successfully:");
    let _ = writeln!(output, "  Host: {host}");
    let _ = writeln!(output, "  Remote: {remote_path}");
    let _ = writeln!(output, "  Local: {}", local_path.display());
    let _ = writeln!(
        output,
        "  Size: {} bytes",
        transfer_result.bytes_transferred
    );
    let _ = writeln!(output, "  Duration: {}ms", transfer_result.duration_ms);
    let _ = writeln!(
        output,
        "  Speed: {:.2} MB/s",
        transfer_result.bytes_per_second / 1_000_000.0
    );
    if let Some(checksum) = &transfer_result.checksum {
        let _ = writeln!(output, "  SHA256: {checksum}");
    }

    println!("{output}");

    Ok(())
}

/// Invoke any registered MCP tool directly via CLI.
///
/// Accepts arguments as `key=value` pairs or a JSON string via `json_args`.
/// Values are coerced to the type declared in the tool's input schema when possible.
///
/// Returns the remote exit code (0 = success, non-zero = tool reported an error).
///
/// # Errors
///
/// Returns an error if:
/// - The tool is not found in the registry
/// - Argument parsing fails
/// - Tool execution fails
pub async fn run_tool(
    config: Arc<Config>,
    tool_name: &str,
    kv_args: &[String],
    json_args: Option<&str>,
    json_output: bool,
    data_reduction: DataReductionFlags,
) -> Result<i32> {
    use crate::mcp::registry::{create_filtered_registry, inject_reduction_schema};

    let registry = create_filtered_registry(&config.tool_groups);

    // Build the arguments JSON
    let args: Option<serde_json::Value> = if let Some(raw) = json_args {
        let val: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| BridgeError::Config(format!("Invalid --json-args: {e}")))?;
        Some(merge_data_reduction(val, &data_reduction))
    } else if kv_args.is_empty() && data_reduction.is_empty() {
        None
    } else {
        // Parse key=value pairs into a JSON object, coercing types via enriched schema
        // (includes data-reduction params like jq_filter, columns, output_format, limit)
        let enriched_schema = registry.get(tool_name).map(|h| {
            let mut schema: serde_json::Value =
                serde_json::from_str(h.schema().input_schema).unwrap_or_default();
            inject_reduction_schema(&mut schema, h.output_kind());
            serde_json::to_string(&schema).ok()
        });
        let schema_ref = enriched_schema.as_ref().and_then(|opt| opt.as_deref());
        let mut map = serde_json::Map::new();
        for pair in kv_args {
            if let Some((key, value)) = pair.split_once('=') {
                let coerced = coerce_value(value, key, schema_ref);
                map.insert(key.to_string(), coerced);
            } else {
                return Err(BridgeError::Config(format!(
                    "Invalid argument '{pair}': expected key=value format"
                )));
            }
        }
        // Inject data-reduction flags only if the user did NOT set the
        // equivalent key=value explicitly (explicit wins).
        Some(merge_data_reduction(
            serde_json::Value::Object(map),
            &data_reduction,
        ))
    };

    // Fast path: if the local daemon is running, forward this tool call
    // to it over the Unix socket. This reuses the daemon's shared SSH
    // connection pool and saves the ~95 ms handshake on every invocation
    // after the first. Falls back to the stateless in-process path on
    // any forwarding error (daemon absent, refused, timeout, etc.).
    let daemon_socket = crate::daemon::default_socket_path();
    if daemon_socket.exists()
        && let Some(forwarded) = try_forward_to_daemon(
            &daemon_socket,
            tool_name,
            args.clone().unwrap_or(serde_json::Value::Null),
        )
        .await?
    {
        return print_daemon_response(&forwarded, json_output);
    }

    // Slow path: stateless in-process execution.
    let ctx = create_context(Arc::clone(&config));
    let result = registry.execute(tool_name, args, &ctx).await?;

    let is_error = result.is_error.unwrap_or(false);
    let exit_code = i32::from(is_error);

    if json_output {
        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| BridgeError::Config(e.to_string()))?;
        println!("{json}");
    } else {
        // Print text content
        for content in &result.content {
            match content {
                crate::mcp::protocol::ToolContent::Text { text } => {
                    println!("{text}");
                }
                _ => {
                    // For non-text content, serialize as JSON
                    if let Ok(s) = serde_json::to_string_pretty(content) {
                        println!("{s}");
                    }
                }
            }
        }
    }

    Ok(exit_code)
}

/// Coerce a string value to the appropriate JSON type based on the tool's input schema.
fn coerce_value(value: &str, key: &str, schema_json: Option<&str>) -> serde_json::Value {
    // Try to extract the expected type from the JSON schema
    if let Some(prop_type) = schema_json
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|schema| {
            schema
                .get("properties")
                .and_then(|p| p.get(key))
                .and_then(|p| p.get("type"))
                .and_then(|t| t.as_str())
                .map(String::from)
        })
    {
        return match prop_type.as_str() {
            "integer" | "number" => value
                .parse::<i64>()
                .map(serde_json::Value::from)
                .or_else(|_| value.parse::<f64>().map(serde_json::Value::from))
                .unwrap_or_else(|_| serde_json::Value::String(value.to_string())),
            "boolean" => match value {
                "true" | "1" | "yes" => serde_json::Value::Bool(true),
                "false" | "0" | "no" => serde_json::Value::Bool(false),
                _ => serde_json::Value::String(value.to_string()),
            },
            "array" | "object" => serde_json::from_str(value)
                .unwrap_or_else(|_| serde_json::Value::String(value.to_string())),
            _ => serde_json::Value::String(value.to_string()),
        };
    }

    // Auto-detect: try JSON literals first, then string
    if (value.starts_with('{') || value.starts_with('['))
        && let Ok(v) = serde_json::from_str(value)
    {
        return v;
    }
    if let Ok(b) = value.parse::<bool>() {
        return serde_json::Value::Bool(b);
    }
    if let Ok(n) = value.parse::<i64>() {
        return serde_json::Value::from(n);
    }
    serde_json::Value::String(value.to_string())
}

/// Show full schema and description for a single tool.
///
/// # Errors
///
/// Returns an error if the tool is not found in the registry.
pub async fn run_describe_tool(
    config: Arc<Config>,
    tool_name: &str,
    json_output: bool,
) -> Result<()> {
    use crate::mcp::registry::{create_filtered_registry, inject_reduction_schema, tool_group};

    let registry = create_filtered_registry(&config.tool_groups);
    let handler = registry
        .get(tool_name)
        .ok_or_else(|| BridgeError::McpUnknownTool {
            tool: tool_name.to_string(),
        })?;

    let schema = handler.schema();
    let group = tool_group(tool_name);
    let output_kind = handler.output_kind();

    // Parse and enrich the schema with data-reduction params (jq_filter, columns, etc.)
    let mut input_schema: serde_json::Value =
        serde_json::from_str(schema.input_schema).unwrap_or_default();
    inject_reduction_schema(&mut input_schema, output_kind);

    if json_output {
        let obj = serde_json::json!({
            "name": schema.name,
            "group": group,
            "description": schema.description,
            "output_kind": format!("{output_kind:?}"),
            "reduction_strategy": output_kind.strategy_hint(),
            "input_schema": input_schema,
        });
        let json =
            serde_json::to_string_pretty(&obj).map_err(|e| BridgeError::Config(e.to_string()))?;
        println!("{json}");
    } else {
        println!("Tool: {}", schema.name);
        println!("Group: {group}");
        println!("Description: {}", schema.description);
        println!();
        println!("Output Kind: {output_kind:?}");
        println!("Reduction Strategy: {}", output_kind.strategy_hint());
        println!("\nInput Schema:");

        // Pretty-print the schema, showing required fields and property types
        if let Some(props) = input_schema.get("properties").and_then(|p| p.as_object()) {
            let required: Vec<&str> = input_schema
                .get("required")
                .and_then(serde_json::Value::as_array)
                .map(|arr| arr.iter().filter_map(serde_json::Value::as_str).collect())
                .unwrap_or_default();

            for (name, prop) in props {
                let prop_type = prop.get("type").and_then(|t| t.as_str()).unwrap_or("any");
                let is_required = required.contains(&name.as_str());
                let req_marker = if is_required { " (required)" } else { "" };
                let desc = prop
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("");

                println!("  {name}: {prop_type}{req_marker}");
                if !desc.is_empty() {
                    println!("    {desc}");
                }

                // Show enum values if present
                if let Some(vals) = prop.get("enum").and_then(|e| e.as_array()) {
                    let enum_strs: Vec<String> =
                        vals.iter().map(std::string::ToString::to_string).collect();
                    println!("    values: [{}]", enum_strs.join(", "));
                }

                // Show default if present
                if let Some(default) = prop.get("default") {
                    println!("    default: {default}");
                }
            }
        }

        println!("\nUsage:");
        println!("  mcp-ssh-bridge tool {tool_name} key=value ...",);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, AuthConfig, HostConfig, HostKeyVerification, HttpTransportConfig,
        LimitsConfig, OsType, SecurityConfig, SessionConfig, SshConfigDiscovery, ToolGroupsConfig,
    };
    use crate::mcp::tool_handlers::utils::shell_escape;
    use std::collections::HashMap;

    // ============== DataReductionFlags merge Tests ==============

    #[test]
    fn test_data_reduction_flags_is_empty_by_default() {
        let flags = DataReductionFlags::default();
        assert!(flags.is_empty());
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_merge_into_empty_args_creates_object() {
        let flags = DataReductionFlags {
            jq: Some(".name".to_string()),
            columns: None,
            limit: Some(5),
            output_format: None,
        };
        let merged = merge_data_reduction(serde_json::Value::Null, &flags);
        let obj = merged.as_object().expect("should become object");
        assert_eq!(obj["jq_filter"], ".name");
        assert_eq!(obj["limit"], 5);
        assert!(!obj.contains_key("columns"));
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_merge_preserves_explicit_key_value_wins() {
        // User already set jq_filter=.custom via key=value; --jq '.flag' must NOT override.
        let mut m = serde_json::Map::new();
        m.insert("host".to_string(), serde_json::Value::from("prod"));
        m.insert("jq_filter".to_string(), serde_json::Value::from(".custom"));
        let args = serde_json::Value::Object(m);

        let flags = DataReductionFlags {
            jq: Some(".flag".to_string()),
            columns: None,
            limit: None,
            output_format: None,
        };
        let merged = merge_data_reduction(args, &flags);
        assert_eq!(merged["jq_filter"], ".custom");
    }

    #[test]
    fn test_merge_injects_columns_as_array() {
        let flags = DataReductionFlags {
            #[cfg(feature = "jq")]
            jq: None,
            columns: Some(vec!["name".to_string(), "status".to_string()]),
            limit: None,
            #[cfg(feature = "jq")]
            output_format: None,
        };
        let merged =
            merge_data_reduction(serde_json::Value::Object(serde_json::Map::new()), &flags);
        let arr = merged["columns"].as_array().expect("columns must be array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], "name");
        assert_eq!(arr[1], "status");
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_merge_injects_output_format_tsv() {
        let flags = DataReductionFlags {
            jq: Some(".[]".to_string()),
            columns: None,
            limit: None,
            output_format: Some("tsv".to_string()),
        };
        let merged =
            merge_data_reduction(serde_json::Value::Object(serde_json::Map::new()), &flags);
        assert_eq!(merged["output_format"], "tsv");
        assert_eq!(merged["jq_filter"], ".[]");
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_merge_preserves_explicit_output_format() {
        let mut m = serde_json::Map::new();
        m.insert("output_format".to_string(), serde_json::Value::from("json"));
        let args = serde_json::Value::Object(m);

        let flags = DataReductionFlags {
            jq: None,
            columns: None,
            limit: None,
            output_format: Some("tsv".to_string()),
        };
        let merged = merge_data_reduction(args, &flags);
        // Explicit "json" wins over --output-format=tsv flag.
        assert_eq!(merged["output_format"], "json");
    }

    #[test]
    fn test_merge_noop_when_flags_empty() {
        let args = serde_json::json!({"host": "prod"});
        let flags = DataReductionFlags::default();
        let merged = merge_data_reduction(args.clone(), &flags);
        assert_eq!(merged, args);
    }

    // ============== shell_escape Tests ==============

    #[test]
    fn test_shell_escape_simple() {
        assert_eq!(shell_escape("simple"), "'simple'");
    }

    #[test]
    fn test_shell_escape_empty() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn test_shell_escape_with_spaces() {
        assert_eq!(shell_escape("with spaces"), "'with spaces'");
    }

    #[test]
    fn test_shell_escape_with_single_quote() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_escape_multiple_single_quotes() {
        assert_eq!(shell_escape("a'b'c"), "'a'\\''b'\\''c'");
    }

    #[test]
    fn test_shell_escape_only_single_quote() {
        assert_eq!(shell_escape("'"), "''\\'''");
    }

    #[test]
    fn test_shell_escape_special_chars() {
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
        assert_eq!(shell_escape("`cmd`"), "'`cmd`'");
        assert_eq!(shell_escape("a;b"), "'a;b'");
        assert_eq!(shell_escape("a|b"), "'a|b'");
        assert_eq!(shell_escape("a&b"), "'a&b'");
    }

    #[test]
    fn test_shell_escape_double_quotes() {
        assert_eq!(shell_escape("\"quoted\""), "'\"quoted\"'");
    }

    #[test]
    fn test_shell_escape_newlines() {
        assert_eq!(shell_escape("line1\nline2"), "'line1\nline2'");
    }

    #[test]
    fn test_shell_escape_tabs() {
        assert_eq!(shell_escape("col1\tcol2"), "'col1\tcol2'");
    }

    #[test]
    fn test_shell_escape_unicode() {
        assert_eq!(shell_escape("日本語"), "'日本語'");
        assert_eq!(shell_escape("émoji 🎉"), "'émoji 🎉'");
    }

    #[test]
    fn test_shell_escape_path() {
        assert_eq!(shell_escape("/path/to/file"), "'/path/to/file'");
        assert_eq!(
            shell_escape("/path with spaces/file"),
            "'/path with spaces/file'"
        );
    }

    #[test]
    fn test_shell_escape_backslash() {
        assert_eq!(shell_escape("a\\b"), "'a\\b'");
    }

    // ============== auth_type_name Tests ==============

    #[test]
    fn test_auth_type_name_key() {
        let auth = AuthConfig::Key {
            path: "~/.ssh/id_rsa".to_string(),
            passphrase: None,
        };
        assert_eq!(auth_type_name(&auth), "SSH Key");
    }

    #[test]
    fn test_auth_type_name_key_with_passphrase() {
        let auth = AuthConfig::Key {
            path: "~/.ssh/id_rsa".to_string(),
            passphrase: Some(zeroize::Zeroizing::new("secret".to_string())),
        };
        assert_eq!(auth_type_name(&auth), "SSH Key");
    }

    #[test]
    fn test_auth_type_name_agent() {
        let auth = AuthConfig::Agent;
        assert_eq!(auth_type_name(&auth), "SSH Agent");
    }

    #[test]
    fn test_auth_type_name_password() {
        let auth = AuthConfig::Password {
            password: zeroize::Zeroizing::new("secret".to_string()),
        };
        assert_eq!(auth_type_name(&auth), "Password");
    }

    // ============== create_context Tests ==============

    #[test]
    fn test_create_context_with_empty_config() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let ctx = create_context(Arc::new(config));

        // Verify context components are created
        assert!(ctx.config.hosts.is_empty());
    }

    #[test]
    fn test_create_context_with_hosts() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test-server".to_string(),
            HostConfig {
                hostname: "192.168.1.1".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Agent,
                description: Some("Test server".to_string()),
                host_key_verification: HostKeyVerification::Strict,
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
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let ctx = create_context(Arc::new(config));

        assert_eq!(ctx.config.hosts.len(), 1);
        assert!(ctx.config.hosts.contains_key("test-server"));
    }

    #[test]
    fn test_create_context_rate_limiter_from_config() {
        let limits = LimitsConfig {
            rate_limit_per_second: 10,
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits,
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let ctx = create_context(Arc::new(config));

        // Rate limiter should be configured
        assert!(ctx.rate_limiter.check("test").is_ok());
    }

    #[test]
    fn test_create_context_preserves_security_config() {
        let security = SecurityConfig {
            whitelist: vec!["ls".to_string(), "pwd".to_string()],
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security,
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let ctx = create_context(Arc::new(config));

        // Validator should reject commands not in whitelist
        assert!(ctx.execute_use_case.validate("ls").is_ok());
        assert!(ctx.execute_use_case.validate("rm -rf /").is_err());
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_shell_escape_very_long_string() {
        let long_str = "a".repeat(10000);
        let escaped = shell_escape(&long_str);
        assert!(escaped.starts_with('\''));
        assert!(escaped.ends_with('\''));
        assert_eq!(escaped.len(), 10002); // 10000 + 2 quotes
    }

    #[test]
    fn test_shell_escape_all_quotes() {
        let all_quotes = "'''''";
        let escaped = shell_escape(all_quotes);
        // Each ' becomes '\'' (4 chars)
        assert!(escaped.contains("'\\''"));
    }

    // ============== Additional shell_escape Tests ==============

    #[test]
    fn test_shell_escape_null_byte() {
        // Null bytes in strings
        let with_null = "before\0after";
        let escaped = shell_escape(with_null);
        assert!(escaped.starts_with('\''));
        assert!(escaped.ends_with('\''));
    }

    #[test]
    fn test_shell_escape_parentheses() {
        assert_eq!(shell_escape("(cmd)"), "'(cmd)'");
        assert_eq!(shell_escape("$(cmd)"), "'$(cmd)'");
    }

    #[test]
    fn test_shell_escape_redirects() {
        assert_eq!(shell_escape("cmd > file"), "'cmd > file'");
        assert_eq!(shell_escape("cmd >> file"), "'cmd >> file'");
        assert_eq!(shell_escape("cmd < file"), "'cmd < file'");
        assert_eq!(shell_escape("2>&1"), "'2>&1'");
    }

    #[test]
    fn test_shell_escape_glob_patterns() {
        assert_eq!(shell_escape("*.txt"), "'*.txt'");
        assert_eq!(shell_escape("file?.log"), "'file?.log'");
        assert_eq!(shell_escape("[abc]"), "'[abc]'");
    }

    #[test]
    fn test_shell_escape_environment_vars() {
        assert_eq!(shell_escape("${VAR}"), "'${VAR}'");
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
        assert_eq!(shell_escape("${HOME:-/default}"), "'${HOME:-/default}'");
    }

    #[test]
    fn test_shell_escape_complex_path() {
        let path = "/home/user/my project's files/file (1).txt";
        let escaped = shell_escape(path);
        // Should handle spaces and apostrophe
        assert!(escaped.contains("'\\''"));
    }

    // ============== Additional create_context Tests ==============

    #[test]
    fn test_create_context_with_custom_limits() {
        let limits = LimitsConfig {
            command_timeout_seconds: 3600,
            max_output_bytes: 50 * 1024 * 1024,
            retry_attempts: 5,
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits,
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let ctx = create_context(Arc::new(config));

        assert_eq!(ctx.config.limits.command_timeout_seconds, 3600);
        assert_eq!(ctx.config.limits.max_output_bytes, 50 * 1024 * 1024);
        assert_eq!(ctx.config.limits.retry_attempts, 5);
    }

    #[test]
    fn test_create_context_with_disabled_audit() {
        let audit = AuditConfig {
            enabled: false,
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit,
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let ctx = create_context(Arc::new(config));
        assert!(!ctx.config.audit.enabled);
    }

    #[test]
    fn test_create_context_with_session_config() {
        let sessions = SessionConfig {
            max_sessions: 50,
            idle_timeout_seconds: 600,
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions,
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let ctx = create_context(Arc::new(config));

        assert_eq!(ctx.config.sessions.max_sessions, 50);
        assert_eq!(ctx.config.sessions.idle_timeout_seconds, 600);
    }

    #[test]
    fn test_create_context_with_multiple_hosts() {
        let mut hosts = HashMap::new();

        for i in 1..=5 {
            hosts.insert(
                format!("server{i}"),
                HostConfig {
                    hostname: format!("192.168.1.{i}"),
                    port: 22,
                    user: "admin".to_string(),
                    auth: AuthConfig::Agent,
                    description: Some(format!("Server {i}")),
                    host_key_verification: HostKeyVerification::Strict,
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
        }

        let config = Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let ctx = create_context(Arc::new(config));
        assert_eq!(ctx.config.hosts.len(), 5);
    }

    #[test]
    fn test_create_context_with_proxy_jump() {
        let mut hosts = HashMap::new();

        hosts.insert(
            "bastion".to_string(),
            HostConfig {
                hostname: "bastion.example.com".to_string(),
                port: 22,
                user: "jump".to_string(),
                auth: AuthConfig::Agent,
                description: Some("Jump host".to_string()),
                host_key_verification: HostKeyVerification::Strict,
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
            "internal".to_string(),
            HostConfig {
                hostname: "internal.local".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Agent,
                description: Some("Internal server".to_string()),
                host_key_verification: HostKeyVerification::Strict,
                proxy_jump: Some("bastion".to_string()),
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
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let ctx = create_context(Arc::new(config));

        let internal = ctx.config.hosts.get("internal").unwrap();
        assert_eq!(internal.proxy_jump, Some("bastion".to_string()));
    }

    // ============== run_status Tests (async) ==============

    #[tokio::test]
    async fn test_run_status_empty_config() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_status(Arc::new(config)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_status_with_hosts() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test-server".to_string(),
            HostConfig {
                hostname: "test.example.com".to_string(),
                port: 2222,
                user: "testuser".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: Some("Test server description".to_string()),
                host_key_verification: HostKeyVerification::AcceptNew,
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
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_status(Arc::new(config)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_status_with_whitelist() {
        let security = SecurityConfig {
            whitelist: vec!["ls".to_string(), "pwd".to_string(), "whoami".to_string()],
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security,
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_status(Arc::new(config)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_status_with_audit_disabled() {
        let audit = AuditConfig {
            enabled: false,
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit,
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_status(Arc::new(config)).await;
        assert!(result.is_ok());
    }

    // ============== run_history Tests (async) ==============

    #[tokio::test]
    async fn test_run_history_empty() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_history(Arc::new(config), 10, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_history_with_host_filter() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_history(Arc::new(config), 10, Some("nonexistent-host")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_history_with_limit_zero() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_history(Arc::new(config), 0, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_history_with_large_limit() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_history(Arc::new(config), 1000, None).await;
        assert!(result.is_ok());
    }

    // ============== run_exec Error Cases (async) ==============

    #[tokio::test]
    async fn test_run_exec_unknown_host() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_exec(Arc::new(config), "unknown-host", "ls", 30, None).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "unknown-host");
            }
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_run_exec_command_denied() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test".to_string(),
            HostConfig {
                hostname: "test.local".to_string(),
                port: 22,
                user: "user".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::Off,
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

        let security = SecurityConfig {
            whitelist: vec!["ls".to_string()], // Only allow ls
            ..Default::default()
        };

        let config = Config {
            hosts,
            security,
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        // Try to execute a command not in whitelist
        let result = run_exec(Arc::new(config), "test", "rm -rf /", 30, None).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { .. } => {}
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    // ============== run_upload Error Cases (async) ==============

    #[tokio::test]
    async fn test_run_upload_unknown_host() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_upload(
            Arc::new(config),
            "unknown-host",
            Path::new("/local/file"),
            "/remote/file",
            "overwrite",
            1024 * 1024,
            false,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "unknown-host");
            }
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_run_upload_invalid_mode() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test".to_string(),
            HostConfig {
                hostname: "test.local".to_string(),
                port: 22,
                user: "user".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::Off,
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
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_upload(
            Arc::new(config),
            "test",
            Path::new("/local/file"),
            "/remote/file",
            "invalid_mode",
            1024 * 1024,
            false,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("Invalid transfer mode"));
            }
            e => panic!("Expected FileTransfer error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_run_upload_file_not_found() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test".to_string(),
            HostConfig {
                hostname: "test.local".to_string(),
                port: 22,
                user: "user".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::Off,
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
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_upload(
            Arc::new(config),
            "test",
            Path::new("/nonexistent/file/that/does/not/exist.txt"),
            "/remote/file",
            "overwrite",
            1024 * 1024,
            false,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("not found"));
            }
            e => panic!("Expected FileTransfer error, got: {e:?}"),
        }
    }

    // ============== run_download Error Cases (async) ==============

    #[tokio::test]
    async fn test_run_download_unknown_host() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_download(
            Arc::new(config),
            "unknown-host",
            "/remote/file",
            Path::new("/local/file"),
            "overwrite",
            1024 * 1024,
            false,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "unknown-host");
            }
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_run_download_invalid_mode() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test".to_string(),
            HostConfig {
                hostname: "test.local".to_string(),
                port: 22,
                user: "user".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::Off,
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
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_download(
            Arc::new(config),
            "test",
            "/remote/file",
            Path::new("/local/file"),
            "bad_mode",
            1024 * 1024,
            false,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("Invalid transfer mode"));
            }
            e => panic!("Expected FileTransfer error, got: {e:?}"),
        }
    }

    // ============== Transfer Mode Parsing ==============

    #[test]
    fn test_transfer_mode_parsing_in_runner() {
        use crate::ssh::TransferMode;

        assert!(TransferMode::parse("overwrite").is_some());
        assert!(TransferMode::parse("append").is_some());
        assert!(TransferMode::parse("resume").is_some());
        assert!(TransferMode::parse("fail_if_exists").is_some());
        assert!(TransferMode::parse("fail-if-exists").is_some());
        assert!(TransferMode::parse("invalid").is_none());
    }

    // ============== Host Config Tests ==============

    #[test]
    fn test_host_config_with_all_auth_types() {
        let key_auth = AuthConfig::Key {
            path: "~/.ssh/id_ed25519".to_string(),
            passphrase: Some(zeroize::Zeroizing::new("secret".to_string())),
        };
        let agent_auth = AuthConfig::Agent;
        let password_auth = AuthConfig::Password {
            password: zeroize::Zeroizing::new("pass123".to_string()),
        };

        assert_eq!(auth_type_name(&key_auth), "SSH Key");
        assert_eq!(auth_type_name(&agent_auth), "SSH Agent");
        assert_eq!(auth_type_name(&password_auth), "Password");
    }

    #[test]
    fn test_host_config_with_different_ports() {
        let mut hosts = HashMap::new();

        for port in [22, 2222, 22222, 443] {
            hosts.insert(
                format!("host-{port}"),
                HostConfig {
                    hostname: "test.local".to_string(),
                    port,
                    user: "user".to_string(),
                    auth: AuthConfig::Agent,
                    description: None,
                    host_key_verification: HostKeyVerification::Off,
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
        }

        assert_eq!(hosts.get("host-22").unwrap().port, 22);
        assert_eq!(hosts.get("host-2222").unwrap().port, 2222);
        assert_eq!(hosts.get("host-22222").unwrap().port, 22222);
        assert_eq!(hosts.get("host-443").unwrap().port, 443);
    }

    #[test]
    fn test_host_key_verification_modes() {
        let modes = [
            HostKeyVerification::Strict,
            HostKeyVerification::AcceptNew,
            HostKeyVerification::Off,
        ];

        for mode in modes {
            let host = HostConfig {
                hostname: "test.local".to_string(),
                port: 22,
                user: "user".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: mode,
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
            };
            // Should not panic
            let _ = format!("{:?}", host.host_key_verification);
        }
    }

    // ============== coerce_value Tests ==============

    #[test]
    fn test_coerce_value_string_no_schema() {
        let v = coerce_value("hello", "key", None);
        assert_eq!(v, serde_json::Value::String("hello".to_string()));
    }

    #[test]
    fn test_coerce_value_integer_auto() {
        let v = coerce_value("42", "key", None);
        assert_eq!(v, serde_json::json!(42));
    }

    #[test]
    fn test_coerce_value_bool_auto() {
        let v = coerce_value("true", "key", None);
        assert_eq!(v, serde_json::json!(true));
    }

    #[test]
    fn test_coerce_value_json_object_auto() {
        let v = coerce_value(r#"{"a":1}"#, "key", None);
        assert_eq!(v, serde_json::json!({"a": 1}));
    }

    #[test]
    fn test_coerce_value_integer_from_schema() {
        let schema = r#"{"type":"object","properties":{"timeout":{"type":"integer"}}}"#;
        let v = coerce_value("30", "timeout", Some(schema));
        assert_eq!(v, serde_json::json!(30));
    }

    #[test]
    fn test_coerce_value_boolean_from_schema() {
        let schema = r#"{"type":"object","properties":{"sudo":{"type":"boolean"}}}"#;
        let v = coerce_value("yes", "sudo", Some(schema));
        assert_eq!(v, serde_json::json!(true));
    }

    #[test]
    fn test_coerce_value_string_from_schema() {
        let schema = r#"{"type":"object","properties":{"host":{"type":"string"}}}"#;
        let v = coerce_value("prod", "host", Some(schema));
        assert_eq!(v, serde_json::Value::String("prod".to_string()));
    }

    #[test]
    fn test_coerce_value_integer_invalid_stays_string() {
        let schema = r#"{"type":"object","properties":{"port":{"type":"integer"}}}"#;
        let v = coerce_value("abc", "port", Some(schema));
        assert_eq!(v, serde_json::Value::String("abc".to_string()));
    }

    #[test]
    fn test_coerce_value_unknown_key_uses_auto() {
        let schema = r#"{"type":"object","properties":{"host":{"type":"string"}}}"#;
        // "extra" is not in schema, falls through to auto-detect
        let v = coerce_value("42", "extra", Some(schema));
        assert_eq!(v, serde_json::json!(42));
    }

    // ============== Additional coerce_value Tests ==============

    #[test]
    fn test_coerce_value_number_float_from_schema() {
        let schema = r#"{"type":"object","properties":{"rate":{"type":"number"}}}"#;
        let v = coerce_value("3.14", "rate", Some(schema));
        #[allow(clippy::approx_constant)]
        let expected = serde_json::json!(3.14);
        assert_eq!(v, expected);
    }

    #[test]
    fn test_coerce_value_boolean_false_variants() {
        let schema = r#"{"type":"object","properties":{"flag":{"type":"boolean"}}}"#;
        assert_eq!(
            coerce_value("false", "flag", Some(schema)),
            serde_json::json!(false)
        );
        assert_eq!(
            coerce_value("0", "flag", Some(schema)),
            serde_json::json!(false)
        );
        assert_eq!(
            coerce_value("no", "flag", Some(schema)),
            serde_json::json!(false)
        );
    }

    #[test]
    fn test_coerce_value_boolean_true_variants() {
        let schema = r#"{"type":"object","properties":{"flag":{"type":"boolean"}}}"#;
        assert_eq!(
            coerce_value("true", "flag", Some(schema)),
            serde_json::json!(true)
        );
        assert_eq!(
            coerce_value("1", "flag", Some(schema)),
            serde_json::json!(true)
        );
        assert_eq!(
            coerce_value("yes", "flag", Some(schema)),
            serde_json::json!(true)
        );
    }

    #[test]
    fn test_coerce_value_boolean_invalid_stays_string() {
        let schema = r#"{"type":"object","properties":{"flag":{"type":"boolean"}}}"#;
        let v = coerce_value("maybe", "flag", Some(schema));
        assert_eq!(v, serde_json::Value::String("maybe".to_string()));
    }

    #[test]
    fn test_coerce_value_array_from_schema() {
        let schema = r#"{"type":"object","properties":{"tags":{"type":"array"}}}"#;
        let v = coerce_value(r#"["a","b"]"#, "tags", Some(schema));
        assert_eq!(v, serde_json::json!(["a", "b"]));
    }

    #[test]
    fn test_coerce_value_array_invalid_stays_string() {
        let schema = r#"{"type":"object","properties":{"tags":{"type":"array"}}}"#;
        let v = coerce_value("not-json", "tags", Some(schema));
        assert_eq!(v, serde_json::Value::String("not-json".to_string()));
    }

    #[test]
    fn test_coerce_value_object_from_schema() {
        let schema = r#"{"type":"object","properties":{"meta":{"type":"object"}}}"#;
        let v = coerce_value(r#"{"key":"val"}"#, "meta", Some(schema));
        assert_eq!(v, serde_json::json!({"key": "val"}));
    }

    #[test]
    fn test_coerce_value_negative_integer() {
        let v = coerce_value("-42", "key", None);
        assert_eq!(v, serde_json::json!(-42));
    }

    #[test]
    fn test_coerce_value_json_array_auto() {
        let v = coerce_value(r"[1,2,3]", "key", None);
        assert_eq!(v, serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn test_coerce_value_false_auto() {
        let v = coerce_value("false", "key", None);
        assert_eq!(v, serde_json::json!(false));
    }

    #[test]
    fn test_coerce_value_invalid_schema_json() {
        // Invalid schema JSON should fall through to auto-detect
        let v = coerce_value("42", "key", Some("not-valid-json"));
        assert_eq!(v, serde_json::json!(42));
    }

    #[test]
    fn test_coerce_value_schema_missing_properties() {
        let schema = r#"{"type":"object"}"#;
        // Schema has no properties key, should fall through
        let v = coerce_value("hello", "key", Some(schema));
        assert_eq!(v, serde_json::Value::String("hello".to_string()));
    }

    // ============== run_validate Tests (async) ==============

    #[tokio::test]
    async fn test_run_validate_empty_config() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        // Should succeed (no hosts is a warning, not error)
        let result = run_validate(Arc::new(config)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_validate_with_invalid_host() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "bad-host".to_string(),
            HostConfig {
                hostname: String::new(), // empty hostname = error
                port: 22,
                user: String::new(), // empty user = error
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::Off,
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
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_validate(Arc::new(config)).await;
        assert!(result.is_err());
    }

    // ============== run_config_diff Tests (async) ==============

    #[tokio::test]
    async fn test_run_config_diff_default_config() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_config_diff(Arc::new(config)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_config_diff_custom_limits() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig {
                command_timeout_seconds: 120,
                max_output_chars: 100_000,
                ..Default::default()
            },
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_config_diff(Arc::new(config)).await;
        assert!(result.is_ok());
    }

    // ============== run_list_tools Tests (async) ==============

    #[tokio::test]
    async fn test_run_list_tools_all() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_list_tools(Arc::new(config), None, false, false, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_groups_only() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_list_tools(Arc::new(config), None, false, true, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_groups_only_json() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_list_tools(Arc::new(config), None, true, true, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_by_group() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_list_tools(Arc::new(config), Some("docker"), false, false, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_search() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_list_tools(Arc::new(config), None, false, false, Some("kubernetes")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_json_output() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_list_tools(Arc::new(config), None, true, false, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_nonexistent_group() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        // Should succeed but list 0 tools
        let result =
            run_list_tools(Arc::new(config), Some("nonexistent"), false, false, None).await;
        assert!(result.is_ok());
    }

    // ============== run_describe_tool Tests (async) ==============

    #[tokio::test]
    async fn test_run_describe_tool_known_tool() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_describe_tool(Arc::new(config), "ssh_exec", false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_describe_tool_json() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_describe_tool(Arc::new(config), "ssh_exec", true).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_describe_tool_unknown() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };

        let result = run_describe_tool(Arc::new(config), "nonexistent_tool", false).await;
        assert!(result.is_err());
    }
}
