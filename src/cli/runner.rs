//! CLI runner functions
//!
//! These functions execute CLI commands by reusing the existing
//! domain logic and tool handlers.

use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use tracing::{info, warn};

use crate::config::{AuditConfig, Config, ShellType};
use crate::domain::ExecuteCommandUseCase;
use crate::domain::output_truncator::truncate_chars;
use crate::domain::use_cases::shell;
use crate::error::{BridgeError, Result};
use crate::mcp::CommandHistory;
use crate::mcp::history::HistoryConfig;
use crate::mcp::protocol::PROTOCOL_VERSION;
use crate::mcp::request_meta::keys as meta_keys;
use crate::mcp::tool_handlers::{SshDownloadHandler, SshUploadHandler};
use crate::ports::ExecutorRouter;
use crate::ports::ToolContext;
use crate::ports::ToolHandler as _;
use crate::security::{
    AuditEvent, AuditLogger, AuditWriterTask, CommandResult, CommandValidator, RateLimiter,
    Sanitizer, drain_audit_writer,
};
use crate::ssh::{
    SessionManager, SshClient, TransferOptions, TransferProgress, is_retryable_error_for,
    with_retry_if,
};

/// Process exit code for **the remote command failed**, as opposed to the
/// bridge failing to run it.
///
/// [`map_exit_code`] and the exit-code table in `README.md`
/// already own 1-5 for the bridge's *own* failures: 1 execution error,
/// 2 CLI usage, 3 SSH connection, 4 security denial, 5 configuration. Reusing
/// any of them for a remote failure would leave a caller unable to tell
/// "the bridge could not run your command" from "your command ran and said
/// no" — the same conflation, one storey up, that this code exists to remove.
/// So a remote failure gets a code of its own.
pub const EXIT_REMOTE_FAILURE: i32 = 6;

/// Process exit code for a configuration error, including any failure of
/// `load_config`, which `main` classifies by call site.
pub const EXIT_CONFIG_ERROR: i32 = 5;

/// Map a `BridgeError` to the process exit code of `bridge-mcp tool`.
///
/// - 1: tool / command execution error (and every variant not listed)
/// - 2: CLI usage error (unknown tool, bad args)
/// - 3: connection / SSH error
/// - 4: security denial
/// - 5: configuration error (including a config that fails to load or parse)
///
/// The `_ => 1` arm is deliberate: an error nobody classified is a generic
/// failure, and a new `BridgeError` variant lands there until someone decides
/// it deserves a code of its own.
///
/// Pure on purpose: `src/main.rs` prints the error and calls
/// `std::process::exit` on the value returned here. Never returns
/// [`EXIT_REMOTE_FAILURE`], which is reserved for a command that ran remotely.
#[must_use]
pub fn map_exit_code(err: &BridgeError) -> i32 {
    match err {
        BridgeError::CommandDenied { .. } => 4,
        BridgeError::UnknownHost { .. } | BridgeError::SshConnection { .. } => 3,
        BridgeError::McpUnknownTool { .. } => 2,
        BridgeError::Config(_)
        | BridgeError::ConfigNotFound { .. }
        | BridgeError::ConfigInvalid { .. }
        | BridgeError::Yaml(_) => EXIT_CONFIG_ERROR,
        _ => 1,
    }
}

/// Derive the process exit code for `bridge-mcp tool` from a tool result.
///
/// Three outcomes, and the order matters:
/// * `remote_exit_code: Some(n)`, `n != 0` — a command ran on the target host
///   and exited non-zero. [`EXIT_REMOTE_FAILURE`].
/// * otherwise `is_error` — the *bridge* refused or failed (rate limit, denied
///   command, declined confirmation). 1, matching `map_exit_code`.
/// * otherwise success. 0.
///
/// `is_error` alone cannot separate the first two cases, which is why the
/// remote code travels beside it (see
/// [`crate::ports::protocol::ToolCallResult::remote_exit_code`]).
///
/// The first arm says "exited non-zero", not "failed", and the difference is
/// load-bearing. For a tool whose command the caller wrote — `ssh_exec`,
/// `ssh_exec_multi` — the handler reports the code WITHOUT setting
/// `is_error`, because `grep` matching nothing exits 1 without having failed.
/// Reading this field first is what lets the process still stop on `&&` while
/// the MCP result stays free of a verdict nobody can justify.
fn tool_exit_code(result: &crate::mcp::protocol::ToolCallResult) -> i32 {
    exit_code_from(result.remote_exit_code, result.is_error.unwrap_or(false))
}

/// The contract of [`tool_exit_code`] over its two raw inputs, so the direct
/// path (a `ToolCallResult`) and the daemon path (a JSON value read off the
/// wire) cannot drift apart.
fn exit_code_from(remote_exit_code: Option<i32>, is_error: bool) -> i32 {
    match remote_exit_code {
        Some(code) if code != 0 => EXIT_REMOTE_FAILURE,
        _ => i32::from(is_error),
    }
}

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
/// Build the JSON-RPC `tools/call` the CLI forwards to a running daemon.
///
/// Split out of [`try_forward_to_daemon`] so the envelope can be asserted
/// without a live socket: the bug this guards against was invisible to every
/// existing test precisely because the request was built inline, mid-I/O.
///
/// The `_meta` envelope is NOT optional. 2026-07-28 deleted the
/// connection-scoped handshake, so every client-to-server request carries the
/// revision it speaks and the capabilities it has, and the server refuses
/// `-32602` when either key is absent
/// (`mcp::request_meta::missing_required_envelope_field`). Without this, every
/// `bridge-mcp tool …` run with a daemon up returned that refusal instead of
/// the tool's output.
///
/// `clientCapabilities` is `{}` on purpose: the CLI has no channel to answer an
/// elicitation or serve a root, and capability lookup is fail-closed, so
/// declaring none is the honest and the safe value.
fn build_daemon_request(
    request_id: &str,
    tool_name: &str,
    arguments: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
            "_meta": {
                meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
                meta_keys::CLIENT_CAPABILITIES: serde_json::json!({}),
                meta_keys::CLIENT_INFO: {
                    "name": "bridge-mcp-cli",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            },
        },
    })
}

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
    let request = build_daemon_request(&request_id, tool_name, &arguments);

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

/// Warning for a daemon whose build differs from this CLI's, or that does not
/// say which build it is. `None` when the revisions match.
///
/// Read from `result._meta[serverInfo]._meta[BUILD_META_KEY].rev`, which the
/// server stamps on every result. A daemon older than the `_meta` exit-code
/// port reports the same protocol revision and crate version as this build, so
/// the build revision is the only thing that tells them apart.
fn daemon_build_warning(result: &serde_json::Value) -> Option<String> {
    let rev = result
        .get("_meta")
        .and_then(|m| m.get(crate::mcp::request_meta::keys::SERVER_INFO))
        .and_then(|i| i.get("_meta"))
        .and_then(|m| m.get(crate::mcp::protocol::BUILD_META_KEY))
        .and_then(|b| b.get("rev"))
        .and_then(serde_json::Value::as_str);
    match rev {
        Some(rev) if rev == crate::mcp::protocol::BUILD_REV => None,
        Some(rev) => Some(format!(
            "warning: the daemon serving this call is build {rev}, this CLI is {}; \
             an older daemon does not carry the remote exit code, so `ssh_exec` may exit 0 \
             where it should exit 6. Restart the daemon.",
            crate::mcp::protocol::BUILD_REV
        )),
        None => Some(
            "warning: the daemon serving this call does not report its build; it may predate \
             the remote exit code, so `ssh_exec` may exit 0 where it should exit 6. \
             Restart the daemon."
                .to_string(),
        ),
    }
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
    // The remote command's own exit code, carried in `_meta` because the
    // result body deliberately cannot hold it. Without this, `ssh_exec` and
    // `ssh_exec_multi` (which never set `isError`) exited 0 through the
    // daemon while exiting 6 on the direct path. A value that is not an
    // integer fitting `i32` is ignored rather than guessed at.
    let remote_exit_code = result
        .get("_meta")
        .and_then(|m| m.get(crate::mcp::protocol::REMOTE_EXIT_CODE_META_KEY))
        .and_then(serde_json::Value::as_i64)
        .and_then(|c| i32::try_from(c).ok());
    let mut exit_code = exit_code_from(remote_exit_code, is_error);

    // The exit-code guarantee above depends on the daemon's build: one from
    // before the `_meta` port answers without the key, and `ssh_exec` then exits
    // 0 again. Make that visible instead of silent. stderr only.
    if let Some(warning) = daemon_build_warning(result) {
        eprintln!("{warning}");
    }

    // A `resultType` other than `complete` (e.g. `input_required`) means the
    // call did not run to completion; printing its content and exiting 0 would
    // claim success for something that never ran. Absent means `complete`.
    if let Some(kind) = result
        .get("resultType")
        .and_then(serde_json::Value::as_str)
        .filter(|k| *k != "complete")
    {
        eprintln!("Error: the daemon answered resultType={kind:?}, not a completed result");
        if exit_code == 0 {
            exit_code = 1;
        }
    }

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
    let serde_json::Value::Object(ref mut map) = args else {
        return args; // unreachable: an object was just ensured above
    };

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
    // Already name-sorted: `ToolRegistry::list_tools` sorts before returning
    // (audit G-14), and `search_is_deterministic_and_ranks_name_matches_first`
    // pins that. The extra `sort_by` this line used to carry was a no-op that
    // read as load-bearing (audit D-F8, 2026-08-20). `retain` below still
    // needs the binding to be `mut`.
    let mut tools = registry.list_tools();

    // Filter by group if specified
    if let Some(group_filter) = group {
        tools.retain(|t| tool_group(&t.name) == group_filter);
    }

    // Filter and rank by search keyword, using the same tiers as
    // `mcp_search_tools`: exact name, name prefix, name substring, description
    // substring. Filtering alone left the list in name order, so
    // `--search kubernetes` led with `ssh_docker_stats` — a description match —
    // ahead of the 83 tools with the word in their name.
    if let Some(query) = search {
        let query_lower = query.to_lowercase();
        let mut ranked: Vec<(u8, _)> = tools
            .into_iter()
            .filter_map(|t| {
                crate::mcp::meta_tools::relevance_rank(&t.name, &t.description, &query_lower)
                    .map(|rank| (rank, t))
            })
            .collect();
        // `list_tools()` is name-sorted and `sort_by_key` is stable, so ties
        // stay alphabetical.
        ranked.sort_by_key(|(rank, _)| *rank);
        tools = ranked.into_iter().map(|(_, t)| t).collect();
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
            // Truncate description to 55 chars (a bit tighter to fit the new
            // column). Character-wise, not byte-wise: descriptions contain `→`
            // and a byte slice inside one panics (audit 2026-08-02).
            let desc = if tool.description.chars().count() > 55 {
                format!("{}...", truncate_chars(&tool.description, 52))
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
pub async fn run_validate(config: Arc<Config>, json_output: bool) -> Result<()> {
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
    if json_output {
        let report = serde_json::json!({
            "valid": issues.is_empty(),
            "hosts": config.hosts.len(),
            "tools": tool_count,
            "security_mode": format!("{:?}", config.security.mode),
            "errors": issues,
            "warnings": warnings,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| BridgeError::Config(e.to_string()))?
        );
    } else if issues.is_empty() && warnings.is_empty() {
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
pub async fn run_config_diff(config: Arc<Config>, json_output: bool) -> Result<()> {
    use crate::config::{LimitsConfig, SecurityConfig};

    let default_security = SecurityConfig::default();
    let default_limits = LimitsConfig::default();

    // Collected first, rendered second, so the text and JSON forms cannot
    // drift apart the way they do when each branch re-derives the comparison.
    let mut diffs = serde_json::Map::new();
    let mut push = |key: &str, current: serde_json::Value, default: serde_json::Value| {
        diffs.insert(
            key.to_string(),
            serde_json::json!({ "current": current, "default": default }),
        );
    };

    if config.security.mode != default_security.mode {
        push(
            "security.mode",
            format!("{:?}", config.security.mode).into(),
            format!("{:?}", default_security.mode).into(),
        );
    }
    if config.limits.command_timeout_seconds != default_limits.command_timeout_seconds {
        push(
            "limits.command_timeout_seconds",
            config.limits.command_timeout_seconds.into(),
            default_limits.command_timeout_seconds.into(),
        );
    }
    if config.limits.max_concurrent_commands != default_limits.max_concurrent_commands {
        push(
            "limits.max_concurrent_commands",
            config.limits.max_concurrent_commands.into(),
            default_limits.max_concurrent_commands.into(),
        );
    }
    if config.limits.rate_limit_per_second != default_limits.rate_limit_per_second {
        push(
            "limits.rate_limit_per_second",
            config.limits.rate_limit_per_second.into(),
            default_limits.rate_limit_per_second.into(),
        );
    }
    if config.limits.max_output_chars != default_limits.max_output_chars {
        push(
            "limits.max_output_chars",
            config.limits.max_output_chars.into(),
            default_limits.max_output_chars.into(),
        );
    }
    if config.security.blacklist.len() != default_security.blacklist.len() {
        push(
            "security.blacklist",
            config.security.blacklist.len().into(),
            default_security.blacklist.len().into(),
        );
    }

    let disabled: Vec<&str> = config
        .tool_groups
        .groups
        .iter()
        .filter(|(_, enabled)| !**enabled)
        .map(|(name, _)| name.as_str())
        .collect();

    if json_output {
        let report = serde_json::json!({
            "hosts": config.hosts.len(),
            "differences": diffs,
            "tool_groups_disabled": disabled,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| BridgeError::Config(e.to_string()))?
        );
        return Ok(());
    }

    println!("=== Configuration Differences (current vs default) ===\n");
    for (key, entry) in &diffs {
        println!(
            "{key}: {} (default: {})",
            entry["current"], entry["default"]
        );
    }
    println!("\nhosts: {} configured", config.hosts.len());
    if !disabled.is_empty() {
        println!("tool_groups.disabled: {disabled:?}");
    }
    println!("\n(Only non-default values are shown)");

    Ok(())
}

/// Create a `ToolContext` from configuration, together with the audit
/// writer task the context's audit logger sends to (if audit logging is
/// enabled). The caller must drain the writer — see [`finish_audit`] —
/// before the process exits, or every event sent through the returned
/// context's audit logger is silently dropped when it goes out of scope.
fn create_context_with_audit(config: Arc<Config>) -> (ToolContext, Option<AuditWriterTask>) {
    let (wiring, audit_task) = create_audit_wiring(&config);
    (create_context_from_wiring(config, &wiring), audit_task)
}

/// The audit half of a CLI invocation: the single [`AuditLogger`] and the
/// pieces needed to write through it, and nothing else.
///
/// It is split out of [`create_context_with_audit`] because the destructive
/// gate has to record its decision **before** the daemon branch, and building
/// the whole [`ToolContext`] there made every call pay for parts only the
/// in-process path uses. Measured on the daemon fast path, debug: 74 ms before
/// the gate was audited, 465 ms with the full context built up front, of which
/// ~332 ms is the two `Sanitizer`s at 70 patterns each (the same run with
/// `security.sanitize.enabled: false` takes 133 ms). The fast path exists to
/// save a ~95 ms handshake, so `run_tool` builds this only for a call the gate
/// actually decided about.
///
/// Every field is handed to [`create_context_from_wiring`] afterwards, so a
/// gated call that falls through to the in-process path builds each of them
/// exactly once — there is never a second `AuditLogger`, and never a second
/// writer task opening the same file.
struct AuditWiring {
    logger: Arc<AuditLogger>,
    use_case: Arc<ExecuteCommandUseCase>,
    validator: Arc<CommandValidator>,
    sanitizer: Arc<Sanitizer>,
    history: Arc<CommandHistory>,
}

/// Build the [`AuditWiring`] and the writer task it sends to.
///
/// The caller must drain the writer — see [`finish_audit_wiring`] — or every
/// event is dropped when the process exits.
fn create_audit_wiring(config: &Arc<Config>) -> (AuditWiring, Option<AuditWriterTask>) {
    let validator = Arc::new(CommandValidator::new(&config.security));
    let known_secrets = config.collect_secret_values();
    let sanitizer = Arc::new(
        Sanitizer::from_config_with_legacy(
            &config.security.sanitize,
            &config.security.sanitize_patterns,
        )
        .with_known_secrets(&known_secrets),
    );
    // Wire the sanitizer so event.command is masked on the tracing sink too
    // (audit 2026-07-05 finding 1 — MCP mode already does this in server.rs).
    let audit_sanitizer =
        Sanitizer::from_config(&config.security.sanitize).with_known_secrets(&known_secrets);
    let (audit_logger, audit_task) =
        AuditLogger::new_with_sanitizer(&config.audit, audit_sanitizer).unwrap_or_else(|e| {
            // This used to fall back in silence, so a run whose audit file
            // could not be opened looked exactly like a run that was audited
            // — including the destructive gate's decision, which the `--yes`
            // help text promises is recorded. An unwritable trail is itself
            // worth a line on stderr.
            warn!(
                path = %config.audit.path.display(),
                error = %e,
                "audit log could not be opened; THIS RUN IS NOT AUDITED"
            );
            (AuditLogger::disabled(), None)
        });
    let audit_logger = Arc::new(audit_logger);
    let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

    let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
        Arc::clone(&validator),
        Arc::clone(&sanitizer),
        Arc::clone(&audit_logger),
        Arc::clone(&history),
    ));

    (
        AuditWiring {
            logger: audit_logger,
            use_case: execute_use_case,
            validator,
            sanitizer,
            history,
        },
        audit_task,
    )
}

/// Finish the [`ToolContext`] from an [`AuditWiring`] already built, reusing
/// every piece rather than constructing a second one.
fn create_context_from_wiring(config: Arc<Config>, wiring: &AuditWiring) -> ToolContext {
    let connection_pool = Arc::new(ExecutorRouter::with_defaults());
    let rate_limiter = Arc::new(RateLimiter::new(config.limits.rate_limit_per_second));
    let session_manager = Arc::new(SessionManager::new(config.sessions.clone()));

    ToolContext::new(
        config,
        Arc::clone(&wiring.validator),
        Arc::clone(&wiring.sanitizer),
        Arc::clone(&wiring.logger),
        Arc::clone(&wiring.history),
        connection_pool,
        Arc::clone(&wiring.use_case),
        rate_limiter,
        session_manager,
    )
}

/// Test helper: the production entry points use `create_context_with_audit`.
#[cfg(test)]
fn create_context(config: Arc<Config>) -> ToolContext {
    create_context_with_audit(config).0
}

/// Let the audit writer drain before the process exits. The writer stops
/// when the last `AuditLogger` sender is dropped, and the context (directly
/// and through `execute_use_case`) holds them all, so the context is
/// consumed here on purpose. A writer that cannot finish in two seconds is
/// abandoned with a warning rather than hanging the CLI.
///
/// This path is the one case where "drop every owner" is a property the code
/// can actually establish: one process, one context, no background task
/// holding a clone. The MCP surfaces cannot, and close their channel
/// explicitly through [`crate::security::AuditLogger::close`] instead. If a
/// clone of the logger is ever handed to something that outlives the context
/// here, this function stops draining and starts waiting out the timeout —
/// so it would have to call `close()` too.
async fn finish_audit(ctx: ToolContext, writer: Option<tokio::task::JoinHandle<()>>) {
    drop(ctx);
    drain_audit_writer(writer).await;
}

/// [`finish_audit`] for the gated path, where the senders are held by an
/// [`AuditWiring`] instead of a [`ToolContext`]. Any context built from the
/// wiring must already have been dropped, or its own clone of the logger keeps
/// the writer alive until the timeout.
async fn finish_audit_wiring(wiring: AuditWiring, writer: Option<tokio::task::JoinHandle<()>>) {
    drop(wiring);
    drain_audit_writer(writer).await;
}

/// Execute a command on a remote host.
///
/// Exits the process with code 1, after the audit event is written, if the
/// remote command failed.
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
    json_output: bool,
) -> Result<()> {
    let (ctx, audit_task) = create_context_with_audit(Arc::clone(&config));
    let audit_writer = audit_task.map(|task| tokio::spawn(task.run()));
    let outcome = run_exec_in_context(&ctx, host, command, timeout, working_dir, json_output).await;
    finish_audit(ctx, audit_writer).await;
    // The audit writer above has already drained (or been given its 2s
    // grace period) by the time we decide whether to exit non-zero, so a
    // failing remote command no longer races its own audit event out of
    // existence the way `std::process::exit` inside the old single body did.
    let exit_code = outcome?;
    if exit_code != 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// The body `run_exec` used to inline, split out so every early return
/// passes through `finish_audit`. Returns the remote exit code (0 on
/// success) instead of calling `std::process::exit` itself, so the caller
/// can drain the audit writer first — mirrors `run_tool_in_context`.
async fn run_exec_in_context(
    ctx: &ToolContext,
    host: &str,
    command: &str,
    timeout: u64,
    working_dir: Option<&str>,
    json_output: bool,
) -> Result<i32> {
    // Get host config
    let host_config = ctx
        .config
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
        ctx.execute_use_case
            .log_denied("ssh_exec", host, command, &reason);
        return Err(e);
    }

    info!(host = %host, command = %command, "Executing SSH command");

    // Build limits with timeout override
    let mut limits = ctx.config.limits.clone();
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
        ctx.config
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
        // `bridge-mcp exec` runs an arbitrary command; see `ssh_exec`. A
        // timeout does not prove it never ran, so it is not replayed.
        |e| is_retryable_error_for(e, false),
    )
    .await;

    let output = output.inspect_err(|e| {
        ctx.execute_use_case
            .log_failure("ssh_exec", host, command, &e.to_string());
    })?;

    // Process success
    // `&[]` is true here, not a placeholder: `bridge-mcp exec` applies no
    // reduction. The global `--columns`, `--limit`, `--jq` and `--output-format`
    // flags parse for it (the last two only under the `jq` feature) but
    // `main.rs` never forwards any of them to `run_exec`, so nothing acted on
    // the output. Do not "fix" this by inventing a list.
    let response =
        ctx.execute_use_case
            .process_success("ssh_exec", host, command, &output.into(), &[]);

    if response.exit_code != 0 {
        warn!(
            host = %host,
            command = %command,
            exit_code = response.exit_code,
            "Command failed"
        );
    }

    // Print the output
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "host": host,
                "command": command,
                "exit_code": response.exit_code,
                "output": response.output,
            }))
            .map_err(|e| BridgeError::Config(e.to_string()))?
        );
    } else {
        println!("{}", response.output);
    }

    // Propagate the remote exit code to the caller instead of exiting the
    // process here — `run_exec` decides when to exit, after the audit
    // writer has drained. `u32` -> `i32` only fails for a code no real
    // process can produce (`response.exit_code` never carries the `u32::MAX`
    // "no code" sentinel `run_history`'s entries use), so `1` is a safe,
    // still-nonzero fallback rather than a case that needs its own error.
    Ok(i32::try_from(response.exit_code).unwrap_or(1))
}

/// Render the `Audit:` block of `bridge-mcp status`.
///
/// G-13 (audit 2026-08-19) found that CLI mode never spawned the audit
/// writer task — `create_context` bound it to `_audit_task` and dropped it,
/// so `AuditLogger::log`'s `let _ = sender.send(event)` discarded every CLI
/// event and nothing was ever appended to `audit.path`. Printing a bare
/// `Enabled: true` next to a `Path:` line read as a promise of a durable
/// file that no CLI command wrote.
///
/// Fixed 2026-09-06 (tasks C.1/C.2): `run_tool`, `run_exec`, `run_history`,
/// `run_upload` and `run_download` now call `create_context_with_audit` and
/// drain the writer through `finish_audit` before returning, so an audit
/// event logged during one of those five CLI commands is appended to
/// `audit.path` the same as an MCP-server-side call, not just emitted to
/// `tracing`/`RUST_LOG`. This function reflects that both surfaces write the
/// same file now.
fn audit_status_lines(audit: &AuditConfig) -> Vec<String> {
    if !audit.enabled {
        return vec!["  Enabled: false".to_string()];
    }

    vec![
        "  Enabled: true (config) - written by the MCP server and by CLI commands".to_string(),
        format!("  Path: {}", audit.path.display()),
    ]
}

/// Show configured hosts and security settings
///
/// # Errors
///
/// This function is infallible in practice but returns `Result` for
/// consistency with other CLI commands.
pub async fn run_status(config: Arc<Config>, json_output: bool) -> Result<()> {
    if json_output {
        let hosts: serde_json::Map<String, serde_json::Value> = config
            .hosts
            .iter()
            .map(|(alias, host)| {
                (
                    alias.clone(),
                    serde_json::json!({
                        "hostname": host.hostname,
                        "port": host.port,
                        "user": host.user,
                        "auth": auth_type_name(&host.auth),
                        "host_key_verification": format!("{:?}", host.host_key_verification),
                        "proxy_jump": host.proxy_jump,
                        "description": host.description,
                    }),
                )
            })
            .collect();

        let report = serde_json::json!({
            "security_mode": format!("{:?}", config.security.mode),
            "whitelist": config.security.whitelist,
            "blacklist": config.security.blacklist,
            "hosts": hosts,
            "limits": {
                "command_timeout_seconds": config.limits.command_timeout_seconds,
                "connection_timeout_seconds": config.limits.connection_timeout_seconds,
                "max_output_bytes": config.limits.max_output_bytes,
                "max_concurrent_commands": config.limits.max_concurrent_commands,
                "retry_attempts": config.limits.retry_attempts,
            },
            "audit": {
                "enabled": config.audit.enabled,
                "path": config.audit.path.display().to_string(),
                "written_by": "mcp-server-and-cli",
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| BridgeError::Config(e.to_string()))?
        );
        return Ok(());
    }

    println!("Bridge MCP Status");
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
    for line in audit_status_lines(&config.audit) {
        println!("{line}");
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
    json_output: bool,
) -> Result<()> {
    let (ctx, audit_task) = create_context_with_audit(config);
    let audit_writer = audit_task.map(|task| tokio::spawn(task.run()));
    let outcome = run_history_in_context(&ctx, limit, host_filter, json_output);
    finish_audit(ctx, audit_writer).await;
    outcome
}

/// The body `run_history` used to inline, split out so every early return
/// passes through `finish_audit`.
fn run_history_in_context(
    ctx: &ToolContext,
    limit: usize,
    host_filter: Option<&str>,
    json_output: bool,
) -> Result<()> {
    let entries = if let Some(host) = host_filter {
        ctx.history.for_host(host, limit)
    } else {
        ctx.history.recent(limit)
    };

    if json_output {
        let rows: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp.to_rfc3339(),
                    "host": e.host,
                    "command": e.command,
                    "success": e.success,
                    // `u32::MAX` is the sentinel for "never produced an exit
                    // code" (the command errored before running). Emit null
                    // rather than 4294967295, which a consumer would read as a
                    // real status.
                    "exit_code": (e.exit_code != u32::MAX).then_some(e.exit_code),
                    "duration_ms": e.duration_ms,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "entries": rows,
                "total": entries.len(),
            }))
            .map_err(|e| BridgeError::Config(e.to_string()))?
        );
        return Ok(());
    }

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
#[expect(clippy::too_many_arguments)]
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
    let (ctx, audit_task) = create_context_with_audit(Arc::clone(&config));
    let audit_writer = audit_task.map(|task| tokio::spawn(task.run()));
    let outcome = run_upload_in_context(
        &ctx,
        host,
        local_path,
        remote_path,
        mode,
        chunk_size,
        verify_checksum,
        preserve_permissions,
        show_progress,
    )
    .await;
    finish_audit(ctx, audit_writer).await;
    outcome
}

/// The body `run_upload` used to inline, split out so every early return
/// passes through `finish_audit`.
#[expect(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_upload_in_context(
    ctx: &ToolContext,
    host: &str,
    local_path: &Path,
    remote_path: &str,
    mode: &str,
    chunk_size: u64,
    verify_checksum: bool,
    preserve_permissions: bool,
    show_progress: bool,
) -> Result<()> {
    // Get host config
    let host_config = ctx
        .config
        .hosts
        .get(host)
        .ok_or_else(|| BridgeError::UnknownHost {
            host: host.to_string(),
        })?;

    let transfer_mode = crate::mcp::tool_handlers::utils::parse_transfer_mode_checked(
        mode,
        verify_checksum,
        "sent",
    )?;

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
        ctx.config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    // Connect to host (via jump host if configured)
    let client = if let Some((jump_name, jump_config)) = jump_host {
        SshClient::connect_via_jump(
            host,
            host_config,
            jump_name,
            jump_config,
            &ctx.config.limits,
        )
        .await?
    } else {
        SshClient::connect(host, host_config, &ctx.config.limits).await?
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
            ctx.audit_logger.log(
                SshUploadHandler.name(),
                AuditEvent::new(
                    host,
                    &format!("SFTP_UPLOAD {} -> {}", local_path.display(), remote_path),
                    CommandResult::Success {
                        exit_code: 0,
                        duration_ms: transfer_result.duration_ms,
                    },
                ),
            );
        }
        Err(e) => {
            ctx.audit_logger.log(
                SshUploadHandler.name(),
                AuditEvent::new(
                    host,
                    &format!("SFTP_UPLOAD {} -> {}", local_path.display(), remote_path),
                    CommandResult::Error {
                        message: e.to_string(),
                    },
                ),
            );
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
#[expect(clippy::too_many_arguments)]
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
    let (ctx, audit_task) = create_context_with_audit(Arc::clone(&config));
    let audit_writer = audit_task.map(|task| tokio::spawn(task.run()));
    let outcome = run_download_in_context(
        &ctx,
        host,
        remote_path,
        local_path,
        mode,
        chunk_size,
        verify_checksum,
        preserve_permissions,
        show_progress,
    )
    .await;
    finish_audit(ctx, audit_writer).await;
    outcome
}

/// The body `run_download` used to inline, split out so every early return
/// passes through `finish_audit`.
#[expect(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_download_in_context(
    ctx: &ToolContext,
    host: &str,
    remote_path: &str,
    local_path: &Path,
    mode: &str,
    chunk_size: u64,
    verify_checksum: bool,
    preserve_permissions: bool,
    show_progress: bool,
) -> Result<()> {
    // Get host config
    let host_config = ctx
        .config
        .hosts
        .get(host)
        .ok_or_else(|| BridgeError::UnknownHost {
            host: host.to_string(),
        })?;

    let transfer_mode = crate::mcp::tool_handlers::utils::parse_transfer_mode_checked(
        mode,
        verify_checksum,
        "received",
    )?;

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
        ctx.config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    // Connect to host (via jump host if configured)
    let client = if let Some((jump_name, jump_config)) = jump_host {
        SshClient::connect_via_jump(
            host,
            host_config,
            jump_name,
            jump_config,
            &ctx.config.limits,
        )
        .await?
    } else {
        SshClient::connect(host, host_config, &ctx.config.limits).await?
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
            ctx.audit_logger.log(
                SshDownloadHandler.name(),
                AuditEvent::new(
                    host,
                    &format!("SFTP_DOWNLOAD {} -> {}", remote_path, local_path.display()),
                    CommandResult::Success {
                        exit_code: 0,
                        duration_ms: transfer_result.duration_ms,
                    },
                ),
            );
        }
        Err(e) => {
            ctx.audit_logger.log(
                SshDownloadHandler.name(),
                AuditEvent::new(
                    host,
                    &format!("SFTP_DOWNLOAD {} -> {}", remote_path, local_path.display()),
                    CommandResult::Error {
                        message: e.to_string(),
                    },
                ),
            );
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
    assume_yes: bool,
) -> Result<i32> {
    run_tool_via(
        config,
        tool_name,
        kv_args,
        json_args,
        json_output,
        data_reduction,
        assume_yes,
        &crate::daemon::default_socket_path(),
    )
    .await
}

/// [`run_tool`] with the daemon socket passed in rather than resolved.
///
/// The public entry point resolves `$XDG_RUNTIME_DIR/bridge-mcp.sock`, which
/// means an **in-process** test of `run_tool` reaches whatever daemon the
/// developer's session happens to have up — and a daemon changes what the
/// audit trail of a call contains, because it serves the execution and the
/// CLI writes only the gate line. `tests/cli_exit_code.rs` isolates that
/// variable with `.env()`, but a lib test has no child process to set the
/// environment of, and `std::env::set_var` is unsafe and racy under the
/// parallel harness. So the path is a parameter here instead, and the test
/// points it at a file that does not exist.
#[expect(clippy::too_many_arguments)]
async fn run_tool_via(
    config: Arc<Config>,
    tool_name: &str,
    kv_args: &[String],
    json_args: Option<&str>,
    json_output: bool,
    data_reduction: DataReductionFlags,
    assume_yes: bool,
    daemon_socket: &std::path::Path,
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
            if h.supports_elevation() {
                crate::mcp::registry::inject_privilege_schema(&mut schema);
            }
            serde_json::to_string(&schema).ok()
        });
        let schema_ref = enriched_schema.as_ref().and_then(|opt| opt.as_deref());
        // Keys the tool actually declares, including the reduction params
        // injected above. Empty when the schema could not be parsed, in which
        // case validation is skipped rather than guessed at.
        let known_keys: Vec<String> = schema_ref
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .and_then(|schema| {
                schema
                    .get("properties")
                    .and_then(serde_json::Value::as_object)
                    .map(|props| props.keys().cloned().collect())
            })
            .unwrap_or_default();

        let mut map = serde_json::Map::new();
        for pair in kv_args {
            if let Some((key, value)) = pair.split_once('=') {
                // An unknown key used to be accepted in silence, so a typo in
                // `jq_filter` or `columns` produced a full, unreduced result
                // that looked exactly like a working one.
                crate::domain::arg_validation::reject_unknown_args(
                    tool_name,
                    std::iter::once(&key.to_string()),
                    &known_keys,
                )?;
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

    // THE DESTRUCTIVE GATE'S DECISION IS TAKEN HERE, before every branch
    // below, because which path serves a call is an accident of whether a
    // daemon happens to be up — and that used to decide whether a destructive
    // tool was refused or ran unchallenged. The daemon path is refused
    // server-side (the CLI declares `clientCapabilities: {}`, fail-closed);
    // the direct path called the registry and never met the gate at all. Same
    // config, same command, opposite outcome, with the default being the
    // unguarded one. That was the 2026-08-31 regression, and nothing below
    // may be allowed to reopen it.
    //
    // `decide_destructive` only *decides*. It writes nothing, which is why it
    // can run before any logger exists: the decision is a value, and the
    // caller records it. A decision taken and not recorded is therefore not
    // expressible — on the recording side because the `match` in
    // `apply_gate_decision` is exhaustive and `NotGated` is its only silent
    // arm, and on THIS side because `GateDecision` is `#[must_use]`, without
    // which `decide_destructive(…);` in statement position compiled in
    // silence (clippy's `must_use_candidate` is pedantic-only and off here).
    let run = ToolRun {
        registry: &registry,
        config: &config,
        daemon_socket,
        json_output,
    };

    let decision = decide_destructive(tool_name, args.as_ref(), assume_yes, &config);

    if matches!(decision, GateDecision::NotGated) {
        // Nothing to record before the daemon branch, so this keeps the shape
        // the CLI had before the gate was audited: no audit wiring until the
        // in-process path actually needs it. It matters because 431 of the 476
        // tools are not destructive and can never produce a gate line, while
        // building the wiring up front cost them 391 ms on the daemon fast
        // path (measured, debug: 74 ms -> 465 ms) — a path that exists to save
        // a ~95 ms handshake. 85% of that is two `Sanitizer`s at 70 patterns.
        return run_ungated_tool(&run, tool_name, args).await;
    }

    // One audit logger and one writer task for this invocation, created above
    // the daemon branch because the decision above has to be recorded and
    // `AuditLogger::log` ends in `let _ = sender.send(event)` — the writer
    // task dies with the process, so every path has to reach `finish_audit`.
    // Only the 45 destructive tools pay for this.
    let (wiring, audit_task) = create_audit_wiring(&config);
    let audit_writer = audit_task.map(|task| tokio::spawn(task.run()));
    let outcome = run_gated_tool(&run, tool_name, args, decision, &wiring).await;
    finish_audit_wiring(wiring, audit_writer).await;
    outcome
}

/// The plumbing one `bridge-mcp tool` invocation carries through both
/// execution paths.
///
/// Bundled rather than threaded: `daemon_socket` became a parameter so a lib
/// test could aim it at a path nothing binds, and that pushed
/// `run_gated_tool` past clippy's argument bound — which `make lint` treats
/// as an error. Grouping it means the next such parameter is added in one
/// place instead of two signatures.
struct ToolRun<'a> {
    registry: &'a crate::mcp::registry::ToolRegistry,
    config: &'a Arc<Config>,
    /// Where a daemon would be listening. Resolved by `run_tool` from
    /// `$XDG_RUNTIME_DIR`; see `run_tool_via` for why it is not read here.
    daemon_socket: &'a std::path::Path,
    json_output: bool,
}

/// Forward to a running daemon, if there is one.
///
/// `Ok(Some(code))` means a daemon answered and its response has been printed.
/// `Ok(None)` means no daemon was reachable and the caller must run the tool
/// in-process.
///
/// The fast path exists because it reuses the daemon's shared SSH connection
/// pool and saves the ~95 ms handshake on every invocation after the first.
///
/// The fallback is narrower than it looks: only a failure to REACH the daemon
/// (absent socket, connection refused) returns `Ok(None)` and drops to the
/// stateless path. A daemon that answers with a JSON-RPC *error* answers
/// `Ok(Some(..))`, and that error is what the user sees. That is deliberate —
/// a tool that failed on the daemon would fail in-process too, and silently
/// re-running it would hide the first failure — but it is why a malformed
/// request envelope surfaced as every `bridge-mcp tool …` returning `-32602`
/// rather than as a quiet fallback.
///
/// # Errors
///
/// Propagates a failure to talk to a daemon that *was* reachable.
async fn forward_to_daemon(
    daemon_socket: &std::path::Path,
    tool_name: &str,
    args: Option<&serde_json::Value>,
    json_output: bool,
) -> Result<Option<i32>> {
    if !daemon_socket.exists() {
        return Ok(None);
    }
    let forwarded = try_forward_to_daemon(
        daemon_socket,
        tool_name,
        args.cloned().unwrap_or(serde_json::Value::Null),
    )
    .await?;
    match forwarded {
        Some(response) => print_daemon_response(&response, json_output).map(Some),
        None => Ok(None),
    }
}

/// A call the gate took a decision about: the decision is recorded first, and
/// every early return below still passes through the caller's `finish_audit_
/// wiring`, so the line survives the process exit.
async fn run_gated_tool(
    run: &ToolRun<'_>,
    tool_name: &str,
    args: Option<serde_json::Value>,
    decision: GateDecision,
    wiring: &AuditWiring,
) -> Result<i32> {
    apply_gate_decision(
        decision,
        &wiring.use_case,
        tool_name,
        gate_host(args.as_ref()),
        &audited_operation(tool_name, args.as_ref()),
    )?;

    if let Some(code) =
        forward_to_daemon(run.daemon_socket, tool_name, args.as_ref(), run.json_output).await?
    {
        return Ok(code);
    }

    // Slow path: stateless in-process execution, reusing the logger that
    // already recorded the gate decision — exactly one per invocation.
    let ctx = create_context_from_wiring(Arc::clone(run.config), wiring);
    run_tool_in_context(run.registry, tool_name, args, &ctx, run.json_output).await
}

/// A call the gate took no decision about, so there is nothing to record
/// before the daemon branch and the audit wiring is built only if the
/// in-process path is reached.
async fn run_ungated_tool(
    run: &ToolRun<'_>,
    tool_name: &str,
    args: Option<serde_json::Value>,
) -> Result<i32> {
    if let Some(code) =
        forward_to_daemon(run.daemon_socket, tool_name, args.as_ref(), run.json_output).await?
    {
        return Ok(code);
    }

    let (ctx, audit_task) = create_context_with_audit(Arc::clone(run.config));
    let audit_writer = audit_task.map(|task| tokio::spawn(task.run()));
    let outcome = run_tool_in_context(run.registry, tool_name, args, &ctx, run.json_output).await;
    finish_audit(ctx, audit_writer).await;
    outcome
}

/// The in-process execution `run_tool` used to inline, split out so every
/// early return passes through `finish_audit`.
async fn run_tool_in_context(
    registry: &crate::mcp::registry::ToolRegistry,
    tool_name: &str,
    args: Option<serde_json::Value>,
    ctx: &ToolContext,
    json_output: bool,
) -> Result<i32> {
    // Strip interactive App components, exactly as `McpServer` does before it
    // answers a `tools/call`. This path calls the registry directly and so
    // bypassed that filter: a terminal has nothing to render an App with, and
    // serializing it made the blob the bulk of the output — on `ssh_storage_df`
    // 3377 of 3950 bytes, and 412 bytes appended to a 6-byte answer that
    // `jq_filter` had just reduced. `structured_content` survives, as there.
    let result = registry.execute(tool_name, args, ctx).await?.without_apps();

    let exit_code = tool_exit_code(&result);

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

/// `by` on the `command_confirmed` line when the `--yes` flag answered.
///
/// A constant rather than a literal at the call site because this value and
/// [`CONFIRMED_BY_PROMPT`] are the whole point of
/// [`crate::security::CommandResult::Confirmed`]: they are what tells "a
/// script flag confirmed this" from "a human at a terminal confirmed this",
/// and a free-form `String` at two call sites would let the two drift.
const CONFIRMED_BY_FLAG: &str = "--yes";

/// `by` on the `command_confirmed` line when a human answered the prompt.
/// See [`CONFIRMED_BY_FLAG`].
const CONFIRMED_BY_PROMPT: &str = "terminal prompt";

/// Longest a single argument value may be before [`audited_operation`]
/// replaces it with its length.
///
/// **This exists because the gate's audit line would otherwise persist the
/// call's arguments in full.** `--yes tool ssh_file_write … content=<a file>`
/// wrote a `command_confirmed` line carrying that whole file.
///
/// How large, exactly, because the obvious figure is wrong: through `argv` the
/// ceiling is `MAX_ARG_STRLEN`, 32 pages — **128 KB per argument** — and
/// `ARG_MAX` for the whole command line; past that `execve` fails with `E2BIG`
/// and the binary never starts, which `tests/cli_exit_code.rs` measures. A
/// daemon-forwarded or MCP-served call carries its arguments as JSON over a
/// socket and has no such limit. So the bound matters for volume — 128 KB a
/// line fills a 100 MB archive in 800 calls, and breaks any JSONL consumer
/// with a line-length bound — and it matters for content at any size: it
/// defeated a deliberate exclusion, since the handler's own audit event for
/// that write is `SFTP_WRITE <path>` and carries no content at all, precisely
/// so the trail does not become a copy of the files it records.
///
/// 256 characters leaves every host alias, path, id, unit name and ordinary
/// shell command intact — the values that make a line worth reading — while no
/// file body survives it. A value over the bound is replaced by
/// `<elided: N chars>`, which states what was dropped: a silent truncation
/// would be another half-true line, which is the fault this whole change
/// exists to remove.
const GATE_AUDIT_MAX_VALUE_CHARS: usize = 256;

/// Hard ceiling on the whole operation string, after per-value elision.
///
/// Per-value elision alone does not bound the line: a call with hundreds of
/// short arguments stays under [`GATE_AUDIT_MAX_VALUE_CHARS`] on every one of
/// them. What goes past this is cut and marked `<truncated: N chars total>`.
const GATE_AUDIT_MAX_OPERATION_CHARS: usize = 2048;

/// What the destructive gate decided. **A value, not an effect** — see
/// [`decide_destructive`] for why that matters.
///
/// `#[must_use]` is the other half of "a decision taken and not recorded is
/// not expressible", and it is the half the type alone did not give. The
/// exhaustive `match` in [`apply_gate_decision`] closes the recording side;
/// without this attribute the **calling** side stayed open —
/// `decide_destructive(…);` in statement position compiled silently, and
/// `clippy::must_use_candidate` does not run here because `src/lib.rs` does
/// not enable `clippy::pedantic`.
#[must_use]
#[derive(Debug)]
enum GateDecision {
    /// The gate took no decision: the policy is off, or the tool is not
    /// annotated destructive. Nothing is recorded, and nothing should be.
    NotGated,
    /// The call may proceed. `by` names what answered:
    /// [`CONFIRMED_BY_FLAG`] or [`CONFIRMED_BY_PROMPT`].
    Confirmed { by: &'static str },
    /// The call is refused. `reason` is both the audit line's reason and the
    /// text the caller sees on stderr — one string, so the two cannot differ.
    Denied { reason: String },
    /// The prompt was shown but its answer could not be read. Refused, and
    /// recorded as a refusal, but the error keeps its I/O kind so the exit
    /// code is not silently reclassified as a security denial.
    Unreadable {
        reason: String,
        error: std::io::Error,
    },
}

/// The host to put on a gate event: the call's `host` argument when it has
/// one, [`crate::security::NO_HOST`] otherwise.
///
/// At the gate the host is an unresolved JSON argument and nothing more — the
/// alias is not looked up until the handler runs, which is why the gate can
/// refuse a call naming a host that does not exist. Three of the 45
/// destructive tools (`ssh_awx_job_cancel`, `ssh_awx_approval_deny`,
/// `ssh_awx_workflow_cancel`) declare no `host` at all, and none declares a
/// plural `hosts`, so the sentinel is the exact answer here and not a
/// fallback for a case that cannot happen.
fn gate_host(args: Option<&serde_json::Value>) -> &str {
    args.and_then(|a| a.get("host"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(crate::security::NO_HOST)
}

/// The `command` field for a gate event: the tool and its arguments, bounded.
///
/// No command has been built yet — the handler does that — so the line
/// carries the *operation*, in the shape `AuditEvent::tagged` documents for an
/// event that ran nothing. The bounds are
/// [`GATE_AUDIT_MAX_VALUE_CHARS`] per value and
/// [`GATE_AUDIT_MAX_OPERATION_CHARS`] overall, both marked where they bite.
///
/// The rule is a size rule on purpose, not a list of content-bearing field
/// names: the gate sees an opaque JSON object for any of 476 tools, so a name
/// list (`content`, `body`, `script`, `playbook`, …) would have to be kept in
/// step with every tool added and would leak in silence the first time a
/// payload was called something else. A size rule cannot rot that way.
fn audited_operation(tool_name: &str, args: Option<&serde_json::Value>) -> String {
    let bounded = match args {
        None => serde_json::Value::Object(serde_json::Map::new()),
        Some(serde_json::Value::Object(map)) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), elide_oversized(v)))
                .collect(),
        ),
        Some(other) => elide_oversized(other),
    };
    let rendered = serde_json::to_string(&bounded).unwrap_or_else(|_| "{}".to_string());
    let operation = format!("{tool_name} {rendered}");
    let total = operation.chars().count();
    if total <= GATE_AUDIT_MAX_OPERATION_CHARS {
        return operation;
    }
    let kept: String = operation
        .chars()
        .take(GATE_AUDIT_MAX_OPERATION_CHARS)
        .collect();
    format!("{kept} <truncated: {total} chars total>")
}

/// Replace one argument value with its length when it is over
/// [`GATE_AUDIT_MAX_VALUE_CHARS`]. Applies to arrays and objects too, by their
/// serialized length, so a nested payload is bounded like a flat one.
fn elide_oversized(value: &serde_json::Value) -> serde_json::Value {
    let len = match value {
        serde_json::Value::String(s) => s.chars().count(),
        other => serde_json::to_string(other).map_or(0, |s| s.chars().count()),
    };
    if len <= GATE_AUDIT_MAX_VALUE_CHARS {
        return value.clone();
    }
    serde_json::Value::String(format!("<elided: {len} chars>"))
}

/// Ask before running a tool annotated `destructiveHint`.
///
/// `security.require_elicitation_on_destructive` is enforced by the MCP server
/// through an elicitation round-trip. A CLI process has no such channel, so the
/// policy had no representation here at all: the direct path ran destructive
/// tools unchallenged while the daemon path refused them, and which one served
/// a given call depended only on whether a daemon happened to be running.
///
/// On a terminal the question is asked. Without one — a script, a CI job, a
/// pipe — there is nobody to ask, so the call is refused unless `--yes` said in
/// advance that it is intended. Refusing by default matches the server's
/// fail-closed posture; `--yes` keeps the scripted case possible and explicit.
///
/// **This function decides and returns; it does not log and does not error.**
/// That is deliberate, and it is what lets the decision be taken before any
/// `AuditLogger` exists — hence before the daemon branch, which is the
/// placement the 2026-08-31 regression turned on. [`apply_gate_decision`]
/// records the decision and turns a refusal into an error, and its `match` is
/// exhaustive, so a new outcome cannot be added here and silently go
/// unrecorded. [`GateDecision::NotGated`] is the only outcome that writes
/// nothing, and it is not a decision.
///
/// All five exits are covered: the policy off and a non-destructive tool (both
/// `NotGated`), `--yes`, a prompt answered, a prompt declined, and a prompt
/// whose answer could not be read.
fn decide_destructive(
    tool_name: &str,
    args: Option<&serde_json::Value>,
    assume_yes: bool,
    config: &Config,
) -> GateDecision {
    use std::io::IsTerminal;

    let stdin = std::io::stdin();
    let is_terminal = stdin.is_terminal();
    decide_destructive_from(
        tool_name,
        args,
        assume_yes,
        config,
        is_terminal,
        &mut stdin.lock(),
    )
}

/// [`decide_destructive`] with the terminal and the answer passed in.
///
/// **The split exists so the prompt branch is reachable by a test, wiring
/// included.** `decision_from_prompt_answer` covers the decision *rule*, but
/// the line that connects it to `read_line` was covered by nothing: replacing
/// `Ok(_) => decision_from_prompt_answer(…)` with a hard-coded
/// `Confirmed { by: CONFIRMED_BY_PROMPT }` left the whole suite green, and
/// that mutation is the worst outcome this task has — an operator types `n`,
/// the command runs, and the audit line says they confirmed. Not being able
/// to reach `IsTerminal` was a fact; not being able to reach the wiring one
/// line below it was a choice, and this undoes it.
///
/// The only thing now outside a test's reach is `std::io::stdin().is_terminal()`
/// itself, i.e. whether the real process has a TTY.
fn decide_destructive_from(
    tool_name: &str,
    args: Option<&serde_json::Value>,
    assume_yes: bool,
    config: &Config,
    stdin_is_terminal: bool,
    answers: &mut dyn std::io::BufRead,
) -> GateDecision {
    use std::io::Write;

    if !config.security.require_elicitation_on_destructive {
        return GateDecision::NotGated;
    }
    if crate::mcp::registry::tool_annotations(tool_name).destructive_hint != Some(true) {
        return GateDecision::NotGated;
    }

    if assume_yes {
        // Recorded, not merely allowed: `--yes` is the point at which a human
        // delegated the decision, and the trail now carries it.
        return GateDecision::Confirmed {
            by: CONFIRMED_BY_FLAG,
        };
    }

    if !stdin_is_terminal {
        return GateDecision::Denied {
            reason: format!(
                "`{tool_name}` is annotated destructive and stdin is not a terminal, \
                 so there is nobody to confirm with. Pass --yes to confirm in advance, \
                 or set security.require_elicitation_on_destructive: false to disable \
                 this gate entirely."
            ),
        };
    }

    // The prompt shows the arguments in full, unlike the audit line: a
    // terminal is ephemeral and the person deciding needs to see exactly what
    // would run. `audited_operation` is what gets persisted.
    let rendered = args
        .and_then(|a| serde_json::to_string(a).ok())
        .unwrap_or_else(|| "{}".to_string());
    eprintln!("\n  DESTRUCTIVE: {tool_name}");
    eprintln!("  {rendered}");
    eprint!("  Proceed? [y/N] ");
    let _ = std::io::stderr().flush();

    let mut answer = String::new();
    match answers.read_line(&mut answer) {
        // Refused, like a declined prompt — but the error keeps its own kind,
        // so the exit code of an unreadable stdin does not become a security
        // denial's.
        Err(error) => GateDecision::Unreadable {
            reason: format!(
                "`{tool_name}` was not confirmed: the answer could not be read from stdin ({error})"
            ),
            error,
        },
        Ok(_) => decision_from_prompt_answer(tool_name, &answer),
    }
}

/// The prompt's answer, mapped to a decision. Split out of
/// [`decide_destructive_from`] so the rule can be read and tested on its own;
/// the wiring that calls it is covered through
/// [`decide_destructive_from`]'s injected reader.
fn decision_from_prompt_answer(tool_name: &str, answer: &str) -> GateDecision {
    if matches!(answer.trim(), "y" | "Y" | "yes" | "Yes") {
        GateDecision::Confirmed {
            by: CONFIRMED_BY_PROMPT,
        }
    } else {
        GateDecision::Denied {
            reason: format!("`{tool_name}` was not confirmed"),
        }
    }
}

/// Record the gate's decision, then turn a refusal into the caller's error.
///
/// **Every decision is written to `audit.path`** through `audit` —
/// `command_confirmed` when the call goes through, naming what answered, and
/// `command_denied` when it is refused, carrying the same reason the caller is
/// about to read on stderr. That is what `--yes`'s help text promises, and
/// until the gate had a logger the promise was kept by a `tracing::warn!`,
/// which reaches stderr and never the audit file.
///
/// It is written **only when audit logging is enabled and its file could be
/// opened**; `create_audit_wiring` warns when it could not, because a run
/// whose gate decision was not written must not look like one that was.
///
/// `host` is the call's `host` argument when it has one and
/// [`crate::security::NO_HOST`] otherwise — see [`gate_host`]. `operation` is
/// the bounded rendering from [`audited_operation`], never the raw arguments.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] when the gate refused, or
/// [`BridgeError::Io`] when the prompt's answer could not be read.
fn apply_gate_decision(
    decision: GateDecision,
    audit: &ExecuteCommandUseCase,
    tool_name: &str,
    host: &str,
    operation: &str,
) -> Result<()> {
    match decision {
        // Not a decision: the policy is off, or the tool is not destructive.
        // A destructive call with no `command_confirmed` line in the CLI's own
        // trail is how a reader sees that it never met this gate.
        GateDecision::NotGated => Ok(()),
        GateDecision::Confirmed { by } => {
            audit.log_confirmed(tool_name, host, operation, by);
            Ok(())
        }
        GateDecision::Denied { reason } => {
            audit.log_denied(tool_name, host, operation, &reason);
            Err(BridgeError::CommandDenied { reason })
        }
        GateDecision::Unreadable { reason, error } => {
            audit.log_denied(tool_name, host, operation, &reason);
            Err(BridgeError::Io(error))
        }
    }
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
    use crate::mcp::registry::{
        create_filtered_registry, inject_reduction_schema, tool_annotations, tool_group,
    };

    let registry = create_filtered_registry(&config.tool_groups);
    let handler = registry
        .get(tool_name)
        .ok_or_else(|| BridgeError::McpUnknownTool {
            tool: tool_name.to_string(),
        })?;

    let schema = handler.schema();
    let group = tool_group(tool_name);
    let output_kind = handler.output_kind();
    // `mcp_describe_tool` has always returned these; the CLI dropped them, so
    // `describe-tool ssh_exec` gave no hint that it is annotated destructive.
    // Knowing that before invoking is the whole point of the annotation.
    let annotations = tool_annotations(tool_name);

    // Parse and enrich the schema with data-reduction params (jq_filter, columns, etc.)
    let mut input_schema: serde_json::Value =
        serde_json::from_str(schema.input_schema).unwrap_or_default();
    inject_reduction_schema(&mut input_schema, output_kind);
    if handler.supports_elevation() {
        crate::mcp::registry::inject_privilege_schema(&mut input_schema);
    }

    if json_output {
        let obj = serde_json::json!({
            "name": schema.name,
            "group": group,
            "description": schema.description,
            "output_kind": format!("{output_kind:?}"),
            "reduction_strategy": output_kind.strategy_hint(),
            "annotations": annotations,
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

        let hint = |flag: Option<bool>| match flag {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unset",
        };
        println!(
            "Annotations: destructive={} read-only={} idempotent={}",
            hint(annotations.destructive_hint),
            hint(annotations.read_only_hint),
            hint(annotations.idempotent_hint),
        );
        if annotations.destructive_hint == Some(true) {
            println!(
                "  WARNING: destructive. Under `security.require_elicitation_on_destructive` \
                 an MCP client is asked to confirm before this runs."
            );
        }

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
        println!("  bridge-mcp tool {tool_name} key=value ...");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, AuthConfig, HostConfig, HostKeyVerification, HttpTransportConfig,
        LimitsConfig, OsType, RedactedSecret, SecurityConfig, SessionConfig, SshConfigDiscovery,
        ToolGroupsConfig,
    };
    use crate::mcp::tool_handlers::utils::shell_escape;
    use std::collections::HashMap;

    // ============== create_context Tests ==============

    #[test]
    fn test_create_context_wires_audit_sanitizer() {
        // AuditConfig::default() carries the REAL path
        // (~/.local/share/bridge-mcp/audit.log), which `create_context`
        // creates and opens.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.audit.path = dir.path().join("audit.log");
        let ctx = create_context(Arc::new(config));
        assert!(
            ctx.audit_logger.has_sanitizer(),
            "CLI audit logger must sanitize event.command (audit 2026-07-05 finding 1)"
        );
    }

    /// A `Config::default()` with one host inserted under `name`, for tests
    /// that need `run_tool` to reach the slow (in-process) path and dispatch
    /// a real tool against it.
    fn test_config_with_host(name: &str, hostname: &str) -> Config {
        let mut config = Config::default();
        config.hosts.insert(
            name.to_string(),
            HostConfig {
                hostname: hostname.to_string(),
                port: 22,
                user: "test".to_string(),
                auth: AuthConfig::Agent,
                description: None,
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
        config
    }

    #[tokio::test]
    async fn run_tool_persists_the_audit_event_of_a_cli_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.log");
        let mut config = test_config_with_host("h", "127.0.0.1");
        config.audit.enabled = true;
        config.audit.path = audit_path.clone();
        // Standard mode denies anything not on an (empty) whitelist before a
        // command is ever attempted — permissive mode lets `validate()` pass
        // so this test exercises the connection path instead.
        config.security.mode = crate::config::SecurityMode::Permissive;
        // Bound the connection attempt: a closed port on 127.0.0.1 gets no
        // RST in this sandbox's network stack, so it would otherwise hang
        // for the full default 10s timeout, times up to 3 retries.
        config.limits.connection_timeout_seconds = 1;
        config.limits.retry_attempts = 0;
        if let Some(host) = config.hosts.get_mut("h") {
            host.port = 1; // reserved, unused: guarantees a connection failure
        }
        // `ssh_exec`'s blacklist-denial path (`log_denied`) does NOT carry
        // the tool name or "ssh_exec" anywhere in the event — only its
        // connection-failure path (`log_failure`, whose event carries the
        // literal `event_type: "ssh_exec"` for every tool) does. So this
        // exercises a failed connection, not a blacklist denial.
        //
        // That literal is no longer the only `event_type` in the log —
        // `log_state_change` writes `"state_change"` and the destructive gate
        // writes `"command_confirmed"` — but it is still the one every
        // command event carries, including this one.
        //
        // The socket is passed in, and points at a name inside this test's own
        // tempdir that nothing binds: this is an IN-PROCESS call, so without
        // it the test would reach whatever daemon the developer's session has
        // up — which serves the execution and leaves only the gate line, one
        // instead of the two asserted below. `tests/cli_exit_code.rs` isolates
        // `XDG_RUNTIME_DIR` with `.env()` for the same reason; there is no
        // child process here to set an environment for, and
        // `std::env::set_var` is unsafe and racy under the parallel harness.
        //
        // `ssh_exec` IS annotated destructive, so the `--yes` below also
        // makes the gate write a `command_confirmed` line to this same file,
        // naming the same tool and the same host. That is why the assertions
        // below select the line by `event_type` rather than searching the
        // whole file for `ssh_exec` or for the host: either of those would
        // now be satisfied by the gate's line alone, even if the run's own
        // event were never written.
        let _ = run_tool_via(
            Arc::new(config),
            "ssh_exec",
            &["host=h".to_string(), "command=echo hi".to_string()],
            None,
            false,
            DataReductionFlags::default(),
            true,
            &dir.path().join("no-daemon-here.sock"),
        )
        .await;
        let log = std::fs::read_to_string(&audit_path).expect("audit.log exists");
        let lines: Vec<&str> = log.lines().collect();
        // Exactly two, in this order: the gate's decision (`--yes` above) and
        // then the run's own event. Asserting the pair is what makes this
        // unsatisfiable by either event alone — a single `log.contains(…)`
        // over the whole file was satisfied by the gate line, which carries
        // the same tool name and the same host.
        assert_eq!(
            lines.len(),
            2,
            "expected the gate line and the run line, got {log:?}"
        );
        assert!(
            lines[0].contains(r#""event_type":"command_confirmed""#),
            "the gate decides first, so its line comes first: {:?}",
            lines[0]
        );
        assert!(
            lines[1].contains(r#""event_type":"ssh_exec""#),
            "the CLI run must persist its own audit event: {:?}",
            lines[1]
        );
        // Pin that line to the host this test configured: the `event_type`
        // literal alone would match any command event from any tool.
        assert!(
            lines[1].contains(r#""host":"h""#),
            "the audit event must record this run's host, got {:?}",
            lines[1]
        );
    }

    // ============== DataReductionFlags merge Tests ==============

    #[test]
    fn test_data_reduction_flags_is_empty_by_default() {
        let flags = DataReductionFlags::default();
        assert!(flags.is_empty());
    }

    /// A daemon-forwarded call MUST carry the `_meta` envelope.
    ///
    /// Regression guard for the 3.0.0 Modern-only cut: the CLI forwards
    /// `tools/call` over the Unix socket, the server made the envelope
    /// mandatory, and nothing updated the client — so with a daemon up, every
    /// one of the 279 tools answered
    /// `-32602 missing _meta["io.modelcontextprotocol/protocolVersion"]`
    /// instead of running. Found by execution against a live daemon; no test
    /// existed that could have caught it.
    #[test]
    fn daemon_request_carries_the_required_meta_envelope() {
        let request = build_daemon_request("req-1", "ssh_exec", &serde_json::json!({"host": "pi"}));

        let meta = request["params"]["_meta"]
            .as_object()
            .expect("params._meta must be an object");

        assert_eq!(
            meta.get(meta_keys::PROTOCOL_VERSION)
                .and_then(serde_json::Value::as_str),
            Some(PROTOCOL_VERSION),
            "the forwarded request must declare the revision it speaks"
        );
        assert!(
            meta.get(meta_keys::CLIENT_CAPABILITIES)
                .is_some_and(serde_json::Value::is_object),
            "clientCapabilities must be present; `{{}}` is the honest value for a \
             CLI that cannot answer an elicitation, but absent is a `-32602`"
        );
        assert!(
            meta.get(meta_keys::CLIENT_INFO)
                .is_some_and(serde_json::Value::is_object),
            "clientInfo must be present"
        );
    }

    /// The envelope declares *no* capabilities, and that is deliberate.
    ///
    /// Capability lookup is fail-closed: claiming `elicitation` here would let
    /// the destructive gate believe a CLI process can answer a confirmation it
    /// has no channel to display.
    #[test]
    fn daemon_request_declares_no_client_capabilities() {
        let request = build_daemon_request("req-2", "ssh_exec", &serde_json::Value::Null);

        let caps = request["params"]["_meta"][meta_keys::CLIENT_CAPABILITIES]
            .as_object()
            .expect("clientCapabilities must be an object");

        assert!(
            caps.is_empty(),
            "the CLI must not claim capabilities it cannot honour, got {caps:?}"
        );
    }

    #[test]
    fn daemon_request_preserves_tool_name_and_arguments() {
        let args = serde_json::json!({"host": "pi", "command": "echo hi"});
        let request = build_daemon_request("req-3", "ssh_exec", &args);

        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["id"], "req-3");
        assert_eq!(request["method"], "tools/call");
        assert_eq!(request["params"]["name"], "ssh_exec");
        assert_eq!(request["params"]["arguments"], args);
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
            passphrase: Some(RedactedSecret::from("secret")),
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
            password: RedactedSecret::from("secret"),
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
            audit: AuditConfig {
                enabled: false,
                ..AuditConfig::default()
            },
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let ctx = create_context(Arc::new(config));

        let internal = ctx.config.hosts.get("internal").unwrap();
        assert_eq!(internal.proxy_jump, Some("bastion".to_string()));
    }

    // ============== audit_status_lines Tests ==============

    /// G-13 (audit 2026-08-19) found `bridge-mcp status` printed
    /// `Enabled: true` + `Path: <file>` while `create_context` dropped the
    /// `AuditWriterTask`, so no CLI invocation ever appended a byte to that
    /// path. Tasks C.1/C.2 (2026-09-06) fixed the underlying gap — `run_tool`,
    /// `run_exec`, `run_history`, `run_upload` and `run_download` now drain
    /// the writer via `finish_audit` — so the status output must now claim
    /// the opposite of what it claimed before: both the MCP server and CLI
    /// commands write to the file.
    #[test]
    fn test_audit_status_lines_say_both_mcp_server_and_cli_write_the_file() {
        let audit = AuditConfig {
            enabled: true,
            path: std::path::PathBuf::from("/var/log/bridge-mcp/audit.log"),
            max_size_mb: 100,
            retain_days: 30,
        };

        let lines = audit_status_lines(&audit);

        assert_eq!(lines.len(), 2, "got {lines:?}");
        assert!(
            !lines[0].contains("tracing only"),
            "must not claim CLI events only reach tracing anymore, got {:?}",
            lines[0]
        );
        assert!(
            lines[0].contains("MCP server") && lines[0].contains("CLI"),
            "the enabled line must say both the MCP server and CLI commands write it, got {:?}",
            lines[0]
        );
        assert!(
            lines[1].contains("/var/log/bridge-mcp/audit.log"),
            "the path must still be shown, got {:?}",
            lines[1]
        );
        assert!(
            !lines[1].contains("only, not by CLI"),
            "must not claim the MCP server writes it exclusively anymore, got {:?}",
            lines[1]
        );
    }

    #[test]
    fn test_audit_status_lines_disabled_prints_one_line() {
        let audit = AuditConfig {
            enabled: false,
            ..AuditConfig::default()
        };

        let lines = audit_status_lines(&audit);

        assert_eq!(lines, vec!["  Enabled: false".to_string()]);
    }

    // ============== run_status Tests (async) ==============

    #[tokio::test]
    async fn test_run_status_empty_config() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_status(Arc::new(config), false).await;
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_status(Arc::new(config), false).await;
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_status(Arc::new(config), false).await;
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

        let result = run_status(Arc::new(config), false).await;
        assert!(result.is_ok());
    }

    // ============== run_history Tests (async) ==============

    #[tokio::test]
    async fn test_run_history_empty() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_history(Arc::new(config), 10, None, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_history_with_host_filter() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_history(Arc::new(config), 10, Some("nonexistent-host"), false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_history_with_limit_zero() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_history(Arc::new(config), 0, None, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_history_with_large_limit() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_history(Arc::new(config), 1000, None, false).await;
        assert!(result.is_ok());
    }

    // ============== run_exec Error Cases (async) ==============

    #[tokio::test]
    async fn test_run_exec_unknown_host() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_exec(Arc::new(config), "unknown-host", "ls", 30, None, false).await;

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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        // Try to execute a command not in whitelist
        let result = run_exec(Arc::new(config), "test", "rm -rf /", 30, None, false).await;

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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

    #[tokio::test]
    async fn test_run_upload_verify_checksum_rejected_in_resume_mode() {
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        // The guard must fire before the local-file-exists check, so this
        // nonexistent path never gets a chance to produce "not found" instead.
        let result = run_upload(
            Arc::new(config),
            "test",
            Path::new("/nonexistent/file/that/does/not/exist.txt"),
            "/remote/file",
            "resume",
            1024 * 1024,
            true,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("verify_checksum"), "got: {reason}");
                assert!(reason.contains("resume"), "got: {reason}");
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

    #[tokio::test]
    async fn test_run_download_verify_checksum_rejected_in_resume_mode() {
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        // The guard must fire before any connection attempt, so this points at
        // a host that would otherwise fail with a connection error, not
        // "verify_checksum"/"resume".
        let result = run_download(
            Arc::new(config),
            "test",
            "/remote/file",
            Path::new("/local/file"),
            "append",
            1024 * 1024,
            true,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("verify_checksum"), "got: {reason}");
                assert!(reason.contains("append"), "got: {reason}");
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
            passphrase: Some(RedactedSecret::from("secret")),
        };
        let agent_auth = AuthConfig::Agent;
        let password_auth = AuthConfig::Password {
            password: RedactedSecret::from("pass123"),
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

    // ============== destructive gate Tests ==============
    //
    // Under `cargo test` stdin is never a TTY, so `decide_destructive` can
    // only reach the branches that decide without asking. The prompt's own
    // decision is reachable anyway, because mapping the answer is a pure
    // function (`decision_from_prompt_answer`) and these tests call it: what
    // stays untested is `IsTerminal` returning true, i.e. the prompt being
    // printed and read at all.

    fn gate_config(require: bool) -> Config {
        let mut config = Config::default();
        config.security.require_elicitation_on_destructive = require;
        config
    }

    /// A use case whose audit logger keeps every event it is handed, so these
    /// tests read the line that was actually written — `event_type`,
    /// `tool_name`, `host`, the result variant — instead of asserting that
    /// some logging function was called.
    ///
    /// The sanitizer is built exactly as `create_audit_wiring` builds it,
    /// legacy `sanitize_patterns` included: a test whose sanitizer is weaker
    /// than production's cannot see a leak that production has.
    fn gate_audit(config: &Config) -> (Arc<AuditLogger>, ExecuteCommandUseCase) {
        let logger = Arc::new(AuditLogger::for_test());
        let use_case = ExecuteCommandUseCase::new(
            Arc::new(CommandValidator::new(&config.security)),
            Arc::new(Sanitizer::from_config_with_legacy(
                &config.security.sanitize,
                &config.security.sanitize_patterns,
            )),
            Arc::clone(&logger),
            Arc::new(CommandHistory::new(&HistoryConfig::default())),
        );
        (logger, use_case)
    }

    /// Decide, then record, exactly as `run_gated_tool` does — so these tests
    /// exercise the production pairing of the two halves, not one of them.
    fn gate(
        tool_name: &str,
        args: Option<&serde_json::Value>,
        assume_yes: bool,
        config: &Config,
        audit: &ExecuteCommandUseCase,
    ) -> Result<()> {
        let decision = decide_destructive(tool_name, args, assume_yes, config);
        apply_gate_decision(
            decision,
            audit,
            tool_name,
            gate_host(args),
            &audited_operation(tool_name, args),
        )
    }

    #[test]
    fn destructive_gate_refuses_without_a_terminal() {
        let config = gate_config(true);
        let (_logger, audit) = gate_audit(&config);
        let err = gate(
            "ssh_exec",
            Some(&serde_json::json!({"host": "pi", "command": "echo hi"})),
            false,
            &config,
            &audit,
        )
        .expect_err("a destructive tool must not run unconfirmed off a terminal");

        let msg = err.to_string();
        assert!(
            msg.contains("--yes"),
            "the refusal must name the way forward, got: {msg}"
        );
    }

    /// The acceptance criterion of T14: a refused destructive call leaves an
    /// audit line. Read off the logger's own record of what it was handed,
    /// not off a counter.
    #[test]
    fn a_refusal_without_a_terminal_is_written_to_the_audit_trail() {
        let config = gate_config(true);
        let (logger, audit) = gate_audit(&config);
        let err = gate(
            "ssh_exec",
            Some(&serde_json::json!({"host": "pi", "command": "rm -rf /tmp/x"})),
            false,
            &config,
            &audit,
        )
        .expect_err("the gate must refuse");

        let events = logger.drain_for_test();
        assert_eq!(events.len(), 1, "expected exactly one event: {events:?}");
        let e = &events[0];
        assert_eq!(e.event_type, "command_denied");
        assert_eq!(e.tool_name.as_deref(), Some("ssh_exec"));
        assert_eq!(e.host, "pi");
        assert!(
            e.command.contains("ssh_exec") && e.command.contains("rm -rf /tmp/x"),
            "the line must say what was refused, got {:?}",
            e.command
        );
        match &e.result {
            CommandResult::Denied { reason } => assert!(
                err.to_string().contains(reason.as_str()),
                "the audited reason must be the one the caller is shown: \
                 audit {reason:?} vs error {err}"
            ),
            r => panic!("a refusal must audit as Denied, got {r:?}"),
        }
    }

    #[test]
    fn destructive_gate_lets_yes_through() {
        let config = gate_config(true);
        let (_logger, audit) = gate_audit(&config);
        gate(
            "ssh_exec",
            Some(&serde_json::json!({"host": "pi"})),
            true,
            &config,
            &audit,
        )
        .expect("--yes is the scripted confirmation");
    }

    /// `--yes`'s help text says "the choice is recorded in the audit log", and
    /// the choice includes the one that lets the call run. Without this line a
    /// reader cannot tell a destructive call that passed the gate from one
    /// that never met it — the 2026-08-31 regression's signature.
    #[test]
    fn yes_writes_a_confirmation_naming_the_flag() {
        let config = gate_config(true);
        let (logger, audit) = gate_audit(&config);
        gate(
            "ssh_exec",
            Some(&serde_json::json!({"host": "pi", "command": "echo hi"})),
            true,
            &config,
            &audit,
        )
        .expect("--yes is the scripted confirmation");

        let events = logger.drain_for_test();
        assert_eq!(events.len(), 1, "expected exactly one event: {events:?}");
        let e = &events[0];
        assert_eq!(e.event_type, "command_confirmed");
        assert_eq!(e.tool_name.as_deref(), Some("ssh_exec"));
        assert_eq!(e.host, "pi");
        match &e.result {
            CommandResult::Confirmed { by } => assert_eq!(
                by, CONFIRMED_BY_FLAG,
                "the line must name what answered, so a script flag is not read \
                 as a human at a prompt"
            ),
            r => panic!("a confirmation must audit as Confirmed, got {r:?}"),
        }
    }

    /// The distinction the `Confirmed` variant exists to carry: a human at a
    /// prompt is not a script flag. Reached through the pure answer mapping,
    /// because `decide_destructive` would need a TTY and this is the half
    /// that decides.
    #[test]
    fn a_prompt_answered_yes_writes_a_confirmation_naming_the_prompt() {
        let config = gate_config(true);
        let (logger, audit) = gate_audit(&config);
        let decision = decision_from_prompt_answer("ssh_exec", "y\n");
        apply_gate_decision(decision, &audit, "ssh_exec", "pi", "ssh_exec {}")
            .expect("`y` confirms");

        let events = logger.drain_for_test();
        assert_eq!(events.len(), 1, "expected exactly one event: {events:?}");
        assert_eq!(events[0].event_type, "command_confirmed");
        match &events[0].result {
            CommandResult::Confirmed { by } => {
                assert_eq!(by, CONFIRMED_BY_PROMPT);
                assert_ne!(
                    by, CONFIRMED_BY_FLAG,
                    "a human answer must not be recorded as the script flag"
                );
            }
            r => panic!("expected Confirmed, got {r:?}"),
        }
    }

    /// The fourth outcome, and the one the first round could not reach at
    /// all: the operator declined.
    #[test]
    fn a_prompt_answered_no_writes_a_denial() {
        let config = gate_config(true);
        let (logger, audit) = gate_audit(&config);
        let decision = decision_from_prompt_answer("ssh_exec", "n\n");
        let err = apply_gate_decision(decision, &audit, "ssh_exec", "pi", "ssh_exec {}")
            .expect_err("anything but yes refuses");

        let events = logger.drain_for_test();
        assert_eq!(events.len(), 1, "expected exactly one event: {events:?}");
        assert_eq!(events[0].event_type, "command_denied");
        match &events[0].result {
            CommandResult::Denied { reason } => assert!(
                err.to_string().contains(reason.as_str()),
                "the audited reason must be the one the caller is shown: \
                 audit {reason:?} vs error {err}"
            ),
            r => panic!("expected Denied, got {r:?}"),
        }
    }

    /// Anything that is not an affirmative is a refusal — including an empty
    /// line, which is what a bare Enter at `[y/N]` sends.
    #[test]
    fn only_an_affirmative_answer_confirms() {
        for yes in ["y", "Y", "yes", "Yes", " y \n"] {
            assert!(
                matches!(
                    decision_from_prompt_answer("t", yes),
                    GateDecision::Confirmed {
                        by: CONFIRMED_BY_PROMPT
                    }
                ),
                "{yes:?} must confirm"
            );
        }
        for no in ["", "\n", "n", "N", "no", "YES PLEASE", "yolo"] {
            assert!(
                matches!(
                    decision_from_prompt_answer("t", no),
                    GateDecision::Denied { .. }
                ),
                "{no:?} must refuse"
            );
        }
    }

    /// The fifth exit, found in review: the prompt was shown but its answer
    /// could not be read. It refuses — and used to refuse writing nothing —
    /// while keeping its own error kind, so an unreadable stdin is not
    /// reported with a security denial's exit code.
    #[test]
    fn an_unreadable_answer_is_recorded_as_a_refusal_but_keeps_its_error_kind() {
        let config = gate_config(true);
        let (logger, audit) = gate_audit(&config);
        let decision = GateDecision::Unreadable {
            reason: "`ssh_exec` was not confirmed: the answer could not be read".to_string(),
            error: std::io::Error::other("stdin went away"),
        };
        let err = apply_gate_decision(decision, &audit, "ssh_exec", "pi", "ssh_exec {}")
            .expect_err("an unread answer must not confirm");
        assert!(
            matches!(err, BridgeError::Io(_)),
            "the error must stay an I/O error, got {err:?}"
        );

        let events = logger.drain_for_test();
        assert_eq!(events.len(), 1, "expected exactly one event: {events:?}");
        assert_eq!(events[0].event_type, "command_denied");
    }

    /// The host is only a JSON argument at the gate — unresolved, and absent
    /// for the destructive tools that take none. It falls back to the one
    /// crate-wide sentinel rather than to an empty string.
    #[test]
    fn a_call_with_no_host_argument_audits_the_no_host_sentinel() {
        let config = gate_config(true);
        let (logger, audit) = gate_audit(&config);
        let _ = gate("ssh_exec", None, false, &config, &audit);

        let events = logger.drain_for_test();
        assert_eq!(events.len(), 1, "expected exactly one event: {events:?}");
        assert_eq!(events[0].host, crate::security::NO_HOST);
    }

    /// A file handed to a destructive tool must not be copied into the trail.
    /// `ssh_file_write`'s own event is `SFTP_WRITE <path>` for exactly this
    /// reason, and a gate line carrying the raw arguments defeated it.
    #[test]
    fn a_large_argument_value_is_elided_from_the_gate_line() {
        let config = gate_config(true);
        let (logger, audit) = gate_audit(&config);
        let content = "S".repeat(400 * 1024);
        let args = serde_json::json!({
            "host": "pi",
            "path": "/etc/motd",
            "content": content,
        });
        gate("ssh_file_write", Some(&args), true, &config, &audit)
            .expect("--yes confirms the write");

        let events = logger.drain_for_test();
        assert_eq!(events.len(), 1, "expected exactly one event: {events:?}");
        let line = &events[0].command;
        assert!(
            !line.contains(&content),
            "the file's content must not reach the trail ({} chars logged)",
            line.chars().count()
        );
        assert!(
            line.contains("<elided: 409600 chars>"),
            "the elision must say what was dropped, got {line:?}"
        );
        // The values worth reading survive: this is a bound, not a blanket.
        assert!(
            line.contains("ssh_file_write") && line.contains("/etc/motd"),
            "the line must still identify the call, got {line:?}"
        );
        assert!(
            line.chars().count() <= GATE_AUDIT_MAX_OPERATION_CHARS,
            "the whole line must stay bounded, got {} chars",
            line.chars().count()
        );
    }

    /// Per-value elision alone does not bound the line: many short values
    /// each pass the per-value test. The overall ceiling is what catches it,
    /// and it marks where it cut.
    #[test]
    fn many_small_values_are_truncated_under_the_overall_ceiling() {
        let mut map = serde_json::Map::new();
        for i in 0..500 {
            map.insert(format!("k{i}"), serde_json::json!("v"));
        }
        let args = serde_json::Value::Object(map);
        let line = audited_operation("ssh_exec", Some(&args));
        assert!(
            line.contains("<truncated:") && line.contains("chars total>"),
            "the truncation must say how much there was, got the tail {:?}",
            &line[line.len().saturating_sub(60)..]
        );
        assert!(line.chars().count() <= GATE_AUDIT_MAX_OPERATION_CHARS + 64);
    }

    /// The shape the CLI actually produces, which neither of the other two
    /// bound tests covered: **several values each just under the per-value
    /// limit**, whose sum is far over the overall ceiling. 500 single-character
    /// values is a synthetic extreme; this is what a real
    /// `ssh_ansible_playbook` or `ssh_k8s_apply` invocation looks like.
    #[test]
    fn several_large_but_unelided_values_still_hit_the_overall_ceiling() {
        let mut map = serde_json::Map::new();
        for i in 0..20 {
            // 200 chars each: under GATE_AUDIT_MAX_VALUE_CHARS, so NOT elided.
            map.insert(format!("field{i}"), serde_json::json!("x".repeat(200)));
        }
        let args = serde_json::Value::Object(map);
        let line = audited_operation("ssh_exec", Some(&args));

        assert!(
            !line.contains("<elided:"),
            "no single value is over the per-value bound, so nothing should be elided"
        );
        assert!(
            line.contains("<truncated:") && line.contains("chars total>"),
            "4000+ chars of unelided values must still be cut, got {} chars",
            line.chars().count()
        );
        assert!(
            line.chars().count() <= GATE_AUDIT_MAX_OPERATION_CHARS + 64,
            "the marker aside, the line must stay at the ceiling, got {} chars",
            line.chars().count()
        );
    }

    /// M4: `log_denied` was the one audit entry point that did not pre-redact,
    /// so a secret matched ONLY by a legacy `sanitize_patterns` entry reached
    /// the refusal line in clear while the confirmation line beside it was
    /// masked. The refusal is the line this gate exists to write.
    ///
    /// **The bound, measured while writing this test:** `Sanitizer::sanitize`
    /// skips the whole regex tier when `literal_detector` finds none of the
    /// built-in `secret_keywords()` in the text — custom and legacy patterns
    /// included. So the same secret with no keyword near it (`--key WIDGETKEY
    /// -4242`) is masked on **neither** line, before this fix or after. That
    /// is a sanitizer limitation, not this gate's, and it is why the payload
    /// below says `--token`.
    #[test]
    fn a_legacy_only_secret_is_masked_in_both_gate_lines() {
        let mut config = gate_config(true);
        // Deliberately not a builtin pattern: only the legacy list covers it.
        config.security.sanitize_patterns = vec!["WIDGETKEY-[0-9]{4}".to_string()];
        let args = serde_json::json!({"host": "pi", "command": "deploy --token WIDGETKEY-4242"});

        let (denied_logger, denied_audit) = gate_audit(&config);
        let _ = gate("ssh_exec", Some(&args), false, &config, &denied_audit)
            .expect_err("no terminal, so refused");
        let denied = denied_logger.drain_for_test();
        assert_eq!(denied.len(), 1);
        assert!(
            !denied[0].command.contains("WIDGETKEY-4242"),
            "a refusal must not leak what a confirmation masks, got {:?}",
            denied[0].command
        );

        let (confirmed_logger, confirmed_audit) = gate_audit(&config);
        gate("ssh_exec", Some(&args), true, &config, &confirmed_audit).expect("--yes confirms");
        let confirmed = confirmed_logger.drain_for_test();
        assert_eq!(confirmed.len(), 1);
        assert!(
            !confirmed[0].command.contains("WIDGETKEY-4242"),
            "got {:?}",
            confirmed[0].command
        );
    }

    /// The gate is the CLI's half of `require_elicitation_on_destructive`, so
    /// turning that policy off must turn the gate off with it — otherwise the
    /// setting means one thing over MCP and another here.
    #[test]
    fn destructive_gate_honours_the_policy_switch() {
        let config = gate_config(false);
        let (logger, audit) = gate_audit(&config);
        gate(
            "ssh_exec",
            Some(&serde_json::json!({"host": "pi"})),
            false,
            &config,
            &audit,
        )
        .expect("with the policy off, nothing should be gated");
        // The negative half of the assertions above: a gate that wrote a line
        // unconditionally would satisfy them all. No decision was taken here,
        // so there is nothing to record.
        assert!(
            logger.drain_for_test().is_empty(),
            "a gate that took no decision must write no line"
        );
        assert!(matches!(
            decide_destructive(
                "ssh_exec",
                Some(&serde_json::json!({"host": "pi"})),
                false,
                &config
            ),
            GateDecision::NotGated
        ));
    }

    #[test]
    fn destructive_gate_ignores_non_destructive_tools() {
        let config = gate_config(true);
        let (logger, audit) = gate_audit(&config);
        gate(
            "ssh_metrics",
            Some(&serde_json::json!({"host": "pi"})),
            false,
            &config,
            &audit,
        )
        .expect("a read-only tool must never be gated");
        assert!(
            logger.drain_for_test().is_empty(),
            "an ungated tool must write no gate line"
        );
        assert!(matches!(
            decide_destructive(
                "ssh_metrics",
                Some(&serde_json::json!({"host": "pi"})),
                false,
                &config
            ),
            GateDecision::NotGated
        ));
    }

    /// `run_tool` builds the audit wiring only for a call that produced a
    /// decision, so `NotGated` has to be exactly the set of calls that write
    /// nothing. Pinning it here keeps the two from drifting apart silently.
    ///
    /// **It reads the journal on both sides**, because the first version of
    /// this test asserted only on the returned value: three `matches!` and no
    /// logger. Its name promised "records nothing" and its body could not
    /// have seen a `Confirmed` that recorded nothing.
    #[test]
    fn not_gated_is_exactly_the_set_that_records_nothing() {
        let on = gate_config(true);
        let off = gate_config(false);
        let args = serde_json::json!({"host": "pi"});

        // Three cases, and for each: the decision AND what reached the trail.
        for (tool, assume_yes, config, gated) in [
            // Destructive + policy on, under --yes: a decision, so a line.
            ("ssh_exec", true, &on, true),
            // Either knob off: no decision, so no line.
            ("ssh_exec", true, &off, false),
            ("ssh_metrics", true, &on, false),
        ] {
            let decision = decide_destructive(tool, Some(&args), assume_yes, config);
            assert_eq!(
                !matches!(decision, GateDecision::NotGated),
                gated,
                "{tool}: wrong decision kind"
            );

            let (logger, audit) = gate_audit(config);
            gate(tool, Some(&args), assume_yes, config, &audit).expect("none of these refuse");
            let events = logger.drain_for_test();
            assert_eq!(
                !events.is_empty(),
                gated,
                "{tool}: `NotGated` must be exactly the set that writes nothing, \
                 got {events:?}"
            );
        }
    }

    /// The prompt branch, wiring included — the mutation that
    /// `decision_from_prompt_answer`'s own tests could not catch: replacing
    /// `Ok(_) => decision_from_prompt_answer(…)` with a hard-coded
    /// confirmation left the whole suite green, and that is an operator
    /// typing `n`, the command running, and the trail saying they agreed.
    #[test]
    fn a_terminal_answer_decides_through_the_wiring_not_around_it() {
        let config = gate_config(true);
        let args = serde_json::json!({"host": "pi", "command": "rm -rf /tmp/x"});

        for (answer, expect_confirmed) in [("y\n", true), ("n\n", false), ("\n", false)] {
            let mut reader = std::io::Cursor::new(answer.as_bytes().to_vec());
            let decision = decide_destructive_from(
                "ssh_exec",
                Some(&args),
                false,
                &config,
                true, // stdin IS a terminal: the branch no test could reach
                &mut reader,
            );
            let (logger, audit) = gate_audit(&config);
            let outcome = apply_gate_decision(
                decision,
                &audit,
                "ssh_exec",
                gate_host(Some(&args)),
                &audited_operation("ssh_exec", Some(&args)),
            );
            let events = logger.drain_for_test();
            assert_eq!(events.len(), 1, "{answer:?}: expected one event");

            if expect_confirmed {
                outcome.expect("`y` must let the call through");
                assert_eq!(events[0].event_type, "command_confirmed");
                match &events[0].result {
                    CommandResult::Confirmed { by } => assert_eq!(by, CONFIRMED_BY_PROMPT),
                    r => panic!("expected Confirmed, got {r:?}"),
                }
            } else {
                outcome.expect_err("anything but yes must refuse");
                assert_eq!(
                    events[0].event_type, "command_denied",
                    "{answer:?}: the operator said no; the trail must not say otherwise"
                );
            }
        }
    }

    /// The fifth exit, through the wiring: a reader that errors. Before the
    /// reader was injectable this branch was reachable only by constructing
    /// the decision by hand, which skipped the line under test.
    #[test]
    fn a_terminal_whose_answer_cannot_be_read_refuses_through_the_wiring() {
        struct Broken;
        impl std::io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("stdin went away"))
            }
        }

        let config = gate_config(true);
        let mut reader = std::io::BufReader::new(Broken);
        let decision = decide_destructive_from("ssh_exec", None, false, &config, true, &mut reader);
        let (logger, audit) = gate_audit(&config);
        let err = apply_gate_decision(decision, &audit, "ssh_exec", "pi", "ssh_exec {}")
            .expect_err("an unread answer must not confirm");
        assert!(
            matches!(err, BridgeError::Io(_)),
            "the error must stay an I/O error, got {err:?}"
        );
        assert_eq!(logger.drain_for_test()[0].event_type, "command_denied");
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        // Should succeed (no hosts is a warning, not error)
        let result = run_validate(Arc::new(config), false).await;
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_validate(Arc::new(config), false).await;
        assert!(result.is_err());
    }

    // ============== run_config_diff Tests (async) ==============

    #[tokio::test]
    async fn test_run_config_diff_default_config() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_config_diff(Arc::new(config), false).await;
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_config_diff(Arc::new(config), false).await;
        assert!(result.is_ok());
    }

    // ============== run_list_tools Tests (async) ==============

    #[tokio::test]
    async fn test_run_list_tools_all() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_list_tools(Arc::new(config), None, false, false, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_groups_only() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_list_tools(Arc::new(config), None, false, true, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_groups_only_json() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_list_tools(Arc::new(config), None, true, true, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_by_group() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_list_tools(Arc::new(config), Some("docker"), false, false, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_search() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_list_tools(Arc::new(config), None, false, false, Some("kubernetes")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_json_output() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_list_tools(Arc::new(config), None, true, false, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_list_tools_nonexistent_group() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_describe_tool(Arc::new(config), "ssh_exec", false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_describe_tool_json() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_describe_tool(Arc::new(config), "ssh_exec", true).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_describe_tool_unknown() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Test fixtures must not
            // open a developer's actual audit file.
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

        let result = run_describe_tool(Arc::new(config), "nonexistent_tool", false).await;
        assert!(result.is_err());
    }

    // ============== print_daemon_response Tests ==============

    #[test]
    fn test_print_daemon_response_error_text() {
        let resp = serde_json::json!({"error": {"code": -32601, "message": "not found"}});
        let code = print_daemon_response(&resp, false).unwrap();
        assert_eq!(code, 1, "JSON-RPC error must map to exit code 1");
    }

    #[test]
    fn test_print_daemon_response_error_json() {
        let resp = serde_json::json!({"error": {"code": -1, "message": "boom"}});
        let code = print_daemon_response(&resp, true).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn test_print_daemon_response_missing_result_and_error() {
        let resp = serde_json::json!({"jsonrpc": "2.0", "id": 1});
        let err = print_daemon_response(&resp, false);
        assert!(err.is_err(), "neither result nor error must be an error");
    }

    #[test]
    fn test_print_daemon_response_is_error_true() {
        let resp = serde_json::json!({
            "result": {"isError": true, "content": [{"type": "text", "text": "failed"}]}
        });
        let code = print_daemon_response(&resp, false).unwrap();
        assert_eq!(code, 1, "isError=true must map to exit code 1");
    }

    #[test]
    fn test_print_daemon_response_success_content_text() {
        let resp = serde_json::json!({
            "result": {"content": [{"type": "text", "text": "hello"}]}
        });
        let code = print_daemon_response(&resp, false).unwrap();
        assert_eq!(code, 0, "success without isError must map to exit code 0");
    }

    #[test]
    fn test_print_daemon_response_success_json_output() {
        let resp = serde_json::json!({
            "result": {"content": [{"type": "text", "text": "hi"}], "isError": false}
        });
        let code = print_daemon_response(&resp, true).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn test_print_daemon_response_content_non_text_item() {
        // A content item without a `text` field falls through to pretty-print.
        let resp = serde_json::json!({
            "result": {"content": [{"type": "resource", "uri": "file:///x"}]}
        });
        let code = print_daemon_response(&resp, false).unwrap();
        assert_eq!(code, 0);
    }

    // ===== `bridge-mcp tool` exit code: remote failure vs bridge failure =====

    /// The defect this task removes: a tool whose remote command exited
    /// non-zero produced process exit 0, so `bridge-mcp tool … && next` ran
    /// `next` after a failure.
    #[test]
    fn a_remote_failure_leaves_a_non_zero_process_exit_code() {
        let result = crate::mcp::protocol::ToolCallResult::text("[exit:1]\nno such user")
            .with_remote_exit_code(1);
        assert_eq!(
            tool_exit_code(&result),
            EXIT_REMOTE_FAILURE,
            "a non-zero remote exit must not be reported as success"
        );
    }

    /// The trap: `is_error` is *also* true for bridge-side refusals (rate
    /// limit, denied command). Those must keep exit 1 — labelling them 6
    /// would announce a remote failure that never happened.
    #[test]
    fn a_bridge_side_error_is_not_reported_as_a_remote_failure() {
        let result = crate::mcp::protocol::ToolCallResult::error(
            "Rate limit exceeded for host 'raspberry'.",
        );
        assert_eq!(
            tool_exit_code(&result),
            1,
            "a bridge-side error is code 1, not the remote-failure code"
        );
    }

    /// Exit 6 is reserved: no code `map_exit_code` can return may equal it.
    ///
    /// Walks `map_exit_code` itself, over one value per arm of the match (every
    /// variant it names) plus catch-all variants, so a new arm returning
    /// `EXIT_REMOTE_FAILURE` fails here. The `_ => 1` arm cannot collide
    /// unless its literal is edited, which the catch-all samples (`SshExec`,
    /// `Cancelled`, `Io`) would catch; a variant added later falls into that
    /// arm and is covered by it. A *new arm* for a new variant is the case
    /// this cannot see until the variant is added to `samples` below.
    #[test]
    fn the_remote_failure_code_does_not_collide_with_the_cli_s_own_codes() {
        let samples = [
            BridgeError::CommandDenied { reason: "r".into() },
            BridgeError::UnknownHost { host: "h".into() },
            BridgeError::SshConnection {
                host: "h".into(),
                reason: "r".into(),
            },
            BridgeError::McpUnknownTool { tool: "t".into() },
            BridgeError::Config("c".into()),
            BridgeError::ConfigNotFound { path: "p".into() },
            BridgeError::ConfigInvalid {
                field: "f".into(),
                reason: "r".into(),
            },
            BridgeError::Yaml(
                serde_saphyr::from_str::<std::collections::HashMap<String, String>>("a: [")
                    .unwrap_err(),
            ),
            BridgeError::SshExec { reason: "r".into() },
            BridgeError::Cancelled,
            BridgeError::Io(std::io::Error::other("io")),
        ];
        let codes: std::collections::BTreeSet<i32> = samples.iter().map(map_exit_code).collect();
        assert!(
            codes.len() > 1,
            "the samples must reach more than one arm, got {codes:?}"
        );
        for err in &samples {
            let code = map_exit_code(err);
            assert_ne!(
                code, EXIT_REMOTE_FAILURE,
                "map_exit_code({err:?}) = {code} collides with EXIT_REMOTE_FAILURE"
            );
            assert_ne!(code, 0, "an error must not map to success: {err:?}");
        }
    }

    /// The daemon path now reads the remote exit code from
    /// `_meta[REMOTE_EXIT_CODE_META_KEY]`, so a bridge-side refusal (no code,
    /// `isError`) is 1 and a remote failure that the tool also calls an error
    /// is 6 — the same two numbers the direct path gives. Responses are built
    /// by the real producer, `JsonRpcResponse::tool_result`, not hand-written
    /// JSON, so a rename of the key breaks the test.
    #[test]
    fn the_daemon_path_distinguishes_a_remote_failure_from_a_bridge_refusal() {
        let remote =
            crate::mcp::protocol::ToolCallResult::text("[exit:3]\nboom").with_remote_exit_code(3);
        let resp = daemon_response_for(&remote);
        assert_eq!(
            print_daemon_response(&resp, false).unwrap(),
            EXIT_REMOTE_FAILURE,
            "a remote failure through the daemon must be 6, as on the direct path"
        );
        assert_eq!(
            print_daemon_response(&resp, false).unwrap(),
            tool_exit_code(&remote)
        );

        let refusal = crate::mcp::protocol::ToolCallResult::error("Rate limit exceeded.");
        assert_eq!(
            print_daemon_response(&daemon_response_for(&refusal), false).unwrap(),
            1,
            "a bridge-side refusal carries no remote code and stays 1"
        );

        // `isError` with no `_meta` at all (an older daemon): still 1.
        let legacy = serde_json::json!({
            "result": {"isError": true, "content": [{"type": "text", "text": "x"}]}
        });
        assert_eq!(print_daemon_response(&legacy, false).unwrap(), 1);
    }

    /// The acceptance criterion: `ssh_exec host=X command=false` must leave a
    /// non-zero `$?` under the daemon. `ssh_exec` reports the code WITHOUT
    /// `isError` (the caller wrote the command), so before the `_meta` key the
    /// daemon path read nothing and exited 0 while the direct path exited 6.
    ///
    /// Observed at `print_daemon_response` on a response the real server
    /// serializer produced; no daemon process is spawned.
    #[test]
    fn the_daemon_path_reports_a_free_form_tool_s_remote_failure() {
        let direct =
            crate::mcp::protocol::ToolCallResult::text("[exit:1]\n").with_remote_exit_code_only(1);
        let resp = daemon_response_for(&direct);
        assert!(
            resp["result"].get("isError").is_none(),
            "this tool sets no verdict, so the code is the only signal: {resp}"
        );
        let code = print_daemon_response(&resp, false).unwrap();
        assert_eq!(code, EXIT_REMOTE_FAILURE);
        assert_eq!(code, tool_exit_code(&direct), "both paths now agree");

        // A successful free-form call still exits 0 (no `_meta` key).
        let ok = crate::mcp::protocol::ToolCallResult::text("fine");
        assert_eq!(
            print_daemon_response(&daemon_response_for(&ok), false).unwrap(),
            0
        );

        // A malformed value is ignored, not guessed at.
        let bad = serde_json::json!({
            "result": {"content": [], "_meta": {
                crate::mcp::protocol::REMOTE_EXIT_CODE_META_KEY: "1"
            }}
        });
        assert_eq!(print_daemon_response(&bad, false).unwrap(), 0);
    }

    /// What a daemon would hand back for `result`: the real server
    /// serializer, wrapped as a JSON-RPC response and round-tripped as text.
    fn daemon_response_for(result: &crate::mcp::protocol::ToolCallResult) -> serde_json::Value {
        let response =
            crate::mcp::protocol::JsonRpcResponse::tool_result(Some(serde_json::json!(1)), result);
        serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap()
    }

    /// A daemon built from another revision, or one that names none, must not
    /// silently lose the exit-code guarantee: the warning fires on a mismatch
    /// and stays silent on a match.
    #[test]
    fn a_daemon_of_another_build_is_warned_about_and_a_matching_one_is_not() {
        let stamp = |rev: &str| {
            serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "_meta": {"io.github.muchiny/build": {"rev": rev}}
                    }
                }
            })
        };
        assert!(daemon_build_warning(&stamp(crate::mcp::protocol::BUILD_REV)).is_none());
        let other = daemon_build_warning(&stamp("0000000-old")).expect("mismatch must warn");
        assert!(other.contains("0000000-old") && other.contains(crate::mcp::protocol::BUILD_REV));
        assert!(
            daemon_build_warning(&serde_json::json!({})).is_some(),
            "a daemon that reports no build must warn"
        );
    }

    /// An answer that is not `complete` must not exit 0.
    #[test]
    fn a_daemon_answer_that_is_not_complete_does_not_exit_zero() {
        let pending = serde_json::json!({
            "result": {"resultType": "input_required", "content": []}
        });
        assert_eq!(print_daemon_response(&pending, false).unwrap(), 1);
        let done = serde_json::json!({"result": {"resultType": "complete", "content": []}});
        assert_eq!(print_daemon_response(&done, false).unwrap(), 0);
    }

    /// A successful call stays 0 even though `remote_exit_code` is carried.
    #[test]
    fn a_successful_tool_call_still_exits_zero() {
        let ok = crate::mcp::protocol::ToolCallResult::text("all good");
        assert_eq!(tool_exit_code(&ok), 0);
        let ok_zero =
            crate::mcp::protocol::ToolCallResult::text("all good").with_remote_exit_code(0);
        assert_eq!(
            tool_exit_code(&ok_zero),
            0,
            "a remote exit code of 0 is a success, not a failure"
        );
    }
}
