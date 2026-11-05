//! Utility functions for tool handlers

use std::time::Instant;

use crate::config::{Config, HostConfig, LimitsConfig, ShellType};
use crate::error::{BridgeError, Result};
use crate::ssh::{SshClient, TransferMode};

/// Milliseconds elapsed since `start`, saturating instead of wrapping.
///
/// For the `duration_ms` of a `CommandResult::StateChanged` audit event: the
/// state tools (`ssh_session_create`, `ssh_tunnel_close`, …) time their own
/// operation, since no `CommandOutput` brings a duration back for them. The
/// `try_from` is what keeps a 584-million-year uptime from reading as a few
/// milliseconds.
///
/// Five other `elapsed_ms` live in the tree, all private to their module, and
/// they do **not** agree: `ssm/mod.rs`, `cloud_exec/gcp.rs` and
/// `cloud_exec/azure.rs` saturate the same way this one does, with
/// `.min(u128::from(u64::MAX)) as u64`, while `ssh_exec_multi.rs` and
/// `ssh_metrics_multi.rs` are a bare `as u64` that wraps. This is the sixth
/// and the only public one; it is not a deduplication of the other five, and
/// unifying them is not owed to the task that added it.
#[must_use]
pub fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Validate a file path for potential path traversal attacks.
///
/// Returns an error if the path contains `..` components that could be used
/// for directory traversal attacks.
pub fn validate_path(path: &str) -> Result<()> {
    // Check for path traversal patterns
    if path.contains("..") {
        return Err(BridgeError::FileTransfer {
            reason: "Path traversal not allowed: path contains '..'".to_string(),
        });
    }
    Ok(())
}

/// Parse a transfer mode, refusing `verify_checksum` with `resume`/`append`.
///
/// Both checks live together because the second one is only meaningful once
/// the first has succeeded, and because all four transfer entry points
/// (`ssh_upload`, `ssh_download`, and the CLI's `run_upload`/`run_download`)
/// need exactly this pair. Keeping it in one place is what stops the two
/// surfaces from drifting apart in wording again.
///
/// `verify_checksum` is refused in `resume`/`append` because neither mode
/// computes a full-file hash (`can_compute_full_checksum` in
/// `src/ssh/sftp.rs` disables it there), and no mode ever compares the hash
/// against anything on the remote host. Returning this explicit refusal
/// beats a silent `checksum: None` the operator reads as "integrity
/// verified".
///
/// `direction` is the past-tense verb for what happened to the bytes that
/// *could* have been hashed: `"sent"` for uploads, `"received"` for
/// downloads. It is user-facing, so keep it specific rather than flattening
/// upload/download into one generic word.
///
/// # Errors
///
/// Returns [`BridgeError::FileTransfer`] when `mode_str` names no known
/// mode, or when `verify_checksum` is combined with `resume`/`append`.
pub fn parse_transfer_mode_checked(
    mode_str: &str,
    verify_checksum: bool,
    direction: &str,
) -> Result<TransferMode> {
    let mode = TransferMode::parse(mode_str).ok_or_else(|| BridgeError::FileTransfer {
        reason: format!(
            "Invalid transfer mode: {mode_str}. Valid modes: overwrite, append, resume, \
             fail_if_exists (also accepted as fail-if-exists)"
        ),
    })?;

    if verify_checksum && matches!(mode, TransferMode::Resume | TransferMode::Append) {
        return Err(BridgeError::FileTransfer {
            reason: format!(
                "verify_checksum is not supported with mode=resume or mode=append: \
                 only the bytes {direction} in this session could be hashed, and no \
                 comparison against the remote host is performed. Transfer with \
                 mode=overwrite to get a source-side SHA256."
            ),
        });
    }

    Ok(mode)
}

/// Shell escape a string for safe use in shell commands
///
/// Wraps the string in single quotes and escapes any existing single quotes.
/// This is the POSIX-only variant. For shell-aware escaping, use [`shell_escape_for`].
///
/// Delegates to [`crate::domain::use_cases::shell::escape`] exactly as
/// [`shell_escape_for`] does. It used to carry its own copy of the same
/// `format!`/`replace` pair — two implementations of a security primitive that
/// happened to agree and that nothing kept in agreement.
pub fn shell_escape(s: &str) -> String {
    shell_escape_for(s, ShellType::Posix)
}

/// Shell escape a string for a specific shell type.
///
/// Delegates to [`crate::domain::use_cases::shell::escape`].
pub fn shell_escape_for(s: &str, shell: ShellType) -> String {
    crate::domain::use_cases::shell::escape(s, shell)
}

/// Refuse a POSIX-only tool on a Windows host, or on any host whose commands
/// do not run in a POSIX shell.
///
/// The `file_ops` and `directory` builders emit `find`, `printf`, `stat` and
/// friends, none of which exist on Windows. Without this the tool shipped a
/// shell script Windows cannot run: over `WinRM` it came back as a PowerShell
/// `CommandNotFoundException`, and over PSRP the error record failed the whole
/// pipeline. Those builders also quote every argument for a POSIX shell, so the
/// shell that will read the command is checked too ([`shell_mismatch`]):
/// `os_type` alone let a `WinRM` host left at the default `os_type: linux` run
/// them in `PowerShell`. Handlers built on `StandardTool` express the same rule
/// with `OS_GUARD` and the same shell check; this is the equivalent for the
/// hand-written ones.
pub fn reject_posix_only_on_windows(
    host_config: &HostConfig,
    tool_name: &str,
) -> Option<crate::mcp::protocol::ToolCallResult> {
    posix_only_refusal(host_config, tool_name).map(crate::mcp::protocol::ToolCallResult::error)
}

/// The refusal [`reject_posix_only_on_windows`] returns, as text, for callers
/// that report it as an error rather than as a tool result (the `file://` and
/// `log://` resources).
///
/// Stricter than the `StandardTool` shell guard on one point: an
/// `os_type: windows` host is refused even when it declares `shell: posix`,
/// because these commands also need the GNU tools (`find`, `stat`, `tail`,
/// `du`) that a Windows host is not assumed to have.
#[must_use]
pub fn posix_only_refusal(host_config: &HostConfig, tool_name: &str) -> Option<String> {
    if host_config.os_type == crate::config::OsType::Windows {
        return Some(format!(
            "Tool '{tool_name}' is not available on Windows hosts — its command \
             is POSIX-only. Use the Windows-specific tools instead."
        ));
    }
    shell_mismatch(tool_name, ShellType::Posix, host_config)
}

/// Why `tool`, whose command quotes its arguments for `tool_shell`, must not
/// run on this host; `None` when the host's commands run in that shell
/// ([`HostConfig::effective_shell`], which follows the protocol where the
/// protocol fixes the interpreter).
///
/// Every builder quotes the caller's arguments for one shell: POSIX single
/// quotes (`'` becomes `'\''`) for the Linux and unrestricted tools,
/// `PowerShell`'s for the Windows ones. In another shell that quoting does not
/// hold. `PowerShell` reads `'a'\''; whoami; #'` as the string `'a'`, a `\`, an
/// empty string, then `;`, so `ssh_git_diff path="a'; whoami; #"` ran `whoami`
/// on a `WinRM` host; `cmd.exe` does not treat `'` as a quote at all, so a `&`
/// inside a quoted value ran a second command there. A built-in tool's
/// command is not checked against the whitelist (`validate_builtin`), so
/// nothing else stands between a tool argument and a command of the caller's
/// choosing.
#[must_use]
pub fn shell_mismatch(
    tool: &str,
    tool_shell: ShellType,
    host_config: &HostConfig,
) -> Option<String> {
    let host_shell = host_config.effective_shell();
    if host_shell == tool_shell {
        return None;
    }
    let hint = if tool_shell == ShellType::PowerShell && host_shell == ShellType::Cmd {
        " If this host's commands do run in PowerShell (an OpenSSH DefaultShell set to \
         PowerShell, say), set `shell: powershell` for it."
    } else {
        ""
    };
    Some(format!(
        "Tool '{tool}' quotes its arguments for {}, but this host runs commands in {}, \
         where that quoting does not hold: refused.{hint}",
        shell_name(tool_shell),
        shell_name(host_shell),
    ))
}

/// Why the AWX tools must not run their `curl` on `host`, the host
/// `awx.ssh_host` names; `None` when it is a Linux host running a POSIX shell.
///
/// Every AWX tool sends a `curl` command whose URL, token and JSON body are
/// POSIX-quoted, and the JSON carries caller strings (a host name, extra
/// variables): on any other shell that quoting does not hold, as for
/// [`shell_mismatch`].
#[must_use]
pub fn awx_host_refusal(host: &str, host_config: &HostConfig) -> Option<String> {
    let shell = host_config.effective_shell();
    let what = if host_config.os_type == crate::config::OsType::Windows {
        "a Windows host".to_string()
    } else if shell == ShellType::Posix {
        return None;
    } else {
        format!("a host whose commands run in {}", shell_name(shell))
    };
    Some(format!(
        "`awx.ssh_host` is '{host}', {what}: the AWX tools send it POSIX-quoted `curl` \
         commands, whose quoting does not hold there, so they are refused. Point \
         `awx.ssh_host` at a Linux host."
    ))
}

/// How a refusal names `shell`.
const fn shell_name(shell: ShellType) -> &'static str {
    match shell {
        ShellType::Posix => "a POSIX shell",
        ShellType::Cmd => "cmd.exe",
        ShellType::PowerShell => "PowerShell",
    }
}

/// Connect to a host, resolving jump host if configured.
///
/// SSH only. Callers are the SFTP-backed handlers (`ssh_ls`, `ssh_upload`,
/// `ssh_download`), which need the SFTP subsystem and therefore cannot run
/// over a non-SSH protocol adapter. Without this guard a host configured as
/// `protocol: winrm` opened a raw SSH connection to the `WinRM` port and failed
/// with `SSH connection failed: Disconnected`, which reads like a broken host
/// rather than a tool that does not apply.
///
/// # Errors
///
/// Returns [`BridgeError::ConfigInvalid`] when the host does not speak SSH.
pub async fn connect_with_jump(
    host_name: &str,
    host_config: &HostConfig,
    limits: &LimitsConfig,
    config: &Config,
) -> Result<SshClient> {
    if host_config.protocol != crate::config::Protocol::Ssh {
        return Err(BridgeError::ConfigInvalid {
            field: "protocol".to_string(),
            reason: format!(
                "host '{host_name}' uses protocol {:?}; SFTP-based tools \
                 (ssh_ls, ssh_upload, ssh_download) require protocol: ssh",
                host_config.protocol
            ),
        });
    }

    let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
        config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    if let Some((jump_name, jump_config)) = jump_host {
        SshClient::connect_via_jump(host_name, host_config, jump_name, jump_config, limits).await
    } else {
        SshClient::connect(host_name, host_config, limits).await
    }
}

/// Save full output to a local file on the MCP server's filesystem.
///
/// Creates parent directories if needed. Returns a confirmation message
/// with byte count on success, or a [`BridgeError::FileTransfer`] on failure.
pub async fn save_output_to_file(path: &str, content: &str) -> Result<String> {
    // Reject path traversal attempts
    if path.contains("..") {
        return Err(BridgeError::FileTransfer {
            reason: "Path traversal not allowed: path contains '..'".to_string(),
        });
    }

    let path = std::path::Path::new(path);

    // Create parent directories if needed
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| BridgeError::FileTransfer {
                reason: format!("Failed to create directory {}: {e}", parent.display()),
            })?;
    }

    // Write with restrictive permissions (0o600) to protect sensitive output
    {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let path_owned = path.to_path_buf();
        let content_owned = content.to_string();
        tokio::task::spawn_blocking(move || {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            opts.mode(0o600);
            let mut file = opts
                .open(&path_owned)
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Failed to write to {}: {e}", path_owned.display()),
                })?;
            file.write_all(content_owned.as_bytes())
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Failed to write to {}: {e}", path_owned.display()),
                })?;
            Ok::<(), BridgeError>(())
        })
        .await
        .map_err(|e| BridgeError::FileTransfer {
            reason: format!("Failed to write to {}: {e}", path.display()),
        })??;
    }

    Ok(format!(
        "Full output saved to {} ({} bytes)",
        path.display(),
        content.len()
    ))
}

/// Parsed columnar CLI output (docker ps, docker stats, kubectl top, etc.).
pub struct ParsedTable {
    /// Column headers, lowercased (e.g., `["container id", "image", "status", "names"]`).
    pub headers: Vec<String>,
    /// Data rows. Each inner `Vec` has the same length as `headers`.
    pub rows: Vec<Vec<String>>,
}

impl ParsedTable {
    /// Convert to TSV (tab-separated values) for token-efficient LLM consumption.
    ///
    /// Returns uppercased header row + tab-separated data rows.
    /// TSV uses 30-40% fewer tokens than JSON for tabular data (pgEdge benchmark).
    /// Select a subset of columns by name (case-insensitive).
    ///
    /// Columns not found in the table are silently ignored.
    /// Returns a new `ParsedTable` with only the matching columns,
    /// preserving their original order in the table.
    #[must_use]
    pub fn select_columns(self, cols: &[String]) -> Self {
        let lowercase_cols: Vec<String> = cols.iter().map(|c| c.to_lowercase()).collect();
        let indices: Vec<usize> = self
            .headers
            .iter()
            .enumerate()
            .filter(|(_, h)| lowercase_cols.contains(h))
            .map(|(i, _)| i)
            .collect();

        // Not one requested name matched a header. Both documented contracts
        // — "unknown columns are silently ignored" (registry.rs) and "header
        // is always preserved" (output_kind.rs) — resolve the same way: every
        // requested column was unknown, so every one is ignored and no
        // filtering happens. Emptying the table instead reported "no data on
        // this host" about data that was there, and the caller could not tell
        // that from a genuine empty result.
        if indices.is_empty() {
            return self;
        }

        let headers = indices.iter().map(|&i| self.headers[i].clone()).collect();
        let rows = self
            .rows
            .iter()
            .map(|row| indices.iter().map(|&i| row[i].clone()).collect())
            .collect();

        Self { headers, rows }
    }

    /// Limit the number of data rows (header is unaffected).
    pub fn limit_rows(&mut self, max: usize) {
        self.rows.truncate(max);
    }

    /// Convert to TSV (tab-separated values) for token-efficient LLM consumption.
    ///
    /// Returns uppercased header row + tab-separated data rows.
    /// TSV uses 30-40% fewer tokens than JSON for tabular data (pgEdge benchmark).
    #[must_use]
    pub fn to_tsv(&self) -> String {
        let mut result = String::new();
        // Header row (uppercase for readability)
        for (i, h) in self.headers.iter().enumerate() {
            if i > 0 {
                result.push('\t');
            }
            result.push_str(&h.to_uppercase());
        }
        // Data rows
        for row in &self.rows {
            result.push('\n');
            for (i, val) in row.iter().enumerate() {
                if i > 0 {
                    result.push('\t');
                }
                result.push_str(val);
            }
        }
        result
    }
}

/// Keep only the app-table columns whose source survived the parse.
///
/// Handlers declare `(key, label, index)`, where `index` is the position of the
/// source header in the parsed table. A `None` index is dropped from BOTH the
/// column list and every row.
///
/// # Why dropping is right and blanking is not
///
/// The app table used to be declared with a fixed column list and the rows
/// built from a table that [`maybe_reduce_table`] may have narrowed. A column
/// the caller filtered out with `columns=` was still announced, and every row
/// carried `""` for it — so the structured view said "this field exists and is
/// empty" about data the caller had asked not to receive. A client rendering it
/// shows blank cells; one reading it cannot tell an absent column from a
/// genuinely empty value.
#[must_use]
pub fn present_columns<'a>(
    spec: &[(&'a str, &'a str, Option<usize>)],
) -> Vec<(&'a str, &'a str, usize)> {
    spec.iter()
        .filter_map(|(key, label, index)| index.map(|i| (*key, *label, i)))
        .collect()
}

/// Build one app-table row object from the columns that survived.
#[must_use]
pub fn row_from(
    live: &[(&str, &str, usize)],
    row: &[String],
) -> serde_json::Map<String, serde_json::Value> {
    live.iter()
        .map(|(key, _, index)| {
            let cell = row.get(*index).map_or("", String::as_str);
            (
                (*key).to_string(),
                serde_json::Value::String(cell.to_string()),
            )
        })
        .collect()
}

/// Whether a header is absent because the CALLER filtered it out.
///
/// Several handlers recover an identity column positionally when the header
/// lookup misses — `docker ps` always emits NAMES last, `docker stats` emits
/// NAME second. That recovery is correct for a PARSER miss (a wide value merges
/// two columns) and actively wrong after a `columns=` reduction: the cell at
/// that fixed position now belongs to a different column, so the fallback would
/// report a container named `Up 3 hours`.
///
/// Returns `true` only when a reduction was requested AND `header` is not in
/// it — the one case where the absence is deliberate.
#[must_use]
pub fn filtered_out_by_caller(
    header: &str,
    dr: &crate::domain::data_reduction::DataReductionArgs,
) -> bool {
    dr.columns
        .as_ref()
        .is_some_and(|cols| !cols.iter().any(|c| c.eq_ignore_ascii_case(header)))
}

/// Apply column filter and row limit to a `ParsedTable` from data reduction args.
#[must_use]
pub fn maybe_reduce_table(
    mut table: ParsedTable,
    dr: &crate::domain::data_reduction::DataReductionArgs,
) -> ParsedTable {
    if let Some(ref cols) = dr.columns {
        table = table.select_columns(cols);
    }
    if let Some(limit) = dr.limit {
        table.limit_rows(usize::try_from(limit).unwrap_or(usize::MAX));
    }
    table
}

/// Does a `kubectl get -o …` value produce a column-aligned table that the
/// MCP Apps table widget (and `to_tsv`) may re-render? Only the default
/// output, `wide` and `custom-columns=…` do. `json`, `yaml`, `name`,
/// `jsonpath=…`, `go-template=…` and `template=…` are documents or bare
/// lists: re-rendering them as a table turned `apiVersion: v1` into
/// `APIVERSION: V1` and flattened every nested key.
#[must_use]
pub(crate) fn kubectl_output_is_table(output: Option<&str>) -> bool {
    match output.map(str::trim) {
        None | Some("" | "wide") => true,
        Some(other) => other.starts_with("custom-columns"),
    }
}

/// Same question for `helm … -o table|json|yaml`.
#[must_use]
pub(crate) fn helm_output_is_table(output: Option<&str>) -> bool {
    matches!(output.map(str::trim), None | Some("" | "table"))
}

/// Parse columnar CLI output using data-driven gutter detection.
///
/// Algorithm:
/// 1. Collect all non-empty lines (first = header, rest = data)
/// 2. Find "data gap" positions: byte positions where ALL data rows have a space
///    (lines shorter than the position count as space — they're padded)
/// 3. Group consecutive data-gap positions into runs
/// 4. Only runs of width ≥ 2 are column boundaries (filters out 1-space gaps
///    within multi-word values like "2 hours ago")
/// 5. Column starts are at the first non-gap position after each run
/// 6. Headers are extracted from the header line at these positions
///
/// This data-driven approach handles:
/// - Multi-word column names ("CONTAINER ID", "MEM USAGE / LIMIT") — data at
///   those positions has non-space chars, so no false split
/// - Tight header spacing (French `df` with 1-space gap between "fichiers" and
///   "Type") — data has a wide gap there, correctly detected
/// - Multi-word values ("2 hours ago") — internal spaces are 1-wide, filtered
///   by the ≥ 2 width requirement
///
/// Returns `None` if fewer than 2 non-empty lines are found.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn parse_columnar_output(output: &str) -> Option<ParsedTable> {
    let lines: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 2 {
        return None;
    }

    // Reject JSON-shaped input: when the first non-empty char is `{` or `[`,
    // the columnar heuristic mangles structured payloads into garbage tables.
    // This typically happens when `jq_filter` was requested but the binary
    // was compiled without the `jq` feature, leaving raw JSON to fall through
    // to `post_process` (see #2B).
    if let Some(first) = lines[0].trim_start().chars().next()
        && (first == '{' || first == '[')
    {
        return None;
    }

    // Tab-separated input (e.g. `helm list -A`): columns are split by `\t`,
    // not space-padded. Detect tabs in the header and switch parser. The
    // space-aligned algorithm below would otherwise produce a single header
    // cell containing the whole first line.
    if lines[0].contains('\t') {
        // Headers are lowercased to match the case-insensitive select_columns
        // contract used by the rest of the pipeline.
        let headers: Vec<String> = lines[0]
            .split('\t')
            .map(|s| s.trim().to_lowercase())
            .collect();
        let n_cols = headers.len();
        let rows: Vec<Vec<String>> = lines[1..]
            .iter()
            .map(|line| {
                let mut cells: Vec<String> =
                    line.split('\t').map(|s| s.trim().to_string()).collect();
                cells.resize(n_cols, String::new());
                cells.truncate(n_cols);
                cells
            })
            .collect();
        return Some(ParsedTable { headers, rows });
    }

    let header_line = lines[0];
    let data_lines = &lines[1..];
    let max_len = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    if max_len == 0 {
        return None;
    }

    // Phase 1: Find positions where ALL data rows have a space (or are
    // shorter). We rely on data alignment, NOT header alignment, because
    // tools like `ss -tunap` emit single-space gaps in the header even though
    // the data is multi-space aligned. The "≥ 2 spaces" run-width filter
    // below keeps multi-word values like "Up 2 hours" intact (their internal
    // 1-space gaps don't qualify) and multi-word headers like "CONTAINER ID"
    // grouped (their data column has 1-space gap inside the value).
    let mut is_data_gap = vec![false; max_len];
    for (pos, gap) in is_data_gap.iter_mut().enumerate() {
        *gap = data_lines
            .iter()
            .all(|l| l.as_bytes().get(pos).is_none_or(|&b| b == b' '));
    }

    // Phase 2: Group consecutive data-gap positions into runs.
    // Only runs of width ≥ 2 are column boundaries.
    // Width ≥ 2 filters out 1-space gaps within multi-word values
    // ("2 hours ago", "Up 2 hours") while keeping real column gaps
    // (CLI tools always pad columns with ≥ 2 spaces).
    let mut col_starts: Vec<usize> = Vec::new();

    // Find start of first column (skip leading gaps)
    let mut i = 0;
    while i < max_len && is_data_gap[i] {
        i += 1;
    }
    if i < max_len {
        col_starts.push(i);
    }

    // Find transitions: content -> gap(width ≥ 2) -> content
    while i < max_len {
        // Skip non-gap positions (column content)
        while i < max_len && !is_data_gap[i] {
            i += 1;
        }
        // Measure gap width
        let gap_start = i;
        while i < max_len && is_data_gap[i] {
            i += 1;
        }
        // Only gaps of width ≥ 2 are real column boundaries
        if i - gap_start >= 2 && i < max_len {
            col_starts.push(i);
        }
    }

    if col_starts.is_empty() {
        return None;
    }

    let header_len = header_line.len();

    // Extract header names from the header line at column boundaries
    let headers: Vec<String> = col_starts
        .iter()
        .enumerate()
        .map(|(idx, &start)| {
            let end = col_starts
                .get(idx + 1)
                .copied()
                .unwrap_or(header_len)
                .min(header_len);
            header_line
                .get(start..end)
                .unwrap_or("")
                .trim()
                .to_lowercase()
        })
        .collect();

    // Extract data row values at column boundaries
    let rows: Vec<Vec<String>> = data_lines
        .iter()
        .map(|line| {
            let line_len = line.len();
            col_starts
                .iter()
                .enumerate()
                .map(|(idx, &start)| {
                    if start >= line_len {
                        return String::new();
                    }
                    let end = col_starts
                        .get(idx + 1)
                        .copied()
                        .unwrap_or(line_len)
                        .min(line_len);
                    line.get(start..end).unwrap_or("").trim().to_string()
                })
                .collect()
        })
        .collect();

    Some(ParsedTable { headers, rows })
}

/// Parse output with a KNOWN, fixed column schema by splitting on whitespace.
///
/// Robust alternative to [`parse_columnar_output`] for commands whose column
/// order is fixed and known ahead of time (`ps aux`, `systemctl list-units
/// --no-legend`). Unlike the space-gutter heuristic, this never merges columns
/// on tight 1-space spacing and never depends on recovering header *names* from
/// aligned text — the headers are supplied by the caller.
///
/// - `headers`: the synthesized column names (lowercased on the way out). The
///   LAST column is greedy: it absorbs the remainder of each line verbatim,
///   preserving internal spaces (a process `COMMAND`, a unit `DESCRIPTION`).
/// - `has_header_line`: discard the command's own header row (e.g. `ps aux`,
///   `ps -o ...`). Pass `false` for header-less output (`--no-legend`).
/// - `strip_glyph`: drop a leading single-character status glyph (`●`/`*`/`×`)
///   that `systemctl` prepends to non-running units. Unit names always contain
///   a `.`, so real first columns are never mistaken for a glyph.
///
/// Returns `None` when no data rows remain.
#[must_use]
pub fn parse_fixed_columns(
    output: &str,
    headers: &[&str],
    has_header_line: bool,
    strip_glyph: bool,
) -> Option<ParsedTable> {
    let n_scalar = headers.len().saturating_sub(1);
    let rows: Vec<Vec<String>> = output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .skip(usize::from(has_header_line))
        .map(|line| {
            let mut rest = line.trim_start();
            if strip_glyph
                && let Some(tok) = rest.split_whitespace().next()
                && tok.chars().count() == 1
                && tok.chars().all(|c| !c.is_alphanumeric())
            {
                rest = rest[tok.len()..].trim_start();
            }
            let mut cols: Vec<String> = Vec::with_capacity(headers.len());
            for _ in 0..n_scalar {
                if let Some((tok, tail)) = rest.split_once(char::is_whitespace) {
                    cols.push(tok.to_string());
                    rest = tail.trim_start();
                } else {
                    cols.push(rest.to_string());
                    rest = "";
                }
            }
            cols.push(rest.trim_end().to_string());
            cols.resize(headers.len(), String::new());
            cols
        })
        .collect();

    if rows.is_empty() {
        return None;
    }

    Some(ParsedTable {
        headers: headers.iter().map(|h| h.to_lowercase()).collect(),
        rows,
    })
}

/// Fixtures shared by the shell-guard tests of the handlers, the pipeline and
/// the resources.
#[cfg(test)]
pub(crate) mod guard_test_support {
    use crate::config::HostConfig;
    use crate::mcp::protocol::ToolContent;
    use crate::ports::{ToolContext, ToolHandler};

    /// A context whose only host, `target`, is built from its YAML-level
    /// fields: `extra` is spliced into the JSON object, e.g.
    /// `r#","shell":"powershell""#`. There is no executor behind it.
    pub(crate) fn context_with_target(os_type: &str, extra: &str) -> ToolContext {
        let json = format!(
            r#"{{"hostname":"10.0.0.1","user":"u","auth":{{"type":"agent"}},"os_type":"{os_type}"{extra}}}"#
        );
        let host: HostConfig = serde_json::from_str(&json).expect("a host config deserializes");
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("target".to_string(), host);
        crate::ports::mock::create_test_context_with_hosts(hosts)
    }

    /// The smallest value `schema` accepts: the first `enum` value, else by
    /// type 1, `"x"`, `false`, an array of one minimal item, or an object with
    /// its `required` properties, each minimal.
    pub(crate) fn minimal_value(schema: &serde_json::Value) -> serde_json::Value {
        if let Some(first) = schema["enum"].as_array().and_then(|e| e.first()) {
            return first.clone();
        }
        match schema["type"].as_str() {
            Some("integer" | "number") => serde_json::json!(1),
            Some("boolean") => serde_json::json!(false),
            Some("array") => serde_json::json!([minimal_value(&schema["items"])]),
            Some("object") => {
                let mut object = serde_json::Map::new();
                let required = schema["required"].as_array().cloned().unwrap_or_default();
                for key in required.iter().filter_map(serde_json::Value::as_str) {
                    object.insert(key.to_string(), minimal_value(&schema["properties"][key]));
                }
                serde_json::Value::Object(object)
            }
            _ => serde_json::json!("x"),
        }
    }

    /// The text of the refusal `handler` returned for `args` without dialing
    /// the host: the timeout turns a guard that let the call through into a
    /// failure instead of a hang on a connection to 10.0.0.1.
    pub(crate) async fn refusal(
        handler: &dyn ToolHandler,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> String {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handler.execute(Some(args), ctx),
        )
        .await
        .expect("the guard must refuse without dialing the host")
        .expect("a refusal is a tool result, not an Err");
        assert_eq!(result.is_error, Some(true));
        let ToolContent::Text { text } = &result.content[0] else {
            panic!("expected a text refusal");
        };
        // The refusal is a policy denial: one audit event, under the tool's
        // name, with no command (none was built) and the same reason.
        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1, "{events:?}");
        let event = &events[0];
        assert_eq!(event.event_type, "command_denied");
        assert_eq!(event.tool_name.as_deref(), Some(handler.name()));
        assert_eq!(event.command, "");
        match &event.result {
            crate::security::CommandResult::Denied { reason } => assert_eq!(reason, text),
            r => panic!("expected Denied, got {r:?}"),
        }
        text.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== app-table column selection ==============

    #[test]
    fn present_columns_drops_the_ones_with_no_source() {
        let live = present_columns(&[
            ("user", "User", Some(0)),
            ("pid", "PID", None),
            ("command", "Command", Some(2)),
        ]);
        assert_eq!(live, vec![("user", "User", 0), ("command", "Command", 2)]);
    }

    #[test]
    fn row_from_emits_only_the_surviving_keys() {
        let live = vec![("user", "User", 0), ("command", "Command", 2)];
        let row = vec![
            "root".to_string(),
            "1".to_string(),
            "/sbin/init".to_string(),
        ];
        let obj = row_from(&live, &row);
        assert_eq!(obj.len(), 2, "{obj:?}");
        assert_eq!(obj["user"], "root");
        assert_eq!(obj["command"], "/sbin/init");
        assert!(!obj.contains_key("pid"), "a dropped column must be ABSENT");
    }

    /// A short row does not panic; the missing cell reads empty.
    #[test]
    fn row_from_tolerates_a_row_shorter_than_the_header() {
        let live = vec![("a", "A", 0), ("b", "B", 5)];
        let obj = row_from(&live, &["x".to_string()]);
        assert_eq!(obj["a"], "x");
        assert_eq!(obj["b"], "");
    }

    /// THE GUARD for the positional fallbacks. `docker ps` recovers NAMES from
    /// the last cell when the parser merges columns — correct for a parse miss,
    /// and wrong after a reduction, where the last cell is a different column.
    #[test]
    fn filtered_out_is_true_only_when_the_caller_asked_for_a_subset() {
        let none = crate::domain::data_reduction::DataReductionArgs::default();
        assert!(
            !filtered_out_by_caller("names", &none),
            "no reduction requested: absence is a parser miss, recovery is allowed"
        );

        let subset = crate::domain::data_reduction::DataReductionArgs {
            columns: Some(vec!["STATUS".to_string()]),
            ..Default::default()
        };
        assert!(
            filtered_out_by_caller("names", &subset),
            "the caller excluded it: recovery must not fire"
        );
        assert!(
            !filtered_out_by_caller("status", &subset),
            "the caller kept it"
        );
        // Header matching is case-insensitive on both sides.
        assert!(!filtered_out_by_caller("STATUS", &subset));
    }

    #[test]
    fn test_parse_transfer_mode_rejects_verify_checksum_with_resume() {
        let err = parse_transfer_mode_checked("resume", true, "sent").unwrap_err();
        match err {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("verify_checksum"));
                assert!(reason.contains("resume"));
                assert!(reason.contains("sent"));
            }
            e => panic!("expected FileTransfer, got: {e:?}"),
        }
    }

    #[test]
    fn test_parse_transfer_mode_rejects_append_with_direction_word() {
        let err = parse_transfer_mode_checked("append", true, "received").unwrap_err();
        match err {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("append"));
                assert!(reason.contains("received"));
            }
            e => panic!("expected FileTransfer, got: {e:?}"),
        }
    }

    #[test]
    fn test_parse_transfer_mode_allows_verify_checksum_with_overwrite() {
        assert_eq!(
            parse_transfer_mode_checked("overwrite", true, "sent").unwrap(),
            TransferMode::Overwrite
        );
    }

    #[test]
    fn test_parse_transfer_mode_allows_resume_when_checksum_disabled() {
        assert_eq!(
            parse_transfer_mode_checked("resume", false, "sent").unwrap(),
            TransferMode::Resume
        );
    }

    #[test]
    fn test_parse_transfer_mode_allows_append_when_checksum_disabled() {
        assert_eq!(
            parse_transfer_mode_checked("append", false, "received").unwrap(),
            TransferMode::Append
        );
    }

    /// The CLI spells this mode with dashes and the MCP schema with
    /// underscores; both reach the same helper, so both must parse.
    #[test]
    fn test_parse_transfer_mode_accepts_both_fail_if_exists_spellings() {
        assert_eq!(
            parse_transfer_mode_checked("fail_if_exists", false, "sent").unwrap(),
            TransferMode::FailIfExists
        );
        assert_eq!(
            parse_transfer_mode_checked("fail-if-exists", false, "sent").unwrap(),
            TransferMode::FailIfExists
        );
    }

    #[test]
    fn test_parse_transfer_mode_rejects_unknown_mode() {
        let err = parse_transfer_mode_checked("teleport", false, "sent").unwrap_err();
        match err {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("Invalid transfer mode"));
                assert!(reason.contains("teleport"));
            }
            e => panic!("expected FileTransfer, got: {e:?}"),
        }
    }

    #[test]
    fn test_shell_escape_simple() {
        assert_eq!(shell_escape("simple"), "'simple'");
    }

    #[test]
    fn test_shell_escape_with_spaces() {
        assert_eq!(shell_escape("with spaces"), "'with spaces'");
    }

    #[test]
    fn test_shell_escape_with_quotes() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_escape_empty() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn test_shell_escape_special_chars() {
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
        assert_eq!(shell_escape("foo;bar"), "'foo;bar'");
        assert_eq!(shell_escape("a`cmd`b"), "'a`cmd`b'");
    }

    // ============== Additional shell_escape Tests ==============

    #[test]
    fn test_shell_escape_multiple_quotes() {
        assert_eq!(shell_escape("a'b'c'd"), "'a'\\''b'\\''c'\\''d'");
    }

    #[test]
    fn test_shell_escape_consecutive_quotes() {
        // '' becomes: open quote, escape first ', escape second ', close quote
        // '' -> ' + '\'' + '\'' + ' = ''\\'''\\'''
        assert_eq!(shell_escape("''"), "''\\'''\\'''");
    }

    #[test]
    fn test_shell_escape_quote_at_start() {
        // 'hello -> ' + '\'' + hello + '
        assert_eq!(shell_escape("'hello"), "''\\''hello'");
    }

    #[test]
    fn test_shell_escape_quote_at_end() {
        assert_eq!(shell_escape("hello'"), "'hello'\\'''");
    }

    #[test]
    fn test_shell_escape_newline() {
        assert_eq!(shell_escape("line1\nline2"), "'line1\nline2'");
    }

    #[test]
    fn test_shell_escape_tab() {
        assert_eq!(shell_escape("col1\tcol2"), "'col1\tcol2'");
    }

    #[test]
    fn test_shell_escape_carriage_return() {
        assert_eq!(shell_escape("a\rb"), "'a\rb'");
    }

    #[test]
    fn test_shell_escape_double_quotes() {
        assert_eq!(shell_escape("\"quoted\""), "'\"quoted\"'");
    }

    #[test]
    fn test_shell_escape_mixed_quotes() {
        assert_eq!(shell_escape("\"it's\""), "'\"it'\\''s\"'");
    }

    #[test]
    fn test_shell_escape_backslash() {
        assert_eq!(shell_escape("a\\b"), "'a\\b'");
    }

    #[test]
    fn test_shell_escape_pipe() {
        assert_eq!(shell_escape("a|b"), "'a|b'");
    }

    #[test]
    fn test_shell_escape_ampersand() {
        assert_eq!(shell_escape("a&b"), "'a&b'");
    }

    #[test]
    fn test_shell_escape_redirect() {
        assert_eq!(shell_escape("a>b"), "'a>b'");
        assert_eq!(shell_escape("a<b"), "'a<b'");
    }

    #[test]
    fn test_shell_escape_wildcard() {
        assert_eq!(shell_escape("*.txt"), "'*.txt'");
        assert_eq!(shell_escape("?file"), "'?file'");
    }

    #[test]
    fn test_shell_escape_bracket() {
        assert_eq!(shell_escape("[abc]"), "'[abc]'");
    }

    #[test]
    fn test_shell_escape_unicode() {
        assert_eq!(shell_escape("日本語"), "'日本語'");
        assert_eq!(shell_escape("emoji🎉"), "'emoji🎉'");
    }

    #[test]
    fn test_shell_escape_path() {
        assert_eq!(shell_escape("/path/to/file"), "'/path/to/file'");
    }

    #[test]
    fn test_shell_escape_path_with_spaces() {
        assert_eq!(
            shell_escape("/path/to/my file.txt"),
            "'/path/to/my file.txt'"
        );
    }

    #[test]
    fn test_shell_escape_very_long_string() {
        let long_str = "a".repeat(10000);
        let escaped = shell_escape(&long_str);
        assert_eq!(escaped.len(), 10002); // 10000 + 2 quotes
    }

    #[test]
    fn test_shell_escape_null_byte() {
        // Null bytes shouldn't happen but test handling
        assert_eq!(shell_escape("a\0b"), "'a\0b'");
    }

    #[test]
    fn test_shell_escape_environment_var() {
        assert_eq!(shell_escape("$HOME/dir"), "'$HOME/dir'");
        assert_eq!(shell_escape("${VAR}"), "'${VAR}'");
    }

    #[test]
    fn test_shell_escape_command_substitution() {
        assert_eq!(shell_escape("$(whoami)"), "'$(whoami)'");
    }

    // ============== validate_path Tests ==============

    #[test]
    fn test_validate_path_normal() {
        assert!(validate_path("/home/user/file.txt").is_ok());
        assert!(validate_path("relative/path/file.txt").is_ok());
        assert!(validate_path("file.txt").is_ok());
    }

    #[test]
    fn test_validate_path_traversal_rejected() {
        assert!(validate_path("../secret").is_err());
        assert!(validate_path("/home/../etc/passwd").is_err());
        assert!(validate_path("foo/../../bar").is_err());
        assert!(validate_path("..").is_err());
    }

    #[test]
    fn test_validate_path_dots_allowed() {
        // Single dots and dots in filenames are fine
        assert!(validate_path("/home/user/.bashrc").is_ok());
        assert!(validate_path("./file.txt").is_ok());
        assert!(validate_path(".hidden").is_ok());
        assert!(validate_path("file.name.txt").is_ok());
    }

    // ============== save_output_to_file Tests ==============

    #[tokio::test]
    async fn test_save_output_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.txt");

        let result = save_output_to_file(path.to_str().unwrap(), "hello world").await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("11 bytes"));

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "hello world");
    }

    #[tokio::test]
    async fn test_save_output_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deep").join("nested").join("output.txt");

        let result = save_output_to_file(path.to_str().unwrap(), "data").await;
        assert!(result.is_ok());
        assert!(path.exists());
    }

    #[tokio::test]
    async fn test_save_output_invalid_path() {
        let result = save_output_to_file("/proc/0/nonexistent/file", "data").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed"));
    }

    // ============== parse_columnar_output Tests ==============

    #[test]
    fn test_parse_columnar_docker_ps() {
        let output = "\
CONTAINER ID   IMAGE          COMMAND        CREATED        STATUS        PORTS                  NAMES
a1b2c3d4e5f6   nginx:latest   \"nginx -g..\"   2 hours ago    Up 2 hours    0.0.0.0:80->80/tcp     web
f6e5d4c3b2a1   redis:7        \"redis-se..\"   3 hours ago    Up 3 hours    6379/tcp               cache";

        let parsed = parse_columnar_output(output).unwrap();
        assert_eq!(parsed.headers.len(), 7);
        assert_eq!(parsed.headers[0], "container id");
        assert_eq!(parsed.headers[1], "image");
        assert_eq!(parsed.headers[6], "names");
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0][1], "nginx:latest");
        assert_eq!(parsed.rows[0][6], "web");
        assert_eq!(parsed.rows[1][1], "redis:7");
        assert_eq!(parsed.rows[1][6], "cache");
    }

    #[test]
    fn test_parse_columnar_docker_stats() {
        let output = "\
CONTAINER ID   NAME   CPU %   MEM USAGE / LIMIT     MEM %   NET I/O         BLOCK I/O       PIDS
a1b2c3d4e5f6   web    0.50%   24.5MiB / 7.77GiB     0.31%   1.2kB / 648B    8.19kB / 0B     2
f6e5d4c3b2a1   db     1.20%   128MiB / 7.77GiB      1.61%   5.4kB / 3.2kB   12.5kB / 4kB    8";

        let parsed = parse_columnar_output(output).unwrap();
        assert_eq!(parsed.headers[1], "name");
        assert_eq!(parsed.headers[2], "cpu %");
        assert_eq!(parsed.headers[3], "mem usage / limit");
        assert_eq!(parsed.headers[4], "mem %");
        assert_eq!(parsed.headers[5], "net i/o");
        assert_eq!(parsed.headers[6], "block i/o");
        assert_eq!(parsed.headers[7], "pids");
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0][1], "web");
        assert_eq!(parsed.rows[0][2], "0.50%");
        assert_eq!(parsed.rows[1][1], "db");
    }

    #[test]
    fn test_parse_columnar_kubectl_top_pods() {
        let output = "\
NAME                           CPU(cores)   MEMORY(bytes)
nginx-deploy-6799fc88d8-abc    3m           52Mi
redis-master-0                 15m          128Mi";

        let parsed = parse_columnar_output(output).unwrap();
        assert_eq!(parsed.headers, vec!["name", "cpu(cores)", "memory(bytes)"]);
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0][0], "nginx-deploy-6799fc88d8-abc");
        assert_eq!(parsed.rows[0][1], "3m");
        assert_eq!(parsed.rows[0][2], "52Mi");
    }

    #[test]
    fn test_parse_columnar_kubectl_top_nodes() {
        let output = "\
NAME     CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%
node-1   250m         12%    1024Mi          25%
node-2   500m         25%    2048Mi          50%";

        let parsed = parse_columnar_output(output).unwrap();
        assert_eq!(parsed.headers.len(), 5);
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0][0], "node-1");
        assert_eq!(parsed.rows[0][2], "12%");
        assert_eq!(parsed.rows[1][4], "50%");
    }

    #[test]
    fn test_parse_columnar_empty() {
        assert!(parse_columnar_output("").is_none());
        assert!(parse_columnar_output("   \n  \n  ").is_none());
    }

    #[test]
    fn test_parse_columnar_header_only() {
        assert!(parse_columnar_output("NAME   IMAGE   STATUS").is_none());
    }

    #[test]
    fn test_parse_columnar_handles_ss_tunap_output() {
        // Regression: `ss -tunap` post_process produced an empty `columns: []`
        // app payload because long process tokens like
        // `users:(("Plex Media Serv",pid=1167191,fd=70))` contain spaces
        // (around the comma-quote sequence on some locales) that broke the
        // gap-detection assumption.
        let ss_output = "Netid State      Recv-Q Send-Q                           Local Address:Port                 Peer Address:Port Process
udp   UNCONN     0      0                                 192.168.1.51:42661                     0.0.0.0:*     users:((\"PlexMediaServer\",pid=1167191,fd=70))
tcp   LISTEN     0      128                                     0.0.0.0:22                       0.0.0.0:*     users:((\"sshd\",pid=1234,fd=3))";
        let parsed = parse_columnar_output(ss_output).expect("expected parse");
        // We expect at least 7 columns (Netid State Recv-Q Send-Q Local Peer Process).
        assert!(
            parsed.headers.len() >= 6,
            "expected ≥ 6 columns, got {:?}",
            parsed.headers
        );
        assert_eq!(parsed.headers[0], "netid");
        assert_eq!(parsed.rows[0][0], "udp");
        assert_eq!(parsed.rows[1][0], "tcp");
    }

    #[test]
    fn test_parse_columnar_handles_tab_separated_helm_output() {
        // Regression: `helm list -A` emits tab-separated columns, not the
        // space-padded format `parse_columnar_output` originally targeted.
        // The result was a one-cell-wide table where the header was the whole
        // first line concatenated.
        let helm_list = "NAME   \tNAMESPACE  \tREVISION\tUPDATED            \tSTATUS  \tCHART          \tAPP VERSION
traefik\tkube-system\t3       \t2026-02-14 20:01:24\tdeployed\ttraefik-39.0.1\tv3.6.8";
        let parsed = parse_columnar_output(helm_list).expect("expected tab-separated parse");
        // Headers are lowercased (case-insensitive select_columns contract).
        assert_eq!(
            parsed.headers,
            vec![
                "name",
                "namespace",
                "revision",
                "updated",
                "status",
                "chart",
                "app version"
            ]
        );
        assert_eq!(parsed.rows.len(), 1);
        assert_eq!(parsed.rows[0][0], "traefik");
        assert_eq!(parsed.rows[0][1], "kube-system");
        assert_eq!(parsed.rows[0][3], "2026-02-14 20:01:24");
        assert_eq!(parsed.rows[0][6], "v3.6.8");
    }

    #[test]
    fn test_parse_columnar_rejects_json_object() {
        // Raw kubectl JSON must not be parsed as a columnar table — when the
        // jq feature is disabled, falling through to columnar parsing on a
        // JSON payload mangles it into garbage TSV (#2B).
        let kubectl_pods = r#"{
    "apiVersion": "v1",
    "items": [
        {
            "metadata": {
                "name": "argocd-server-7d4d46b98-tbq4h",
                "namespace": "argocd"
            }
        }
    ]
}"#;
        assert!(parse_columnar_output(kubectl_pods).is_none());
    }

    #[test]
    fn test_parse_columnar_rejects_json_array() {
        let docker_inspect = r#"[
    {"Id": "abc", "Name": "/web1"},
    {"Id": "def", "Name": "/web2"}
]"#;
        assert!(parse_columnar_output(docker_inspect).is_none());
    }

    #[test]
    fn test_parse_columnar_short_lines() {
        // With data-driven detection, columns with no data in ANY row
        // cannot be detected (STATUS has no values). This is expected:
        // real CLI output always has data in every column.
        let output = "\
NAME           IMAGE          STATUS
container1     nginx:latest
short";

        let parsed = parse_columnar_output(output).unwrap();
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0][0], "container1");
        assert_eq!(parsed.rows[0][1], "nginx:latest");
        assert_eq!(parsed.rows[1][0], "short");
        assert_eq!(parsed.rows[1][1], ""); // even shorter
    }

    // ============== to_tsv Tests ==============

    #[test]
    fn test_to_tsv_basic() {
        let output = "\
NAME           IMAGE          STATUS
container1     nginx:latest   Up 2 hours
container2     redis:7        Up 3 hours";

        let parsed = parse_columnar_output(output).unwrap();
        let tsv = parsed.to_tsv();
        let lines: Vec<&str> = tsv.lines().collect();
        assert_eq!(lines[0], "NAME\tIMAGE\tSTATUS");
        assert_eq!(lines[1], "container1\tnginx:latest\tUp 2 hours");
        assert_eq!(lines[2], "container2\tredis:7\tUp 3 hours");
    }

    #[test]
    fn test_to_tsv_single_row() {
        let output = "\
NAME     CPU
node-1   250m";

        let parsed = parse_columnar_output(output).unwrap();
        let tsv = parsed.to_tsv();
        assert_eq!(tsv, "NAME\tCPU\nnode-1\t250m");
    }

    #[test]
    fn test_shell_escape_for_posix() {
        let escaped = shell_escape_for("hello world", ShellType::Posix);
        assert!(escaped.contains("hello world"));
    }

    #[test]
    fn test_shell_escape_for_cmd() {
        let escaped = shell_escape_for("hello world", ShellType::Cmd);
        assert_ne!(escaped, "");
    }

    #[test]
    fn test_shell_escape_for_powershell() {
        let escaped = shell_escape_for("it's a test", ShellType::PowerShell);
        assert_ne!(escaped, "");
    }

    #[test]
    fn test_to_tsv_empty_rows() {
        let table = ParsedTable {
            headers: vec!["NAME".to_string(), "VALUE".to_string()],
            rows: vec![],
        };
        let tsv = table.to_tsv();
        assert_eq!(tsv, "NAME\tVALUE");
    }

    // ============== select_columns Tests ==============

    #[test]
    fn test_select_columns_basic() {
        let table = ParsedTable {
            headers: vec!["name".into(), "cpu".into(), "mem".into(), "status".into()],
            rows: vec![
                vec!["web".into(), "45%".into(), "128M".into(), "running".into()],
                vec!["db".into(), "12%".into(), "256M".into(), "running".into()],
            ],
        };
        let filtered = table.select_columns(&["NAME".into(), "STATUS".into()]);
        assert_eq!(filtered.headers, vec!["name", "status"]);
        assert_eq!(filtered.rows[0], vec!["web", "running"]);
        assert_eq!(filtered.rows[1], vec!["db", "running"]);
    }

    #[test]
    fn test_select_columns_case_insensitive() {
        let table = ParsedTable {
            headers: vec!["container id".into(), "image".into()],
            rows: vec![vec!["abc123".into(), "nginx".into()]],
        };
        let filtered = table.select_columns(&["Container ID".into(), "IMAGE".into()]);
        assert_eq!(filtered.headers, vec!["container id", "image"]);
        assert_eq!(filtered.rows[0], vec!["abc123", "nginx"]);
    }

    #[test]
    fn test_select_columns_unknown_ignored() {
        let table = ParsedTable {
            headers: vec!["name".into(), "cpu".into()],
            rows: vec![vec!["web".into(), "45%".into()]],
        };
        let filtered = table.select_columns(&["NAME".into(), "NONEXISTENT".into()]);
        assert_eq!(filtered.headers, vec!["name"]);
        assert_eq!(filtered.rows[0], vec!["web"]);
    }

    #[test]
    fn select_columns_all_unknown_is_a_no_op() {
        let table = ParsedTable {
            headers: vec!["name".into(), "cpu".into()],
            rows: vec![vec!["web".into(), "45%".into()]],
        };
        let filtered = table.select_columns(&["NOPE".into(), "ALSO_NOPE".into()]);

        // Both documented contracts point the same way: unknown columns are
        // silently ignored, and the header is always preserved. If EVERY
        // requested column is unknown, every one is ignored — so nothing is
        // filtered. Returning an empty table instead told the caller "there
        // is no data here", which is a different and false claim.
        assert_eq!(filtered.headers, vec!["name", "cpu"]);
        assert_eq!(filtered.rows, vec![vec!["web", "45%"]]);
    }

    #[test]
    fn select_columns_partial_match_still_filters() {
        let table = ParsedTable {
            headers: vec!["name".into(), "cpu".into()],
            rows: vec![vec!["web".into(), "45%".into()]],
        };
        let filtered = table.select_columns(&["NAME".into(), "NOPE".into()]);

        // A partial match is unchanged: the known column is kept, the unknown
        // one ignored. Without this the no-op above would also pass if the
        // filter stopped working entirely.
        assert_eq!(filtered.headers, vec!["name"]);
        assert_eq!(filtered.rows, vec![vec!["web"]]);
    }

    #[test]
    fn test_select_columns_preserves_table_order() {
        let table = ParsedTable {
            headers: vec!["a".into(), "b".into(), "c".into(), "d".into()],
            rows: vec![vec!["1".into(), "2".into(), "3".into(), "4".into()]],
        };
        // Request in reverse order — output follows table column order, not request order
        let filtered = table.select_columns(&["D".into(), "B".into()]);
        assert_eq!(filtered.headers, vec!["b", "d"]);
        assert_eq!(filtered.rows[0], vec!["2", "4"]);
    }

    // ============== limit_rows Tests ==============

    #[test]
    fn test_limit_rows() {
        let mut table = ParsedTable {
            headers: vec!["name".into(), "value".into()],
            rows: vec![
                vec!["a".into(), "1".into()],
                vec!["b".into(), "2".into()],
                vec!["c".into(), "3".into()],
                vec!["d".into(), "4".into()],
                vec!["e".into(), "5".into()],
            ],
        };
        table.limit_rows(2);
        assert_eq!(table.rows.len(), 2);
        assert_eq!(table.rows[0][0], "a");
        assert_eq!(table.rows[1][0], "b");
    }

    #[test]
    fn test_limit_rows_larger_than_table() {
        let mut table = ParsedTable {
            headers: vec!["name".into()],
            rows: vec![vec!["a".into()], vec!["b".into()]],
        };
        table.limit_rows(100);
        assert_eq!(table.rows.len(), 2);
    }

    // ============== Locale-aware parsing Tests ==============

    /// Verify that English `df -hT` output (produced by `LC_ALL=C`) is parseable.
    #[test]
    fn test_parse_english_df_output() {
        // Realistic df -hT output with proper column alignment
        let output = "\
Filesystem      Type   Size  Used Avail Use% Mounted on\n\
/dev/nvme0n1p2  ext4   917G  592G  279G  69% /\n\
tmpfs           tmpfs  4.0G   32K  4.0G   1% /dev/shm\n\
/dev/nvme0n1p1  vfat   510M   90M  421M  18% /boot/firmware";
        let parsed = parse_columnar_output(output).unwrap();
        let hdrs = &parsed.headers;
        // Debug: print actual headers if assertion fails
        assert!(
            hdrs.iter()
                .any(|h| h.contains("filesystem") || h.contains("type")),
            "Expected filesystem-like header, got: {hdrs:?}"
        );
        assert!(
            parsed.rows.len() >= 2,
            "Expected ≥2 rows, got: {}",
            parsed.rows.len()
        );
    }

    /// Verify that English `systemctl list-units` output is parseable.
    #[test]
    fn test_parse_english_systemctl_output() {
        // Realistic systemctl output with proper spacing
        let output = "\
UNIT                          LOAD   ACTIVE SUB     DESCRIPTION\n\
cron.service                  loaded active running Regular background program processing daemon\n\
ssh.service                   loaded active running OpenBSD Secure Shell server";
        let parsed = parse_columnar_output(output).unwrap();
        let hdrs = &parsed.headers;
        assert!(
            hdrs.iter()
                .any(|h| h.contains("unit") || h.contains("load")),
            "Expected unit-like header, got: {hdrs:?}"
        );
        assert_eq!(parsed.rows.len(), 2, "Expected 2 rows");
    }

    #[tokio::test]
    async fn test_save_output_path_traversal_rejected() {
        let result = save_output_to_file("../../../etc/passwd", "evil").await;
        assert!(result.is_err());
    }

    // ============== parse_fixed_columns Tests ==============

    const PS_COLS: &[&str] = &[
        "user", "pid", "%cpu", "%mem", "vsz", "rss", "tty", "stat", "start", "time", "command",
    ];

    #[test]
    fn test_fixed_ps_aux_real() {
        // Real `ps aux`: 8-char user (`message+`) AND 7-digit PID (`2411977`) —
        // the exact pair that collapsed parse_columnar_output to 3 merged cols.
        let out = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n\
root           1  0.0  0.1  26336 16336 ?        Ss   May25  15:49 /usr/lib/systemd/systemd --system --deserialize=46\n\
message+     564  0.0  0.0   9232  6016 ?        Ss   May25   6:50 /usr/bin/dbus-daemon --system --address=systemd:\n\
muchini  2411977  0.0  0.0   2772  1664 ?        S    22:06   0:00 [kworker]\n";
        let p = parse_fixed_columns(out, PS_COLS, true, false).expect("parse");
        assert_eq!(p.headers.len(), 11);
        assert_eq!(p.headers[0], "user");
        assert_eq!(p.headers[10], "command");
        assert_eq!(p.rows.len(), 3);
        // Row 0: user/pid extracted, command keeps its internal spaces verbatim.
        assert_eq!(p.rows[0][0], "root");
        assert_eq!(p.rows[0][1], "1");
        assert_eq!(p.rows[0][2], "0.0");
        assert_eq!(
            p.rows[0][10],
            "/usr/lib/systemd/systemd --system --deserialize=46"
        );
        // Row 1: 8-char username stays whole, not merged with PID.
        assert_eq!(p.rows[1][0], "message+");
        assert_eq!(p.rows[1][1], "564");
        // Row 2: 7-digit PID with shorter username — still cleanly split.
        assert_eq!(p.rows[2][0], "muchini");
        assert_eq!(p.rows[2][1], "2411977");
    }

    #[test]
    fn test_fixed_ps_user_filtered_schema() {
        // `ps -u U -o pid,ppid,...` — no USER column, leads with pid/ppid.
        let cols = &["pid", "ppid", "%cpu", "%mem", "command"];
        let out = "    PID    PPID %CPU %MEM COMMAND\n\
    774       1  0.0  0.1 /usr/lib/systemd/systemd --user\n";
        let p = parse_fixed_columns(out, cols, true, false).expect("parse");
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0][0], "774");
        assert_eq!(p.rows[0][1], "1");
        assert_eq!(p.rows[0][4], "/usr/lib/systemd/systemd --user");
    }

    const SVC_COLS: &[&str] = &["unit", "load", "active", "sub", "description"];

    #[test]
    fn test_fixed_systemctl_no_legend_real() {
        // Real `systemctl list-units --type=service --no-pager --no-legend`:
        // NO header line, a leading glyph on non-running units, multi-word desc.
        let out = "  alsa-restore.service                loaded active     exited       Save/Restore Sound Card State\n\
* cloudflared.service                 loaded activating auto-restart cloudflared DNS over HTTPS proxy\n\
  ssh.service                         loaded active     running      OpenBSD Secure Shell server\n";
        let p = parse_fixed_columns(out, SVC_COLS, false, true).expect("parse");
        assert_eq!(p.rows.len(), 3);
        // No header eaten — first service is a real data row.
        assert_eq!(p.rows[0][0], "alsa-restore.service");
        assert_eq!(p.rows[0][1], "loaded");
        assert_eq!(p.rows[0][2], "active");
        assert_eq!(p.rows[0][3], "exited");
        assert_eq!(p.rows[0][4], "Save/Restore Sound Card State");
        // Glyph `*` stripped; unit name intact.
        assert_eq!(p.rows[1][0], "cloudflared.service");
        assert_eq!(p.rows[1][2], "activating");
        assert_eq!(p.rows[1][3], "auto-restart");
        assert_eq!(p.rows[1][4], "cloudflared DNS over HTTPS proxy");
        assert_eq!(p.rows[2][0], "ssh.service");
    }

    #[test]
    fn test_fixed_columns_empty_and_header_only() {
        assert!(parse_fixed_columns("", SVC_COLS, false, true).is_none());
        // header line present but no data rows
        assert!(parse_fixed_columns("USER PID COMMAND\n", PS_COLS, true, false).is_none());
    }

    #[test]
    fn test_fixed_columns_pads_short_rows() {
        // A row with fewer tokens than the schema pads the tail with empties.
        let cols = &["a", "b", "c", "d"];
        let p = parse_fixed_columns("x y\n", cols, false, false).expect("parse");
        assert_eq!(p.rows[0], vec!["x", "y", "", ""]);
    }

    // ============== reject_posix_only_on_windows ==============

    fn host_with_os(os_type: &str) -> HostConfig {
        let json = format!(
            r#"{{"hostname":"h","user":"u","auth":{{"type":"agent"}},"os_type":"{os_type}"}}"#
        );
        serde_json::from_str(&json).expect("a minimal host config deserializes")
    }

    /// The builders behind `ssh_find`, `ssh_file_write` and `ssh_file_stat`
    /// emit `find`, `printf` and `stat`; a Windows host must be refused before
    /// any of that is sent, and the refusal must name the tool.
    #[test]
    fn reject_posix_only_on_windows_refuses_a_windows_host() {
        let refusal = reject_posix_only_on_windows(&host_with_os("windows"), "ssh_find")
            .expect("a Windows host must be refused");
        assert_eq!(refusal.is_error, Some(true));
        let crate::mcp::protocol::ToolContent::Text { text } = &refusal.content[0] else {
            panic!("expected a text refusal");
        };
        assert!(
            text.contains("ssh_find"),
            "refusal must name the tool: {text}"
        );
        assert!(
            text.contains("Windows"),
            "refusal must name the platform: {text}"
        );
    }

    #[test]
    fn reject_posix_only_on_windows_lets_a_linux_host_through() {
        assert!(reject_posix_only_on_windows(&host_with_os("linux"), "ssh_find").is_none());
    }

    /// A host from its YAML-level fields: `extra` is spliced into the JSON
    /// object, e.g. `r#","shell":"powershell""#`.
    fn host_from(os_type: &str, extra: &str) -> HostConfig {
        let json = format!(
            r#"{{"hostname":"h","user":"u","auth":{{"type":"agent"}},"os_type":"{os_type}"{extra}}}"#
        );
        serde_json::from_str(&json).expect("a host config deserializes")
    }

    /// The case that was exploited: a `WinRM` host left at the default
    /// `os_type: linux` passed every OS check while `PowerShell` read the
    /// POSIX-quoted arguments.
    #[cfg(feature = "winrm")]
    #[test]
    fn posix_only_refusal_refuses_a_winrm_host_left_at_os_type_linux() {
        let host = host_from("linux", r#","protocol":"winrm""#);
        let refusal = posix_only_refusal(&host, "ssh_find").expect("WinRM runs PowerShell");
        assert!(refusal.contains("ssh_find"), "{refusal}");
        assert!(refusal.contains("PowerShell"), "{refusal}");
    }

    #[test]
    fn posix_only_refusal_refuses_a_linux_host_whose_shell_is_powershell() {
        let host = host_from("linux", r#","shell":"powershell""#);
        let refusal = posix_only_refusal(&host, "ssh_tail").expect("PowerShell is not POSIX");
        assert!(refusal.contains("a POSIX shell"), "{refusal}");
        assert!(refusal.contains("PowerShell"), "{refusal}");
    }

    #[test]
    fn awx_host_refusal_lets_a_posix_linux_host_through() {
        assert!(awx_host_refusal("awx", &host_from("linux", "")).is_none());
    }

    #[test]
    fn awx_host_refusal_refuses_windows_and_non_posix_hosts() {
        let windows = awx_host_refusal("dc", &host_from("windows", r#","shell":"posix""#))
            .expect("a Windows host is refused");
        assert!(
            windows.contains("'dc'") && windows.contains("Windows"),
            "{windows}"
        );
        let pwsh = awx_host_refusal("box", &host_from("linux", r#","shell":"powershell""#))
            .expect("a PowerShell host is refused");
        assert!(
            pwsh.contains("PowerShell") && pwsh.contains("awx.ssh_host"),
            "{pwsh}"
        );
    }

    /// The AWX guard follows the shell the protocol imposes, not `os_type` or
    /// an explicit `shell`: a `WinRM` host left at `os_type: linux` runs
    /// `PowerShell`, and so does a PSRP host that says `shell: posix`.
    #[cfg(feature = "winrm")]
    #[test]
    fn awx_host_refusal_refuses_a_winrm_host_left_at_os_type_linux() {
        let refusal = awx_host_refusal("w", &host_from("linux", r#","protocol":"winrm""#))
            .expect("WinRM runs PowerShell");
        assert!(
            refusal.contains("PowerShell") && refusal.contains("awx.ssh_host"),
            "{refusal}"
        );
    }

    #[cfg(feature = "psrp")]
    #[test]
    fn awx_host_refusal_ignores_shell_posix_on_a_psrp_host() {
        let host = host_from("linux", r#","protocol":"psrp","shell":"posix""#);
        let refusal = awx_host_refusal("p", &host).expect("PSRP runs PowerShell");
        assert!(refusal.contains("PowerShell"), "{refusal}");
    }

    #[cfg(feature = "ssm")]
    #[test]
    fn awx_host_refusal_follows_the_ssm_document() {
        let pwsh = host_from(
            "linux",
            &format!(
                r#","protocol":"ssm","description":"{}""#,
                crate::config::SSM_POWERSHELL_DOCUMENT
            ),
        );
        let refusal =
            awx_host_refusal("s", &pwsh).expect("the PowerShell document runs PowerShell");
        assert!(refusal.contains("PowerShell"), "{refusal}");
        let posix = host_from(
            "linux",
            &format!(
                r#","protocol":"ssm","description":"{}""#,
                crate::config::SSM_SHELL_DOCUMENT
            ),
        );
        assert!(awx_host_refusal("s", &posix).is_none());
    }

    /// Every `ssh_awx_*` tool refuses a Windows `awx.ssh_host` before sending
    /// anything. The mock executor answers every command, so a tool that lost
    /// its guard returns its usual output instead of the refusal and fails
    /// here; the count fails if a new AWX tool is not covered.
    #[tokio::test]
    async fn every_awx_tool_refuses_a_windows_awx_host() {
        let base = guard_test_support::context_with_target("windows", r#","shell":"powershell""#);
        let mut config = (*base.config).clone();
        config.awx = Some(crate::config::AwxConfig {
            ssh_host: "target".to_string(),
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
        let registry = crate::mcp::registry::create_all_enabled_registry();
        let mut checked = 0;
        for tool in registry.list_tools() {
            if !tool.name.starts_with("ssh_awx_") {
                continue;
            }
            let mut args = guard_test_support::minimal_value(&tool.input_schema);
            // Tools that check their arguments further before the host lookup.
            if tool.name == "ssh_awx_host_update" {
                args["description"] = serde_json::json!("x");
            }
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                registry.execute(&tool.name, Some(args.clone()), &ctx),
            )
            .await
            .unwrap_or_else(|_| panic!("{}: timed out", tool.name))
            .unwrap_or_else(|e| panic!("{} {args}: {e}", tool.name));
            assert_eq!(result.is_error, Some(true), "{}", tool.name);
            let crate::mcp::protocol::ToolContent::Text { text } = &result.content[0] else {
                panic!("{}: expected a text refusal", tool.name);
            };
            assert!(
                text.contains("`awx.ssh_host` is 'target'"),
                "{}: {text}",
                tool.name
            );
            // The refusal is audited under the registered name, for the AWX host.
            let events = ctx.audit_logger.drain_for_test();
            assert_eq!(events.len(), 1, "{}: {events:?}", tool.name);
            assert_eq!(events[0].event_type, "command_denied", "{}", tool.name);
            assert_eq!(
                events[0].tool_name.as_deref(),
                Some(tool.name.as_str()),
                "{}",
                tool.name
            );
            assert_eq!(events[0].host, "target", "{}", tool.name);
            checked += 1;
        }
        assert_eq!(checked, 43, "AWX tools checked");
    }

    #[test]
    fn shell_mismatch_is_none_when_the_shells_agree() {
        assert!(shell_mismatch("t", ShellType::Posix, &host_from("linux", "")).is_none());
        assert!(shell_mismatch("t", ShellType::Cmd, &host_from("windows", "")).is_none());
        let pwsh = host_from("windows", r#","shell":"powershell""#);
        assert!(shell_mismatch("t", ShellType::PowerShell, &pwsh).is_none());
    }

    /// A Windows tool on a Windows SSH host without `shell`: the host is
    /// taken to be `cmd.exe`, and the refusal says how to declare `PowerShell`
    /// when that is what the host really runs.
    #[test]
    fn shell_mismatch_tells_a_cmd_host_how_to_declare_powershell() {
        let refusal = shell_mismatch(
            "ssh_win_service_list",
            ShellType::PowerShell,
            &host_from("windows", ""),
        )
        .expect("cmd.exe is not PowerShell");
        assert!(refusal.contains("ssh_win_service_list"), "{refusal}");
        assert!(refusal.contains("cmd.exe"), "{refusal}");
        assert!(refusal.contains("`shell: powershell`"), "{refusal}");
    }

    /// The hint is only for the one case it fixes: a POSIX tool on a
    /// `PowerShell` host must not be told to declare `PowerShell`.
    #[test]
    fn shell_mismatch_gives_no_hint_outside_the_cmd_case() {
        let host = host_from("linux", r#","shell":"powershell""#);
        let refusal = shell_mismatch("t", ShellType::Posix, &host).expect("mismatch");
        assert!(!refusal.contains("`shell: powershell`"), "{refusal}");
    }

    // ============== kubectl_output_is_table / helm_output_is_table ==============

    #[test]
    fn kubectl_table_formats_are_recognised() {
        for output in [
            None,
            Some(""),
            Some("wide"),
            Some("custom-columns=NAME:.metadata.name"),
        ] {
            assert!(kubectl_output_is_table(output), "{output:?} is a table");
        }
    }

    #[test]
    fn kubectl_document_formats_are_not_tables() {
        for output in [
            "json",
            "yaml",
            "name",
            "jsonpath={.items[*].metadata.name}",
            "go-template={{.metadata.name}}",
            "template={{.metadata.name}}",
        ] {
            assert!(
                !kubectl_output_is_table(Some(output)),
                "{output:?} is not a table"
            );
        }
    }

    #[test]
    fn helm_output_formats() {
        assert!(helm_output_is_table(None));
        assert!(helm_output_is_table(Some("table")));
        assert!(!helm_output_is_table(Some("json")));
        assert!(!helm_output_is_table(Some("yaml")));
    }
}
