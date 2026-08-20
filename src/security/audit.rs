use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::AuditConfig;

/// Result of a command execution for audit purposes
#[derive(Debug, Clone, Serialize)]
pub enum CommandResult {
    Success { exit_code: u32, duration_ms: u64 },
    Error { message: String },
    Denied { reason: String },
}

/// Audit event for logging
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub host: String,
    pub command: String,
    /// Name of the tool that generated this event (e.g., `ssh_redis_cli`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub result: CommandResult,
}

impl AuditEvent {
    /// Create a new audit event
    #[must_use]
    pub fn new(host: &str, command: &str, result: CommandResult) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type: "ssh_exec".to_string(),
            host: host.to_string(),
            command: command.to_string(),
            tool_name: None,
            result,
        }
    }

    /// Create an event for a denied command
    #[must_use]
    pub fn denied(host: &str, command: &str, reason: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type: "command_denied".to_string(),
            host: host.to_string(),
            command: command.to_string(),
            tool_name: None,
            result: CommandResult::Denied {
                reason: reason.to_string(),
            },
        }
    }

    /// Set the tool name for this audit event.
    #[must_use]
    pub fn with_tool_name(mut self, name: &str) -> Self {
        self.tool_name = Some(name.to_string());
        self
    }
}

/// Audit logger that writes events to a file and/or tracing
///
/// Uses an async channel to avoid blocking on file writes.
pub struct AuditLogger {
    /// Only `needs_rotation`, `rotate` and `cleanup_old_files` ever read
    /// this, and all three are test-only (F6) — the writer task carries its
    /// own copy of the settings it needs. Gated so a release build does not
    /// clone an `AuditConfig` nothing reads.
    #[cfg(test)]
    config: AuditConfig,
    sender: Option<mpsc::UnboundedSender<AuditEvent>>,
    sanitizer: Option<Arc<crate::security::Sanitizer>>,
    /// Clock used for the retention cutoff; injectable so the boundary
    /// (mtime == cutoff) is deterministically testable. Read only by
    /// `cleanup_old_files`, which is test-only (F6); the writer task calls
    /// `cleanup_old_audit_files` with the real clock directly.
    #[cfg(test)]
    now_fn: fn() -> DateTime<Utc>,
}

/// Background task that writes audit events to a file
pub struct AuditWriterTask {
    rx: mpsc::UnboundedReceiver<AuditEvent>,
    file: File,
    sanitizer: Option<Arc<crate::security::Sanitizer>>,
    /// Live audit log path, needed to rename and reopen on rotation.
    path: PathBuf,
    /// `max_size_mb` in bytes. `0` disables rotation.
    max_bytes: u64,
    retain_days: u32,
    /// Bytes in the live file. Seeded from the file's current length so a
    /// restart on an already-large log rotates on the next event instead of
    /// growing without bound.
    written_bytes: u64,
}

impl AuditWriterTask {
    /// Run the writer task, consuming events from the channel
    pub async fn run(mut self) {
        while let Some(mut event) = self.rx.recv().await {
            // Defensive: sanitize at the writer side too in case a logger
            // sent us an event without sanitizing first. Belt-and-braces:
            // when both sides share the same `Arc<Sanitizer>` we guarantee
            // no secret ever lands in the JSONL file.
            if let Some(ref s) = self.sanitizer {
                event.command = s.sanitize(&event.command).into_owned();
            }
            if let Ok(json) = serde_json::to_string(&event) {
                let line = format!("{json}\n");
                let line_len = line.len() as u64;
                // Clone file handle for spawn_blocking
                if let Ok(mut file) = self.file.try_clone() {
                    let written = tokio::task::spawn_blocking(move || {
                        if let Err(e) = file.write_all(line.as_bytes()) {
                            warn!(error = %e, "Failed to write audit event to file");
                            return false;
                        }
                        if let Err(e) = file.flush() {
                            warn!(error = %e, "Failed to flush audit log file");
                            return false;
                        }
                        true
                    })
                    .await
                    .unwrap_or(false);

                    if written {
                        self.written_bytes = self.written_bytes.saturating_add(line_len);
                        self.rotate_if_needed();
                    }
                }
            }
        }
    }

    /// Rotate the live audit log once it has grown past `max_size_mb`.
    ///
    /// G-26 (audit 2026-08-19): this is the ONLY production caller of
    /// rotation. It has to live here because this task owns the open `File`
    /// handle — renaming the path from anywhere else would leave every later
    /// event appended to the renamed inode.
    ///
    /// A rotation failure never drops audit events -- that would be strictly
    /// worse than an oversized log. But it does permanently disable rotation
    /// for this task (see `reopen_after_rotation` for the same reasoning on
    /// the sibling arm): the causes of a failing `rename(2)` here are all
    /// persistent (EROFS remount, permission change, parent directory moved
    /// or deleted, MAC denial, an external logrotate that removed the live
    /// log), so retrying once per event would issue an unbounded stream of
    /// doomed syscalls and `warn!` lines that can never succeed.
    fn rotate_if_needed(&mut self) {
        if self.max_bytes == 0 || self.written_bytes < self.max_bytes {
            return;
        }

        if let Err(e) = rename_with_timestamp(&self.path, Utc::now()) {
            error!(
                error = %e,
                path = %self.path.display(),
                "Failed to rotate audit log; disabling further rotation for \
                 this run (events keep landing in the current, oversized file \
                 until the process restarts)"
            );
            self.max_bytes = 0;
            return;
        }
        cleanup_old_audit_files(&self.path, self.retain_days, Utc::now());

        self.reopen_after_rotation();
    }

    /// Reopen the live audit log after `rotate_if_needed` has already
    /// renamed it aside.
    ///
    /// IMPORTANT (fix round 1 of the 2026-08-19 audit corrections): a
    /// failure here used to be a `warn!` with `self.file` and
    /// `written_bytes` left untouched. Since the rename already succeeded,
    /// `self.file` was left pointing at the RENAMED (now-archived) inode —
    /// every subsequent event would keep landing in a file nobody tails,
    /// and because `written_bytes` was never reset, `rotate_if_needed`
    /// would immediately try to rotate again on the very next event,
    /// calling `rename_with_timestamp` on a source that no longer exists at
    /// `self.path` — failing the exact same way, forever, once per event.
    /// A rename(2) syscall failing on every single event is strictly worse
    /// than the oversized-log problem rotation exists to solve.
    ///
    /// On failure this now logs once, at `error!` (a human should notice
    /// this), and permanently disables further rotation attempts for this
    /// task by zeroing `max_bytes` — `rotate_if_needed`'s guard clause then
    /// short-circuits on every future call. Events keep landing in the
    /// renamed file until the process restarts; that is a known, bounded
    /// degradation instead of an unbounded per-event retry loop.
    fn reopen_after_rotation(&mut self) {
        match open_audit_file(&self.path) {
            Ok(file) => {
                self.file = file;
                self.written_bytes = 0;
            }
            Err(e) => {
                error!(
                    error = %e,
                    path = %self.path.display(),
                    "Failed to reopen audit log after rotation; disabling further \
                     rotation for this run (events will keep landing in the \
                     rotated file until the process restarts)"
                );
                self.max_bytes = 0;
            }
        }
    }
}

/// Open (creating if needed) the audit log in append mode, 0600 on unix.
fn open_audit_file(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Rename `path` to `<file_name>.<YYYYmmdd_HHMMSS>` in the same directory.
///
/// MINOR (fix round 1, audit 2026-08-19): `%Y%m%d_%H%M%S` is one-second
/// resolution. Two rotations inside the same wall-clock second used to
/// collide on this name, and `fs::rename` silently clobbers an existing
/// destination on Unix — the first archive would just vanish. If the
/// timestamped name is already taken, an incrementing numeric suffix is
/// appended until a free name is found, so a collision loses nothing.
fn rename_with_timestamp(path: &Path, now: DateTime<Utc>) -> std::io::Result<()> {
    let timestamp = now.format("%Y%m%d_%H%M%S");
    let base_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("audit.log");

    let mut rotated_path = path.with_file_name(format!("{base_name}.{timestamp}"));
    let mut suffix: u32 = 1;
    while rotated_path.exists() {
        rotated_path = path.with_file_name(format!("{base_name}.{timestamp}.{suffix}"));
        suffix += 1;
    }

    std::fs::rename(path, rotated_path)
}

/// Whether `name` is one of `live_file_name`'s rotated archives, i.e. exactly
/// the shape `rename_with_timestamp` writes: `<live file name>.<YYYYmmdd_HHMMSS>`
/// with an optional `.<n>` same-second collision counter.
///
/// F2 (re-review of the 2026-08-19 audit corrections): the first fix scoped
/// the retention sweep with `starts_with("<live file name>.")` — "anything
/// after a dot". That is not the shape rotation writes, and it captures files
/// that belong to somebody else: a second instance configured `audit.path:
/// .../audit.log.staging` has a LIVE log starting with `audit.log.`, so the
/// busy instance would delete it on its first rotation, silently. An external
/// logrotate's `audit.log.1` and `audit.log.gz` are caught the same way.
/// Matching the suffix shape exactly is what makes the sweep safe.
fn is_own_rotated_archive(name: &str, live_file_name: &str) -> bool {
    let Some(suffix) = name
        .strip_prefix(live_file_name)
        .and_then(|rest| rest.strip_prefix('.'))
    else {
        return false;
    };

    // `<YYYYmmdd_HHMMSS>`, optionally followed by `.<n>`.
    let (timestamp, counter) = match suffix.split_once('.') {
        Some((timestamp, counter)) => (timestamp, Some(counter)),
        None => (suffix, None),
    };

    // Byte-wise so a multibyte filename can never panic on a slice boundary.
    let timestamp = timestamp.as_bytes();
    let timestamp_ok = timestamp.len() == 15
        && timestamp[8] == b'_'
        && timestamp[..8].iter().all(u8::is_ascii_digit)
        && timestamp[9..].iter().all(u8::is_ascii_digit);

    let counter_ok = match counter {
        None => true,
        Some(counter) => !counter.is_empty() && counter.as_bytes().iter().all(u8::is_ascii_digit),
    };

    timestamp_ok && counter_ok
}

/// Remove this log's own rotated archives whose mtime predates the retention
/// cutoff. `retain_days == 0` disables cleanup.
///
/// CRITICAL (fix round 1 of the 2026-08-19 audit corrections): this used to
/// delete EVERY file in `path`'s parent directory older than `retain_days`,
/// with no filename check — `audit.path: ~/audit.log` swept the operator's
/// entire home directory. Only files matching `<live file name>.<suffix>`
/// (the shape `rename_with_timestamp` produces) are eligible; nothing else
/// in that directory belongs to this writer. See `is_own_rotated_archive` for
/// why the match has to be the exact archive shape and not a bare prefix.
///
/// F7 (re-review): the sweep is no longer silent. Removal used to be
/// `let _ = std::fs::remove_file(...)` with no log line and no counter, so a
/// sweep that deleted nothing (EACCES, EBUSY, an already-vanished file) was
/// indistinguishable from one that deleted every archive in the directory —
/// on the very release that turns this destructive code path on for the
/// first time.
fn cleanup_old_audit_files(path: &Path, retain_days: u32, now: DateTime<Utc>) {
    if retain_days == 0 {
        return;
    }

    let Some(parent) = path.parent() else {
        return;
    };
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let cutoff = now - chrono::Duration::days(i64::from(retain_days));

    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(e) => {
            warn!(
                error = %e,
                directory = %parent.display(),
                "Failed to scan the audit directory for expired archives"
            );
            return;
        }
    };

    let mut removed: usize = 0;
    for entry in entries.flatten() {
        let entry_name = entry.file_name();
        if !is_own_rotated_archive(&entry_name.to_string_lossy(), file_name) {
            continue;
        }
        if let Ok(metadata) = entry.metadata()
            && let Ok(modified) = metadata.modified()
        {
            let modified: DateTime<Utc> = modified.into();
            if modified < cutoff {
                match std::fs::remove_file(entry.path()) {
                    Ok(()) => removed += 1,
                    Err(e) => warn!(
                        error = %e,
                        archive = %entry.path().display(),
                        "Failed to remove an expired audit archive"
                    ),
                }
            }
        }
    }

    info!(removed, cutoff = %cutoff, "audit retention swept archives");
}

impl AuditLogger {
    /// Create a new async audit logger with the given configuration
    ///
    /// Returns the logger and an optional writer task that must be spawned.
    ///
    /// # Errors
    ///
    /// Returns an error if the audit log file cannot be created or opened.
    pub fn new(config: &AuditConfig) -> std::io::Result<(Self, Option<AuditWriterTask>)> {
        if !config.enabled {
            return Ok((Self::disabled(), None));
        }

        // Ensure parent directory exists
        if let Some(parent) = config.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = open_audit_file(&config.path)?;
        // Seed the rotation counter from the existing file so a restart on an
        // already-oversized log rotates on the next event (G-26).
        let written_bytes = file.metadata().map(|m| m.len()).unwrap_or(0);

        // Create channel for async logging
        let (tx, rx) = mpsc::unbounded_channel();

        let logger = Self {
            #[cfg(test)]
            config: config.clone(),
            sender: Some(tx),
            sanitizer: None,
            #[cfg(test)]
            now_fn: Utc::now,
        };

        let task = AuditWriterTask {
            rx,
            file,
            sanitizer: None,
            path: config.path.clone(),
            max_bytes: config.max_size_mb.saturating_mul(1024 * 1024),
            retain_days: config.retain_days,
            written_bytes,
        };

        Ok((logger, Some(task)))
    }

    /// Like `new` but applies a sanitizer to `event.command` before write/log.
    ///
    /// The same `Arc<Sanitizer>` is shared between the logger (for tracing
    /// emission) and the writer task (for the JSONL file), so secrets are
    /// masked on both sinks.
    ///
    /// # Errors
    ///
    /// Returns an error if the audit log file cannot be created or opened.
    pub fn new_with_sanitizer(
        config: &AuditConfig,
        sanitizer: crate::security::Sanitizer,
    ) -> std::io::Result<(Self, Option<AuditWriterTask>)> {
        let (mut logger, task) = Self::new(config)?;
        let san = Arc::new(sanitizer);
        logger.sanitizer = Some(Arc::clone(&san));
        let task = task.map(|mut t| {
            t.sanitizer = Some(san);
            t
        });
        Ok((logger, task))
    }

    /// Whether a sanitizer is wired to mask `event.command` before logging.
    #[must_use]
    pub fn has_sanitizer(&self) -> bool {
        self.sanitizer.is_some()
    }

    /// Create a disabled audit logger (for testing or when audit is off)
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            #[cfg(test)]
            config: AuditConfig::default(),
            sender: None,
            sanitizer: None,
            #[cfg(test)]
            now_fn: Utc::now,
        }
    }

    /// Test-only clock override so retention-boundary behavior is
    /// deterministic.
    #[cfg(test)]
    fn set_clock(&mut self, now_fn: fn() -> DateTime<Utc>) {
        self.now_fn = now_fn;
    }

    /// Log an audit event (non-blocking)
    ///
    /// The event is sent to a background task for file writing.
    /// If a sanitizer is configured, `event.command` is masked BEFORE the
    /// tracing emission and BEFORE the channel send (so neither sink ever
    /// sees the unredacted command).
    pub fn log(&self, event: AuditEvent) {
        let mut event = event;
        if let Some(ref s) = self.sanitizer {
            event.command = s.sanitize(&event.command).into_owned();
        }

        // Always log to tracing (fast, synchronous)
        Self::log_to_tracing(&event);

        // Send to channel for async file writing
        if let Some(ref sender) = self.sender {
            let _ = sender.send(event);
        }
    }

    /// Log event to tracing (synchronous, fast)
    fn log_to_tracing(event: &AuditEvent) {
        match &event.result {
            CommandResult::Success {
                exit_code,
                duration_ms,
            } => {
                info!(
                    event_type = %event.event_type,
                    host = %event.host,
                    command = %event.command,
                    exit_code = exit_code,
                    duration_ms = duration_ms,
                    "Audit: command executed"
                );
            }
            CommandResult::Error { message } => {
                info!(
                    event_type = %event.event_type,
                    host = %event.host,
                    command = %event.command,
                    error = %message,
                    "Audit: command failed"
                );
            }
            CommandResult::Denied { reason } => {
                info!(
                    event_type = %event.event_type,
                    host = %event.host,
                    command = %event.command,
                    reason = %reason,
                    "Audit: command denied"
                );
            }
        }
    }

    /// Check if the audit log needs rotation (exceeds max size)
    ///
    /// `#[cfg(test)]` (F6, re-review of the 2026-08-19 audit corrections),
    /// matching what `ResourceRegistry::schemes` got for the same reason.
    /// It has no production caller in any branch or tag — `AuditWriterTask`
    /// owns the open file handle and is the only place that can safely
    /// rotate — and its semantics now actively contradict the writer task's:
    /// `len/(1024*1024) >= max_size_mb` is TRUE for `max_size_mb: 0`, the
    /// exact value that means "rotation disabled" in `rotate_if_needed`. A
    /// consumer polling `needs_rotation()` and calling `rotate()` would also
    /// drive straight into the failure mode `rotate_if_needed` guards
    /// against, since `rotate()` renames without reopening. `pub(crate)`
    /// alone would still be flagged as dead code in a non-test build.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn needs_rotation(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        if let Ok(metadata) = std::fs::metadata(&self.config.path) {
            let size_mb = metadata.len() / (1024 * 1024);
            return size_mb >= self.config.max_size_mb;
        }

        false
    }

    /// Rotate the audit log file
    ///
    /// `#[cfg(test)]` for the same reason as `needs_rotation` — see there.
    /// This renames and never reopens, so anything outside a test that
    /// called it while an `AuditWriterTask` held the handle would leave
    /// every later event appended to the renamed inode.
    ///
    /// # Errors
    ///
    /// Returns an error if the log file cannot be renamed during rotation.
    #[cfg(test)]
    pub(crate) fn rotate(&self) -> std::io::Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let path = &self.config.path;
        if !path.exists() {
            return Ok(());
        }

        rename_with_timestamp(path, Utc::now())?;

        // Clean up old files if retention is configured
        self.cleanup_old_files();

        Ok(())
    }

    /// Remove audit files older than retention period
    ///
    /// Uses the injectable clock (`now_fn`) so the retention boundary stays
    /// deterministically testable; the writer task calls the same free
    /// function (`cleanup_old_audit_files`) with the real clock. Test-only
    /// alongside its only callers, `rotate` and the retention tests.
    #[cfg(test)]
    fn cleanup_old_files(&self) {
        cleanup_old_audit_files(&self.config.path, self.config.retain_days, (self.now_fn)());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::Sanitizer;
    use std::path::{Path, PathBuf};

    /// Check if a path is within the configured audit directory
    fn is_valid_audit_path(path: &Path, config: &AuditConfig) -> bool {
        if let (Some(config_parent), Some(path_parent)) = (config.path.parent(), path.parent()) {
            return path_parent == config_parent;
        }
        false
    }

    #[test]
    fn test_has_sanitizer_reports_wiring() {
        let config = AuditConfig::default();
        let (plain, _task) = AuditLogger::new(&config).unwrap();
        assert!(
            !plain.has_sanitizer(),
            "plain logger must not report a sanitizer"
        );

        let (wired, _task) =
            AuditLogger::new_with_sanitizer(&config, Sanitizer::with_defaults()).unwrap();
        assert!(
            wired.has_sanitizer(),
            "new_with_sanitizer must wire the sanitizer"
        );
    }

    #[test]
    fn test_audit_event_with_tool_name() {
        let event = AuditEvent::new(
            "host1",
            "redis-cli INFO",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 50,
            },
        )
        .with_tool_name("ssh_redis_cli");

        assert_eq!(event.tool_name, Some("ssh_redis_cli".to_string()));
    }

    #[test]
    fn test_audit_event_without_tool_name() {
        let event = AuditEvent::new(
            "host1",
            "ls",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 10,
            },
        );
        assert_eq!(event.tool_name, None);
    }

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            "test-host",
            "ls -la",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 100,
            },
        );

        assert_eq!(event.host, "test-host");
        assert_eq!(event.command, "ls -la");
        assert_eq!(event.event_type, "ssh_exec");
    }

    #[test]
    fn test_audit_event_denied() {
        let event = AuditEvent::denied("test-host", "rm -rf /", "Matches blacklist");

        assert_eq!(event.event_type, "command_denied");
        match event.result {
            CommandResult::Denied { reason } => {
                assert!(reason.contains("blacklist"));
            }
            _ => panic!("Expected Denied result"),
        }
    }

    #[test]
    fn test_disabled_logger() {
        let logger = AuditLogger::disabled();
        let event = AuditEvent::new(
            "test",
            "echo test",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 10,
            },
        );

        // Should not panic
        logger.log(event);
    }

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::new(
            "prod-server",
            "docker ps",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 250,
            },
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("prod-server"));
        assert!(json.contains("docker ps"));
        assert!(json.contains("250"));
    }

    #[test]
    fn test_valid_audit_path() {
        let config = AuditConfig {
            enabled: true,
            path: PathBuf::from("/var/log/bridge-mcp/audit.log"),
            max_size_mb: 10,
            retain_days: 30,
        };

        let valid = PathBuf::from("/var/log/bridge-mcp/audit.log.20240101");
        let invalid = PathBuf::from("/tmp/audit.log");

        assert!(is_valid_audit_path(&valid, &config));
        assert!(!is_valid_audit_path(&invalid, &config));
    }

    // ============== CommandResult Tests ==============

    #[test]
    fn test_command_result_success_serialization() {
        let result = CommandResult::Success {
            exit_code: 0,
            duration_ms: 100,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"Success\""));
        assert!(json.contains("\"exit_code\":0"));
        assert!(json.contains("\"duration_ms\":100"));
    }

    #[test]
    fn test_command_result_error_serialization() {
        let result = CommandResult::Error {
            message: "Connection refused".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"Error\""));
        assert!(json.contains("Connection refused"));
    }

    #[test]
    fn test_command_result_denied_serialization() {
        let result = CommandResult::Denied {
            reason: "Blacklisted command".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"Denied\""));
        assert!(json.contains("Blacklisted command"));
    }

    #[test]
    fn test_command_result_clone() {
        let result = CommandResult::Success {
            exit_code: 42,
            duration_ms: 500,
        };
        let cloned = result.clone();
        match cloned {
            CommandResult::Success {
                exit_code,
                duration_ms,
            } => {
                assert_eq!(exit_code, 42);
                assert_eq!(duration_ms, 500);
            }
            _ => panic!("Expected Success"),
        }
    }

    // ============== AuditEvent Tests ==============

    #[test]
    fn test_audit_event_with_error_result() {
        let event = AuditEvent::new(
            "server1",
            "failing-command",
            CommandResult::Error {
                message: "Command not found".to_string(),
            },
        );

        assert_eq!(event.event_type, "ssh_exec");
        match event.result {
            CommandResult::Error { message } => {
                assert_eq!(message, "Command not found");
            }
            _ => panic!("Expected Error result"),
        }
    }

    #[test]
    fn test_audit_event_timestamp() {
        let event = AuditEvent::new(
            "test",
            "ls",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 10,
            },
        );

        // Timestamp should be recent (within last minute)
        let now = Utc::now();
        let diff = now.signed_duration_since(event.timestamp);
        assert!(diff.num_seconds() < 60);
    }

    #[test]
    fn test_audit_event_clone() {
        let event = AuditEvent::new(
            "host1",
            "echo hello",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 5,
            },
        );

        let cloned = event.clone();
        assert_eq!(event.host, cloned.host);
        assert_eq!(event.command, cloned.command);
        assert_eq!(event.event_type, cloned.event_type);
    }

    #[test]
    fn test_audit_event_debug() {
        let event = AuditEvent::denied("host", "rm -rf /", "blacklisted");
        let debug_str = format!("{event:?}");
        assert!(debug_str.contains("AuditEvent"));
        assert!(debug_str.contains("command_denied"));
    }

    // ============== AuditLogger Tests ==============

    #[test]
    fn test_disabled_logger_needs_rotation() {
        let logger = AuditLogger::disabled();
        assert!(!logger.needs_rotation());
    }

    #[test]
    fn test_disabled_logger_rotate() {
        let logger = AuditLogger::disabled();
        // Should not panic
        assert!(logger.rotate().is_ok());
    }

    #[test]
    fn test_audit_logger_with_temp_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("test-audit.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 10,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        assert!(task.is_some());

        // Log an event
        let event = AuditEvent::new(
            "test",
            "echo test",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 1,
            },
        );
        logger.log(event);

        // Check needs_rotation (should be false for small file)
        assert!(!logger.needs_rotation());
    }

    #[test]
    fn test_audit_logger_disabled_config() {
        let config = AuditConfig {
            enabled: false,
            path: PathBuf::from("/tmp/never-created.log"),
            max_size_mb: 10,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        assert!(task.is_none()); // No task for disabled logger

        // Log should not panic
        let event = AuditEvent::denied("test", "rm -rf /", "test");
        logger.log(event);
    }

    // ============== Full Event Serialization Tests ==============

    #[test]
    fn test_full_event_json_structure() {
        let event = AuditEvent::new(
            "prod-server",
            "systemctl status nginx",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 150,
            },
        );

        let json = serde_json::to_string(&event).unwrap();

        // Parse back to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("timestamp").is_some());
        assert_eq!(parsed["event_type"], "ssh_exec");
        assert_eq!(parsed["host"], "prod-server");
        assert_eq!(parsed["command"], "systemctl status nginx");
        assert!(parsed.get("result").is_some());
    }

    #[test]
    fn test_denied_event_json_structure() {
        let event = AuditEvent::denied("prod-server", "rm -rf /", "Matches blacklist pattern");

        let json = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["event_type"], "command_denied");
        assert!(
            parsed["result"]["Denied"]["reason"]
                .as_str()
                .unwrap()
                .contains("blacklist")
        );
    }

    // ============== Mutation Testing Coverage ==============

    #[tokio::test]
    async fn test_audit_writer_task_writes_events() {
        use std::io::Read;
        use tokio::sync::mpsc;

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("writer-test.log");

        // Create file and channel
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_path)
            .unwrap();

        let (tx, rx) = mpsc::unbounded_channel();
        let task = AuditWriterTask {
            rx,
            file,
            sanitizer: None,
            path: audit_path.clone(),
            max_bytes: 0, // rotation disabled: this test only checks the write path
            retain_days: 7,
            written_bytes: 0,
        };

        // Send an event
        let event = AuditEvent::new(
            "writer-test-host",
            "echo writer-test",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 42,
            },
        );
        tx.send(event).unwrap();

        // Drop sender to close channel
        drop(tx);

        // Run the task (will complete when channel closes)
        task.run().await;

        // Verify file contents
        let mut contents = String::new();
        std::fs::File::open(&audit_path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();

        assert!(contents.contains("writer-test-host"));
        assert!(contents.contains("echo writer-test"));
        assert!(contents.contains("42"));
    }

    /// G-26 (audit 2026-08-19): `rotate()` and `needs_rotation()` have existed
    /// since the first release with NO production caller in any branch or tag,
    /// while README.md documents `max_size_mb` / `retain_days` as working
    /// settings. The writer task owns the file handle, so it is the only place
    /// that can rename and reopen; this test drives the real task.
    #[tokio::test]
    async fn test_writer_task_rotates_past_max_size() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 1,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        let handle = tokio::spawn(task.expect("enabled audit must yield a writer task").run());

        // 24 events x ~64 KiB of command text = ~1.5 MiB: one rotation at the
        // 16th event, then ~0.5 MiB in the fresh file. Exactly one rotation.
        let big_command = "x".repeat(64 * 1024);
        for _ in 0..24 {
            logger.log(AuditEvent::new(
                "rotate-host",
                &big_command,
                CommandResult::Success {
                    exit_code: 0,
                    duration_ms: 1,
                },
            ));
        }

        drop(logger); // closes the channel so run() returns
        handle.await.unwrap();

        let rotated: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("audit.log."))
            .collect();

        assert_eq!(
            rotated.len(),
            1,
            "writer task must rotate exactly once past max_size_mb"
        );
        assert!(
            audit_path.exists(),
            "writer task must reopen the live audit log after rotating"
        );

        let live_len = std::fs::metadata(&audit_path).unwrap().len();
        assert!(
            live_len > 0 && live_len < 1024 * 1024,
            "post-rotation log must start fresh and keep receiving events, got {live_len} bytes"
        );
    }

    /// G-26's BREAKING marker rests entirely on `AuditWriterTask`'s
    /// `written_bytes` being SEEDED from the live file's existing length in
    /// `AuditLogger::new`: an operator already carrying a log over
    /// `max_size_mb` gets rotation — and therefore the retention sweep — on
    /// the very FIRST event after upgrading, not gradually. That is the
    /// whole reason the CHANGELOG calls the change a step function rather
    /// than a slow ramp.
    ///
    /// F12 (re-review of the 2026-08-19 audit corrections): replacing that
    /// seeding with `let written_bytes = 0;` left every single test in this
    /// module green. The most consequential behaviour in the change had no
    /// coverage at all. This is that test:
    /// `test_writer_task_rotates_past_max_size` reaches the threshold by
    /// writing 1.5 MiB of events, so it passes with or without the seeding;
    /// here ONE small event is the entire write volume, and only the seed
    /// can carry the counter over the threshold.
    #[tokio::test]
    async fn test_writer_task_seeds_written_bytes_from_existing_log() {
        // A log left behind by a pre-upgrade run, already past max_size_mb.
        const PRE_EXISTING: usize = 2 * 1024 * 1024;

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, vec![b'x'; PRE_EXISTING]).unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 1,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        let handle = tokio::spawn(task.expect("enabled audit must yield a writer task").run());

        // Exactly one small event: a few hundred bytes, nowhere near 1 MiB.
        logger.log(AuditEvent::new(
            "seed-host",
            "echo hi",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 1,
            },
        ));

        drop(logger); // closes the channel so run() returns
        handle.await.unwrap();

        let archives: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| is_own_rotated_archive(&e.file_name().to_string_lossy(), "audit.log"))
            .collect();

        assert_eq!(
            archives.len(),
            1,
            "a single small event on an already-oversized log must rotate it \
             immediately: written_bytes has to be seeded from the file's \
             existing length, not from zero"
        );

        let archived_len = std::fs::metadata(archives[0].path()).unwrap().len();
        assert!(
            archived_len > PRE_EXISTING as u64,
            "the archive must carry the pre-existing bytes plus the event \
             that tripped rotation, got {archived_len}"
        );

        let live_len = std::fs::metadata(&audit_path).unwrap().len();
        assert_eq!(
            live_len, 0,
            "the reopened live log must start empty after rotation"
        );
    }

    /// IMPORTANT (fix round 1 of the 2026-08-19 audit corrections): before
    /// this fix, a reopen failure after a successful rename left `self.file`
    /// pointing at the RENAMED (now-archived) inode with `written_bytes`
    /// untouched -- so every later event kept landing in a file nobody
    /// tails, AND every later event re-attempted the rename, which fails
    /// every time (the source no longer exists at `self.path`), forever.
    /// The fix must instead permanently disable further rotation attempts
    /// once a reopen fails, logging once rather than looping.
    ///
    /// `reopen_after_rotation` is unit-tested directly (rather than through
    /// the full rename+reopen chain) because a filesystem state where rename
    /// legitimately succeeds but the immediately following create at the
    /// vacated name legitimately fails is not reproducible portably without
    /// racing the OS -- disk-full and inode-exhaustion are the only real
    /// causes, and this test cannot safely manufacture either on a shared
    /// dev VM. A missing parent directory reproduces the reopen failure
    /// deterministically and portably.
    #[test]
    fn test_reopen_after_rotation_failure_disables_further_rotation() {
        let temp_dir = tempfile::tempdir().unwrap();
        // Parent directory does not exist: open_audit_file must fail with
        // ENOENT, deterministically and without touching any OS resource
        // limit or filling the disk.
        let unreachable_path = temp_dir.path().join("missing-dir").join("audit.log");

        // Placeholder handle for the `file` field; its own path is
        // irrelevant to what's under test (open_audit_file's success/failure
        // on `path`).
        let placeholder_path = temp_dir.path().join("placeholder.log");
        let file = open_audit_file(&placeholder_path).unwrap();

        let (_tx, rx) = mpsc::unbounded_channel();
        let mut task = AuditWriterTask {
            rx,
            file,
            sanitizer: None,
            path: unreachable_path,
            max_bytes: 1,
            retain_days: 7,
            written_bytes: 999,
        };

        task.reopen_after_rotation();

        assert_eq!(
            task.max_bytes, 0,
            "a reopen failure must permanently disable further rotation \
             attempts instead of retry-looping a rename that can only fail \
             the same way forever"
        );
    }

    /// F1 (re-review of the 2026-08-19 audit corrections): the reopen arm
    /// was hardened to disable rotation after a failure, but the RENAME arm
    /// kept `warn!`-and-return with `written_bytes` and `max_bytes` left
    /// untouched. `rotate_if_needed`'s guard (`written_bytes < max_bytes`)
    /// therefore never short-circuits again, so every subsequent audit
    /// event issues another doomed `rename(2)` plus another `warn!` --
    /// forever. An EROFS remount, a permission change, a moved or deleted
    /// directory, a MAC denial, or an external logrotate removing the live
    /// log all reach this arm. Both arms must degrade identically: log once
    /// at `error!`, then permanently disable rotation for this task.
    #[test]
    fn test_rename_failure_disables_further_rotation() {
        let temp_dir = tempfile::tempdir().unwrap();
        // Parent directory does not exist, so `rename(2)` on this source
        // fails with ENOENT every single time -- a permanently failing
        // rotation, deterministic and portable, without manufacturing
        // disk-full or a read-only mount on a shared dev VM.
        let unreachable_path = temp_dir.path().join("missing-dir").join("audit.log");

        // Placeholder handle for the `file` field; only `path` is under test.
        let placeholder_path = temp_dir.path().join("placeholder.log");
        let file = open_audit_file(&placeholder_path).unwrap();

        let (_tx, rx) = mpsc::unbounded_channel();
        let mut task = AuditWriterTask {
            rx,
            file,
            sanitizer: None,
            path: unreachable_path,
            max_bytes: 1,
            retain_days: 7,
            written_bytes: 999,
        };

        task.rotate_if_needed();

        assert_eq!(
            task.max_bytes, 0,
            "a rename failure must permanently disable further rotation, \
             not leave the guard armed so that every later event re-issues \
             the same doomed rename(2)"
        );

        // With rotation disabled the guard clause must short-circuit even
        // when the byte counter is back above the (now zero) threshold, so
        // repeated events cannot resurrect the retry loop.
        for _ in 0..4 {
            task.written_bytes = 999;
            task.rotate_if_needed();
            assert_eq!(
                task.max_bytes, 0,
                "rotation must stay permanently disabled once it has failed"
            );
        }
    }

    /// `max_size_mb: 0` must DISABLE rotation in the writer task rather than
    /// rotate on every single event (which would shred the log directory).
    #[tokio::test]
    async fn test_writer_task_treats_zero_max_size_as_disabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 0,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        let handle = tokio::spawn(task.unwrap().run());

        for _ in 0..3 {
            logger.log(AuditEvent::new(
                "zero-host",
                "echo hi",
                CommandResult::Success {
                    exit_code: 0,
                    duration_ms: 1,
                },
            ));
        }

        drop(logger);
        handle.await.unwrap();

        let entries: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "max_size_mb=0 must not rotate: expected only audit.log"
        );
    }

    #[test]
    fn test_audit_logger_log_sends_to_channel() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("log-test.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        assert!(task.is_some(), "Task should be created for enabled logger");

        // Log multiple events
        for i in 0..3 {
            let event = AuditEvent::new(
                &format!("host-{i}"),
                &format!("cmd-{i}"),
                CommandResult::Success {
                    exit_code: i,
                    duration_ms: u64::from(i) * 10,
                },
            );
            logger.log(event);
        }

        // The sender should still be valid (not panic)
        assert!(logger.sender.is_some());
    }

    #[test]
    fn test_needs_rotation_true_when_file_exceeds_size() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("rotation-test.log");

        // Create a file larger than 1 MB (set max_size_mb to 1)
        let large_content = "x".repeat(1024 * 1024 + 100); // 1 MB + 100 bytes
        std::fs::write(&audit_path, large_content).unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 1, // 1 MB threshold
            retain_days: 7,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        assert!(
            logger.needs_rotation(),
            "Should need rotation when file exceeds max_size_mb"
        );
    }

    #[test]
    fn test_needs_rotation_false_when_file_under_size() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("small-file.log");

        // Create a small file (much smaller than 1 MB)
        std::fs::write(&audit_path, "small content").unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10, // 10 MB threshold
            retain_days: 7,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        assert!(
            !logger.needs_rotation(),
            "Should not need rotation when file is small"
        );
    }

    #[test]
    fn test_rotate_renames_file_with_timestamp() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("rotate-test.log");

        // Create original file
        std::fs::write(&audit_path, "original content").unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 10,
            retain_days: 7,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();

        // Rotate
        logger.rotate().unwrap();

        // Original file should be renamed (no longer exist at original path)
        assert!(!audit_path.exists(), "Original file should be renamed");

        // A rotated file should exist in the same directory
        let entries: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "Should have exactly one rotated file");

        // Rotated filename should contain timestamp pattern
        let rotated_name = entries[0].file_name().to_string_lossy().to_string();
        assert!(
            rotated_name.starts_with("rotate-test.log."),
            "Rotated file should have timestamp suffix"
        );
    }

    /// MINOR (fix round 1 of the 2026-08-19 audit corrections): the rotated
    /// name is `<file name>.<YYYYmmdd_HHMMSS>` -- one-second resolution.
    /// Two rotations within the same wall-clock second previously collided
    /// on that name and `fs::rename` silently clobbered the first archive.
    /// Drives `rename_with_timestamp` directly with a FIXED `now` twice in
    /// a row (rather than racing the real clock) to deterministically
    /// reproduce the same-second collision.
    #[test]
    fn test_rename_with_timestamp_does_not_clobber_a_same_second_collision() {
        fn fixed_now() -> DateTime<Utc> {
            chrono::DateTime::parse_from_rfc3339("2026-01-31T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        std::fs::write(&audit_path, "first rotation's content").unwrap();
        rename_with_timestamp(&audit_path, fixed_now()).unwrap();

        // A second rotation in the SAME second: a fresh live file appears
        // again at the original path (as the writer task's reopen does),
        // and rotates again with an identical timestamp.
        std::fs::write(&audit_path, "second rotation's content").unwrap();
        rename_with_timestamp(&audit_path, fixed_now()).unwrap();

        let archived: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("audit.log."))
            .collect();

        assert_eq!(
            archived.len(),
            2,
            "two same-second rotations must produce two distinct archives, not one clobbered file"
        );

        let contents: std::collections::HashSet<String> = archived
            .iter()
            .map(|e| std::fs::read_to_string(e.path()).unwrap())
            .collect();
        assert!(
            contents.contains("first rotation's content"),
            "the first archive must survive the second rotation"
        );
        assert!(
            contents.contains("second rotation's content"),
            "the second archive must also be present"
        );
    }

    #[test]
    fn test_cleanup_old_files_removes_expired() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        // Create the main audit file
        std::fs::write(&audit_path, "current log").unwrap();

        // Create an "old" file (we'll set its mtime to the past using filetime)
        let old_file = temp_dir.path().join("audit.log.20200101_000000");
        std::fs::write(&old_file, "old content").unwrap();

        // Set modification time to 100 days ago
        let old_time = SystemTime::now() - Duration::from_hours(2400);
        filetime::set_file_mtime(&old_file, filetime::FileTime::from_system_time(old_time))
            .unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30, // Keep files for 30 days
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        // Old file should be deleted
        assert!(!old_file.exists(), "Old file should be deleted");
    }

    #[test]
    fn test_cleanup_keeps_file_at_exact_cutoff() {
        // Strict `<` in the retention check: a file whose mtime is exactly
        // equal to the cutoff must NOT be deleted. Fixed clock + fixed mtime
        // make the boundary reachable deterministically.
        fn fixed_now() -> DateTime<Utc> {
            chrono::DateTime::parse_from_rfc3339("2026-01-31T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "current log").unwrap();

        let boundary_file = temp_dir.path().join("audit.log.20260101_000000");
        std::fs::write(&boundary_file, "boundary content").unwrap();

        let cutoff = fixed_now() - chrono::Duration::days(30);
        filetime::set_file_mtime(
            &boundary_file,
            filetime::FileTime::from_system_time(std::time::SystemTime::from(cutoff)),
        )
        .unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30,
        };

        let (mut logger, _) = AuditLogger::new(&config).unwrap();
        logger.set_clock(fixed_now);
        logger.cleanup_old_files();

        assert!(
            boundary_file.exists(),
            "file with mtime == cutoff must be kept (strict <)"
        );
    }

    #[test]
    fn test_cleanup_old_files_keeps_recent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        // Create the main audit file
        std::fs::write(&audit_path, "current log").unwrap();

        // Create a recent file (default mtime is now)
        let recent_file = temp_dir.path().join("audit.log.20240601_120000");
        std::fs::write(&recent_file, "recent content").unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        // Recent file should still exist
        assert!(recent_file.exists(), "Recent file should be kept");
    }

    #[test]
    fn test_cleanup_old_files_respects_zero_retain_days() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        std::fs::write(&audit_path, "current log").unwrap();

        // A real rotated archive of THIS log, backdated well past any
        // plausible cutoff. F2 (re-review): this fixture used to be named
        // `audit.log.old` with a current mtime, so it survived on BOTH
        // counts and proved nothing about `retain_days: 0`. It now survives
        // only because the sweep is disabled.
        let old_file = temp_dir.path().join("audit.log.20200101_000000");
        std::fs::write(&old_file, "old content").unwrap();
        let old_time = SystemTime::now() - Duration::from_hours(2400); // 100 days
        filetime::set_file_mtime(&old_file, filetime::FileTime::from_system_time(old_time))
            .unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 0, // 0 means no cleanup
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        // File should still exist (retain_days=0 disables cleanup)
        assert!(
            old_file.exists(),
            "Files should not be deleted when retain_days=0"
        );
    }

    #[test]
    fn test_cleanup_old_files_boundary_exact_cutoff_date() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "current").unwrap();

        // Create file exactly at the cutoff (should be deleted if using <, kept if using <=).
        // Both fixtures carry the real `<name>.<YYYYmmdd_HHMMSS>` archive
        // shape (F2); the embedded timestamp is never parsed, the mtime set
        // below is what retention decides on.
        let exactly_at_cutoff = temp_dir.path().join("audit.log.20250101_000000");
        std::fs::write(&exactly_at_cutoff, "at cutoff").unwrap();

        // Set mtime to exactly 30 days ago
        let retain_days = 30u32;
        let cutoff_time =
            SystemTime::now() - Duration::from_secs(u64::from(retain_days) * 24 * 60 * 60);
        filetime::set_file_mtime(
            &exactly_at_cutoff,
            filetime::FileTime::from_system_time(cutoff_time),
        )
        .unwrap();

        // Create file just before cutoff (31 days ago, should definitely be deleted)
        let before_cutoff = temp_dir.path().join("audit.log.20241201_000000");
        std::fs::write(&before_cutoff, "31 days old").unwrap();
        let old_time = SystemTime::now() - Duration::from_hours(744);
        filetime::set_file_mtime(
            &before_cutoff,
            filetime::FileTime::from_system_time(old_time),
        )
        .unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        // File older than cutoff should be deleted
        assert!(
            !before_cutoff.exists(),
            "File older than retain_days should be deleted"
        );
    }

    /// CRITICAL (fix round 1 of the 2026-08-19 audit corrections):
    /// `cleanup_old_audit_files` deleted EVERY file in `audit.path`'s parent
    /// directory older than `retain_days`, with no filename check at all —
    /// via `let _ = std::fs::remove_file(...)`, silently. It had no
    /// production caller before the G-26 fix wired `rotate_if_needed` into
    /// the writer task; it now runs on every rotation. With a config like
    /// `path: ~/audit.log`, that swept the operator's entire home directory.
    /// Cleanup must only ever touch this log's OWN rotated archives, named
    /// `<file name>.<suffix>` by `rename_with_timestamp` — nothing else in
    /// that directory is this writer's to delete.
    #[test]
    fn test_cleanup_old_files_never_deletes_files_outside_its_own_lineage() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "current log").unwrap();

        // A legitimate rotated archive of THIS log: must still be removed
        // once past retention -- the fix must not overcorrect into deleting
        // nothing.
        let own_archive = temp_dir.path().join("audit.log.20200101_000000");
        std::fs::write(&own_archive, "old archive").unwrap();

        // Files this writer never created, sitting in the same directory --
        // exactly the shape of `audit.path: ~/audit.log`, where the parent
        // directory is $HOME.
        let foreign_dotfile = temp_dir.path().join(".bash_history");
        std::fs::write(&foreign_dotfile, "some shell history").unwrap();
        let foreign_doc = temp_dir.path().join("quarterly-report.pdf");
        std::fs::write(&foreign_doc, "not ours").unwrap();
        // Shares the live log's name as a literal prefix but is not one of
        // its rotated archives (no "." separator after "audit.log") --
        // must also survive.
        let lookalike = temp_dir.path().join("audit.log-backup");
        std::fs::write(&lookalike, "not a rotated archive").unwrap();

        let old_time = SystemTime::now() - Duration::from_hours(2400); // 100 days
        for f in [&own_archive, &foreign_dotfile, &foreign_doc, &lookalike] {
            filetime::set_file_mtime(f, filetime::FileTime::from_system_time(old_time)).unwrap();
        }

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        assert!(
            !own_archive.exists(),
            "its own expired rotated archive must still be removed"
        );
        assert!(
            foreign_dotfile.exists(),
            "a file this writer never created must survive no matter how old"
        );
        assert!(
            foreign_doc.exists(),
            "a file this writer never created must survive no matter how old"
        );
        assert!(
            lookalike.exists(),
            "a name that merely starts with the live log's name, but isn't \
             <name>.<timestamp>, must survive"
        );
    }

    /// F2 (re-review of the 2026-08-19 audit corrections): the first fix
    /// scoped the sweep with `starts_with("<live file name>.")` -- i.e.
    /// "anything after a dot". That is not the shape `rename_with_timestamp`
    /// writes, and it captures files that belong to somebody else. A SECOND
    /// bridge-mcp instance configured `audit.path: .../audit.log.staging`
    /// has a LIVE log whose name starts with `audit.log.`, so the busy
    /// instance deletes it on its first rotation -- silently, since removal
    /// is `let _ = std::fs::remove_file(...)`. An external logrotate's
    /// `audit.log.1` and `audit.log.gz` are swept by the same predicate.
    /// Only the exact `<name>.<YYYYmmdd_HHMMSS>` shape, with the optional
    /// `.<n>` same-second collision counter, is this writer's to delete.
    #[test]
    fn test_cleanup_never_deletes_a_sibling_instances_live_log() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "current log").unwrap();

        // A second instance's LIVE audit log, and one of ITS rotated
        // archives. Both start with `audit.log.`; neither is ours.
        let sibling_live = temp_dir.path().join("audit.log.staging");
        std::fs::write(&sibling_live, "the other instance's live log").unwrap();
        let sibling_archive = temp_dir.path().join("audit.log.staging.20260101_000000");
        std::fs::write(&sibling_archive, "the other instance's archive").unwrap();

        // An external logrotate's output for the same file.
        let logrotate_numbered = temp_dir.path().join("audit.log.1");
        std::fs::write(&logrotate_numbered, "logrotate copy").unwrap();
        let logrotate_gz = temp_dir.path().join("audit.log.gz");
        std::fs::write(&logrotate_gz, "logrotate compressed").unwrap();

        // Ours, and it must still be swept -- the fix must not overcorrect
        // into deleting nothing.
        let own_archive = temp_dir.path().join("audit.log.20200101_000000");
        std::fs::write(&own_archive, "our archive").unwrap();
        let own_collision_archive = temp_dir.path().join("audit.log.20200101_000000.1");
        std::fs::write(&own_collision_archive, "our same-second archive").unwrap();

        let old_time = SystemTime::now() - Duration::from_hours(2400); // 100 days
        for f in [
            &sibling_live,
            &sibling_archive,
            &logrotate_numbered,
            &logrotate_gz,
            &own_archive,
            &own_collision_archive,
        ] {
            filetime::set_file_mtime(f, filetime::FileTime::from_system_time(old_time)).unwrap();
        }

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        assert!(
            sibling_live.exists(),
            "another instance's LIVE audit log must never be deleted by this \
             instance's retention sweep"
        );
        assert!(
            sibling_archive.exists(),
            "another instance's rotated archive must never be deleted by this \
             instance's retention sweep"
        );
        assert!(
            logrotate_numbered.exists(),
            "an external logrotate's audit.log.1 is not ours to delete"
        );
        assert!(
            logrotate_gz.exists(),
            "an external logrotate's audit.log.gz is not ours to delete"
        );
        assert!(
            !own_archive.exists(),
            "our own expired archive must still be swept"
        );
        assert!(
            !own_collision_archive.exists(),
            "our own expired same-second-collision archive must still be swept"
        );
    }

    /// F7 (re-review of the 2026-08-19 audit corrections): removal was
    /// `let _ = std::fs::remove_file(...)` with no log line anywhere, and no
    /// counter. The CHANGELOG names silent deletion as reason (1) for G-26's
    /// BREAKING marker and then leaves it silent. On the first release where
    /// this code path deletes anything at all, a sweep that removed nothing
    /// (EACCES, EBUSY, an already-vanished file) has to be distinguishable
    /// from one that removed every archive in the directory.
    #[test]
    #[tracing_test::traced_test]
    fn test_cleanup_logs_what_it_swept() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "current log").unwrap();

        let expired_a = temp_dir.path().join("audit.log.20200101_000000");
        let expired_b = temp_dir.path().join("audit.log.20200102_000000");
        for f in [&expired_a, &expired_b] {
            std::fs::write(f, "old archive").unwrap();
            filetime::set_file_mtime(
                f,
                filetime::FileTime::from_system_time(
                    SystemTime::now() - Duration::from_hours(2400), // 100 days
                ),
            )
            .unwrap();
        }

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        assert!(
            !expired_a.exists() && !expired_b.exists(),
            "both expired archives must actually be swept"
        );
        assert!(
            logs_contain("audit retention swept archives"),
            "the retention sweep must leave a log line saying it ran"
        );
        assert!(
            logs_contain("removed=2"),
            "the retention sweep must report HOW MANY archives it deleted"
        );
    }

    #[test]
    fn test_needs_rotation_size_calculation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("size-test.log");

        // Create file exactly at 1 MB boundary
        let one_mb = 1024 * 1024;
        let content = "x".repeat(one_mb);
        std::fs::write(&audit_path, &content).unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 1, // 1 MB threshold
            retain_days: 7,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();

        // Exactly 1 MB should trigger rotation (>= check)
        assert!(
            logger.needs_rotation(),
            "File exactly at max_size_mb should need rotation"
        );

        // Now create a file just under 1 MB
        let under_one_mb = "x".repeat(one_mb - 100);
        std::fs::write(&audit_path, &under_one_mb).unwrap();

        // Re-check - should not need rotation
        assert!(
            !logger.needs_rotation(),
            "File under max_size_mb should not need rotation"
        );
    }

    #[tokio::test]
    async fn test_log_actually_writes_event_to_file() {
        use std::io::Read;

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("log-write-test.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 10,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        let task = task.expect("Task should exist for enabled logger");

        // Create a unique event
        let event = AuditEvent::new(
            "log-write-test-host",
            "unique-command-12345",
            CommandResult::Success {
                exit_code: 42,
                duration_ms: 999,
            },
        );

        // Call log() - this should send the event to the channel
        logger.log(event);

        // Drop logger to close the channel
        drop(logger);

        // Run the writer task to completion
        task.run().await;

        // Verify the event was written to the file
        let mut contents = String::new();
        std::fs::File::open(&audit_path)
            .expect("Audit file should exist")
            .read_to_string(&mut contents)
            .expect("Should read file");

        assert!(
            contents.contains("log-write-test-host"),
            "File should contain the host: {contents}"
        );
        assert!(
            contents.contains("unique-command-12345"),
            "File should contain the command: {contents}"
        );
        assert!(
            contents.contains("42"),
            "File should contain exit code: {contents}"
        );
        assert!(
            contents.contains("999"),
            "File should contain duration: {contents}"
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_log_to_tracing_emits_trace() {
        // Create a disabled logger (doesn't need file)
        let logger = AuditLogger::disabled();

        // Create an event
        let event = AuditEvent::new(
            "tracing-test-host",
            "tracing-test-command",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 100,
            },
        );

        // Call log() which internally calls log_to_tracing
        logger.log(event);

        // Verify tracing output was captured
        // tracing_test::traced_test captures logs and we can assert on them
        assert!(logs_contain("tracing-test-host"));
        assert!(logs_contain("tracing-test-command"));
        assert!(logs_contain("Audit: command executed"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_log_to_tracing_emits_denied_trace() {
        let logger = AuditLogger::disabled();
        let event = AuditEvent::denied("denied-host", "rm -rf /", "blacklisted pattern");

        logger.log(event);

        assert!(logs_contain("denied-host"));
        assert!(logs_contain("Audit: command denied"));
        assert!(logs_contain("blacklisted pattern"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_log_to_tracing_emits_error_trace() {
        let logger = AuditLogger::disabled();
        let event = AuditEvent::new(
            "error-host",
            "failing-cmd",
            CommandResult::Error {
                message: "Connection refused".to_string(),
            },
        );

        logger.log(event);

        assert!(logs_contain("error-host"));
        assert!(logs_contain("Audit: command failed"));
        assert!(logs_contain("Connection refused"));
    }

    // ============== Tests to catch previously-missed mutations ==============

    #[test]
    fn test_cleanup_old_files_respects_cutoff_boundary() {
        use std::fs;

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        // Create a rotated archive of THIS log and backdate it to 31 days
        // ago. Fix round 1 (audit 2026-08-19): these used to be named
        // `old_audit.log` / `recent_audit.log` -- filenames that are NOT
        // `<live file name>.<suffix>`, which only ever passed because
        // `cleanup_old_audit_files` had no filename filter at all (the
        // CRITICAL bug fixed alongside this test). F2 (re-review): the
        // replacements `audit.log.old31` / `audit.log.recent` were not the
        // archive shape either -- they only passed the prefix-only
        // predicate that F2 replaced. These are real
        // `<name>.<YYYYmmdd_HHMMSS>` archives now. The embedded timestamp is
        // never parsed: retention is decided on the file's mtime, set below.
        let old_file = temp_dir.path().join("audit.log.20250701_000000");
        fs::write(&old_file, "old data").unwrap();
        let old_time = filetime::FileTime::from_system_time(
            std::time::SystemTime::now() - std::time::Duration::from_hours(744),
        );
        filetime::set_file_mtime(&old_file, old_time).unwrap();

        // Create a recent rotated archive (today)
        let recent_file = temp_dir.path().join("audit.log.20260801_120000");
        fs::write(&recent_file, "recent data").unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            retain_days: 30,
            ..Default::default()
        };

        let (logger, _task) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        // Old file (31 days) should be removed (31 > 30)
        assert!(
            !old_file.exists(),
            "File older than retain_days should be cleaned up"
        );

        // Recent file should remain
        assert!(recent_file.exists(), "Recent file should not be cleaned up");
    }
}
