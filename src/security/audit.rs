use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{info, warn};

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
    config: AuditConfig,
    sender: Option<mpsc::UnboundedSender<AuditEvent>>,
    sanitizer: Option<Arc<crate::security::Sanitizer>>,
}

/// Background task that writes audit events to a file
pub struct AuditWriterTask {
    rx: mpsc::UnboundedReceiver<AuditEvent>,
    file: File,
    sanitizer: Option<Arc<crate::security::Sanitizer>>,
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
                // Clone file handle for spawn_blocking
                if let Ok(mut file) = self.file.try_clone() {
                    let _ = tokio::task::spawn_blocking(move || {
                        if let Err(e) = file.write_all(line.as_bytes()) {
                            warn!(error = %e, "Failed to write audit event to file");
                        }
                        if let Err(e) = file.flush() {
                            warn!(error = %e, "Failed to flush audit log file");
                        }
                    })
                    .await;
                }
            }
        }
    }
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

        let file = {
            let mut opts = OpenOptions::new();
            opts.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(&config.path)?
        };

        // Create channel for async logging
        let (tx, rx) = mpsc::unbounded_channel();

        let logger = Self {
            config: config.clone(),
            sender: Some(tx),
            sanitizer: None,
        };

        let task = AuditWriterTask {
            rx,
            file,
            sanitizer: None,
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

    /// Create a disabled audit logger (for testing or when audit is off)
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            config: AuditConfig::default(),
            sender: None,
            sanitizer: None,
        }
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
    #[must_use]
    pub fn needs_rotation(&self) -> bool {
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
    /// # Errors
    ///
    /// Returns an error if the log file cannot be renamed during rotation.
    pub fn rotate(&self) -> std::io::Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let path = &self.config.path;
        if !path.exists() {
            return Ok(());
        }

        // Generate rotated filename with timestamp
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let rotated_name = format!(
            "{}.{timestamp}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("audit.log")
        );
        let rotated_path = path.with_file_name(rotated_name);

        // Rename current file
        std::fs::rename(path, &rotated_path)?;

        // Clean up old files if retention is configured
        self.cleanup_old_files();

        Ok(())
    }

    /// Remove audit files older than retention period
    fn cleanup_old_files(&self) {
        let retain_days = self.config.retain_days;
        if retain_days == 0 {
            return;
        }

        let Some(parent) = self.config.path.parent() else {
            return;
        };

        let cutoff = Utc::now() - chrono::Duration::days(i64::from(retain_days));

        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata()
                    && let Ok(modified) = metadata.modified()
                {
                    let modified: DateTime<Utc> = modified.into();
                    if modified < cutoff {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Check if a path is within the configured audit directory
    fn is_valid_audit_path(path: &Path, config: &AuditConfig) -> bool {
        if let (Some(config_parent), Some(path_parent)) = (config.path.parent(), path.parent()) {
            return path_parent == config_parent;
        }
        false
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
            path: PathBuf::from("/var/log/mcp-ssh-bridge/audit.log"),
            max_size_mb: 10,
            retain_days: 30,
        };

        let valid = PathBuf::from("/var/log/mcp-ssh-bridge/audit.log.20240101");
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
        let old_time = SystemTime::now() - Duration::from_secs(100 * 24 * 60 * 60);
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
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        std::fs::write(&audit_path, "current log").unwrap();

        // Create a file that would be old
        let old_file = temp_dir.path().join("audit.log.old");
        std::fs::write(&old_file, "old content").unwrap();

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

        // Create file exactly at the cutoff (should be deleted if using <, kept if using <=)
        let exactly_at_cutoff = temp_dir.path().join("audit.log.cutoff");
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
        let before_cutoff = temp_dir.path().join("audit.log.old31");
        std::fs::write(&before_cutoff, "31 days old").unwrap();
        let old_time = SystemTime::now() - Duration::from_secs(31 * 24 * 60 * 60);
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

        // Create a file and backdate it to 31 days ago
        let old_file = temp_dir.path().join("old_audit.log");
        fs::write(&old_file, "old data").unwrap();
        let old_time = filetime::FileTime::from_system_time(
            std::time::SystemTime::now() - std::time::Duration::from_secs(31 * 86400),
        );
        filetime::set_file_mtime(&old_file, old_time).unwrap();

        // Create a recent file (today)
        let recent_file = temp_dir.path().join("recent_audit.log");
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
