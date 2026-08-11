//! Command history tracking
//!
//! This module lives in the domain layer because command history is a core
//! business concern used by `ExecuteCommandUseCase` for recording executions.

use std::collections::VecDeque;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::Serialize;

/// A record of an executed command
#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub command: String,
    pub exit_code: u32,
    pub duration_ms: u64,
    pub success: bool,
}

impl HistoryEntry {
    /// Create a new history entry
    #[must_use]
    pub fn new(host: &str, command: &str, exit_code: u32, duration_ms: u64) -> Self {
        Self {
            timestamp: Utc::now(),
            host: host.to_string(),
            command: command.to_string(),
            exit_code,
            duration_ms,
            success: exit_code == 0,
        }
    }

    /// Create a failed entry (for connection/execution errors)
    #[must_use]
    pub fn failed(host: &str, command: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            host: host.to_string(),
            command: command.to_string(),
            exit_code: u32::MAX,
            duration_ms: 0,
            success: false,
        }
    }
}

/// Configuration for command history
#[derive(Debug, Clone)]
pub struct HistoryConfig {
    /// Maximum number of entries to keep
    pub max_entries: usize,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self { max_entries: 100 }
    }
}

/// Command history manager
pub struct CommandHistory {
    entries: Mutex<VecDeque<HistoryEntry>>,
    max_entries: usize,
}

impl CommandHistory {
    /// Create a new command history
    #[must_use]
    pub fn new(config: &HistoryConfig) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(config.max_entries)),
            max_entries: config.max_entries,
        }
    }

    /// Create with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(&HistoryConfig::default())
    }

    /// Add an entry to the history
    pub fn add(&self, entry: HistoryEntry) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };

        // Remove oldest if at capacity
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }

        entries.push_back(entry);
    }

    /// Record a successful command execution
    pub fn record_success(&self, host: &str, command: &str, exit_code: u32, duration_ms: u64) {
        self.add(HistoryEntry::new(host, command, exit_code, duration_ms));
    }

    /// Record a failed command execution
    pub fn record_failure(&self, host: &str, command: &str) {
        self.add(HistoryEntry::failed(host, command));
    }

    /// Get the most recent entries
    pub fn recent(&self, limit: usize) -> Vec<HistoryEntry> {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };

        entries.iter().rev().take(limit).cloned().collect()
    }

    /// Get all entries for a specific host
    pub fn for_host(&self, host: &str, limit: usize) -> Vec<HistoryEntry> {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };

        entries
            .iter()
            .rev()
            .filter(|e| e.host == host)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get entries newer than `since`, most recent first.
    ///
    /// Used by the MCP `history://recent?since=1h` resource query to expose a
    /// time-scoped audit trail to agents.
    pub fn recent_since(&self, since: DateTime<Utc>, limit: usize) -> Vec<HistoryEntry> {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };

        entries
            .iter()
            .rev()
            .filter(|e| e.timestamp >= since)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get entries for a specific host that are newer than `since`.
    ///
    /// Used by the MCP `history://recent?host=X&since=1h` resource query.
    pub fn for_host_since(
        &self,
        host: &str,
        since: DateTime<Utc>,
        limit: usize,
    ) -> Vec<HistoryEntry> {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };

        entries
            .iter()
            .rev()
            .filter(|e| e.host == host && e.timestamp >= since)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get the total number of entries
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |e| e.len())
    }

    /// Check if history is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all history
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_entry_success() {
        let entry = HistoryEntry::new("test-host", "ls -la", 0, 100);
        assert!(entry.success);
        assert_eq!(entry.exit_code, 0);
        assert_eq!(entry.host, "test-host");
        assert_eq!(entry.command, "ls -la");
    }

    #[test]
    fn test_history_entry_failure() {
        let entry = HistoryEntry::failed("test-host", "bad-command");
        assert!(!entry.success);
        assert_eq!(entry.exit_code, u32::MAX);
    }

    #[test]
    fn test_history_add_and_recent() {
        let history = CommandHistory::with_defaults();

        history.record_success("host1", "cmd1", 0, 100);
        history.record_success("host2", "cmd2", 0, 200);
        history.record_success("host1", "cmd3", 1, 300);

        let recent = history.recent(10);
        assert_eq!(recent.len(), 3);
        // Most recent first
        assert_eq!(recent[0].command, "cmd3");
        assert_eq!(recent[1].command, "cmd2");
        assert_eq!(recent[2].command, "cmd1");
    }

    #[test]
    fn test_history_for_host() {
        let history = CommandHistory::with_defaults();

        history.record_success("host1", "cmd1", 0, 100);
        history.record_success("host2", "cmd2", 0, 200);
        history.record_success("host1", "cmd3", 0, 300);

        let host1_entries = history.for_host("host1", 10);
        assert_eq!(host1_entries.len(), 2);
        assert_eq!(host1_entries[0].command, "cmd3");
        assert_eq!(host1_entries[1].command, "cmd1");
    }

    #[test]
    fn test_history_max_entries() {
        let config = HistoryConfig { max_entries: 3 };
        let history = CommandHistory::new(&config);

        history.record_success("host", "cmd1", 0, 100);
        history.record_success("host", "cmd2", 0, 100);
        history.record_success("host", "cmd3", 0, 100);
        history.record_success("host", "cmd4", 0, 100);

        assert_eq!(history.len(), 3);

        let recent = history.recent(10);
        assert_eq!(recent[0].command, "cmd4");
        assert_eq!(recent[2].command, "cmd2");
        // cmd1 was evicted
    }

    #[test]
    fn test_history_recent_since_filters_older_entries() {
        let history = CommandHistory::with_defaults();
        history.record_success("h", "cmd_old", 0, 100);
        history.record_success("h", "cmd_new", 0, 100);

        // Arbitrary cutoff far in the past — both entries must pass.
        let far_past = Utc::now() - chrono::Duration::days(365);
        assert_eq!(history.recent_since(far_past, 10).len(), 2);

        // Cutoff in the future — no entries.
        let future = Utc::now() + chrono::Duration::days(1);
        assert!(history.recent_since(future, 10).is_empty());
    }

    #[test]
    fn test_history_for_host_since_combines_filters() {
        let history = CommandHistory::with_defaults();
        history.record_success("prod", "cmd1", 0, 100);
        history.record_success("staging", "cmd2", 0, 100);
        history.record_success("prod", "cmd3", 0, 100);

        let cutoff = Utc::now() - chrono::Duration::hours(1);
        let prod_entries = history.for_host_since("prod", cutoff, 10);
        assert_eq!(prod_entries.len(), 2);
        assert!(prod_entries.iter().all(|e| e.host == "prod"));
    }

    #[test]
    fn test_history_for_host_since_respects_limit() {
        let history = CommandHistory::with_defaults();
        for i in 0..5 {
            history.record_success("prod", &format!("cmd{i}"), 0, 100);
        }
        let cutoff = Utc::now() - chrono::Duration::hours(1);
        let truncated = history.for_host_since("prod", cutoff, 2);
        assert_eq!(truncated.len(), 2);
    }

    #[test]
    fn test_history_clear() {
        let history = CommandHistory::with_defaults();

        history.record_success("host", "cmd1", 0, 100);
        history.record_success("host", "cmd2", 0, 100);

        assert_eq!(history.len(), 2);

        history.clear();
        assert!(history.is_empty());
    }

    /// `is_empty()` must return `false` after recording — kills the
    /// `replace -> true` mutation on line 181 that the existing
    /// post-clear assertion (which expects `true`) cannot detect.
    #[test]
    fn test_history_is_empty_false_after_record() {
        let history = CommandHistory::with_defaults();
        assert!(history.is_empty(), "fresh history is empty");
        history.record_success("host", "cmd", 0, 100);
        assert!(
            !history.is_empty(),
            "history with one entry must not be empty"
        );
    }
}
