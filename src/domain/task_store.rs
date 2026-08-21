//! Task Store
//!
//! Thread-safe store for MCP Task lifecycle management (MCP 2025-11-25+).
//! Tasks wrap long-running tool executions and allow clients to poll for
//! status and retrieve results asynchronously.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::ports::protocol::{TaskInfo, TaskStatus};

/// Returned by [`TaskStore::list_tasks`] when the supplied pagination cursor
/// names no live task.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Invalid pagination cursor: {cursor}")]
pub struct InvalidCursor {
    /// The cursor value the client sent.
    pub cursor: String,
}

/// Internal task entry stored in the registry.
struct TaskEntry {
    info: TaskInfo,
    /// Serialized `ToolCallResult` (set when task reaches a terminal state).
    result: Option<Value>,
    /// Token to cancel the background worker.
    cancel_token: CancellationToken,
    /// Monotonic creation time for TTL checks.
    created: Instant,
    /// Per-task TTL.
    ttl: Duration,
}

impl TaskEntry {
    fn is_terminal(&self) -> bool {
        is_terminal_status(self.info.status)
    }

    fn is_expired(&self) -> bool {
        self.created.elapsed() >= self.ttl
    }
}

/// Thread-safe task store with TTL-based expiration.
///
/// Follows the same patterns as `OutputCache`: `RwLock<HashMap>`, lazy
/// cleanup, and capacity-based eviction.
pub struct TaskStore {
    tasks: RwLock<HashMap<String, TaskEntry>>,
    max_tasks: usize,
    default_ttl_ms: u64,
    default_poll_interval_ms: u64,
}

/// Outcome of a bounded wait on a task's result.
///
/// G-1 (audit 2026-08-19): the wait used to be unbounded and returned a
/// bare `Option<Value>`, which had no way to say "still running" — so the
/// only honest thing it could do was park forever. Three outcomes make the
/// bound expressible.
#[derive(Debug, Clone)]
pub enum TaskWaitOutcome {
    /// The task reached a terminal state and published a result.
    Ready(Value),
    /// The wait budget elapsed with the task still running. Carries the
    /// task's current status so the caller can answer the poll instead of
    /// erroring.
    TimedOut(Box<TaskInfo>),
    /// No such task, the entry expired, or it is terminal with no stored
    /// result (a cancelled task). Callers map all three to the same
    /// "no result" answer they always have.
    NotFound,
}

impl TaskWaitOutcome {
    /// The stored result, if the wait resolved with one.
    #[must_use]
    pub fn into_result(self) -> Option<Value> {
        match self {
            Self::Ready(value) => Some(value),
            Self::TimedOut(_) | Self::NotFound => None,
        }
    }
}

/// Terminal-status predicate usable without a `TaskEntry` in hand.
const fn is_terminal_status(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
    )
}

impl TaskStore {
    /// Create a new task store.
    ///
    /// - `max_tasks`: Maximum number of concurrent tasks.
    /// - `default_ttl_ms`: Default TTL in milliseconds.
    /// - `default_poll_interval_ms`: Suggested poll interval in milliseconds.
    #[must_use]
    pub fn new(max_tasks: usize, default_ttl_ms: u64, default_poll_interval_ms: u64) -> Self {
        Self {
            tasks: RwLock::new(HashMap::new()),
            max_tasks,
            default_ttl_ms,
            default_poll_interval_ms,
        }
    }

    /// Create a new task and return its ID + cancellation token.
    ///
    /// The caller should spawn a background worker using the returned
    /// `CancellationToken` and call `complete_task` or `fail_task` when done.
    pub async fn create_task(
        &self,
        requested_ttl_ms: Option<u64>,
    ) -> Option<(String, CancellationToken)> {
        let task_id = uuid::Uuid::new_v4().to_string();
        let ttl_ms = requested_ttl_ms.map_or(self.default_ttl_ms, |t| t.min(self.default_ttl_ms));

        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let cancel_token = CancellationToken::new();

        let entry = TaskEntry {
            info: TaskInfo {
                task_id: task_id.clone(),
                status: TaskStatus::Working,
                status_message: Some("Task is being processed.".to_string()),
                created_at: now.clone(),
                last_updated_at: now,
                ttl: ttl_ms,
                poll_interval: self.default_poll_interval_ms,
            },
            result: None,
            cancel_token: cancel_token.clone(),
            created: Instant::now(),
            ttl: Duration::from_millis(ttl_ms),
        };

        let mut tasks = self.tasks.write().await;

        // Lazy cleanup of expired tasks
        tasks.retain(|_, e| !e.is_expired());

        // Check capacity
        if tasks.len() >= self.max_tasks {
            return None;
        }

        tasks.insert(task_id.clone(), entry);
        Some((task_id, cancel_token))
    }

    /// Mark a task as completed and store the result.
    pub async fn complete_task(&self, task_id: &str, result: Value) -> Option<TaskInfo> {
        let mut tasks = self.tasks.write().await;
        let entry = tasks.get_mut(task_id)?;

        if entry.is_terminal() {
            return Some(entry.info.clone());
        }

        entry.info.status = TaskStatus::Completed;
        entry.info.status_message = Some("Task completed successfully.".to_string());
        entry.info.last_updated_at =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        entry.result = Some(result);

        Some(entry.info.clone())
    }

    /// Mark a task as failed and store the error result.
    pub async fn fail_task(&self, task_id: &str, message: &str, result: Value) -> Option<TaskInfo> {
        let mut tasks = self.tasks.write().await;
        let entry = tasks.get_mut(task_id)?;

        if entry.is_terminal() {
            return Some(entry.info.clone());
        }

        entry.info.status = TaskStatus::Failed;
        entry.info.status_message = Some(message.to_string());
        entry.info.last_updated_at =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        entry.result = Some(result);

        Some(entry.info.clone())
    }

    /// Cancel a task. Returns error string if the task is already terminal.
    pub async fn cancel_task(&self, task_id: &str) -> Result<TaskInfo, String> {
        let mut tasks = self.tasks.write().await;
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| format!("Task not found: {task_id}"))?;

        if entry.is_terminal() {
            return Err(format!(
                "Cannot cancel task in terminal state: {:?}",
                entry.info.status
            ));
        }

        entry.info.status = TaskStatus::Cancelled;
        entry.info.status_message = Some("Task was cancelled by request.".to_string());
        entry.info.last_updated_at =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        entry.cancel_token.cancel();

        Ok(entry.info.clone())
    }

    /// Get the current status of a task.
    pub async fn get_task(&self, task_id: &str) -> Option<TaskInfo> {
        let tasks = self.tasks.read().await;
        let entry = tasks.get(task_id)?;

        if entry.is_expired() {
            return None;
        }

        Some(entry.info.clone())
    }

    /// Get the result of a terminal task (non-blocking).
    pub async fn get_result(&self, task_id: &str) -> Option<Value> {
        let tasks = self.tasks.read().await;
        let entry = tasks.get(task_id)?;

        if entry.is_expired() {
            return None;
        }

        entry.result.clone()
    }

    /// List tasks with cursor-based pagination.
    ///
    /// Tasks are sorted by creation time (task ID is UUID, so we sort by
    /// `created_at`). Returns `(tasks, next_cursor)`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCursor`] when `cursor` names no live task. Clamping
    /// to the head instead replayed a page the client had already consumed,
    /// and TTL eviction can stale a cursor mid-loop, so the two cases must
    /// be distinguishable.
    pub async fn list_tasks(
        &self,
        cursor: Option<&str>,
        page_size: usize,
    ) -> Result<(Vec<TaskInfo>, Option<String>), InvalidCursor> {
        let tasks = self.tasks.read().await;

        let mut entries: Vec<_> = tasks
            .values()
            .filter(|e| !e.is_expired())
            .map(|e| &e.info)
            .collect();

        // Sort by creation time for stable pagination
        entries.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        // Apply cursor: skip entries up to and including the cursor task_id
        let start = if let Some(cursor_id) = cursor {
            entries
                .iter()
                .position(|info| info.task_id == cursor_id)
                .ok_or_else(|| InvalidCursor {
                    cursor: cursor_id.to_string(),
                })?
                + 1
        } else {
            0
        };

        let page: Vec<TaskInfo> = entries
            .into_iter()
            .skip(start)
            .take(page_size)
            .cloned()
            .collect();

        let next_cursor = if page.len() == page_size {
            page.last().map(|info| info.task_id.clone())
        } else {
            None
        };

        Ok((page, next_cursor))
    }

    /// Remove all expired tasks.
    pub async fn cleanup(&self) {
        let mut tasks = self.tasks.write().await;
        tasks.retain(|_, e| !e.is_expired());
    }

    /// Return the current number of tasks.
    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.tasks.read().await.len()
    }

    /// Return whether the task store is empty.
    #[cfg(test)]
    pub async fn is_empty(&self) -> bool {
        self.tasks.read().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    fn test_result() -> Value {
        json!({
            "content": [{"type": "text", "text": "ok"}],
        })
    }

    fn error_result() -> Value {
        json!({
            "content": [{"type": "text", "text": "error"}],
            "isError": true,
        })
    }

    #[tokio::test]
    async fn test_create_task_returns_id_and_token() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let result = store.create_task(None).await;
        assert!(result.is_some());

        let (id, token) = result.unwrap();
        assert!(!id.is_empty());
        assert!(!token.is_cancelled());
    }

    #[tokio::test]
    async fn test_create_task_with_custom_ttl() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(Some(30_000)).await.unwrap();

        let info = store.get_task(&id).await.unwrap();
        assert_eq!(info.ttl, 30_000);
    }

    #[tokio::test]
    async fn test_create_task_at_capacity_returns_none() {
        let store = TaskStore::new(2, 60_000, 2_000);
        store.create_task(None).await.unwrap();
        store.create_task(None).await.unwrap();

        let result = store.create_task(None).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_task_returns_working_status() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();

        let info = store.get_task(&id).await.unwrap();
        assert_eq!(info.status, TaskStatus::Working);
        assert_eq!(info.poll_interval, 2_000);
    }

    #[tokio::test]
    async fn test_get_task_nonexistent_returns_none() {
        let store = TaskStore::new(10, 60_000, 2_000);
        assert!(store.get_task("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_complete_task_lifecycle() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();

        let info = store.complete_task(&id, test_result()).await.unwrap();
        assert_eq!(info.status, TaskStatus::Completed);

        let result = store.get_result(&id).await.unwrap();
        assert_eq!(result["content"][0]["text"], "ok");
    }

    #[tokio::test]
    async fn test_fail_task_lifecycle() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();

        let info = store
            .fail_task(&id, "SSH timeout", error_result())
            .await
            .unwrap();
        assert_eq!(info.status, TaskStatus::Failed);
        assert_eq!(info.status_message.as_deref(), Some("SSH timeout"));

        let result = store.get_result(&id).await.unwrap();
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_cancel_task_lifecycle() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, token) = store.create_task(None).await.unwrap();
        assert!(!token.is_cancelled());

        let info = store.cancel_task(&id).await.unwrap();
        assert_eq!(info.status, TaskStatus::Cancelled);
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn test_cancel_terminal_task_returns_error() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        store.complete_task(&id, test_result()).await;

        let result = store.cancel_task(&id).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("terminal"));
    }

    #[tokio::test]
    async fn test_cancel_nonexistent_task_returns_error() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let result = store.cancel_task("nonexistent").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[tokio::test]
    async fn test_double_complete_is_idempotent() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();

        store.complete_task(&id, test_result()).await;
        let info = store
            .complete_task(&id, json!({"other": "value"}))
            .await
            .unwrap();
        // Should still be completed with original result
        assert_eq!(info.status, TaskStatus::Completed);
        let result = store.get_result(&id).await.unwrap();
        assert_eq!(result["content"][0]["text"], "ok");
    }

    #[tokio::test]
    async fn test_list_tasks_empty() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (tasks, cursor) = store.list_tasks(None, 10).await.unwrap();
        assert!(tasks.is_empty());
        assert!(cursor.is_none());
    }

    #[tokio::test]
    async fn test_list_tasks_returns_all() {
        let store = TaskStore::new(10, 60_000, 2_000);
        store.create_task(None).await.unwrap();
        store.create_task(None).await.unwrap();
        store.create_task(None).await.unwrap();

        let (tasks, cursor) = store.list_tasks(None, 10).await.unwrap();
        assert_eq!(tasks.len(), 3);
        assert!(cursor.is_none());
    }

    #[tokio::test]
    async fn test_list_tasks_pagination() {
        let store = TaskStore::new(10, 60_000, 2_000);
        for _ in 0..5 {
            store.create_task(None).await.unwrap();
        }

        let (page1, cursor1) = store.list_tasks(None, 2).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert!(cursor1.is_some());

        let (page2, cursor2) = store.list_tasks(cursor1.as_deref(), 2).await.unwrap();
        assert_eq!(page2.len(), 2);
        assert!(cursor2.is_some());

        let (page3, cursor3) = store.list_tasks(cursor2.as_deref(), 2).await.unwrap();
        assert_eq!(page3.len(), 1);
        assert!(cursor3.is_none());
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        // 0ms TTL = immediate expiry
        let store = TaskStore::new(10, 0, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();

        // Task should be expired immediately
        assert!(store.get_task(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_removes_expired() {
        let store = TaskStore::new(10, 0, 2_000);
        store.create_task(None).await.unwrap();
        store.create_task(None).await.unwrap();

        store.cleanup().await;
        assert_eq!(store.len().await, 0);
    }

    #[tokio::test]
    async fn test_expired_tasks_freed_on_create() {
        // max 2 tasks, 0ms TTL
        let store = TaskStore::new(2, 0, 2_000);
        store.create_task(None).await.unwrap();
        store.create_task(None).await.unwrap();

        // Expired tasks should be cleaned up, allowing new creation
        let result = store.create_task(None).await;
        assert!(result.is_some());
    }

    // ============== State Transition Conflicts ==============

    #[tokio::test]
    async fn test_complete_after_cancel_is_no_op() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        store.cancel_task(&id).await.unwrap();

        // Completing a cancelled task should be a no-op (already terminal)
        let info = store.complete_task(&id, test_result()).await.unwrap();
        assert_eq!(info.status, TaskStatus::Cancelled);
        // Result should NOT be stored
        assert!(store.get_result(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_fail_after_cancel_is_no_op() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        store.cancel_task(&id).await.unwrap();

        let info = store
            .fail_task(&id, "too late", error_result())
            .await
            .unwrap();
        assert_eq!(info.status, TaskStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_cancel_after_fail_returns_error() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        store.fail_task(&id, "boom", error_result()).await;

        let result = store.cancel_task(&id).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("terminal"));
    }

    #[tokio::test]
    async fn test_double_fail_is_idempotent() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();

        store
            .fail_task(&id, "first error", error_result())
            .await
            .unwrap();
        let info = store
            .fail_task(&id, "second error", json!({"other": true}))
            .await
            .unwrap();
        // Should keep original failure
        assert_eq!(info.status, TaskStatus::Failed);
        assert_eq!(info.status_message.as_deref(), Some("first error"));
    }

    #[tokio::test]
    async fn test_double_cancel_returns_error() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        store.cancel_task(&id).await.unwrap();

        let result = store.cancel_task(&id).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("terminal"));
    }

    // ============== get_result Edge Cases ==============

    #[tokio::test]
    async fn test_get_result_nonexistent_returns_none() {
        let store = TaskStore::new(10, 60_000, 2_000);
        assert!(store.get_result("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_get_result_working_returns_none() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        // Working task has no result yet
        assert!(store.get_result(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_get_result_after_fail() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        store.fail_task(&id, "error", error_result()).await;

        let result = store.get_result(&id).await.unwrap();
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_get_result_after_cancel_returns_none() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        store.cancel_task(&id).await.unwrap();

        // Cancelled tasks have no result stored
        assert!(store.get_result(&id).await.is_none());
    }

    // ============== Pagination Edge Cases ==============

    #[tokio::test]
    async fn test_list_tasks_with_stale_cursor_is_rejected() {
        let store = TaskStore::new(10, 60_000, 2_000);
        store.create_task(None).await.unwrap();
        store.create_task(None).await.unwrap();

        // A cursor naming no live task used to silently restart from the
        // head, replaying a page the client had already consumed. TTL
        // eviction can stale a cursor mid-loop, so the caller must be able
        // to tell "start over" from "your cursor is gone".
        let err = store
            .list_tasks(Some("stale-cursor-id"), 10)
            .await
            .expect_err("a stale cursor must be an error, not a silent restart");
        assert_eq!(err.cursor, "stale-cursor-id");
        assert!(err.to_string().contains("stale-cursor-id"));
    }

    #[tokio::test]
    async fn test_list_tasks_valid_cursor_still_paginates() {
        let store = TaskStore::new(10, 60_000, 2_000);
        for _ in 0..3 {
            store.create_task(None).await.unwrap();
        }

        let (page1, cursor1) = store.list_tasks(None, 2).await.unwrap();
        assert_eq!(page1.len(), 2);
        let cursor1 = cursor1.expect("first page must yield a cursor");

        let (page2, cursor2) = store.list_tasks(Some(&cursor1), 2).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert!(cursor2.is_none());
    }

    #[tokio::test]
    async fn test_list_tasks_mixed_statuses() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id1, _) = store.create_task(None).await.unwrap();
        let (id2, _) = store.create_task(None).await.unwrap();
        let (id3, _) = store.create_task(None).await.unwrap();

        store.complete_task(&id1, test_result()).await;
        store.fail_task(&id2, "error", error_result()).await;
        store.cancel_task(&id3).await.unwrap();

        // All should be listed regardless of status
        let (tasks, _) = store.list_tasks(None, 10).await.unwrap();
        assert_eq!(tasks.len(), 3);

        let statuses: Vec<_> = tasks.iter().map(|t| t.status).collect();
        assert!(statuses.contains(&TaskStatus::Completed));
        assert!(statuses.contains(&TaskStatus::Failed));
        assert!(statuses.contains(&TaskStatus::Cancelled));
    }

    // ============== TTL Edge Cases ==============

    #[tokio::test]
    async fn test_custom_ttl_capped_at_default() {
        // Store has default TTL of 10_000ms
        let store = TaskStore::new(10, 10_000, 2_000);
        // Request a much larger TTL
        let (id, _) = store.create_task(Some(1_000_000)).await.unwrap();

        let info = store.get_task(&id).await.unwrap();
        // Should be capped to the store default
        assert_eq!(info.ttl, 10_000);
    }

    #[tokio::test]
    async fn test_is_empty() {
        let store = TaskStore::new(10, 60_000, 2_000);
        assert!(store.is_empty().await);

        store.create_task(None).await.unwrap();
        assert!(!store.is_empty().await);
    }

    // ============== Concurrent Access ==============

    #[tokio::test]
    async fn test_concurrent_access() {
        let store = Arc::new(TaskStore::new(100, 60_000, 2_000));

        let mut handles = Vec::new();
        for _ in 0..20 {
            let store = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                let (id, _) = store.create_task(None).await.unwrap();
                let info = store.get_task(&id).await.unwrap();
                assert_eq!(info.status, TaskStatus::Working);
                store.complete_task(&id, test_result()).await;
                let info = store.get_task(&id).await.unwrap();
                assert_eq!(info.status, TaskStatus::Completed);
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    /// MCP 2026-07-28 tasks are polled: no store method may park its caller.
    /// A source-text guard, because "this function does not exist" has no
    /// runtime expression. `include_str!` resolves relative to this file.
    ///
    /// Scoped to the production half of the file, split at the `mod tests`
    /// boundary: `include_str!` pulls in this very test, and its own
    /// assertion arguments are the literal strings `"fn wait_for_result"`
    /// and `"watch::Sender"` — scanning the whole file would make the guard
    /// match itself and fail unconditionally, regardless of whether the
    /// production code it is meant to police still exists.
    #[test]
    fn task_store_exposes_no_blocking_wait() {
        let src = include_str!("task_store.rs");
        let production = src
            .split_once("#[cfg(test)]\nmod tests {")
            .map_or(src, |(before, _)| before);
        assert!(
            !production.contains("fn wait_for_result"),
            "tasks are polled in 3.0.0 — `wait_for_result` reintroduces the \
             G-1 session freeze (issue #131) and must not exist"
        );
        assert!(
            !production.contains("watch::Sender"),
            "the watch channel existed only to wake `wait_for_result`"
        );
    }
}
