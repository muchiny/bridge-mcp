//! Task Store
//!
//! Thread-safe store for MCP Task lifecycle management (MCP 2025-11-25+).
//! Tasks wrap long-running tool executions and allow clients to poll for
//! status and retrieve results asynchronously.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::{RwLock, watch};
use tokio_util::sync::CancellationToken;

use crate::ports::protocol::{TaskInfo, TaskStatus};

/// Internal task entry stored in the registry.
struct TaskEntry {
    info: TaskInfo,
    /// Serialized `ToolCallResult` (set when task reaches a terminal state).
    result: Option<Value>,
    /// Token to cancel the background worker.
    cancel_token: CancellationToken,
    /// Signals `wait_for_result` waiters.
    ///
    /// A `watch` channel, not a `Notify`, because this must carry *state*
    /// rather than an edge. Two failures follow from an edge: a
    /// `notify_waiters()` landing between the waiter releasing the read
    /// guard and arming `notified()` was simply lost, and an entry evicted
    /// while a waiter was parked left nothing alive to ever notify it
    /// again. A `watch` receiver subscribed under the read guard observes
    /// any later send, and dropping this sender (which happens exactly when
    /// the entry leaves the map) resolves parked waiters instead of
    /// stranding them.
    ///
    /// It carries the RESULT, not a bare flag. A flag forced the woken waiter
    /// to look the entry up again, and TTL eviction winning that second race
    /// turned a genuinely completed task into `None` — indistinguishable from
    /// "never had a result" (issue #132). Publishing the value through the
    /// channel removes the second lookup entirely rather than narrowing the
    /// window.
    result_ready: watch::Sender<Option<Value>>,
    /// Monotonic creation time for TTL checks.
    created: Instant,
    /// Per-task TTL.
    ttl: Duration,
}

impl TaskEntry {
    fn is_terminal(&self) -> bool {
        matches!(
            self.info.status,
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
        )
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
        let (result_ready, _) = watch::channel(None);

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
            result_ready,
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
        entry.result_ready.send_replace(entry.result.clone());

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
        entry.result_ready.send_replace(entry.result.clone());

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
        entry.result_ready.send_replace(entry.result.clone());

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

    /// Wait until the task reaches a terminal state, then return the result.
    ///
    /// Returns `None` if the task doesn't exist.
    pub async fn wait_for_result(&self, task_id: &str) -> Option<Value> {
        // Subscribe while still holding the read guard. The terminal check
        // and the subscription are therefore atomic with respect to the
        // writers, which all take the write guard — so a completion cannot
        // slip through between the two.
        let mut rx = {
            let tasks = self.tasks.read().await;
            let entry = tasks.get(task_id)?;

            if entry.is_terminal() {
                return entry.result.clone();
            }

            entry.result_ready.subscribe()
        };

        // `changed()` errors only once every sender is gone, which happens
        // exactly when the entry is dropped from the map — TTL eviction while
        // this waiter was parked. Resolving with `None` is the honest answer;
        // the previous code waited forever for a notification nothing could
        // still send.
        if rx.changed().await.is_err() {
            return None;
        }

        // Read the value out of the channel, not out of the map. The entry may
        // already have been evicted by TTL — see the field's doc comment.
        rx.borrow_and_update().clone()
    }

    /// List tasks with cursor-based pagination.
    ///
    /// Tasks are sorted by creation time (task ID is UUID, so we sort by
    /// `created_at`). Returns `(tasks, next_cursor)`.
    pub async fn list_tasks(
        &self,
        cursor: Option<&str>,
        page_size: usize,
    ) -> (Vec<TaskInfo>, Option<String>) {
        let tasks = self.tasks.read().await;

        let mut entries: Vec<_> = tasks
            .values()
            .filter(|e| !e.is_expired())
            .map(|e| &e.info)
            .collect();

        // Sort by creation time for stable pagination
        entries.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        // Apply cursor: skip entries until we find the cursor task_id
        let start = if let Some(cursor_id) = cursor {
            entries
                .iter()
                .position(|info| info.task_id == cursor_id)
                .map_or(0, |pos| pos + 1)
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

        (page, next_cursor)
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
    async fn test_wait_for_result_already_terminal() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        store.complete_task(&id, test_result()).await;

        let result = tokio::time::timeout(Duration::from_secs(5), store.wait_for_result(&id))
            .await
            .expect("must not hang")
            .unwrap();
        assert_eq!(result["content"][0]["text"], "ok");
    }

    #[tokio::test]
    async fn test_wait_for_result_blocks_then_resolves() {
        let store = Arc::new(TaskStore::new(10, 60_000, 2_000));
        let (id, _) = store.create_task(None).await.unwrap();

        let store2 = Arc::clone(&store);
        let id2 = id.clone();
        let waiter = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), store2.wait_for_result(&id2)).await
        });

        // Small delay then complete
        tokio::time::sleep(Duration::from_millis(50)).await;
        store.complete_task(&id, test_result()).await;

        let result = waiter.await.unwrap().expect("must not hang").unwrap();
        assert_eq!(result["content"][0]["text"], "ok");
    }

    // Regression test straight from the audit brief: complete the task before
    // `wait_for_result` is even called. NOTE (see task-7-report.md for the
    // full write-up): this passes on both the old `Notify` code and the new
    // `watch` code, because it never reaches the notifier at all — the
    // sequential `.await`s here mean `complete_task` fully finishes (and the
    // entry is already terminal) before `wait_for_result` starts, so it
    // returns via the `is_terminal()` fast path either way. It is kept
    // because the brief specifies it verbatim, but
    // `wait_for_result_returns_none_when_evicted_while_parked` below is the
    // test that actually distinguishes old from new behavior.
    #[tokio::test(start_paused = true)]
    async fn wait_for_result_survives_a_completion_between_subscribe_and_await() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        // Complete in exactly the window the old code lost: after the guard would
        // have been released, before the waiter parks.
        store.complete_task(&id, test_result()).await;
        // 5s to match this file's other guards. The clock is paused, so this
        // never costs wall-clock; a round hour here trips a stable-only clippy
        // lint that wants `Duration::from_hours`, an API this crate's MSRV
        // (1.94) cannot be assumed to have.
        let got = tokio::time::timeout(Duration::from_secs(5), store.wait_for_result(&id))
            .await
            .expect("must not hang");
        assert!(got.is_some());
    }

    // A dropped `Sender` (entry evicted from the map) must resolve a parked
    // waiter with `None`, not park it forever. Non-zero TTL and no
    // `start_paused`: a 0ms TTL would make this vacuous (see task-7-report.md),
    // and TTL checks use `std::time::Instant`, which the paused tokio clock
    // does not advance.
    /// Issue #132. A task that genuinely completed must return its result even
    /// if TTL eviction removes the entry before the woken waiter re-reads the
    /// map. The old code signalled with a bare flag and then looked the entry
    /// up again, so losing that race turned a real result into `None` —
    /// indistinguishable from "this task never had one".
    #[tokio::test]
    async fn wait_for_result_yields_the_result_even_if_evicted_before_the_reread() {
        let store = Arc::new(TaskStore::new(10, 50, 2_000));
        let (id, _) = store.create_task(None).await.unwrap();

        let store2 = Arc::clone(&store);
        let id2 = id.clone();
        let waiter = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), store2.wait_for_result(&id2)).await
        });

        // Park the waiter AND let the 50ms TTL lapse first, so that complete
        // and evict can then run back-to-back with no sleep between them —
        // a sleep there hands the waiter its re-read and hides the race.
        tokio::time::sleep(Duration::from_millis(120)).await;

        store.complete_task(&id, test_result()).await;
        store.cleanup().await;
        assert!(store.is_empty().await, "entry should have been evicted");

        let result = waiter.await.unwrap().expect("must not hang");
        assert_eq!(
            result.expect("a completed task must not resolve to None")["content"][0]["text"],
            "ok"
        );
    }

    #[tokio::test]
    async fn wait_for_result_returns_none_when_evicted_while_parked() {
        let store = Arc::new(TaskStore::new(10, 50, 2_000));
        let (id, _) = store.create_task(None).await.unwrap();

        let store2 = Arc::clone(&store);
        let id2 = id.clone();
        let waiter = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), store2.wait_for_result(&id2)).await
        });

        // Give the waiter time to read the still-`Working` entry and park on
        // it, then let the 50ms TTL genuinely elapse (real wall-clock sleep)
        // and force the lazy-cleanup eviction.
        tokio::time::sleep(Duration::from_millis(200)).await;
        store.cleanup().await;
        assert!(store.is_empty().await, "entry should have been evicted");

        let result = waiter
            .await
            .unwrap()
            .expect("eviction must wake the parked waiter, not hang it");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_wait_for_result_nonexistent() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let result =
            tokio::time::timeout(Duration::from_secs(5), store.wait_for_result("nonexistent"))
                .await
                .expect("must not hang");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_list_tasks_empty() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (tasks, cursor) = store.list_tasks(None, 10).await;
        assert!(tasks.is_empty());
        assert!(cursor.is_none());
    }

    #[tokio::test]
    async fn test_list_tasks_returns_all() {
        let store = TaskStore::new(10, 60_000, 2_000);
        store.create_task(None).await.unwrap();
        store.create_task(None).await.unwrap();
        store.create_task(None).await.unwrap();

        let (tasks, cursor) = store.list_tasks(None, 10).await;
        assert_eq!(tasks.len(), 3);
        assert!(cursor.is_none());
    }

    #[tokio::test]
    async fn test_list_tasks_pagination() {
        let store = TaskStore::new(10, 60_000, 2_000);
        for _ in 0..5 {
            store.create_task(None).await.unwrap();
        }

        let (page1, cursor1) = store.list_tasks(None, 2).await;
        assert_eq!(page1.len(), 2);
        assert!(cursor1.is_some());

        let (page2, cursor2) = store.list_tasks(cursor1.as_deref(), 2).await;
        assert_eq!(page2.len(), 2);
        assert!(cursor2.is_some());

        let (page3, cursor3) = store.list_tasks(cursor2.as_deref(), 2).await;
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

    // ============== wait_for_result Edge Cases ==============

    #[tokio::test]
    async fn test_wait_for_result_on_failed_task() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        store.fail_task(&id, "boom", error_result()).await;

        let result = tokio::time::timeout(Duration::from_secs(5), store.wait_for_result(&id))
            .await
            .expect("must not hang")
            .unwrap();
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_wait_for_result_on_cancelled_task() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task(None).await.unwrap();
        store.cancel_task(&id).await.unwrap();

        // Cancelled task: wait returns immediately with None (no result)
        let result = tokio::time::timeout(Duration::from_secs(5), store.wait_for_result(&id))
            .await
            .expect("must not hang");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_wait_for_result_blocks_then_resolves_on_cancel() {
        let store = Arc::new(TaskStore::new(10, 60_000, 2_000));
        let (id, _) = store.create_task(None).await.unwrap();

        let store2 = Arc::clone(&store);
        let id2 = id.clone();
        let waiter = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), store2.wait_for_result(&id2)).await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        store.cancel_task(&id).await.unwrap();

        let result = waiter.await.unwrap().expect("must not hang");
        assert!(result.is_none());
    }

    // ============== Pagination Edge Cases ==============

    #[tokio::test]
    async fn test_list_tasks_with_stale_cursor() {
        let store = TaskStore::new(10, 60_000, 2_000);
        store.create_task(None).await.unwrap();
        store.create_task(None).await.unwrap();

        // Use a non-existent cursor — should return from the start
        let (tasks, _) = store.list_tasks(Some("stale-cursor-id"), 10).await;
        assert_eq!(tasks.len(), 2);
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
        let (tasks, _) = store.list_tasks(None, 10).await;
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
}
