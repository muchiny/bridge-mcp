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

/// Human-readable summary for a completed task's `statusMessage`.
///
/// **This function inspects a WIRE key from inside the domain layer**, which
/// is why it is named rather than inlined: `result` is an opaque `Value` to
/// this store, and reading `isError` out of it couples the domain to the
/// `ToolCallResult` shape defined in the ports layer. Three lines buried in
/// `complete_task` get moved or deleted without anyone meeting that question;
/// a named function with this comment keeps it in view.
///
/// It is tolerated here for one reason. MCP 2026-07-28 makes a tool call that
/// returned `isError: true` a COMPLETION, not a failure — so after that rule,
/// a clean result and a failed one share a status **by design**, and
/// `statusMessage` is the only field left that separates them for a human.
/// The operator who used to filter on `status == "failed"` has this sentence
/// and nothing else. Saying "successfully" over a failed playbook would be a
/// lie in the last readable field. The spec lists "Summaries for `completed`
/// status" as exactly this field's purpose.
///
/// The coupling is pre-existing, not new: `TaskEntry::result` is already
/// documented as a serialized `ToolCallResult`. If it ever widens further,
/// the honest fix is for the adapter to pass the summary in.
fn completion_summary(result: &Value) -> &'static str {
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        "Task completed with a tool error."
    } else {
        "Task completed successfully."
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
    ///
    /// Takes no TTL. MCP 2026-07-28 removed the client's ability to propose
    /// one — "the server picks it unilaterally" — so this method used to
    /// accept a `requested_ttl_ms` that it capped at the store default, and
    /// after `params.task` was deleted no caller could pass anything but
    /// `None`. The capping outlived the input it capped, exercised only by
    /// the tests that pinned it. The store's configured default is now the
    /// only source of a task's TTL.
    pub async fn create_task(&self) -> Option<(String, CancellationToken)> {
        let task_id = uuid::Uuid::new_v4().to_string();
        let ttl_ms = self.default_ttl_ms;

        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let cancel_token = CancellationToken::new();

        let entry = TaskEntry {
            info: TaskInfo {
                task_id: task_id.clone(),
                status: TaskStatus::Working,
                status_message: Some("Task is being processed.".to_string()),
                created_at: now.clone(),
                last_updated_at: now,
                // `Some`, always: this store evicts on TTL, so claiming
                // unlimited retention with `null` would be a lie. Clamping
                // rather than refusing: a TTL beyond `i64::MAX` ms is 292
                // million years.
                ttl_ms: Some(i64::try_from(ttl_ms).unwrap_or(i64::MAX)),
                poll_interval_ms: Some(
                    i64::try_from(self.default_poll_interval_ms).unwrap_or(i64::MAX),
                ),
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
        entry.info.status_message = Some(completion_summary(&result).to_string());
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

    /// Cancel a task. `None` means no such task; everything else is a
    /// successful cancellation request.
    ///
    /// Cancellation is COOPERATIVE and eventually consistent in MCP
    /// 2026-07-28: "The request signals intent, and the server decides
    /// whether and when to honor it", and a task "MAY ultimately reach a
    /// terminal status other than `cancelled` if the work finished before
    /// cancellation could take effect."
    ///
    /// So an already-terminal task is NOT an error here — it is precisely the
    /// race the spec describes, and the client is told it may delete its state
    /// as soon as it sends the request. The terminal state is returned
    /// untouched: overwriting a `completed` task with `cancelled` would
    /// destroy a result the client is entitled to fetch, and would report work
    /// that DID happen as work that was called off.
    pub async fn cancel_task(&self, task_id: &str) -> Option<TaskInfo> {
        let mut tasks = self.tasks.write().await;
        let entry = tasks.get_mut(task_id)?;

        if entry.is_terminal() {
            return Some(entry.info.clone());
        }

        entry.info.status = TaskStatus::Cancelled;
        entry.info.status_message = Some("Task was cancelled by request.".to_string());
        entry.info.last_updated_at =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        entry.cancel_token.cancel();

        Some(entry.info.clone())
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
        let result = store.create_task().await;
        assert!(result.is_some());

        let (id, token) = result.unwrap();
        assert!(!id.is_empty());
        assert!(!token.is_cancelled());
    }

    /// Supersedes `test_create_task_with_custom_ttl` AND
    /// `test_custom_ttl_capped_at_default`, which both exercised a
    /// client-proposed TTL: "There is no client-supplied TTL — the server
    /// picks it unilaterally." Nothing is left to propose, so nothing is left
    /// to cap.
    ///
    /// Two stores rather than one: a task carrying `Some(60_000)` proves
    /// nothing about where the number came from, because a hardcoded constant
    /// would satisfy it just as well. Two different defaults do.
    #[tokio::test]
    async fn create_task_takes_its_ttl_from_the_store() {
        let short = TaskStore::new(10, 30_000, 2_000);
        let long = TaskStore::new(10, 60_000, 2_000);

        let (short_id, _) = short.create_task().await.unwrap();
        let (long_id, _) = long.create_task().await.unwrap();

        assert_eq!(
            short.get_task(&short_id).await.unwrap().ttl_ms,
            Some(30_000)
        );
        assert_eq!(long.get_task(&long_id).await.unwrap().ttl_ms, Some(60_000));
    }

    #[tokio::test]
    async fn test_create_task_at_capacity_returns_none() {
        let store = TaskStore::new(2, 60_000, 2_000);
        store.create_task().await.unwrap();
        store.create_task().await.unwrap();

        let result = store.create_task().await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_task_returns_working_status() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task().await.unwrap();

        let info = store.get_task(&id).await.unwrap();
        assert_eq!(info.status, TaskStatus::Working);
        assert_eq!(info.poll_interval_ms, Some(2_000));
    }

    #[tokio::test]
    async fn test_get_task_nonexistent_returns_none() {
        let store = TaskStore::new(10, 60_000, 2_000);
        assert!(store.get_task("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_complete_task_lifecycle() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task().await.unwrap();

        let info = store.complete_task(&id, test_result()).await.unwrap();
        assert_eq!(info.status, TaskStatus::Completed);

        let result = store.get_result(&id).await.unwrap();
        assert_eq!(result["content"][0]["text"], "ok");
    }

    #[tokio::test]
    async fn test_fail_task_lifecycle() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task().await.unwrap();

        let info = store
            .fail_task(&id, "SSH timeout", error_result())
            .await
            .unwrap();
        assert_eq!(info.status, TaskStatus::Failed);
        assert_eq!(info.status_message.as_deref(), Some("SSH timeout"));

        let result = store.get_result(&id).await.unwrap();
        assert_eq!(result["isError"], true);
    }

    /// Both a clean result and a tool error land on `completed` — that IS the
    /// 2026-07-28 rule — so `statusMessage` is the only field left that tells
    /// a human which one happened.
    #[tokio::test]
    async fn complete_task_distinguishes_a_tool_error_in_its_status_message() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (ok_id, _) = store.create_task().await.unwrap();
        let (err_id, _) = store.create_task().await.unwrap();

        store.complete_task(&ok_id, test_result()).await;
        store.complete_task(&err_id, error_result()).await;

        let ok = store.get_task(&ok_id).await.unwrap();
        let err = store.get_task(&err_id).await.unwrap();

        assert_eq!(ok.status, TaskStatus::Completed);
        assert_eq!(err.status, TaskStatus::Completed);
        assert_ne!(
            ok.status_message, err.status_message,
            "the two outcomes are indistinguishable without this field"
        );
        assert_eq!(
            err.status_message.unwrap(),
            "Task completed with a tool error."
        );
        assert_eq!(ok.status_message.unwrap(), "Task completed successfully.");
    }

    #[tokio::test]
    async fn test_cancel_task_lifecycle() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, token) = store.create_task().await.unwrap();
        assert!(!token.is_cancelled());

        let info = store.cancel_task(&id).await.unwrap();
        assert_eq!(info.status, TaskStatus::Cancelled);
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    /// Supersedes `test_cancel_terminal_task_returns_error`, which asserted
    /// the refusal 2026-07-28 removed.
    ///
    /// The load-bearing half is the second assertion, not the first: a
    /// cancellation that "succeeds" by overwriting `completed` with
    /// `cancelled` would destroy a stored result the client may still fetch,
    /// and would report work that finished as work that was called off.
    async fn cancel_after_complete_is_accepted_and_changes_nothing() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task().await.unwrap();
        store.complete_task(&id, test_result()).await;

        let info = store
            .cancel_task(&id)
            .await
            .expect("a known task is never `not found`");
        assert_eq!(info.status, TaskStatus::Completed);

        let after = store.get_task(&id).await.unwrap();
        assert_eq!(after.status, TaskStatus::Completed);
        assert!(
            store.get_result(&id).await.is_some(),
            "the stored result must survive a late cancellation"
        );
    }

    #[tokio::test]
    /// The one case that stays an error: `None` means no such task, which is
    /// what the handler turns into `-32602`. Without this, `cancel_task`
    /// returning `Some` for everything would pass every other cancel test.
    async fn cancel_nonexistent_task_is_none() {
        let store = TaskStore::new(10, 60_000, 2_000);
        assert!(store.cancel_task("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_double_complete_is_idempotent() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task().await.unwrap();

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
    async fn test_ttl_expiry() {
        // 0ms TTL = immediate expiry
        let store = TaskStore::new(10, 0, 2_000);
        let (id, _) = store.create_task().await.unwrap();

        // Task should be expired immediately
        assert!(store.get_task(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_removes_expired() {
        let store = TaskStore::new(10, 0, 2_000);
        store.create_task().await.unwrap();
        store.create_task().await.unwrap();

        store.cleanup().await;
        assert_eq!(store.len().await, 0);
    }

    #[tokio::test]
    async fn test_expired_tasks_freed_on_create() {
        // max 2 tasks, 0ms TTL
        let store = TaskStore::new(2, 0, 2_000);
        store.create_task().await.unwrap();
        store.create_task().await.unwrap();

        // Expired tasks should be cleaned up, allowing new creation
        let result = store.create_task().await;
        assert!(result.is_some());
    }

    // ============== State Transition Conflicts ==============

    #[tokio::test]
    async fn test_complete_after_cancel_is_no_op() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task().await.unwrap();
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
        let (id, _) = store.create_task().await.unwrap();
        store.cancel_task(&id).await.unwrap();

        let info = store
            .fail_task(&id, "too late", error_result())
            .await
            .unwrap();
        assert_eq!(info.status, TaskStatus::Cancelled);
    }

    #[tokio::test]
    /// Supersedes `test_cancel_after_fail_returns_error`. Same rule as the
    /// completed case, on the other terminal status.
    async fn cancel_after_fail_is_accepted_and_changes_nothing() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task().await.unwrap();
        store.fail_task(&id, "boom", error_result()).await;

        let info = store.cancel_task(&id).await.expect("a known task");
        assert_eq!(info.status, TaskStatus::Failed);
        assert_eq!(
            store.get_task(&id).await.unwrap().status,
            TaskStatus::Failed
        );
    }

    #[tokio::test]
    async fn test_double_fail_is_idempotent() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task().await.unwrap();

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
    /// Supersedes `test_double_cancel_returns_error`. A client "MAY delete
    /// all state associated with the task as soon as it sends a
    /// cancellation", so it cannot know a second send is redundant — the
    /// second send must not be an error.
    async fn double_cancel_is_idempotent() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task().await.unwrap();
        store.cancel_task(&id).await.unwrap();

        let info = store.cancel_task(&id).await.expect("a known task");
        assert_eq!(info.status, TaskStatus::Cancelled);
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
        let (id, _) = store.create_task().await.unwrap();
        // Working task has no result yet
        assert!(store.get_result(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_get_result_after_fail() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task().await.unwrap();
        store.fail_task(&id, "error", error_result()).await;

        let result = store.get_result(&id).await.unwrap();
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_get_result_after_cancel_returns_none() {
        let store = TaskStore::new(10, 60_000, 2_000);
        let (id, _) = store.create_task().await.unwrap();
        store.cancel_task(&id).await.unwrap();

        // Cancelled tasks have no result stored
        assert!(store.get_result(&id).await.is_none());
    }

    // ============== TTL Edge Cases ==============

    #[tokio::test]
    async fn test_is_empty() {
        let store = TaskStore::new(10, 60_000, 2_000);
        assert!(store.is_empty().await);

        store.create_task().await.unwrap();
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
                let (id, _) = store.create_task().await.unwrap();
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
        // `expect`, never `map_or(src, ..)`: falling back to the WHOLE file
        // makes this guard scan its own assertion arguments, so it fails
        // unconditionally — red for a reason that has nothing to do with
        // the production code it polices, and the next reader "repairs"
        // the wrong thing. A missing boundary is a broken guard, and a
        // broken guard must say which of the two it is.
        let (production, _) = src.split_once("#[cfg(test)]\nmod tests {").expect(
            "the `#[cfg(test)] mod tests {` boundary must exist for this guard to scope itself",
        );
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
