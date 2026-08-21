use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Instant;

use serde_json::{Value, json};
use tokio::sync::{RwLock, Semaphore, mpsc};
use tokio::task::JoinSet;
use tracing::{Instrument, debug, error, info, warn};

use crate::config::{Config, ConfigWatcher};
use crate::domain::output_truncator::truncate_chars;
use crate::domain::{
    ExecuteCommandUseCase, OutputCache, TaskStore, TaskWaitOutcome, TunnelManager,
};
use crate::error::Result;
use crate::mcp::instructions;
use crate::ports::ExecutorRouter;
use crate::ports::ToolContext;
use crate::security::{AuditLogger, AuditWriterTask, CommandValidator, RateLimiter, Sanitizer};
use crate::ssh::SessionManager;

use super::completion_provider::DefaultCompletionProvider;
use super::logger::McpLogger;
use super::pending_requests::{ClientResponse, PendingRequests};
use super::progress::ProgressReporter;
use super::protocol::{IncomingMessage, JsonRpcMessage, RootsListResult};
use super::request_meta::RequestMeta;
use super::session_context::SessionContext;
use super::subscriptions::{NotificationTopic, SubscriptionRegistry, SubscriptionsListenParams};
use super::transport::{Session, Transport, stdio::StdioTransport};

use super::history::CommandHistory;
use super::prompt_registry::{PromptRegistry, create_default_prompt_registry};
use super::protocol::{
    BUILD_META_KEY, BUILD_REV, CANCELLED_ERROR_CODE, ClientInfo, CompletionRef, CompletionResult,
    CompletionsCapability, CompletionsCompleteParams, CompletionsCompleteResult, CreateTaskResult,
    Icon, InitializeParams, InitializeResult, JsonRpcError, JsonRpcNotification, JsonRpcRequest,
    JsonRpcResponse, LogLevel, LoggingCapability, LoggingSetLevelParams, PROTOCOL_VERSION,
    PromptsCapability, PromptsGetParams, PromptsGetResult, PromptsListResult, ResourcesCapability,
    ResourcesListResult, ResourcesReadParams, ResourcesReadResult, SERVER_ICON_URL, SERVER_NAME,
    SERVER_VERSION, SUPPORTED_PROTOCOL_VERSIONS, ServerCapabilities, ServerInfo, TaskCancelParams,
    TaskGetParams, TaskListParams, TaskListResult, TaskRequestsCapability, TaskResultParams,
    TaskToolsCapability, TasksCapability, ToolCallParams, ToolCallResult, ToolContent,
    ToolsCapability, ToolsListResult, WriterMessage,
};
use super::registry::{ToolRegistry, create_filtered_registry};
use super::resource_registry::{ResourceRegistry, create_default_resource_registry};

/// MCP Server that communicates over stdio
pub struct McpServer {
    config: Arc<RwLock<Config>>,
    validator: Arc<CommandValidator>,
    sanitizer: Arc<Sanitizer>,
    audit_logger: Arc<AuditLogger>,
    history: Arc<CommandHistory>,
    connection_pool: Arc<ExecutorRouter>,
    execute_use_case: Arc<ExecuteCommandUseCase>,
    rate_limiter: Arc<RateLimiter>,
    registry: ToolRegistry,
    prompt_registry: PromptRegistry,
    resource_registry: ResourceRegistry,
    session_manager: Arc<SessionManager>,
    tunnel_manager: Arc<TunnelManager>,
    output_cache: Arc<OutputCache>,
    task_store: Arc<TaskStore>,
    initialized: AtomicBool,
    concurrent_limit: Arc<Semaphore>,
    client_info: RwLock<Option<ClientInfo>>,
    /// Live `subscriptions/listen` subscriptions (MCP 2026-07-28).
    ///
    /// A notification type is delivered only to the subscriptions that
    /// named it; a session that never sent `subscriptions/listen`
    /// receives nothing. Entries are dropped when the session ends
    /// (`serve_session`) or when their channel closes (publish-time
    /// pruning).
    subscriptions: SubscriptionRegistry,
    /// Current minimum log level for MCP logging notifications.
    log_level: Arc<AtomicU8>,
    /// MCP logger for sending `notifications/message` to the client.
    /// Initialized in `run()` once the writer channel is ready.
    mcp_logger: Arc<RwLock<Option<Arc<McpLogger>>>>,
    /// Completion provider for argument auto-completion.
    completion_provider: DefaultCompletionProvider,
    /// Application metrics for token consumption analytics.
    metrics: Arc<crate::metrics::Metrics>,
}

/// Per-session map of in-flight JSON-RPC request ids to their
/// `CancellationToken`.
///
/// FIND-038 (audit 2026-05-09): the previous implementation kept a
/// server-singleton map keyed on the JSON-RPC `id` alone. Because the
/// `id` is caller-chosen and is NOT scoped to a session, a concurrent
/// client B could send `notifications/cancelled { requestId: "<A's id>" }`
/// and cancel an in-flight request belonging to client A.
///
/// Allocating a fresh `ActiveRequests` per session in
/// `serve_session()` makes lookups session-local: a cancel notification
/// arriving on session B can only ever drain session B's map.
///
/// `std::sync::Mutex` (not `tokio::sync::Mutex`) because we only hold the
/// lock for hashmap insert/remove — no `.await` inside the critical
/// section.
#[derive(Clone, Default)]
pub struct ActiveRequests(
    Arc<std::sync::Mutex<HashMap<String, tokio_util::sync::CancellationToken>>>,
);

impl ActiveRequests {
    /// Build a fresh empty active-requests map.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(std::sync::Mutex::new(HashMap::new())))
    }

    /// Register a new in-flight request and return its `CancellationToken`.
    ///
    /// The caller must call [`Self::unregister`] when the request completes
    /// (success or error) to avoid the map growing unbounded.
    #[must_use]
    pub fn register(&self, request_id: String) -> tokio_util::sync::CancellationToken {
        let token = tokio_util::sync::CancellationToken::new();
        if let Ok(mut map) = self.0.lock() {
            map.insert(request_id, token.clone());
        }
        token
    }

    /// Remove a request from the in-flight map.
    ///
    /// No-op if the request was already removed (e.g. cancelled before
    /// completion). Tolerates a poisoned mutex silently — losing track of
    /// one request is not worth a panic in a long-running server.
    pub fn unregister(&self, request_id: &str) {
        if let Ok(mut map) = self.0.lock() {
            map.remove(request_id);
        }
    }

    /// Cancel an in-flight request by ID.
    ///
    /// Returns `true` if a matching request was found and cancelled,
    /// `false` if the ID is unknown (already completed or never existed).
    ///
    /// The map entry is removed atomically with the cancel signal so a
    /// follow-up [`Self::unregister`] call from the spawned task becomes
    /// a no-op.
    pub fn cancel(&self, request_id: &str) -> bool {
        let token = match self.0.lock() {
            Ok(mut map) => map.remove(request_id),
            Err(_) => return false,
        };
        if let Some(token) = token {
            token.cancel();
            true
        } else {
            false
        }
    }

    /// Number of currently-registered in-flight requests. Test helper.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.lock().map_or(0, |m| m.len())
    }

    /// Snapshot of currently-registered request ids. Test helper.
    #[cfg(test)]
    fn contains(&self, id: &str) -> bool {
        self.0.lock().is_ok_and(|m| m.contains_key(id))
    }
}

/// Character cap on the serialized-arguments summary embedded in the
/// destructive-confirmation prompt.
const SUMMARY_MAX_CHARS: usize = 300;

/// Character cap on the `command` rendered into the destructive-confirmation
/// prompt. Mirrors the 4000-char cap `ElicitationService` already applies to
/// the diff: an uncapped command produces a prompt the operator cannot read,
/// let alone approve.
const PLAN_COMMAND_MAX_CHARS: usize = 2000;

/// Extract the `command` field from tool arguments for the destructive
/// confirmation plan, if present and a string. Returns `None` otherwise.
///
/// The command is truncated by **characters**, never bytes — a byte slice
/// through a multi-byte character panics, and the release profile aborts on
/// panic.
fn plan_command_from_args(arguments: Option<&Value>) -> Option<String> {
    arguments
        .and_then(|v| v.get("command"))
        .and_then(Value::as_str)
        .map(|cmd| {
            if cmd.chars().count() > PLAN_COMMAND_MAX_CHARS {
                format!(
                    "{}\n… (command truncated)",
                    truncate_chars(cmd, PLAN_COMMAND_MAX_CHARS)
                )
            } else {
                cmd.to_string()
            }
        })
}

impl McpServer {
    /// Create a new MCP server with the given configuration
    ///
    /// Returns the server and an optional audit writer task that must be spawned.
    pub fn new(config: Config) -> (Self, Option<AuditWriterTask>) {
        // Create command validator with pre-compiled regex patterns
        let validator = Arc::new(CommandValidator::new(&config.security));

        // Create sanitizer with advanced config (supports categories and custom replacements)
        // Also includes legacy sanitize_patterns for backward compatibility
        let known_secrets = config.collect_secret_values();
        let sanitizer = Arc::new(
            Sanitizer::from_config_with_legacy(
                &config.security.sanitize,
                &config.security.sanitize_patterns,
            )
            .with_known_secrets(&known_secrets),
        );

        // Create audit logger (async with background writer task)
        // Vuln 3 (audit 2026-05-09): wire a sanitizer so `event.command` is
        // masked before tracing emission AND before file write — the audit
        // log used to leak MYSQL_PWD/PGPASSWORD/Bearer tokens/webhook URLs.
        let sanitizer_for_audit =
            crate::security::Sanitizer::from_config(&config.security.sanitize)
                .with_known_secrets(&known_secrets);
        let (audit_logger, audit_task) =
            match AuditLogger::new_with_sanitizer(&config.audit, sanitizer_for_audit) {
                Ok((logger, task)) => (logger, task),
                Err(e) => {
                    warn!(error = %e, "Failed to create audit logger, using disabled logger");
                    (AuditLogger::disabled(), None)
                }
            };
        let audit_logger = Arc::new(audit_logger);

        // Create command history
        let history = Arc::new(CommandHistory::with_defaults());

        // Create executor router (protocol-aware connection dispatcher)
        let connection_pool = Arc::new(ExecutorRouter::with_defaults());

        // Create execute command use case
        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        // Create tool registry filtered by tool group configuration
        let registry = create_filtered_registry(&config.tool_groups);

        // Create prompt registry with default prompts
        let prompt_registry = create_default_prompt_registry();

        // Create resource registry with default handlers
        let resource_registry = create_default_resource_registry();

        // Create concurrency limiter using config value
        let max_concurrent = config.limits.max_concurrent_commands;
        let concurrent_limit = Arc::new(Semaphore::new(max_concurrent));

        // Create rate limiter (0 = disabled by default)
        let rate_limiter = Arc::new(RateLimiter::new(config.limits.rate_limit_per_second));

        // Create session manager for persistent shells
        let session_manager = Arc::new(SessionManager::new(config.sessions.clone()));

        // Create tunnel manager
        let tunnel_manager = Arc::new(TunnelManager::new(20));

        // Create output cache for paginated retrieval of truncated outputs
        let output_cache = Arc::new(OutputCache::new(
            config.limits.output_cache_ttl_seconds,
            config.limits.output_cache_max_entries,
        ));

        // Create task store for async task management (MCP 2025-11-25+)
        let task_store = Arc::new(TaskStore::new(
            config.limits.max_tasks,
            config.limits.max_task_ttl_ms,
            config.limits.task_poll_interval_ms,
        ));

        let server = Self {
            config: Arc::new(RwLock::new(config)),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool,
            execute_use_case,
            rate_limiter,
            registry,
            prompt_registry,
            resource_registry,
            session_manager,
            tunnel_manager,
            output_cache,
            task_store,
            initialized: AtomicBool::new(false),
            concurrent_limit,
            client_info: RwLock::new(None),
            subscriptions: SubscriptionRegistry::new(),
            log_level: Arc::new(AtomicU8::new(LogLevel::Warning.severity())),
            mcp_logger: Arc::new(RwLock::new(None)),
            completion_provider: DefaultCompletionProvider,
            metrics: Arc::new(crate::metrics::Metrics::new()),
        };

        (server, audit_task)
    }

    /// Allocate a fresh per-session pending-requests handle.
    ///
    /// Test helper used by `tests/multisession_isolation.rs` to verify
    /// that two sessions on the same `McpServer` instance get independent
    /// `Arc<PendingRequests>` instances (Vuln 8 audit 2026-05-09).
    /// Integration tests live in their own crate so this helper cannot
    /// be `#[cfg(test)]`; it is gated `#[doc(hidden)]` instead so it
    /// stays out of the public docs.
    #[doc(hidden)]
    #[must_use]
    pub fn allocate_session_pending_for_test(&self) -> Arc<PendingRequests> {
        Arc::new(PendingRequests::new())
    }

    /// Allocate a fresh per-session capabilities handle.
    ///
    /// Test helper used by `tests/multisession_isolation.rs` to verify
    /// that two sessions on the same `McpServer` instance get independent
    /// `Arc<SessionCapabilities>` instances (Vuln 9 audit 2026-05-09).
    /// Integration tests live in their own crate so this helper cannot
    /// be `#[cfg(test)]`; it is gated `#[doc(hidden)]` instead so it
    /// stays out of the public docs.
    #[doc(hidden)]
    #[must_use]
    pub fn allocate_session_capabilities_for_test(
        &self,
    ) -> Arc<crate::mcp::session_capabilities::SessionCapabilities> {
        Arc::new(crate::mcp::session_capabilities::SessionCapabilities::new())
    }

    /// Allocate a fresh per-session `ActiveRequests` handle.
    ///
    /// Test helper used by `tests/cross_session_cancel.rs` to verify
    /// that two sessions on the same `McpServer` instance get independent
    /// `ActiveRequests` instances (FIND-038 audit 2026-05-09).
    /// Integration tests live in their own crate so this helper cannot
    /// be `#[cfg(test)]`; it is gated `#[doc(hidden)]` instead so it
    /// stays out of the public docs.
    #[doc(hidden)]
    #[must_use]
    pub fn allocate_session_active_requests_for_test(&self) -> ActiveRequests {
        ActiveRequests::new()
    }

    /// Allocate a fresh per-session `runtime_max_output_chars` slot.
    ///
    /// Test helper used by `tests/per_session_state.rs` to verify
    /// that two sessions on the same `McpServer` instance get independent
    /// runtime override slots (FIND-033 audit 2026-05-09).
    #[doc(hidden)]
    #[must_use]
    pub fn allocate_session_runtime_max_output_for_test(&self) -> Arc<RwLock<Option<usize>>> {
        Arc::new(RwLock::new(None))
    }

    /// Allocate a fresh per-session resource-subscriptions map.
    ///
    /// Test helper used by `tests/per_session_state.rs` to verify
    /// that two sessions on the same `McpServer` instance get independent
    /// subscription maps (FIND-036 audit 2026-05-09).
    #[doc(hidden)]
    #[must_use]
    pub fn allocate_session_resource_subs_for_test(
        &self,
    ) -> Arc<RwLock<HashMap<String, Vec<String>>>> {
        Arc::new(RwLock::new(HashMap::new()))
    }

    /// Allocate a fresh per-session roots vec.
    ///
    /// Test helper used by `tests/per_session_state.rs` to verify
    /// that two sessions on the same `McpServer` instance get independent
    /// `Vec<RootEntry>` instances (FIND-037 audit 2026-05-09).
    #[doc(hidden)]
    #[must_use]
    pub fn allocate_session_roots_for_test(
        &self,
    ) -> Arc<RwLock<Vec<crate::mcp::protocol::RootEntry>>> {
        Arc::new(RwLock::new(Vec::new()))
    }

    /// Create a `ToolContext` for tool execution
    ///
    /// This reads a snapshot of the current configuration, ensuring
    /// consistent config values during a single tool execution.
    /// Build a `ToolContext` for a single request.
    ///
    /// Pass `cancel_token = Some(token)` to allow long-running tools to race
    /// their work against a MCP `notifications/cancelled`. Pass `None` for
    /// handlers that don't participate in cancellation (resources/list,
    /// prompts/get, etc.).
    /// Ask the client to confirm a destructive tool call via `elicitation/create`.
    ///
    /// Returns `Ok(())` when the operation is allowed (not destructive, feature
    /// disabled, or user confirmed). Returns `Err(msg)` with a user-facing
    /// reason string when the operation must be blocked (user declined,
    /// cancelled, elicitation unsupported, or transport unavailable).
    async fn check_destructive_elicitation(
        &self,
        tool_name: &str,
        arguments: Option<&Value>,
        session: Option<&SessionContext>,
    ) -> std::result::Result<(), String> {
        let require = {
            let cfg = self.config.read().await;
            cfg.security.require_elicitation_on_destructive
        };
        if !require {
            return Ok(());
        }

        let is_destructive = super::registry::tool_annotations(tool_name)
            .destructive_hint
            .unwrap_or(false);
        if !is_destructive {
            return Ok(());
        }

        // Per-session capabilities (Vuln 9 audit 2026-05-09): the server no
        // longer keeps a global `client_supports_elicitation` AtomicBool, so
        // the gate MUST consult THIS session's `SessionCapabilities`. Without
        // a session handle (legacy non-MCP code paths), refuse the operation
        // since we cannot prove the connected client advertised the capability.
        let Some(session) = session else {
            return Err(format!(
                "Tool `{tool_name}` is destructive and `require_elicitation_on_destructive` is enabled, but no session context is available — the operation cannot be confirmed."
            ));
        };
        if !session.supports_elicitation() {
            return Err(format!(
                "Tool `{tool_name}` is destructive and `require_elicitation_on_destructive` is enabled, but the client does not support elicitation. Either upgrade the client or set `security.require_elicitation_on_destructive: false`."
            ));
        }

        let tx = session.notification_tx.clone();
        // Per-session pending-requests map (Vuln 8 audit 2026-05-09): the
        // server no longer keeps a global handle, so the elicitation
        // round-trip MUST run against the session-local map.
        let pending = Arc::clone(&session.pending);

        let summary = arguments.map_or_else(
            || "(no arguments)".to_string(),
            |v| {
                let s = serde_json::to_string(v).unwrap_or_default();
                // Truncate by CHARACTERS: `&s[..300]` panics when byte 300
                // lands inside a multi-byte char (accented args are routine),
                // and `panic = "abort"` in the release profile turns that into
                // a full server kill.
                if s.chars().count() > SUMMARY_MAX_CHARS {
                    format!("{}… (truncated)", truncate_chars(&s, SUMMARY_MAX_CHARS))
                } else {
                    s
                }
            },
        );

        let requester = Arc::new(super::client_requester::ClientRequester::new(
            tx,
            pending,
            std::time::Duration::from_mins(2),
        ));
        let elicitation = super::elicitation::ElicitationService::new(requester);
        elicitation.set_supported(true);

        let plan = super::elicitation::ElicitationPlan {
            command: plan_command_from_args(arguments),
            diff: None,
        };
        match elicitation
            .confirm_destructive_with_plan(tool_name, &summary, Some(plan))
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) | Err(super::client_requester::ClientRequestError::Declined) => Err(format!(
                "User declined execution of destructive tool `{tool_name}`."
            )),
            Err(super::client_requester::ClientRequestError::Cancelled) => Err(format!(
                "User cancelled confirmation for destructive tool `{tool_name}`."
            )),
            Err(e) => Err(format!(
                "Elicitation failed for destructive tool `{tool_name}`: {e}"
            )),
        }
    }

    async fn create_tool_context(
        &self,
        cancel_token: Option<tokio_util::sync::CancellationToken>,
        progress_token: Option<Value>,
        session: Option<&SessionContext>,
    ) -> ToolContext {
        // Read config snapshot
        let mut config_snapshot = {
            let guard = self.config.read().await;
            guard.clone()
        };

        // Resolve the `client_overrides` profile from THIS request's
        // `io.modelcontextprotocol/clientInfo` (MCP 2026-07-28). Modern
        // clients never send `initialize`, so the handshake-time resolution
        // in `handle_initialize` never runs for them and the profile would
        // otherwise be silently ignored.
        if let Some(name) = session.and_then(SessionContext::request_client_name) {
            config_snapshot.limits.max_output_chars = config_snapshot
                .limits
                .effective_max_output_chars(Some(name));
        }

        // Apply per-session runtime override to the snapshot so handlers
        // see THIS session's effective value (FIND-033 audit 2026-05-09).
        // Applied AFTER the per-request profile above: `runtime_max_output`
        // is written by an explicit operator action (`ssh_config_set`) or by
        // a legacy `initialize`, and either must beat a name-matched profile.
        if let Some(s) = session
            && let Some(runtime_val) = *s.runtime_max_output.read().await
        {
            config_snapshot.limits.max_output_chars = runtime_val;
        }

        let mut ctx = ToolContext::new(
            Arc::new(config_snapshot),
            Arc::clone(&self.validator),
            Arc::clone(&self.sanitizer),
            Arc::clone(&self.audit_logger),
            Arc::clone(&self.history),
            Arc::clone(&self.connection_pool),
            Arc::clone(&self.execute_use_case),
            Arc::clone(&self.rate_limiter),
            Arc::clone(&self.session_manager),
        );
        ctx.tunnel_manager = Arc::clone(&self.tunnel_manager);
        ctx.output_cache = Some(Arc::clone(&self.output_cache));
        // Per-session runtime override slot exposed to `ssh_config_set`
        // (FIND-033 audit 2026-05-09). When the writer mutates this slot,
        // subsequent `create_tool_context` calls on the SAME session pick
        // up the new value — and only this session's tool calls are
        // affected.
        if let Some(s) = session {
            ctx.runtime_max_output_chars = Some(Arc::clone(&s.runtime_max_output));
            ctx.roots.clone_from(&*s.roots.read().await);
        }
        ctx.metrics = Some(Arc::clone(&self.metrics));
        ctx.cancel_token = cancel_token;
        ctx.notification_tx = session.map(|s| s.notification_tx.clone());
        ctx.progress_token = progress_token;
        ctx.pending_requests = session.map(|s| Arc::clone(&s.pending));
        // Per-session capabilities (Vuln 9 audit 2026-05-09): the server no
        // longer holds global `client_supports_*` flags. Snapshot the
        // current session's flags into `ToolContext`; default to `false`
        // when no session handle is available (legacy non-MCP code paths).
        ctx.client_supports_elicitation = session.is_some_and(SessionContext::supports_elicitation);
        ctx.client_supports_sampling = session.is_some_and(SessionContext::supports_sampling);
        ctx.mcp_logger = self.mcp_logger.read().await.as_ref().map(Arc::clone);
        ctx
    }

    /// Run the server over stdio (reading JSON-RPC from stdin, writing
    /// responses to stdout).
    ///
    /// This is a thin wrapper around [`Self::serve`] that plugs in the
    /// default [`StdioTransport`]. It exists so existing entry points
    /// (binary `main.rs`, tests) keep working unchanged while the daemon
    /// path can use [`Self::serve`] with a different transport.
    ///
    /// # Arguments
    ///
    /// * `audit_task` — optional background task for async audit logging.
    /// * `config_path` — optional path to config file for hot-reload support.
    ///
    /// # Errors
    ///
    /// Propagates any I/O error from the transport or its sessions.
    pub async fn run(
        self: Arc<Self>,
        audit_task: Option<AuditWriterTask>,
        config_path: Option<&Path>,
    ) -> Result<()> {
        let transport = StdioTransport::new();
        self.serve(transport, audit_task, config_path).await
    }

    /// Serve MCP requests over an arbitrary [`Transport`].
    ///
    /// Generic entry point that drives the accept loop: one `Session`
    /// per client, one spawned task per session. Cleanup tasks and the
    /// config watcher are owned by this method (global to the server
    /// instance, shared across all sessions).
    ///
    /// # Arguments
    ///
    /// * `transport` — any type implementing [`Transport`]. For stdio
    ///   this yields a single session and then `None`; for a Unix
    ///   socket listener it yields one session per client connection.
    /// * `audit_task` — optional audit writer background task.
    /// * `config_path` — optional config path for hot-reload watching.
    ///
    /// # Errors
    ///
    /// Returns an error only if the transport itself produces one.
    /// Per-session I/O errors are logged and close that session
    /// without aborting the accept loop.
    pub async fn serve<T: Transport>(
        self: Arc<Self>,
        mut transport: T,
        audit_task: Option<AuditWriterTask>,
        config_path: Option<&Path>,
    ) -> Result<()> {
        // Spawn audit writer task if enabled (global, shared).
        if let Some(task) = audit_task {
            tokio::spawn(task.run());
        }

        // Spawn cleanup tasks (global, shared across sessions).
        let cleanup_handles = self.spawn_cleanup_tasks();

        // Start config watcher. The watcher holds a closure that reads
        // the *current* `notification_tx` from the server each time a
        // reload fires — this keeps A.2 regression-free for stdio
        // (single session) and A.3 will make it per-session aware.
        let _config_watcher = config_path.and_then(|path| self.spawn_config_watcher(path));

        info!("Bridge MCP server starting...");

        // Accept loop: one session at a time, spawn into a JoinSet so we
        // can drain in-flight sessions before tearing down shared state.
        // Without the drain, a single-session transport like stdio would
        // exit `serve()` immediately after accept() returns None, killing
        // the spawned `serve_session` task before it has read a single
        // byte from stdin.
        let mut sessions: JoinSet<()> = JoinSet::new();
        while let Some(session) = transport.accept().await {
            let server = Arc::clone(&self);
            sessions.spawn(async move {
                server.serve_session(session).await;
            });
        }

        info!("Transport accept loop ended, draining in-flight sessions");

        while let Some(res) = sessions.join_next().await {
            if let Err(e) = res
                && !e.is_cancelled()
            {
                error!(error = %e, "session task failed");
            }
        }

        info!("All sessions drained, shutting down");

        // Shutdown global resources.
        for h in cleanup_handles {
            h.abort();
        }
        self.tunnel_manager.close_all().await;
        self.session_manager.close_all().await;
        self.connection_pool.close_all().await;
        transport.shutdown().await;

        Ok(())
    }

    /// Spawn the four per-server cleanup tasks (session manager, task
    /// store, output cache, connection pool) and return their join handles
    /// so the serve loop can abort them on shutdown.
    fn spawn_cleanup_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let cleanup_sm = Arc::clone(&self.session_manager);
        let sm_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_mins(1));
            loop {
                interval.tick().await;
                cleanup_sm.cleanup().await;
            }
        });

        let cleanup_ts = Arc::clone(&self.task_store);
        let ts_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_mins(1));
            loop {
                interval.tick().await;
                cleanup_ts.cleanup().await;
            }
        });

        let cleanup_oc = Arc::clone(&self.output_cache);
        let oc_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_mins(1));
            loop {
                interval.tick().await;
                cleanup_oc.cleanup().await;
            }
        });

        let cleanup_cp = Arc::clone(&self.connection_pool);
        let cp_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_mins(1));
            loop {
                interval.tick().await;
                cleanup_cp.cleanup().await;
            }
        });

        vec![sm_handle, ts_handle, oc_handle, cp_handle]
    }

    /// Start a config file watcher that publishes `list_changed`
    /// notifications on reload.
    ///
    /// FIND-034 (audit 2026-05-09) replaced a single global sender with a
    /// fanout, so the reload reached every live session. MCP 2026-07-28
    /// narrows that again: a server MUST NOT deliver a notification type
    /// nobody subscribed to. The reload therefore publishes through
    /// [`SubscriptionRegistry`], which delivers only to the subscriptions
    /// that named each topic in `subscriptions/listen` — a session that
    /// never subscribed now receives nothing at all.
    fn spawn_config_watcher(&self, path: &Path) -> Option<ConfigWatcher> {
        let subscriptions = self.subscriptions.clone();
        let on_reload: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            subscriptions.publish_topic(NotificationTopic::ToolsListChanged);
            subscriptions.publish_topic(NotificationTopic::ResourcesListChanged);
        });

        ConfigWatcher::with_notifications(
            path,
            Arc::clone(&self.config),
            Some(Arc::clone(&self.validator)),
            on_reload,
        )
        .map_err(|e| {
            warn!(error = %e, "Failed to start config watcher, hot-reload disabled");
            e
        })
        .ok()
    }

    /// Methods that must never queue behind the command-concurrency
    /// semaphore.
    ///
    /// G-1 (audit 2026-08-19): `limits.max_concurrent_commands` exists to
    /// cap concurrent *command execution*. Applying it to every method
    /// froze whole sessions, because the reader loop acquires the permit
    /// BEFORE it spawns the handler — so N parked `tasks/result` long
    /// polls (N = the limit, 5 by default) meant the client's next message
    /// was never read at all. Measured: N=4 still answered `ping`; N=5
    /// answered neither `ping` nor `tasks/cancel` — the one request that
    /// could have released the parked polls — and was still dead after
    /// 208 s.
    ///
    /// Neither `ping` nor any `tasks/*` method does remote work, so
    /// exempting them costs no concurrency budget. Task-augmented
    /// `tools/call` work is governed instead by the permit the task worker
    /// itself takes in `handle_tools_call_async`.
    fn is_concurrency_exempt(method: &str) -> bool {
        method == "ping" || method.starts_with("tasks/")
    }

    /// Drive one full client session: spawn a per-session writer task,
    /// then run the reader loop dispatching JSON-RPC requests.
    ///
    /// The writer is moved into its own `tokio::spawn` so it can run
    /// concurrently with the reader; notifications and responses are
    /// multiplexed through the `mpsc::Sender<WriterMessage>` that
    /// [`Self::notification_tx`] caches for this session.
    #[allow(clippy::too_many_lines)]
    async fn serve_session(self: Arc<Self>, session: Session) {
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(100);

        // Allocate the per-session bundle: pending-requests map (Vuln 8),
        // capability flags (Vuln 9), active-requests map (FIND-038),
        // notification tx, runtime override slot (FIND-033), resource
        // subscriptions map (FIND-036), and roots vec (FIND-037). Every
        // field is Arc-wrapped so cloning the bundle into spawned tasks
        // is cheap.
        let session_ctx = SessionContext::new(tx.clone());

        // Create / refresh MCP logger (writes `notifications/message`
        // to the client) now that we have a tx for this session.
        // FIND-035: McpLogger is gated by the SESSION's log_level so
        // `notifications/setLevel` from this client cannot mute another
        // client's notifications.
        let mcp_logger = Arc::new(McpLogger::new(
            Arc::clone(&session_ctx.log_level),
            tx.clone(),
        ));
        *self.mcp_logger.write().await = Some(Arc::clone(&mcp_logger));

        // Writer task: consume the channel, forward every message to
        // the session's writer half. The writer is moved in here; it
        // cannot be shared (SessionWriter is Send but not Sync).
        let mut session_writer = session.writer;
        let writer_handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = session_writer.send(msg).await {
                    error!(error = %e, "Session writer failed, closing");
                    break;
                }
            }
        });

        // Reader loop: pull parsed messages from the session reader
        // and dispatch them exactly like the legacy stdin loop.
        let mut reader = session.reader;
        info!("MCP session started");

        while let Some(msg_result) = reader.recv().await {
            let incoming = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    error!(error = %e, "Failed to parse message");
                    let response = JsonRpcResponse::error(
                        None,
                        JsonRpcError::parse_error(format!("Invalid JSON: {e}")),
                    );
                    let _ = tx.send(WriterMessage::Response(Box::new(response))).await;
                    continue;
                }
            };

            match incoming {
                IncomingMessage::Single(message) => {
                    let Some(request) = Self::route_incoming_message(message, &session_ctx) else {
                        continue;
                    };

                    // Acquire permit (blocks if at concurrency limit).
                    // Control-plane methods are exempt — see
                    // `is_concurrency_exempt` for why blocking here is a
                    // whole-session freeze and not just a queue.
                    let permit = if Self::is_concurrency_exempt(&request.method) {
                        None
                    } else if let Ok(permit) = self.concurrent_limit.clone().acquire_owned().await {
                        Some(permit)
                    } else {
                        error!("Semaphore closed unexpectedly");
                        break;
                    };

                    let server = Arc::clone(&self);
                    let tx = tx.clone();

                    // Register the request so `notifications/cancelled`
                    // can find its `CancellationToken`. We normalize
                    // the id to a String the same way
                    // `route_incoming_message` does.
                    let request_id: Option<String> = request.id.as_ref().map(|v| match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    });
                    let cancel_token = request_id
                        .as_ref()
                        .map(|id| session_ctx.active_requests.register(id.clone()));
                    // Kept alongside the token moved into the handler below
                    // so the send site can confirm the token ACTUALLY fired
                    // — see `should_write_back`.
                    let cancel_token_for_suppression = cancel_token.clone();
                    let rid_cleanup = request_id;
                    let session_ctx_for_task = session_ctx.clone();

                    // Attach request-scoped tracing fields. `.instrument()`
                    // (not `.entered()`) because `EnteredSpan` is not
                    // `Send` and can't cross await points in a spawned
                    // task.
                    let span = tracing::info_span!(
                        "mcp.request",
                        id = ?rid_cleanup,
                        method = %request.method,
                    );
                    tokio::spawn(
                        async move {
                            let response = server
                                .handle_request_with_cancel(
                                    request,
                                    cancel_token,
                                    Some(&session_ctx_for_task),
                                )
                                .await;
                            let token_was_cancelled = cancel_token_for_suppression
                                .as_ref()
                                .is_some_and(tokio_util::sync::CancellationToken::is_cancelled);
                            if McpServer::should_write_back(&response, token_was_cancelled) {
                                let _ = tx.send(WriterMessage::Response(Box::new(response))).await;
                            } else {
                                debug!(
                                    id = ?rid_cleanup,
                                    "Suppressing response for a cancelled request"
                                );
                            }
                            if let Some(rid) = rid_cleanup {
                                session_ctx_for_task.active_requests.unregister(&rid);
                            }
                            drop(permit);
                        }
                        .instrument(span),
                    );
                }
                IncomingMessage::Batch(messages) => {
                    if messages.is_empty() {
                        let response = JsonRpcResponse::error(
                            None,
                            JsonRpcError::invalid_request("Empty batch"),
                        );
                        let _ = tx.send(WriterMessage::Response(Box::new(response))).await;
                        continue;
                    }

                    // Reject batches containing `initialize` (MCP spec)
                    let has_initialize = messages
                        .iter()
                        .any(|m| m.method.as_deref() == Some("initialize"));
                    if has_initialize {
                        let response = JsonRpcResponse::error(
                            None,
                            JsonRpcError::invalid_request(
                                "initialize must not be part of a batch request",
                            ),
                        );
                        let _ = tx.send(WriterMessage::Response(Box::new(response))).await;
                        continue;
                    }

                    // Execute batch requests in parallel
                    let server = Arc::clone(&self);
                    let tx_batch = tx.clone();
                    tokio::spawn(async move {
                        let mut handles = Vec::with_capacity(messages.len());
                        for message in messages {
                            let server = Arc::clone(&server);
                            handles.push(tokio::spawn(async move {
                                // Notifications (no method) don't produce responses
                                let method = message.method?;
                                let request = JsonRpcRequest {
                                    jsonrpc: message.jsonrpc,
                                    id: message.id,
                                    method,
                                    params: message.params,
                                };
                                // Notifications (no id) don't produce responses per JSON-RPC 2.0
                                let is_notification = request.id.is_none();
                                let response = server.handle_request(request).await;
                                if is_notification {
                                    None
                                } else {
                                    Some(response)
                                }
                            }));
                        }
                        let mut responses = Vec::new();
                        for handle in handles {
                            if let Ok(Some(response)) = handle.await {
                                responses.push(response);
                            }
                        }
                        if !responses.is_empty() {
                            let _ = tx_batch.send(WriterMessage::BatchResponse(responses)).await;
                        }
                    });
                }
            }
        }

        info!("Client disconnected, session ending");

        // Drop every subscription this session opened. The spec's "never
        // deliver an unrequested notification type" invariant is only
        // maintainable if dead subscriptions cannot linger behind a
        // reused channel.
        self.subscriptions.remove_for_tx(&tx);

        // Signal writer to stop and wait for it.
        drop(tx);
        let _ = writer_handle.await;
    }

    /// Whether a finished request's response should be written back.
    ///
    /// MCP: after a `notifications/cancelled`, the receiver SHOULD NOT send
    /// a result or an error for the cancelled request id. Returning the
    /// -32800 envelope violated that. The envelope is still built inside
    /// `handle_tools_call` — the HTTP transport has no cancellation
    /// notification path and needs a terminal answer — so the suppression
    /// lives here, at the stdio write site.
    fn should_send_response(response: &JsonRpcResponse) -> bool {
        response
            .error
            .as_ref()
            .is_none_or(|e| e.code != CANCELLED_ERROR_CODE)
    }

    /// Whether a finished request's response should be written back, given
    /// whether its own per-request `CancellationToken` actually fired.
    ///
    /// `should_send_response` alone keys on the error CODE. That is correct
    /// today only because `CANCELLED_ERROR_CODE` has exactly one producer:
    /// the token registered for this request id, fired by
    /// `notifications/cancelled` (see `handle_cancellation_notification`).
    /// Requiring `token_was_cancelled` too means a future -32800 producer
    /// unrelated to a real cancellation cannot silently vanish here.
    fn should_write_back(response: &JsonRpcResponse, token_was_cancelled: bool) -> bool {
        Self::should_send_response(response) || !token_was_cancelled
    }

    /// Parse an incoming line as a single JSON-RPC message or a batch.
    pub fn parse_incoming(
        trimmed: &str,
    ) -> std::result::Result<IncomingMessage, serde_json::Error> {
        let trimmed = trimmed.trim_start();
        if trimmed.starts_with('[') {
            let batch: Vec<JsonRpcMessage> = serde_json::from_str(trimmed)?;
            Ok(IncomingMessage::Batch(batch))
        } else {
            let msg: JsonRpcMessage = serde_json::from_str(trimmed)?;
            Ok(IncomingMessage::Single(msg))
        }
    }

    /// Route a single incoming message: client response or client request.
    ///
    /// Returns `Some(JsonRpcRequest)` if it's a request to be dispatched,
    /// or `None` if it was handled inline (e.g., a client response or notification).
    ///
    /// The `session_pending` argument is the per-session pending-requests
    /// map (Vuln 8 audit 2026-05-09). Client responses to server-initiated
    /// requests are resolved against THIS session's map only — a different
    /// client on the same daemon cannot resolve a request another session
    /// initiated.
    ///
    /// The `session_active_requests` argument is the per-session
    /// active-requests map (FIND-038 audit 2026-05-09). Client cancel
    /// notifications are dispatched against THIS session's map only — a
    /// different client cannot cancel a request another session is
    /// running.
    /// Synchronous by design (audit 2026-08-02): this runs inside
    /// `serve_session`'s reader loop, so anything awaited here stalls the
    /// only task able to read the client's next message. Work that needs
    /// to await — including the `roots/list` round-trip — is spawned.
    fn route_incoming_message(
        message: JsonRpcMessage,
        session: &SessionContext,
    ) -> Option<JsonRpcRequest> {
        // If no method, it's a response to a server-initiated request (elicitation/sampling)
        if message.method.is_none() {
            if let Some(id) = &message.id {
                let id_str = match id {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let response = if let Some(error) = message.error {
                    ClientResponse::Error {
                        code: error.code,
                        message: error.message,
                        data: error.data,
                    }
                } else {
                    ClientResponse::Success(message.result.unwrap_or(Value::Null))
                };
                if !session.pending.resolve(&id_str, response) {
                    debug!(id = %id_str, "Received response for unknown request ID");
                }
            }
            return None;
        }

        // Handle client notifications (no response needed per JSON-RPC 2.0)
        if message.method.as_deref() == Some("notifications/roots/list_changed") {
            // This branch bypasses `handle_request_with_cancel`, so attach
            // the notification's own `_meta` envelope here — otherwise a
            // Modern client that declares `roots` per-request would be
            // ignored by the `supports_roots()` gate in `spawn_fetch_roots`.
            let scoped =
                session.with_request_meta(RequestMeta::from_params(message.params.as_ref()));
            Self::handle_roots_changed(&scoped);
            return None;
        }
        if message.method.as_deref() == Some("notifications/cancelled") {
            Self::handle_cancellation_notification(
                &session.active_requests,
                message.params.as_ref(),
            );
            return None;
        }
        if message.method.as_deref() == Some("notifications/initialized") {
            Self::handle_initialized_notification(session);
            return None;
        }

        // Anything still here with no `id` is a JSON-RPC Notification we do
        // not act on — `notifications/progress` against a server-issued
        // progressToken is the reachable case. JSON-RPC 2.0 §4.1 forbids
        // replying to a Notification; the old code fell through and built a
        // request whose response carried no id at all.
        if message.id.is_none() {
            debug!(
                method = message.method.as_deref().unwrap_or("<none>"),
                "Ignoring unhandled JSON-RPC notification (no id, no response sent)"
            );
            return None;
        }

        // It's a client request — convert to JsonRpcRequest
        Some(JsonRpcRequest {
            jsonrpc: message.jsonrpc,
            id: message.id,
            method: message.method.unwrap_or_default(),
            params: message.params,
        })
    }

    /// Start a roots fetch **off** the session reader loop.
    ///
    /// Audit 2026-08-02: [`Self::fetch_roots`] must never be awaited from
    /// `route_incoming_message`, because that runs inside
    /// `serve_session`'s reader loop — the only place the client's
    /// `roots/list` *response* can be read. Awaiting inline deadlocked the
    /// session against itself until the 10s `ClientRequester` timeout
    /// expired, delaying the first `tools/list` of every session that
    /// advertises the `roots` capability.
    ///
    /// Fire-and-forget is correct here: nothing in the request path reads
    /// `session.roots` synchronously, and a client that never answers
    /// simply leaves the slot empty.
    fn spawn_fetch_roots(session: &SessionContext) {
        if !session.supports_roots() {
            return;
        }
        let session = session.clone();
        tokio::spawn(async move {
            Self::fetch_roots(&session).await;
        });
    }

    /// Fetch roots from the client after initialization.
    ///
    /// Uses the SESSION-LOCAL pending-requests map so a `roots/list`
    /// response coming back from the client is resolved against this
    /// session only (Vuln 8 audit 2026-05-09). The fetched roots are
    /// stored on the session-local roots slot (FIND-037 audit
    /// 2026-05-09): a different client's `roots/list` response cannot
    /// overwrite this session's roots.
    ///
    /// Always call via [`Self::spawn_fetch_roots`] from the reader loop —
    /// awaiting this inline deadlocks the session (audit 2026-08-02).
    async fn fetch_roots(session: &SessionContext) {
        if !session.supports_roots() {
            return;
        }

        let requester = super::client_requester::ClientRequester::new(
            session.notification_tx.clone(),
            Arc::clone(&session.pending),
            std::time::Duration::from_secs(10),
        );

        match requester.send_request("roots/list", json!({})).await {
            Ok(value) => {
                if let Ok(result) = serde_json::from_value::<RootsListResult>(value) {
                    info!(count = result.roots.len(), "Received client roots");
                    *session.roots.write().await = result.roots;
                }
            }
            Err(e) => {
                debug!(error = %e, "Failed to fetch roots from client");
            }
        }
    }

    /// Handle `notifications/roots/list_changed` — re-fetch roots.
    fn handle_roots_changed(session: &SessionContext) {
        info!("Client roots changed, re-fetching");
        Self::spawn_fetch_roots(session);
    }

    /// Handle `notifications/initialized` — fetch client roots if supported.
    /// No response is emitted (per JSON-RPC 2.0 notification semantics).
    fn handle_initialized_notification(session: &SessionContext) {
        info!("Client sent notifications/initialized; fetching roots");
        Self::spawn_fetch_roots(session);
    }

    /// Handle a single JSON-RPC request and return the response.
    ///
    /// This is the public stable API — it always calls the dispatch with
    /// `cancel_token = None`, meaning cancellation is not wired for this
    /// request. The stdio `run()` loop uses the internal
    /// `handle_request_with_cancel` variant to honor MCP
    /// `notifications/cancelled`.
    ///
    /// Server-to-client features (elicitation, sampling) are unavailable on
    /// this code path because no per-session pending-requests map is
    /// supplied. Use [`Self::serve`] / `Self::serve_session` (private) for full
    /// MCP feature support.
    pub async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        self.handle_request_with_cancel(request, None, None).await
    }

    /// Dispatch a JSON-RPC request with an optional cancellation token
    /// and an optional per-session notification sender.
    ///
    /// The token is propagated to `handle_tools_call` (synchronous path),
    /// where it reaches the `ToolContext` so long-running handlers can race
    /// their SSH work against `token.cancelled()`.
    ///
    /// The `notification_tx` channel lets tool handlers send
    /// server-initiated messages (elicitation, sampling, progress,
    /// logging) back to *this specific client session* — which is the
    /// critical bit for multi-session transports like the daemon Unix
    /// socket, where a global sender would race across clients.
    ///
    /// Other methods ignore the token either because they are fast
    /// (tools/list, prompts/get, resources/read) or because they have their
    /// own cancellation mechanism (tools/call async via `tasks/cancel`).
    pub(crate) async fn handle_request_with_cancel(
        &self,
        request: JsonRpcRequest,
        cancel_token: Option<tokio_util::sync::CancellationToken>,
        session: Option<&SessionContext>,
    ) -> JsonRpcResponse {
        let id = request.id.clone();

        // Per-request `_meta` envelope (MCP 2026-07-28). Parsed ONCE here,
        // at the single dispatch chokepoint, and attached to a per-request
        // clone of the session bundle. Every downstream consumer already
        // receives `Option<&SessionContext>`, so no handler signature
        // changes. Parsing must happen before `handle_tools_call`, which
        // consumes `params` by value into `ToolCallParams`.
        let scoped_session =
            session.map(|s| s.with_request_meta(RequestMeta::from_params(request.params.as_ref())));
        let session = scoped_session.as_ref();

        match request.method.as_str() {
            "initialize" => self.handle_initialize(id, request.params, session).await,
            "tools/list" => self.handle_tools_list(id, request.params.as_ref()).await,
            "tools/call" => {
                self.handle_tools_call(id, request.params, cancel_token, session)
                    .await
            }
            "prompts/list" => self.handle_prompts_list(id),
            "prompts/get" => self.handle_prompts_get(id, request.params).await,
            "resources/list" => self.handle_resources_list(id).await,
            "resources/read" => self.handle_resources_read(id, request.params).await,
            "tasks/get" => self.handle_tasks_get(id, request.params).await,
            "tasks/result" => self.handle_tasks_result(id, request.params).await,
            "tasks/list" => self.handle_tasks_list(id, request.params).await,
            "tasks/cancel" => self.handle_tasks_cancel(id, request.params).await,
            // The 2025-06-18 schema names this method `completion/complete`
            // (SINGULAR) and that is the ONLY spelling the installed client
            // sends. The plural was carried over from an earlier draft; keep
            // both so neither client generation gets -32601.
            "completion/complete" | "completions/complete" => {
                self.handle_completions_complete(id, request.params)
            }
            "logging/setLevel" => self.handle_logging_set_level(id, request.params, session),
            "resources/templates/list" => self.handle_resource_templates_list(id),
            "resources/subscribe" => Self::handle_resource_subscribe(id, request.params, session),
            "resources/unsubscribe" => {
                Self::handle_resource_unsubscribe(id, request.params, session)
            }
            "subscriptions/listen" => {
                self.handle_subscriptions_listen(id, request.params, session)
                    .await
            }
            "ping" => JsonRpcResponse::success(id, json!({})),
            _ => {
                error!(method = %request.method, "Unknown method");
                JsonRpcResponse::error(id, JsonRpcError::method_not_found(&request.method))
            }
        }
    }

    /// Build the server extensions map based on current configuration.
    ///
    /// Auto-detects: tasks (always), output-pagination (always, since
    /// `OutputCache` is always created), multi-host (if >1 host configured).
    async fn build_server_extensions(&self) -> Option<HashMap<String, Value>> {
        use super::protocol::extensions;

        let mut exts = HashMap::new();
        exts.insert(extensions::TASKS.to_string(), json!({}));
        exts.insert(extensions::OUTPUT_PAGINATION.to_string(), json!({}));

        let host_count = self.config.read().await.hosts.len();
        if host_count > 1 {
            exts.insert(
                extensions::MULTI_HOST.to_string(),
                json!({ "hosts": host_count }),
            );
        }

        Some(exts)
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_initialize(
        &self,
        id: Option<Value>,
        params: Option<Value>,
        session: Option<&SessionContext>,
    ) -> JsonRpcResponse {
        // Parse initialize params, negotiate version, and store client info
        let mut negotiated_version = PROTOCOL_VERSION.to_string();

        if let Some(p) = params {
            // Read `protocolVersion` off the RAW value before the typed
            // deserialize can swallow it. `InitializeParams` requires
            // `clientInfo`, so a client that omits only `clientInfo.version`
            // lost BOTH its requested protocol version and its advertised
            // `capabilities.elicitation` to the `Err` arm below. The version
            // is the one field we can always recover; do that first.
            if let Some(requested) = p.get("protocolVersion").and_then(Value::as_str)
                && SUPPORTED_PROTOCOL_VERSIONS.contains(&requested)
            {
                negotiated_version = requested.to_string();
            }

            match serde_json::from_value::<InitializeParams>(p) {
                Ok(init_params) => {
                    info!(
                        client = %init_params.client_info.name,
                        version = %init_params.client_info.version,
                        protocol = %init_params.protocol_version,
                        "Client connected"
                    );

                    // MCP version negotiation: echo client version if we support it,
                    // otherwise respond with our latest version
                    if SUPPORTED_PROTOCOL_VERSIONS.contains(&init_params.protocol_version.as_str())
                    {
                        negotiated_version = init_params.protocol_version.clone();
                    }

                    // Resolve per-client max_output_chars override
                    let (effective, yaml_default) = {
                        let config = self.config.read().await;
                        (
                            config
                                .limits
                                .effective_max_output_chars(Some(&init_params.client_info.name)),
                            config.limits.max_output_chars,
                        )
                    };
                    if effective != yaml_default {
                        info!(
                            client = %init_params.client_info.name,
                            max_output_chars = effective,
                            "Applied client-specific max_output_chars override"
                        );
                        // Per-session runtime override (FIND-033 audit 2026-05-09):
                        // write to THIS session's slot only; concurrent clients
                        // with different `client_overrides` profiles do not
                        // contaminate each other.
                        if let Some(s) = session {
                            *s.runtime_max_output.write().await = Some(effective);
                        }
                    }

                    // Per-session capabilities (Vuln 9 audit 2026-05-09): write
                    // each client's advertised flags to its OWN
                    // `SessionCapabilities`, not a server-wide AtomicBool. The
                    // legacy non-MCP code paths (`handle_request`) pass `None`
                    // and silently drop these flags — that's fine because they
                    // also can't initiate elicitation/sampling/roots.
                    if init_params.capabilities.roots.is_some() {
                        if let Some(s) = session {
                            s.caps.set_supports_roots(true);
                        }
                        info!("Client supports roots capability");
                    }

                    if init_params.capabilities.elicitation.is_some() {
                        if let Some(s) = session {
                            s.caps.set_supports_elicitation(true);
                        }
                        info!("Client supports elicitation capability");
                    }

                    if init_params.capabilities.sampling.is_some() {
                        if let Some(s) = session {
                            s.caps.set_supports_sampling(true);
                        }
                        info!("Client supports sampling capability");
                    }

                    *self.client_info.write().await = Some(init_params.client_info);
                }
                Err(e) => {
                    // Not fatal — the spec lets us fall forward — but this
                    // silently costs the client its advertised capabilities
                    // (elicitation, sampling, roots) and its clientInfo, so
                    // it must be visible at the default log level.
                    warn!(
                        error = %e,
                        negotiated_version = %negotiated_version,
                        "Could not parse initialize params; client capabilities and clientInfo \
                         are being ignored for this session"
                    );
                }
            }
        }

        self.initialized.store(true, Ordering::SeqCst);

        let instructions = {
            let config = self.config.read().await;
            instructions::build_instructions(&config, self.registry.len())
        };

        let result = InitializeResult {
            protocol_version: negotiated_version,
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: true }),
                prompts: Some(PromptsCapability { list_changed: true }),
                resources: Some(ResourcesCapability {
                    // G-6 (audit 2026-08-19): NOT `true`. Nothing in this
                    // crate ever sends `notifications/resources/updated`, and
                    // since both `resources/subscribe` and
                    // `resources/unsubscribe` now refuse with -32601,
                    // `resource_subs` is neither written nor read by any
                    // request path — it survives only for the handlers that
                    // will restore it alongside an emitter. `listChanged`
                    // stays true because `spawn_config_watcher` really does
                    // broadcast `resources_list_changed` on reload.
                    // Flip this back to `true` in the same commit that adds
                    // the emitter, never before.
                    subscribe: false,
                    list_changed: true,
                }),
                tasks: Some(TasksCapability {
                    list: json!({}),
                    cancel: json!({}),
                    requests: TaskRequestsCapability {
                        tools: Some(TaskToolsCapability { call: json!({}) }),
                    },
                }),
                completions: Some(CompletionsCapability {}),
                logging: Some(LoggingCapability {}),
                extensions: self.build_server_extensions().await,
            },
            server_info: ServerInfo {
                name: SERVER_NAME.to_string(),
                version: SERVER_VERSION.to_string(),
                description: Some(
                    "Secure SSH bridge for remote server management via MCP".to_string(),
                ),
                website_url: Some("https://github.com/muchiny/bridge-mcp".to_string()),
                icons: Some(vec![Icon {
                    src: SERVER_ICON_URL.to_string(),
                    mime_type: Some("image/svg+xml".to_string()),
                    sizes: Some(vec!["any".to_string()]),
                    theme: None,
                }]),
                meta: Some(build_provenance_meta()),
            },
            instructions: Some(instructions),
        };

        JsonRpcResponse::success_or_serialize_error(id, &result)
    }

    async fn handle_tools_list(
        &self,
        id: Option<Value>,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        use super::registry::tool_group;
        use crate::config::types::ToolListingMode;

        let page_size = 50;
        let listing = self.config.read().await.tool_groups.listing;

        // Filtering by annotation hints and tool group
        let filter_read_only = params
            .and_then(|p| p.get("readOnlyHint"))
            .and_then(Value::as_bool);
        let filter_destructive = params
            .and_then(|p| p.get("destructiveHint"))
            .and_then(Value::as_bool);
        let filter_group = params.and_then(|p| p.get("group")).and_then(|v| v.as_str());

        // Progressive mode: only the discovery meta-tools + the generic
        // dispatcher are listed — the full registry (~2K chars of schema
        // per tool) stays out of the client's context and is fetched on
        // demand via mcp_describe_tool.
        let mut all_tools = if listing == ToolListingMode::Progressive {
            Vec::new()
        } else {
            self.registry.list_tools()
        };
        let mut meta_defs = super::meta_tools::definitions();
        // Advertised in BOTH modes because it is dispatchable in both: the
        // rewrite at the top of `handle_tools_call` is not gated on the listing
        // mode (audit G-21, 2026-08-19).
        meta_defs.push(super::meta_tools::call_tool_definition());
        meta_defs.extend(all_tools);
        all_tools = meta_defs;

        if let Some(group_name) = filter_group {
            all_tools.retain(|t| tool_group(&t.name) == group_name);
        }
        if let Some(read_only) = filter_read_only {
            all_tools.retain(|t| {
                t.annotations
                    .as_ref()
                    .and_then(|a| a.read_only_hint)
                    .unwrap_or(false)
                    == read_only
            });
        }
        if let Some(destructive) = filter_destructive {
            all_tools.retain(|t| {
                t.annotations
                    .as_ref()
                    .and_then(|a| a.destructive_hint)
                    .unwrap_or(false)
                    == destructive
            });
        }

        // Cursor-based pagination (only when cursor is provided)
        let cursor = params
            .and_then(|p| p.get("cursor"))
            .and_then(|c| c.as_str());

        let (page, next_cursor) = if let Some(cursor_val) = cursor {
            // `unwrap_or(0)` silently turned a garbage cursor into "start
            // over", which is indistinguishable from a legitimate first page.
            let Ok(start) = cursor_val.parse::<usize>() else {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!(
                        "Invalid pagination cursor: {cursor_val}"
                    )),
                );
            };
            // Saturating: a cursor of `usize::MAX` parses cleanly, and the
            // plain `start + page_size` overflowed before `.min()` could clamp
            // it — panic in debug, silent wrap in release (audit D-F7,
            // 2026-08-20).
            let end = start.saturating_add(page_size).min(all_tools.len());
            let page = if start < all_tools.len() {
                all_tools[start..end].to_vec()
            } else {
                Vec::new()
            };
            let next = if end < all_tools.len() {
                Some(end.to_string())
            } else {
                None
            };
            (page, next)
        } else {
            // No cursor: return all tools (no pagination)
            (all_tools, None)
        };

        let result = ToolsListResult {
            tools: page,
            next_cursor,
        };

        JsonRpcResponse::success_or_serialize_error(id, &result)
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_tools_call(
        &self,
        id: Option<Value>,
        params: Option<Value>,
        cancel_token: Option<tokio_util::sync::CancellationToken>,
        session: Option<&SessionContext>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let mut call_params: ToolCallParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        info!(tool = %call_params.name, "Tool call");

        // The name the client actually put on the wire, captured before the
        // `mcp_call_tool` rewrite below replaces it with the inner tool. Any
        // error raised after that point must still be attributable to the
        // request the client sent (audit D-F1, 2026-08-20).
        let outer_name = call_params.name.clone();

        // Generic dispatcher (progressive listing mode): rewrite to the inner
        // tool BEFORE the elicitation gate and annotation lookups, so the
        // target tool's own safety semantics apply. A rewritten name equal to
        // CALL_TOOL again falls through to the registry and fails as unknown —
        // no recursion. Any future runtime RBAC enforcement must likewise key
        // on this REWRITTEN (inner) name — enforcement keyed on the
        // transport-level outer name (`mcp_call_tool`) would be bypassable
        // via this dispatcher.
        if call_params.name == super::meta_tools::CALL_TOOL {
            match super::meta_tools::unwrap_call_tool(call_params.arguments.as_ref()) {
                Ok((inner_name, inner_args)) => {
                    info!(inner_tool = %inner_name, "mcp_call_tool dispatch");
                    call_params.name = inner_name;
                    call_params.arguments = inner_args;
                }
                Err(msg) => {
                    return JsonRpcResponse::success_or_serialize_error(
                        id,
                        &ToolCallResult::error(msg),
                    );
                }
            }
        }

        // Progressive-discovery meta-tools are dispatched before the registry
        // so they can inspect the registry itself. They are read-only and
        // argument-validated locally, so they skip the elicitation gate and
        // the task/progress plumbing.
        if super::meta_tools::is_meta_tool(&call_params.name) {
            // `execution.taskSupport` is "forbidden" for the three meta-tools:
            // they are dispatched here, ahead of the task branch below, so a
            // `task` object would otherwise be accepted and silently dropped.
            //
            // `mcp_call_tool` advertises "optional" and rewrote `name` above,
            // so this can fire for a request whose wire-level tool name was the
            // dispatcher. Name both ends rather than only the rewritten one.
            if call_params.task.is_some() {
                let via = (outer_name != call_params.name).then_some(outer_name.as_str());
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::task_not_supported_via(&call_params.name, via),
                );
            }
            let result = super::meta_tools::execute(
                &call_params.name,
                call_params.arguments.as_ref(),
                &self.registry,
            )
            .unwrap_or_else(|| ToolCallResult::error("unreachable: meta-tool dispatch"));
            return JsonRpcResponse::success_or_serialize_error(id, &result.without_apps());
        }

        // Create progress reporter if the client sent a progressToken.
        // Use the per-session `notification_tx` only — there is no
        // cross-session fallback (FIND-034 audit 2026-05-09).
        let progress_reporter = call_params
            .meta
            .as_ref()
            .and_then(|m| m.progress_token.clone())
            .and_then(|token| {
                let tx = session.map(|s| s.notification_tx.clone())?;
                Some(ProgressReporter::new(token, tx, Some(3)))
            });

        // Destructive-op gate: when `security.require_elicitation_on_destructive`
        // is set, ask the client to confirm via `elicitation/create` before
        // executing any tool annotated `destructive_hint: true`. Runs before the
        // task branch so async task creation itself is gated.
        if let Err(msg) = self
            .check_destructive_elicitation(
                &call_params.name,
                call_params.arguments.as_ref(),
                session,
            )
            .await
        {
            return JsonRpcResponse::success_or_serialize_error(id, &ToolCallResult::error(msg));
        }

        // Task-augmented request: spawn background worker and return immediately.
        // MCP Tasks have their own cancellation via `tasks/cancel`; we don't
        // propagate the request-level `cancel_token` here because the task
        // lives beyond the enclosing request.
        if let Some(task_request) = call_params.task {
            return self
                .handle_tools_call_async(
                    call_params.name,
                    call_params.arguments,
                    task_request,
                    id,
                    call_params
                        .meta
                        .as_ref()
                        .and_then(|m| m.progress_token.clone()),
                    session,
                )
                .await;
        }

        // Synchronous path
        if let Some(ref reporter) = progress_reporter {
            reporter.report(1, Some("Preparing execution..."));
        }

        let ctx = self
            .create_tool_context(
                cancel_token,
                call_params
                    .meta
                    .as_ref()
                    .and_then(|m| m.progress_token.clone()),
                session,
            )
            .await;

        if let Some(ref reporter) = progress_reporter {
            reporter.report(2, Some(&format!("Executing {}...", call_params.name)));
        }

        let start = Instant::now();
        let tool_name = call_params.name.clone();
        let host_for_metrics = call_params
            .arguments
            .as_ref()
            .and_then(|v| v.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or("local")
            .to_string();

        match self
            .registry
            .execute(&call_params.name, call_params.arguments, &ctx)
            .await
        {
            Ok(result) => {
                let elapsed_ms = start.elapsed().as_millis();

                if let Some(ref reporter) = progress_reporter {
                    reporter.report(3, Some("Done"));
                }

                // Compute output size for logging and metrics
                let output_chars: usize = result
                    .content
                    .iter()
                    .map(|c| match c {
                        ToolContent::Text { text } => text.len(),
                        _ => 0,
                    })
                    .sum();
                let is_truncated = result.content.iter().any(|c| {
                    matches!(c,
                    ToolContent::Text { text } if text.contains("output_id:"))
                });

                // Record metrics
                self.metrics.record_tool_call(&tool_name, &host_for_metrics);
                self.metrics
                    .record_tool_output(&tool_name, output_chars as u64);

                // Contextual log: give Claude structured info about the execution
                if let Some(logger) = self.mcp_logger.read().await.as_ref() {
                    logger.log(
                        super::protocol::LogLevel::Debug,
                        "bridge-mcp",
                        json!({
                            "event": "tool_complete",
                            "tool": tool_name,
                            "duration_ms": elapsed_ms,
                            "output_chars": output_chars,
                            "truncated": is_truncated,
                        }),
                    );
                }

                // Strip non-standard App content items — clients that don't
                // advertise MCP Apps support reject unknown content types.
                let result = result.without_apps();

                JsonRpcResponse::success_or_serialize_error(id, &result)
            }
            Err(e) => {
                let elapsed_ms = start.elapsed().as_millis();
                error!(error = %e, "Tool call failed");
                self.metrics.record_tool_call(&tool_name, "unknown");
                self.metrics.record_tool_error();

                if let Some(logger) = self.mcp_logger.read().await.as_ref() {
                    logger.log(
                        super::protocol::LogLevel::Error,
                        "bridge-mcp",
                        json!({
                            "event": "tool_failed",
                            "tool": tool_name,
                            "duration_ms": elapsed_ms,
                            "error": e.to_string(),
                        }),
                    );
                }
                if let Some(ref reporter) = progress_reporter {
                    reporter.report(3, Some(&format!("Failed: {e}")));
                }

                // Cancellation gets a proper JSON-RPC error with the
                // `-32800` "Request Cancelled" code so clients can tell it
                // apart from a plain tool failure.
                if matches!(e, crate::error::BridgeError::Cancelled) {
                    return JsonRpcResponse::error(id, JsonRpcError::cancelled(None));
                }

                // An unregistered tool name is a bad `name` PARAMETER, not a
                // tool that ran and failed. The `isError` envelope is
                // reserved for the latter, so an unknown name gets -32602.
                if let crate::error::BridgeError::McpUnknownTool { ref tool } = e {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params(format!("Unknown tool: {tool}")),
                    );
                }

                // Everything else — a tool that executed and failed — stays
                // in the tool-result envelope.
                let error_result = ToolCallResult::error(e.to_string());
                JsonRpcResponse::success_or_serialize_error(id, &error_result)
            }
        }
    }

    /// Handle a task-augmented `tools/call`: create a task, spawn a background
    /// worker, and return `CreateTaskResult` immediately.
    async fn handle_tools_call_async(
        &self,
        tool_name: String,
        arguments: Option<Value>,
        task_request: super::protocol::TaskRequest,
        id: Option<Value>,
        progress_token: Option<Value>,
        session: Option<&SessionContext>,
    ) -> JsonRpcResponse {
        // Get the handler first to validate the tool exists. Must agree with
        // the synchronous path: an unregistered name is -32602, not an
        // isError tool result.
        let Some(handler) = self.registry.get(&tool_name) else {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params(format!("Unknown tool: {tool_name}")),
            );
        };
        let handler = Arc::clone(handler);

        // Create the task
        let Some((task_id, cancel_token)) = self.task_store.create_task(task_request.ttl).await
        else {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::internal_error("Task limit reached, try again later"),
            );
        };

        // Get the initial task info for the response
        let Some(task_info) = self.task_store.get_task(&task_id).await else {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::internal_error("Task created but expired immediately (TTL too low)"),
            );
        };

        // Clone dependencies for the background worker.
        let task_store = Arc::clone(&self.task_store);
        // G-9 (audit 2026-08-19): the enclosing `tools/call` releases its own
        // permit the instant this function returns `CreateTaskResult`, and
        // the worker below used to acquire nothing — so task-augmented calls
        // escaped `limits.max_concurrent_commands` entirely (measured: 12/12
        // accepted with `task`, 0/12 without). The effective ceiling became
        // `max_tasks` (50), i.e. up to 50 concurrent SSH connections against
        // an sshd whose MaxStartups is 10:30:100. The worker takes its own
        // permit instead.
        //
        // This is only safe because `ping` and every `tasks/*` method are
        // exempt from that same semaphore (see `is_concurrency_exempt`):
        // workers legitimately holding all five permits is now the normal
        // busy state, and the control plane must stay answerable through it.
        let concurrent_limit = Arc::clone(&self.concurrent_limit);
        // Per-session tx ONLY (FIND-034 audit 2026-05-09): the task
        // notification must reach the SAME client that created the task,
        // never any other live session. If no session is attached
        // (legacy non-MCP code path), the notification is silently
        // dropped — same effect as before.
        let task_notification_tx = session.map(|s| s.notification_tx.clone());

        // SEP-1686: emit `notifications/tasks/status` for the initial
        // non-existent → working transition. The worker emits the matching
        // terminal notification on completion/failure/cancellation.
        if let Some(tx) = task_notification_tx.as_ref() {
            let msg = WriterMessage::Notification(JsonRpcNotification::task_status(&task_info));
            let _ = tx.try_send(msg);
        }

        // Propagate the task's cancel_token into the ToolContext so the
        // handler can do clean shutdown (e.g. evicting the SSH connection
        // from the pool) when the task is cancelled via `tasks/cancel`.
        let ctx = self
            .create_tool_context(Some(cancel_token.clone()), progress_token, session)
            .await;

        // Spawn the background worker
        tokio::spawn(async move {
            // Wait for a concurrency slot before doing any remote work. A
            // `tasks/cancel` arriving while we are queued here must still
            // win — otherwise cancelling a queued task would do nothing
            // until it finally started.
            let _permit = tokio::select! {
                permit = concurrent_limit.acquire_owned() => if let Ok(permit) = permit {
                    permit
                } else {
                    error!("Semaphore closed unexpectedly, dropping task worker");
                    return;
                },
                () = cancel_token.cancelled() => return,
            };

            let result = tokio::select! {
                res = handler.execute(arguments, &ctx) => res,
                () = cancel_token.cancelled() => {
                    // Task was cancelled, no need to store result
                    return;
                }
            };

            // Store the result and send notification
            let info = match result {
                Ok(tool_result) => {
                    let tool_result = tool_result.without_apps();
                    let result_value =
                        serde_json::to_value(&tool_result).unwrap_or_else(|e| json!({
                            "content": [{"type": "text", "text": format!("Serialization error: {e}")}],
                            "isError": true,
                        }));
                    task_store.complete_task(&task_id, result_value).await
                }
                Err(e) => {
                    let error_result = ToolCallResult::error(e.to_string());
                    let result_value =
                        serde_json::to_value(&error_result).unwrap_or_else(|e| json!({
                            "content": [{"type": "text", "text": format!("Serialization error: {e}")}],
                            "isError": true,
                        }));
                    task_store
                        .fail_task(&task_id, &e.to_string(), result_value)
                        .await
                }
            };

            // Send status notification (best-effort) on the per-session
            // tx so it reaches the originating client only.
            if let Some(info) = info
                && let Some(tx) = task_notification_tx.as_ref()
            {
                let msg = WriterMessage::Notification(JsonRpcNotification::task_status(&info));
                let _ = tx.try_send(msg);
            }
        });

        // Return CreateTaskResult immediately
        let create_result = CreateTaskResult {
            task: task_info,
            meta: None,
        };
        JsonRpcResponse::success_or_serialize_error(id, &create_result)
    }

    fn handle_prompts_list(&self, id: Option<Value>) -> JsonRpcResponse {
        let result = PromptsListResult {
            prompts: self.prompt_registry.list(),
        };

        JsonRpcResponse::success_or_serialize_error(id, &result)
    }

    async fn handle_prompts_get(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let get_params: PromptsGetParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        info!(prompt = %get_params.name, "Prompt get");

        let ctx = self.create_tool_context(None, None, None).await;

        match self
            .prompt_registry
            .get_messages(&get_params.name, get_params.arguments, &ctx)
            .await
        {
            Ok(messages) => {
                let result = PromptsGetResult { messages };
                JsonRpcResponse::success_or_serialize_error(id, &result)
            }
            Err(e) => {
                error!(error = %e, "Prompt get failed");
                JsonRpcResponse::error(id, JsonRpcError::invalid_params(e.to_string()))
            }
        }
    }

    async fn handle_resources_list(&self, id: Option<Value>) -> JsonRpcResponse {
        let ctx = self.create_tool_context(None, None, None).await;

        match self.resource_registry.list(&ctx).await {
            Ok(resources) => {
                let result = ResourcesListResult { resources };
                JsonRpcResponse::success_or_serialize_error(id, &result)
            }
            Err(e) => {
                error!(error = %e, "Resources list failed");
                JsonRpcResponse::error(id, JsonRpcError::internal_error(e.to_string()))
            }
        }
    }

    async fn handle_resources_read(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let read_params: ResourcesReadParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        info!(uri = %read_params.uri, "Resource read");

        let ctx = self.create_tool_context(None, None, None).await;

        match self.resource_registry.read(&read_params.uri, &ctx).await {
            Ok(contents) => {
                let result = ResourcesReadResult { contents };
                JsonRpcResponse::success_or_serialize_error(id, &result)
            }
            Err(e) => {
                error!(error = %e, "Resource read failed");
                // G-7 (audit 2026-08-19; corrected in fix round 1): an
                // unroutable scheme, a malformed URI (`McpInvalidRequest`),
                // or a host name that isn't configured (`UnknownHost`) are
                // all the caller's mistake. A rate limit is deliberately
                // NOT in this arm — the request was well-formed, so it keeps
                // the `-32603` it returned before task 33 touched this path
                // (`BridgeError::RateLimitExceeded` falls to the `_` arm
                // below). A real execution failure (SSH down, a remote
                // error) also stays `-32603`.
                //
                // F10 (batch H re-review): `-32603` is NOT a spec signal to
                // retry. JSON-RPC 2.0 calls it "Internal JSON-RPC error" and
                // says nothing about retryability; MCP defines no rate-limit
                // code. It is used here because it restores prior behaviour
                // and `-32602` was actively harmful. A dedicated
                // `-32000..=-32099` code with `error.data.retryAfter` is
                // filed for 3.0.0.
                let error = match &e {
                    crate::error::BridgeError::McpInvalidRequest(msg) => {
                        JsonRpcError::invalid_params(msg.clone())
                    }
                    crate::error::BridgeError::UnknownHost { .. } => {
                        JsonRpcError::invalid_params(e.to_string())
                    }
                    _ => JsonRpcError::internal_error(e.to_string()),
                };
                JsonRpcResponse::error(id, error)
            }
        }
    }

    // =========================================================================
    // Resource template & subscription handlers
    // =========================================================================

    /// List the per-host resource templates.
    ///
    /// G-7 (audit 2026-08-19): this used to publish a single hardcoded
    /// `ssh://{host}/{path}`, a scheme no handler answers — every expansion
    /// failed — while `file://` and `log://`, the two genuinely
    /// template-based handlers, were published nowhere. Templates are now
    /// derived from the registry: one per (templated handler x configured
    /// host). Hosts are sorted so the list is stable across processes
    /// (`config.hosts` is a `HashMap`).
    fn handle_resource_templates_list(&self, id: Option<Value>) -> JsonRpcResponse {
        use super::protocol::ResourceTemplate;

        let Ok(config) = self.config.try_read() else {
            return JsonRpcResponse::success(id, json!({ "resourceTemplates": [] }));
        };

        let mut hosts: Vec<&String> = config.hosts.keys().collect();
        hosts.sort();

        let mut templates: Vec<ResourceTemplate> = Vec::new();
        for handler in self.resource_registry.templated_handlers() {
            let Some(path_expr) = handler.path_template() else {
                continue;
            };
            let scheme = handler.scheme();
            for host in &hosts {
                templates.push(ResourceTemplate {
                    uri_template: format!("{scheme}://{host}/{path_expr}"),
                    name: format!("{scheme} on {host}"),
                    description: Some(handler.description().to_string()),
                    mime_type: None,
                });
            }
        }

        JsonRpcResponse::success_or_serialize_error(id, &json!({ "resourceTemplates": templates }))
    }

    /// Handle `subscriptions/listen` (MCP 2026-07-28,
    /// `basic/patterns/subscriptions`).
    ///
    /// Registers this session's opt-in filter, answers the request with
    /// the allocated `subscriptionId`, and emits the
    /// `notifications/subscriptions/acknowledged` notification carrying
    /// the subset the server actually honours.
    ///
    /// The immediate `result` is this server's reading of the one thing
    /// the spec leaves open: the request carries an `id`, so JSON-RPC 2.0
    /// demands a response, and holding it open for the life of the stream
    /// would park a task for the whole session — exactly the long-poll
    /// pathology 2.2.0 fixed for `tasks/result` (G-1). Answer now,
    /// stream through notifications.
    /// SPEC: verify against
    /// <https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions>
    async fn handle_subscriptions_listen(
        &self,
        id: Option<Value>,
        params: Option<Value>,
        session: Option<&SessionContext>,
    ) -> JsonRpcResponse {
        let Some(session) = session else {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_request(
                    "subscriptions/listen requires an active MCP session",
                ),
            );
        };
        let Some(params) = params else {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params("subscriptions/listen requires params.notifications"),
            );
        };
        let listen: SubscriptionsListenParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!(
                        "Invalid subscriptions/listen params: {e}"
                    )),
                );
            }
        };

        // Echo only what we can honour: a URI whose scheme no resource
        // handler serves would never produce a single notification.
        let schemes = self.resource_registry.schemes();
        let filter = listen.notifications.restricted_to_schemes(&schemes);

        let sub_id = self
            .subscriptions
            .register(filter.clone(), session.notification_tx.clone());

        let ack_filter = match serde_json::to_value(&filter) {
            Ok(v) => v,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::internal_error(format!("Serialization error: {e}")),
                );
            }
        };
        let _ = session
            .notification_tx
            .send(WriterMessage::Notification(
                JsonRpcNotification::subscriptions_acknowledged(sub_id, &ack_filter),
            ))
            .await;

        JsonRpcResponse::success(id, json!({ "subscriptionId": sub_id }))
    }

    /// Subscribe to resource notifications.
    ///
    /// IMPORTANT (fix round 1 of the 2026-08-19 audit corrections, task 31
    /// follow-up): `handle_initialize` advertises
    /// `resources.subscribe: false` (G-6) because nothing in this crate
    /// ever emits `notifications/resources/updated` — but this handler used
    /// to hand out a `subscriptionId` regardless (writing it into the
    /// per-session `resource_subs` map added for FIND-036, audit
    /// 2026-05-09), promising a notification the handshake had just
    /// disclaimed. Refuse the call outright: a client should get the same
    /// response it would get for any method the server does not implement.
    /// Takes no `&self` (clippy `unused_self`) while it is just a constant
    /// refusal; restore the real body (uri parsing, per-session
    /// `resource_subs` write) in the SAME commit that adds the notification
    /// emitter, never before — see git history for the previous
    /// implementation.
    fn handle_resource_subscribe(
        id: Option<Value>,
        _params: Option<Value>,
        _session: Option<&SessionContext>,
    ) -> JsonRpcResponse {
        JsonRpcResponse::error(id, JsonRpcError::method_not_found("resources/subscribe"))
    }

    /// Unsubscribe from resource notifications.
    ///
    /// IMPORTANT (F9 of the 2026-08-19 batch H re-review): this used to
    /// return `{}` success while its sibling `handle_resource_subscribe`
    /// returned -32601, so a client probing which half of the subscription
    /// pair exists got two contradictory answers about ONE disclaimed
    /// capability. `handle_initialize` advertises
    /// `resources.subscribe: false`; reference MCP servers register neither
    /// handler when `subscribe` is undeclared, so both answer
    /// method-not-found. Succeeding at cancelling a subscription that can
    /// never be created is the same honesty defect G-6 was raised about,
    /// one method over.
    ///
    /// Takes no `&self` and is no longer `async` (clippy `unused_self`)
    /// while it is just a constant refusal. Restore the real body — uri
    /// parsing and the per-session `resource_subs` removal added for
    /// FIND-036, audit 2026-05-09 — in the SAME commit that adds the
    /// notification emitter and restores `handle_resource_subscribe`,
    /// never before. See git history for the previous implementation.
    fn handle_resource_unsubscribe(
        id: Option<Value>,
        _params: Option<Value>,
        _session: Option<&SessionContext>,
    ) -> JsonRpcResponse {
        JsonRpcResponse::error(id, JsonRpcError::method_not_found("resources/unsubscribe"))
    }

    // =========================================================================
    // Cancellation notification handler
    // =========================================================================

    /// Handle a `notifications/cancelled` notification from the client.
    ///
    /// Looks up the `requestId` in the **session-local** [`ActiveRequests`]
    /// map and fires the associated `CancellationToken`. Long-running tool
    /// handlers see the fired token and bail out cleanly via their
    /// `tokio::select!` branch (see
    /// [`crate::mcp::standard_tool::StandardToolHandler::execute`]).
    ///
    /// FIND-038 (audit 2026-05-09): the previous implementation looked up
    /// the request in a server-singleton map, allowing a concurrent client
    /// to cancel any other client's in-flight request by guessing or
    /// observing the JSON-RPC `id`. The lookup is now scoped to
    /// `session_active_requests`, the per-session map allocated in
    /// `serve_session()`.
    ///
    /// Silently ignores:
    /// - Notifications with no `requestId` (malformed).
    /// - Notifications for unknown request IDs (already completed, the
    ///   request belongs to a different session, or the caller mistakenly
    ///   used a task `taskId` — tasks are cancelled via the separate
    ///   `tasks/cancel` request).
    ///
    /// This follows MCP 2025-11-25 spec guidance:
    /// *"Invalid cancellation notifications SHOULD be ignored by the
    ///  receiver."*
    fn handle_cancellation_notification(
        session_active_requests: &ActiveRequests,
        params: Option<&Value>,
    ) {
        let Some(request_id_val) = params.and_then(|p| p.get("requestId")) else {
            debug!("notifications/cancelled with no requestId, ignoring");
            return;
        };

        // JSON-RPC ids can be strings or numbers; normalize to String.
        let request_id: String = match request_id_val {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };

        // Optional reason for logs.
        let reason = params
            .and_then(|p| p.get("reason"))
            .and_then(Value::as_str)
            .unwrap_or("");

        if session_active_requests.cancel(&request_id) {
            info!(
                request_id = %request_id,
                reason = %reason,
                "Cancelled in-flight request"
            );
        } else {
            debug!(
                request_id = %request_id,
                "Cancellation for unknown or already-completed request"
            );
        }
    }

    // =========================================================================
    // Task handlers (MCP 2025-11-25+)
    // =========================================================================

    async fn handle_tasks_get(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let get_params: TaskGetParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        match self.task_store.get_task(&get_params.task_id).await {
            Some(info) => JsonRpcResponse::success_or_serialize_error(id, &info),
            None => JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params(format!("Task not found: {}", get_params.task_id)),
            ),
        }
    }

    async fn handle_tasks_result(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let result_params: TaskResultParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        // Wait for the task's result, bounded by the store's poll budget.
        match self
            .task_store
            .wait_for_result(&result_params.task_id)
            .await
        {
            TaskWaitOutcome::Ready(result) => {
                // Inject task correlation metadata
                let mut response = result;
                if let Some(obj) = response.as_object_mut() {
                    obj.insert(
                        "_meta".to_string(),
                        json!({
                            "io.modelcontextprotocol/related-task": {
                                "taskId": result_params.task_id
                            }
                        }),
                    );
                }
                JsonRpcResponse::success(id, response)
            }
            // G-1: the poll budget elapsed with the task still running.
            // Hand back the current status so the client stays in a normal
            // poll loop — erroring here would make a slow task look like a
            // missing one.
            TaskWaitOutcome::TimedOut(info) => {
                let Ok(mut response) = serde_json::to_value(&*info) else {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::internal_error("Failed to serialize task status"),
                    );
                };
                if let Some(obj) = response.as_object_mut() {
                    obj.insert(
                        "_meta".to_string(),
                        json!({
                            "io.modelcontextprotocol/related-task": {
                                "taskId": result_params.task_id
                            }
                        }),
                    );
                }
                JsonRpcResponse::success(id, response)
            }
            TaskWaitOutcome::NotFound => {
                // A cancelled task is still in the store and still visible via
                // `tasks/get` and `tasks/list`; `cancel_task` simply never sets
                // `entry.result`. Reporting "Task not found" contradicted both
                // other endpoints (audit G-23, 2026-08-19). Storing a terminal
                // result for cancelled tasks is deliberately out of scope here.
                //
                // The "(cancelled tasks record none)" parenthetical below is
                // only true while `complete_task` and `fail_task` both always
                // assign `entry.result` — `Cancelled` is the sole status that
                // can reach this arm. Give either of them an early return and
                // the wording becomes a lie; the `status` field in `data` will
                // still be right.
                let (message, data) = match self.task_store.get_task(&result_params.task_id).await {
                    Some(info) => {
                        // Wire spelling, not `{:?}`: `TaskStatus` carries
                        // `#[serde(rename_all = "lowercase")]`, so Debug said
                        // `Cancelled` here while `tasks/get` said `cancelled`
                        // for the same task (audit D-F3, 2026-08-20).
                        let status = serde_json::to_value(info.status).unwrap_or(Value::Null);
                        let status_text = status.as_str().unwrap_or("unknown");
                        (
                            format!(
                                "Task {} reached terminal state {status_text} without storing a \
                                 result (cancelled tasks record none); use tasks/get for its \
                                 status",
                                result_params.task_id
                            ),
                            Some(json!({
                                "taskId": result_params.task_id,
                                "status": status,
                            })),
                        )
                    }
                    None => (format!("Task not found: {}", result_params.task_id), None),
                };
                let mut error = JsonRpcError::invalid_params(message);
                if let Some(data) = data {
                    error = error.with_data(data);
                }
                JsonRpcResponse::error(id, error)
            }
        }
    }

    async fn handle_tasks_list(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        let list_params: TaskListParams = params
            .and_then(|p| serde_json::from_value(p).ok())
            .unwrap_or(TaskListParams { cursor: None });

        let (tasks, next_cursor) = match self
            .task_store
            .list_tasks(list_params.cursor.as_deref(), 20)
            .await
        {
            Ok(page) => page,
            Err(e) => {
                // A cursor naming no live task is a client error, not a
                // reason to silently replay page 1. TTL eviction can stale a
                // cursor between two polls of the same loop.
                return JsonRpcResponse::error(id, JsonRpcError::invalid_params(e.to_string()));
            }
        };

        let result = TaskListResult { tasks, next_cursor };
        JsonRpcResponse::success_or_serialize_error(id, &result)
    }

    async fn handle_tasks_cancel(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let cancel_params: TaskCancelParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        match self.task_store.cancel_task(&cancel_params.task_id).await {
            Ok(info) => JsonRpcResponse::success_or_serialize_error(id, &info),
            Err(e) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(e)),
        }
    }

    // ========================================================================
    // Completions
    // ========================================================================

    fn handle_completions_complete(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        use crate::ports::CompletionProvider;

        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let complete_params: CompletionsCompleteParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        // We need a sync config snapshot for completion. Use try_read to avoid
        // blocking; if the config lock is held, return empty completions.
        let Ok(config) = self.config.try_read() else {
            return JsonRpcResponse::success_or_serialize_error(
                id,
                &CompletionsCompleteResult {
                    completion: CompletionResult {
                        values: Vec::new(),
                        total: None,
                        has_more: None,
                    },
                },
            );
        };

        // Build a minimal ToolContext with just the config for completion lookups.
        // CompletionProvider only uses ctx.config.
        let ctx = ToolContext::new(
            Arc::new(config.clone()),
            Arc::clone(&self.validator),
            Arc::clone(&self.sanitizer),
            Arc::clone(&self.audit_logger),
            Arc::clone(&self.history),
            Arc::clone(&self.connection_pool),
            Arc::clone(&self.execute_use_case),
            Arc::clone(&self.rate_limiter),
            Arc::clone(&self.session_manager),
        );

        let values = match &complete_params.reference {
            CompletionRef::Prompt { name } => self
                .completion_provider
                .complete_prompt_argument(
                    name,
                    &complete_params.argument.name,
                    &complete_params.argument.value,
                    &ctx,
                )
                .unwrap_or_default(),
            CompletionRef::Resource { uri } => self
                .completion_provider
                .complete_resource_argument(
                    uri,
                    &complete_params.argument.name,
                    &complete_params.argument.value,
                    &ctx,
                )
                .unwrap_or_default(),
        };

        let total = values.len();
        let has_more = total > 100;
        let values: Vec<String> = values.into_iter().take(100).collect();

        JsonRpcResponse::success_or_serialize_error(
            id,
            &CompletionsCompleteResult {
                completion: CompletionResult {
                    values,
                    total: Some(total),
                    has_more: if has_more { Some(true) } else { None },
                },
            },
        )
    }

    // ========================================================================
    // Logging
    // ========================================================================

    fn handle_logging_set_level(
        &self,
        id: Option<Value>,
        params: Option<Value>,
        session: Option<&SessionContext>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let level_params: LoggingSetLevelParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        // FIND-035: write to the SESSION's log_level so that
        // `notifications/setLevel` from this client cannot mute another
        // session's `notifications/message` stream. Falls back to the
        // server-wide field for legacy non-session call paths (tests).
        let target = if let Some(s) = session {
            Arc::clone(&s.log_level)
        } else {
            Arc::clone(&self.log_level)
        };
        target.store(level_params.level.severity(), Ordering::Relaxed);
        info!(level = ?level_params.level, "MCP log level updated");

        JsonRpcResponse::success(id, json!({}))
    }
}

/// Vendor-namespaced build provenance for `serverInfo._meta`.
///
/// Built through `serde_json::Map` rather than `json!` so the key stays a
/// single source of truth (`BUILD_META_KEY`) instead of a duplicated literal.
fn build_provenance_meta() -> Value {
    let mut map = serde_json::Map::new();
    map.insert(
        BUILD_META_KEY.to_string(),
        json!({
            "rev": BUILD_REV,
            "version": SERVER_VERSION,
        }),
    );
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, HttpTransportConfig, LimitsConfig, SecurityConfig, SessionConfig,
        SshConfigDiscovery, ToolGroupsConfig,
    };
    use crate::mcp::transport::{SessionReader, SessionWriter};
    use serde_json::json;
    use std::collections::HashMap;

    /// Build the `Config` used by `create_test_server()`.
    ///
    /// Tests in this module exercise the full handler inventory
    /// (pagination, group filters, etc.). FIND-024 changed the
    /// default profile to a minimal 8-group set, so we explicitly
    /// opt every group in for the test fixture. Production code paths
    /// continue to use whatever the operator put in `tool_groups`.
    ///
    /// Extracted from `create_test_server()` so other tests (e.g. the
    /// progressive-listing test) can start from the same baseline and
    /// then flip a single field, instead of duplicating the whole
    /// struct literal.
    fn test_config() -> Config {
        Config {
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
            tool_groups: crate::mcp::registry::all_enabled_tool_groups_config_for_test(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        }
    }

    fn create_test_server() -> McpServer {
        let (server, _audit_task) = McpServer::new(test_config());
        server
    }

    /// Same fixture as `create_test_server`, with the limits block swapped.
    /// Used by tests that need a poll budget measured in milliseconds
    /// rather than the production 60 s (2 000 ms poll interval x 30).
    fn create_test_server_with_limits(limits: LimitsConfig) -> McpServer {
        let config = Config {
            limits,
            ..test_config()
        };
        let (server, _audit_task) = McpServer::new(config);
        server
    }

    // ================= in-memory session harness (G-1 / G-9) =================
    //
    // `serve_session`'s reader loop is one of two places the concurrency
    // semaphore is taken (the other is the task worker spawned from
    // `handle_tools_call_async`, G-9) — and the only one that also gates
    // reading the client's *next* message, so a test that calls the
    // handlers directly cannot see the reader-loop freeze at all. These
    // two adapters let a test drive the real reader loop with a scripted
    // message sequence and read back everything it writes.

    /// Feeds `serve_session` a scripted sequence of client messages.
    struct ChannelReader {
        rx: mpsc::UnboundedReceiver<IncomingMessage>,
    }

    #[async_trait::async_trait]
    impl SessionReader for ChannelReader {
        async fn recv(&mut self) -> Option<std::result::Result<IncomingMessage, String>> {
            self.rx.recv().await.map(Ok)
        }
    }

    /// Collects everything the session writes back.
    struct ChannelWriter {
        tx: mpsc::UnboundedSender<WriterMessage>,
    }

    #[async_trait::async_trait]
    impl SessionWriter for ChannelWriter {
        async fn send(&mut self, msg: WriterMessage) -> crate::error::Result<()> {
            let _ = self.tx.send(msg);
            Ok(())
        }
    }

    /// Build an in-memory `Session` plus the two ends used to drive it:
    /// a sender that plays the client, and a receiver of server output.
    fn in_memory_session() -> (
        Session,
        mpsc::UnboundedSender<IncomingMessage>,
        mpsc::UnboundedReceiver<WriterMessage>,
    ) {
        let (client_tx, client_rx) = mpsc::unbounded_channel::<IncomingMessage>();
        let (server_tx, server_rx) = mpsc::unbounded_channel::<WriterMessage>();
        let session = Session {
            reader: Box::new(ChannelReader { rx: client_rx }),
            writer: Box::new(ChannelWriter { tx: server_tx }),
        };
        (session, client_tx, server_rx)
    }

    /// One JSON-RPC request, shaped exactly as a reader hands it to the loop.
    fn client_request(id: i64, method: &str, params: Option<Value>) -> IncomingMessage {
        IncomingMessage::Single(JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(id)),
            method: Some(method.to_string()),
            params,
            result: None,
            error: None,
        })
    }

    /// G-1 regression, straight from the audit's own reproduction.
    ///
    /// `tasks/result` is a long poll. It used to take a permit from
    /// `limits.max_concurrent_commands` (default 5) INSIDE the reader loop,
    /// so N parked polls froze the entire session: the loop blocks on
    /// `acquire_owned()` before it spawns the handler, so the client's next
    /// message is never read. The audit measured the boundary exactly —
    /// N=4 still answered `ping`, N=5 answered neither `ping` nor
    /// `tasks/cancel` (the one call that could have released the polls),
    /// and it was still dead 208 s later. This table walks across it.
    #[tokio::test]
    async fn ping_survives_parked_task_polls_at_and_past_the_concurrency_limit() {
        for parked_polls in [1_usize, 2, 3, 4, 5, 6] {
            let server = Arc::new(create_test_server());
            assert_eq!(
                server.concurrent_limit.available_permits(),
                5,
                "fixture must keep the default max_concurrent_commands"
            );

            // Tasks nobody will ever complete: every `tasks/result` parks.
            let mut task_ids = Vec::new();
            for _ in 0..parked_polls {
                let (task_id, _cancel) =
                    server.task_store.create_task(Some(600_000)).await.unwrap();
                task_ids.push(task_id);
            }

            let (session, client_tx, mut server_rx) = in_memory_session();
            let serve = tokio::spawn(Arc::clone(&server).serve_session(session));

            let mut next_id: i64 = 1;
            for task_id in &task_ids {
                client_tx
                    .send(client_request(
                        next_id,
                        "tasks/result",
                        Some(json!({ "taskId": task_id })),
                    ))
                    .unwrap();
                next_id += 1;
            }

            // Let the reader loop consume every poll before the ping arrives.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            client_tx.send(client_request(9999, "ping", None)).unwrap();

            let msg = tokio::time::timeout(std::time::Duration::from_secs(3), server_rx.recv())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "session froze with {parked_polls} parked tasks/result polls: \
                     ping was never answered"
                    )
                })
                .expect("session writer channel closed");

            match msg {
                WriterMessage::Response(response) => {
                    assert_eq!(
                        response.id,
                        Some(json!(9999)),
                        "the first answer must be the ping, not a parked poll"
                    );
                    assert!(response.error.is_none(), "ping must succeed");
                }
                _ => panic!("expected a ping response, got a notification or a batch"),
            }

            serve.abort();
        }
    }

    /// `spawn_cleanup_tasks` must actually spawn one loop per expiring
    /// resource. Returning an empty vec compiles and lets the serve loop
    /// run normally, but silently disables session/task/output-cache/pool
    /// expiry for the lifetime of the process — nothing else in the tree
    /// notices. Caught as a MISSED mutant on 2026-08-11.
    #[tokio::test]
    async fn test_spawn_cleanup_tasks_spawns_one_loop_per_resource() {
        let server = create_test_server();
        let handles = server.spawn_cleanup_tasks();

        assert_eq!(
            handles.len(),
            4,
            "expected one cleanup loop per expiring resource \
             (session manager, task store, output cache, connection pool)"
        );
        assert!(
            handles.iter().all(|h| !h.is_finished()),
            "a cleanup loop exited immediately instead of ticking forever"
        );

        for handle in handles {
            handle.abort();
        }
    }

    #[tokio::test]
    async fn test_handle_initialize_negotiates_matching_version() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), None)
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // Server echoes back the client's version when supported
        assert_eq!(result["protocolVersion"], "2025-11-25");
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
        assert_eq!(result["serverInfo"]["version"], SERVER_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
    }

    /// G-6 (audit 2026-08-19): the handshake advertised
    /// `resources.subscribe: true` while the server has no emitter at all —
    /// `notifications/resources/updated` appears nowhere in the tree, and
    /// `SessionContext::resource_subs` is now neither written nor read — both
    /// `resources/subscribe` and `resources/unsubscribe` refuse with -32601.
    /// A client that trusted the flag would subscribe and then wait forever.
    /// Advertise the truth until an emitter exists.
    #[tokio::test]
    async fn test_initialize_does_not_advertise_resource_subscriptions() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), None)
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();

        assert_eq!(
            result["capabilities"]["resources"]["subscribe"],
            json!(false),
            "resources.subscribe must stay false until the server actually \
             emits notifications/resources/updated"
        );
        assert_eq!(
            result["capabilities"]["resources"]["listChanged"],
            json!(true),
            "listChanged IS honored (config reload broadcasts \
             resources_list_changed) and must stay advertised"
        );
    }

    #[tokio::test]
    async fn test_handle_initialize_negotiates_older_version() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), None)
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // Server echoes back an older supported version
        assert_eq!(result["protocolVersion"], "2025-06-18");
    }

    #[tokio::test]
    async fn test_handle_initialize_unsupported_version_returns_latest() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "1999-01-01",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), None)
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // Unsupported version: server responds with its latest
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn test_handle_initialize_no_params_uses_default_version() {
        let server = create_test_server();

        let response = server.handle_initialize(Some(json!(1)), None, None).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn test_handle_initialize_includes_server_metadata() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), None)
            .await;
        let result = response.result.unwrap();

        assert!(result["serverInfo"]["description"].is_string());
        assert!(result["serverInfo"]["websiteUrl"].is_string());
        assert!(result["instructions"].is_string());
    }

    #[tokio::test]
    async fn test_handle_initialize_sets_initialized_flag() {
        let server = create_test_server();
        assert!(!server.initialized.load(Ordering::SeqCst));

        server.handle_initialize(Some(json!(1)), None, None).await;

        assert!(server.initialized.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_handle_initialize_includes_extensions() {
        let server = create_test_server();
        let response = server.handle_initialize(Some(json!(1)), None, None).await;
        let result = response.result.unwrap();
        let caps = &result["capabilities"];

        // Completions and logging capabilities are present
        assert!(caps["completions"].is_object());
        assert!(caps["logging"].is_object());

        // Extensions should contain tasks + output-pagination at minimum
        let exts = &caps["extensions"];
        assert!(exts.is_object(), "extensions should be an object");
        assert!(
            exts["io.modelcontextprotocol/tasks"].is_object(),
            "tasks extension should be present"
        );
        assert!(
            exts["com.bridge-mcp/output-pagination"].is_object(),
            "output-pagination extension should be present"
        );
    }

    #[tokio::test]
    async fn test_handle_tools_list_returns_all_registered_tools() {
        let server = create_test_server();

        let response = server.handle_tools_list(Some(json!(1)), None).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();

        // Verify default tools are present
        let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

        assert!(tool_names.contains(&"ssh_exec"));
        assert!(tool_names.contains(&"ssh_status"));
        assert!(tool_names.contains(&"ssh_history"));
        assert!(tool_names.contains(&"ssh_upload"));
        assert!(tool_names.contains(&"ssh_download"));
    }

    #[tokio::test]
    async fn test_handle_tools_list_tools_have_required_fields() {
        let server = create_test_server();

        let response = server.handle_tools_list(Some(json!(1)), None).await;

        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();

        for tool in tools {
            assert!(tool["name"].is_string(), "Tool missing name");
            assert!(tool["description"].is_string(), "Tool missing description");
            assert!(tool["inputSchema"].is_object(), "Tool missing inputSchema");
        }
    }

    #[tokio::test]
    async fn test_handle_tools_call_missing_params() {
        let server = create_test_server();

        let response = server
            .handle_tools_call(Some(json!(1)), None, None, None)
            .await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602); // Invalid params
        assert!(error.message.contains("Missing"));
    }

    #[tokio::test]
    async fn test_handle_tools_call_invalid_params() {
        let server = create_test_server();
        let params = json!({
            "invalid": "structure"
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602); // Invalid params
    }

    #[tokio::test]
    async fn test_handle_tools_call_unknown_tool() {
        let server = create_test_server();
        let params = json!({
            "name": "nonexistent_tool",
            "arguments": {}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        // A name that is not in the registry is an invalid `name` PARAMETER,
        // so it is a JSON-RPC error, not a tool result. The previous comment
        // here claimed "(MCP spec)" for the isError envelope — that is false;
        // the spec reserves isError for a tool that RAN and failed.
        let error = response
            .error
            .expect("an unknown tool must be a JSON-RPC error");
        assert_eq!(error.code, -32602);
        assert!(
            error.message.contains("nonexistent_tool"),
            "error must name the unknown tool, got: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn test_destructive_gate_blocks_when_elicitation_unsupported() {
        // Enable the gate; client has not advertised elicitation support.
        // Use all-enabled tool groups to keep `ssh_cron_remove` registered
        // (FIND-024 default profile excludes the `cron` group).
        let mut config = Config {
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
            tool_groups: crate::mcp::registry::all_enabled_tool_groups_config_for_test(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };
        config.security.require_elicitation_on_destructive = true;
        let (server, _task) = McpServer::new(config);
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        // session_ctx.caps.supports_elicitation() defaults to false.

        // ssh_cron_remove is annotated destructive
        let params = json!({
            "name": "ssh_cron_remove",
            "arguments": {"host": "prod", "name": "backup"}
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session_ctx))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["isError"].as_bool().unwrap_or(false));
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("does not support elicitation"),
            "unexpected error text: {text}"
        );
    }

    #[tokio::test]
    async fn test_tools_list_surfaces_meta_tools() {
        let server = create_test_server();
        let response = server.handle_tools_list(Some(json!(1)), None).await;
        let tools = response.result.unwrap()["tools"]
            .as_array()
            .cloned()
            .unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&super::super::meta_tools::LIST_TOOL_GROUPS));
        assert!(names.contains(&super::super::meta_tools::SEARCH_TOOLS));
        assert!(names.contains(&super::super::meta_tools::DESCRIBE_TOOL));
        // G-21 (audit 2026-08-19): the `mcp_call_tool` rewrite at the top of
        // `handle_tools_call` is UNCONDITIONAL, so the dispatcher is callable in
        // full mode too. Listing it only in progressive mode left a
        // callable-but-undocumented method. Advertise where it is dispatchable.
        assert!(names.contains(&super::super::meta_tools::CALL_TOOL));
    }

    #[tokio::test]
    async fn test_tools_list_progressive_mode_lists_only_meta_tools() {
        let mut config = test_config();
        config.tool_groups.listing = crate::config::types::ToolListingMode::Progressive;
        let (server, _audit) = McpServer::new(config);

        let response = server.handle_tools_list(Some(json!(1)), None).await;
        let tools = response.result.unwrap()["tools"]
            .as_array()
            .cloned()
            .unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

        assert_eq!(
            names.len(),
            4,
            "exactly 4 tools in progressive mode: {names:?}"
        );
        assert!(names.contains(&super::super::meta_tools::LIST_TOOL_GROUPS));
        assert!(names.contains(&super::super::meta_tools::SEARCH_TOOLS));
        assert!(names.contains(&super::super::meta_tools::DESCRIBE_TOOL));
        assert!(names.contains(&super::super::meta_tools::CALL_TOOL));
    }

    #[tokio::test]
    async fn test_tools_call_dispatches_list_tool_groups() {
        let server = create_test_server();
        let params = json!({
            "name": super::super::meta_tools::LIST_TOOL_GROUPS,
            "arguments": {}
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;
        let result = response.result.unwrap();
        assert_ne!(result["isError"].as_bool(), Some(true));
        let structured = &result["structuredContent"];
        assert!(structured["total_groups"].as_u64().unwrap_or(0) > 0);
        assert!(structured["groups"].is_array());
    }

    #[tokio::test]
    async fn test_tools_call_dispatches_search_tools() {
        let server = create_test_server();
        let params = json!({
            "name": super::super::meta_tools::SEARCH_TOOLS,
            "arguments": {"query": "docker", "limit": 3}
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;
        let result = response.result.unwrap();
        assert_ne!(result["isError"].as_bool(), Some(true));
        let structured = &result["structuredContent"];
        let results = structured["results"].as_array().unwrap();
        assert!(!results.is_empty());
        assert!(results.len() <= 3);
    }

    #[tokio::test]
    async fn test_tools_call_dispatches_describe_tool() {
        let server = create_test_server();
        // First find a real tool via list
        let list_response = server.handle_tools_list(Some(json!(1)), None).await;
        let first_real = list_response.result.unwrap()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|t| {
                let name = t["name"].as_str()?.to_string();
                // G-21 (audit 2026-08-19): `mcp_call_tool` is now listed in full
                // mode too, and `is_meta_tool` deliberately does not recognize it
                // (it's a dispatcher, not one of the three meta-tools) — exclude
                // it explicitly so this still finds an actual registry tool.
                (!super::super::meta_tools::is_meta_tool(&name)
                    && name != super::super::meta_tools::CALL_TOOL)
                    .then_some(name)
            })
            .expect("registry has a real tool");

        let params = json!({
            "name": super::super::meta_tools::DESCRIBE_TOOL,
            "arguments": {"name": first_real}
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;
        let result = response.result.unwrap();
        assert_ne!(result["isError"].as_bool(), Some(true));
        let structured = &result["structuredContent"];
        assert_eq!(structured["name"], first_real);
        assert!(structured["input_schema"].is_object());
        assert!(structured["reduction_strategy"].is_string());
    }

    #[tokio::test]
    async fn test_call_tool_dispatches_inner_meta_tool() {
        let server = create_test_server();
        let params = json!({
            "name": super::super::meta_tools::CALL_TOOL,
            "arguments": {"name": super::super::meta_tools::LIST_TOOL_GROUPS}
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(
            !result["isError"].as_bool().unwrap_or(false),
            "got: {result}"
        );
    }

    #[tokio::test]
    async fn test_task_on_meta_tool_is_rejected() {
        let server = create_test_server();
        let params = json!({
            "name": super::super::meta_tools::LIST_TOOL_GROUPS,
            "arguments": {},
            "task": {"ttl": 60000}
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        let error = response
            .error
            .expect("a task on a taskSupport=forbidden tool must be a JSON-RPC error");
        assert_eq!(error.code, -32601);
        assert!(
            error.message.contains("taskSupport"),
            "got: {}",
            error.message
        );
        // Called directly, so nothing to attribute: the message stays as it
        // was and `data` carries no `via` (audit D-F1, 2026-08-20).
        assert!(
            !error.message.contains("reached via"),
            "a direct call has no dispatcher to name: {}",
            error.message
        );
        let data = error.data.expect("structured error data");
        assert_eq!(
            data["tool"],
            json!(super::super::meta_tools::LIST_TOOL_GROUPS)
        );
        assert!(data.get("via").is_none(), "got: {data}");
    }

    /// D-F1 (audit 2026-08-20): `mcp_call_tool` advertises
    /// `execution.taskSupport: "optional"` and, in `listing: progressive`, is
    /// the client's only tool that does — the other three advertise
    /// `"forbidden"`. But the dispatcher rewrites `params.name` to the inner
    /// tool BEFORE the meta-tool guard runs, so a task-augmented
    /// `mcp_call_tool` wrapping a discovery meta-tool was refused under a name
    /// (`mcp_search_tools`) the client never put on the wire. The refusal is
    /// correct — the meta-tools are dispatched ahead of the task branch — but
    /// it must name both ends and carry machine-readable `data` so a client can
    /// branch without parsing English.
    #[tokio::test]
    async fn test_task_via_call_tool_names_both_tools() {
        let server = create_test_server();

        for inner in [
            super::super::meta_tools::LIST_TOOL_GROUPS,
            super::super::meta_tools::SEARCH_TOOLS,
            super::super::meta_tools::DESCRIBE_TOOL,
        ] {
            let params = json!({
                "name": super::super::meta_tools::CALL_TOOL,
                "arguments": {
                    "name": inner,
                    "arguments": {"query": "restart", "name": "ssh_status"}
                },
                "task": {"ttl": 60000}
            });
            let response = server
                .handle_tools_call(Some(json!(1)), Some(params), None, None)
                .await;

            let error = response
                .error
                .unwrap_or_else(|| panic!("{inner} via mcp_call_tool must be a JSON-RPC error"));
            assert_eq!(error.code, -32601);
            assert!(
                error.message.contains(inner),
                "error must name the inner tool, got: {}",
                error.message
            );
            assert!(
                error.message.contains(super::super::meta_tools::CALL_TOOL),
                "error must name the dispatcher the client actually called, got: {}",
                error.message
            );

            let data = error.data.expect("structured error data");
            assert_eq!(data["tool"], json!(inner));
            assert_eq!(data["via"], json!(super::super::meta_tools::CALL_TOOL));
        }
    }

    #[tokio::test]
    async fn test_task_through_call_tool_is_accepted() {
        let server = create_test_server();
        let params = json!({
            "name": super::super::meta_tools::CALL_TOOL,
            "arguments": {"name": "ssh_status", "arguments": {}},
            "task": {"ttl": 60000}
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        assert!(response.error.is_none(), "{:?}", response.error);
        let result = response.result.expect("CreateTaskResult");
        assert_eq!(result["task"]["status"], "working");
    }

    #[tokio::test]
    async fn test_call_tool_missing_name_is_tool_error() {
        let server = create_test_server();
        let params = json!({
            "name": super::super::meta_tools::CALL_TOOL,
            "arguments": {}
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        let result = response.result.unwrap();
        assert!(result["isError"].as_bool().unwrap_or(false));
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(text.contains("`name`"), "got: {text}");
    }

    #[tokio::test]
    async fn test_call_tool_unknown_inner_tool() {
        let server = create_test_server();
        let params = json!({
            "name": super::super::meta_tools::CALL_TOOL,
            "arguments": {"name": "ssh_does_not_exist"}
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        // Normal unknown-tool error path — proves the rewrite fell through
        // to the registry rather than being swallowed by a meta branch. Since
        // G-22 (-32602 for unknown tool, both call sites) this is a JSON-RPC
        // error, not an isError tool result. Naming the INNER tool in the
        // message (not just the -32602 code) pins that the rewrite actually
        // happened — a regression that dropped it entirely would still
        // reach the registry with `mcp_call_tool` as the name and still
        // fail with -32602, but wouldn't mention `ssh_does_not_exist`.
        let error = response.error.expect("unknown inner tool must be -32602");
        assert_eq!(error.code, -32602);
        assert!(
            error.message.contains("ssh_does_not_exist"),
            "must name the inner tool the rewrite dispatched to, got: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn test_call_tool_self_reference_is_unknown_tool() {
        // Regression test pinning the single-`if` no-recursion property: a
        // client that wraps `mcp_call_tool` as its own inner tool name must
        // NOT be dispatched again — `call_params.name` is rewritten exactly
        // once, so the (still-)CALL_TOOL name falls through to the registry
        // and fails as an ordinary unknown tool.
        let server = create_test_server();
        let params = json!({
            "name": super::super::meta_tools::CALL_TOOL,
            "arguments": {"name": super::super::meta_tools::CALL_TOOL}
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        // Since G-22, an unknown tool (including this self-reference falling
        // through to the registry) is a JSON-RPC error, not an isError
        // tool result.
        let error = response
            .error
            .expect("self-reference must not recurse, must fail as unknown tool");
        assert_eq!(error.code, -32602);
        assert!(
            error.message.to_lowercase().contains("unknown tool"),
            "got: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn test_destructive_gate_enabled_by_default() {
        // FIND-022: default config now sets
        // `require_elicitation_on_destructive = true` (security-first).
        // A destructive tool call from a session whose client did NOT
        // advertise elicitation MUST be rejected by the gate before
        // execution.
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        // session_ctx.caps.supports_elicitation() defaults to false —
        // the gate should refuse.
        let params = json!({
            "name": "ssh_cron_remove",
            "arguments": {"host": "nonexistent", "name": "x"}
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session_ctx))
            .await;
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("does not support elicitation"),
            "gate must fire by default (FIND-022): {text}"
        );
    }

    #[test]
    fn test_plan_command_from_args_caps_by_chars() {
        // Long ASCII command is capped and marked.
        let args = json!({"command": "a".repeat(PLAN_COMMAND_MAX_CHARS + 500)});
        let cmd = plan_command_from_args(Some(&args)).expect("command extracted");
        assert!(cmd.ends_with("\n… (command truncated)"));
        assert_eq!(
            cmd.trim_end_matches("\n… (command truncated)")
                .chars()
                .count(),
            PLAN_COMMAND_MAX_CHARS
        );

        // Multibyte command must not panic and must cap on chars, not bytes.
        let args = json!({"command": "é".repeat(PLAN_COMMAND_MAX_CHARS + 500)});
        let cmd = plan_command_from_args(Some(&args)).expect("command extracted");
        assert_eq!(
            cmd.trim_end_matches("\n… (command truncated)")
                .chars()
                .count(),
            PLAN_COMMAND_MAX_CHARS
        );

        // Short command passes through untouched.
        let args = json!({"command": "systemctl restart nginx"});
        assert_eq!(
            plan_command_from_args(Some(&args)).as_deref(),
            Some("systemctl restart nginx")
        );

        // No `command` field, no plan.
        assert!(plan_command_from_args(Some(&json!({"host": "prod"}))).is_none());
        assert!(plan_command_from_args(None).is_none());
    }

    #[tokio::test]
    async fn test_destructive_elicitation_summary_survives_multibyte_args() {
        // Regression: the destructive-gate summary used to slice the
        // serialized args with `&s[..300]` — a BYTE index. Any multibyte
        // char straddling byte 300 panicked ("byte index is not a char
        // boundary"), and `panic = "abort"` made that kill the server.
        // The pad loop flips the prefix parity so at least one iteration
        // lands mid-char whatever the serializer's key order.
        for pad in 0..4_usize {
            let server = create_test_server();
            let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
            let session_ctx = SessionContext::new(tx);
            session_ctx.caps.set_supports_elicitation(true);

            let params = json!({
                "name": "ssh_cron_remove",
                "arguments": {
                    "host": "h".repeat(pad),
                    "name": "é".repeat(400),
                }
            });
            // After the fix this call blocks on the elicitation round-trip;
            // the timeout is the "did not panic" success path.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                server.handle_tools_call(Some(json!(1)), Some(params), None, Some(&session_ctx)),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn test_destructive_elicitation_prompt_is_bounded() {
        // Regression: `plan_command_from_args` used to copy the whole
        // `command` arg into the elicitation prompt with no cap (the diff
        // next to it is capped at 4000), producing a prompt too large for
        // the client to render or the operator to approve.
        let server = create_test_server();
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        session_ctx.caps.set_supports_elicitation(true);

        let params = json!({
            "name": "ssh_cron_remove",
            "arguments": {
                "host": "prod",
                "name": "x",
                "command": "a".repeat(50_000),
            }
        });
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            server.handle_tools_call(Some(json!(1)), Some(params), None, Some(&session_ctx)),
        )
        .await;

        let msg = rx
            .try_recv()
            .expect("elicitation/create must have been sent");
        match msg {
            WriterMessage::Request(req) => {
                let params = req.params.expect("params");
                let message = params["message"].as_str().expect("message").to_string();
                assert!(
                    message.len() < 10_000,
                    "elicitation prompt must be bounded, got {} bytes",
                    message.len()
                );
            }
            _ => panic!("expected a WriterMessage::Request"),
        }
    }

    #[tokio::test]
    async fn test_destructive_gate_applies_through_call_tool() {
        // Regression test: Task 8 added an `mcp_call_tool` dispatcher that
        // rewrites the call to the inner tool BEFORE the destructive-elicitation
        // gate. This test pins the security property: even when a destructive tool
        // is reached VIA mcp_call_tool, the gate still blocks it if the session
        // lacks elicitation support.
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        // session_ctx.caps.supports_elicitation() defaults to false —
        // the gate should refuse, even through the dispatcher.
        let params = json!({
            "name": super::super::meta_tools::CALL_TOOL,
            "arguments": {
                "name": "ssh_cron_remove",
                "arguments": {"host": "nonexistent", "name": "x"}
            }
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session_ctx))
            .await;
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("does not support elicitation"),
            "gate must fire on inner tool after dispatcher rewrite: {text}"
        );
    }

    #[tokio::test]
    async fn test_handle_request_unknown_method() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "unknown/method".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32601); // Method not found
        assert!(error.message.contains("unknown/method"));
    }

    #[tokio::test]
    async fn test_handle_request_ping() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(42)),
            method: "ping".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
        assert_eq!(response.id, Some(json!(42)));
    }

    #[tokio::test]
    async fn test_route_initialized_notification_emits_no_response() {
        // Per JSON-RPC 2.0 / MCP spec, notifications carry no `id` and MUST NOT
        // receive a response. `route_incoming_message` must short-circuit
        // `notifications/initialized` so it never reaches the dispatcher.
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let message = super::super::protocol::JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: Some("notifications/initialized".to_string()),
            params: None,
            result: None,
            error: None,
        };

        let session_ctx = SessionContext::new(tx);
        let routed = McpServer::route_incoming_message(message, &session_ctx);

        assert!(routed.is_none(), "notification must not be dispatched");
        assert!(
            rx.try_recv().is_err(),
            "no JSON-RPC response must be emitted for a notification"
        );
    }

    #[tokio::test]
    async fn test_route_initialized_notification_fetches_roots_when_supported() {
        // When the client advertised roots support during initialize,
        // receiving `notifications/initialized` must trigger a server-initiated
        // `roots/list` request on the writer channel.
        //
        // The fetch is spawned (audit 2026-08-02), so routing returns at
        // once and the `roots/list` request lands on tx from the detached
        // task.
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        session_ctx.caps.set_supports_roots(true);
        let message = super::super::protocol::JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: Some("notifications/initialized".to_string()),
            params: None,
            result: None,
            error: None,
        };

        assert!(
            McpServer::route_incoming_message(message, &session_ctx).is_none(),
            "a notification is never dispatched"
        );

        let sent = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("expected a roots/list request within 2s")
            .expect("channel closed unexpectedly");
        match sent {
            WriterMessage::Request(req) => {
                assert_eq!(req.method, "roots/list");
            }
            _ => panic!("expected WriterMessage::Request(roots/list)"),
        }
    }

    /// Regression (audit 2026-08-02): `notifications/initialized` must NOT
    /// block the session reader loop while the `roots/list` round-trip is
    /// in flight.
    ///
    /// `route_incoming_message` runs *inside* `serve_session`'s reader loop.
    /// When `fetch_roots` was awaited inline, the loop could not read the
    /// client's `roots/list` response — the very message it was waiting
    /// for — so every session stalled for the full `ClientRequester`
    /// timeout (10s) before serving its first request. Claude Code
    /// advertises the `roots` capability, so its `tools/list` health check
    /// timed out with `MCP error -32001` on every connect.
    ///
    /// The fetch is fire-and-forget: routing returns immediately and the
    /// roots land on the session slot whenever the client answers.
    #[tokio::test]
    async fn test_route_initialized_notification_does_not_block_reader_loop() {
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        session_ctx.caps.set_supports_roots(true);
        let message = super::super::protocol::JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: Some("notifications/initialized".to_string()),
            params: None,
            result: None,
            error: None,
        };

        // No client response is ever sent. Routing must still return well
        // inside the 10s ClientRequester timeout — 500ms is two orders of
        // magnitude below it, so this cannot flake on a slow machine
        // without also being a real regression. `route_incoming_message`
        // being synchronous is the structural half of the guarantee; this
        // wall-clock bound is the behavioural half, and it survives a
        // future refactor that makes the function async again.
        let started = std::time::Instant::now();
        let routed = McpServer::route_incoming_message(message, &session_ctx);
        let elapsed = started.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "initialized notification blocked the reader loop for {elapsed:?}"
        );
        assert!(routed.is_none(), "a notification is never dispatched");

        // The fetch still happened — just off the reader loop.
        let sent = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("expected a roots/list request within 2s")
            .expect("channel closed unexpectedly");
        match sent {
            WriterMessage::Request(req) => assert_eq!(req.method, "roots/list"),
            _ => panic!("expected WriterMessage::Request(roots/list)"),
        }
    }

    #[tokio::test]
    async fn test_handle_tools_call_ssh_status_returns_content() {
        let server = create_test_server();
        let params = json!({
            "name": "ssh_status",
            "arguments": {}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["content"].is_array());
        let content = result["content"].as_array().unwrap();
        assert!(!content.is_empty());
        assert_eq!(content[0]["type"], "text");
    }

    #[test]
    fn test_handle_prompts_list_returns_all_prompts() {
        let server = create_test_server();
        let response = server.handle_prompts_list(Some(json!(1)));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let prompts = result["prompts"].as_array().unwrap();

        assert_eq!(prompts.len(), 7);

        let names: Vec<&str> = prompts
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"system-health"));
        assert!(names.contains(&"deploy"));
        assert!(names.contains(&"security-audit"));
        assert!(names.contains(&"troubleshoot"));
        assert!(names.contains(&"docker-health"));
        assert!(names.contains(&"k8s-overview"));
        assert!(names.contains(&"backup-verify"));
    }

    #[test]
    fn test_handle_prompts_list_prompts_have_required_fields() {
        let server = create_test_server();
        let response = server.handle_prompts_list(Some(json!(1)));

        let result = response.result.unwrap();
        let prompts = result["prompts"].as_array().unwrap();

        for prompt in prompts {
            assert!(prompt["name"].is_string(), "Prompt missing name");
            assert!(
                prompt["description"].is_string(),
                "Prompt missing description"
            );
        }
    }

    #[tokio::test]
    async fn test_handle_prompts_get_system_health() {
        let server = create_test_server();
        let params = json!({
            "name": "system-health",
            "arguments": {
                "host": "test-server"
            }
        });

        let response = server
            .handle_prompts_get(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let messages = result["messages"].as_array().unwrap();

        assert!(!messages.is_empty());
        assert_eq!(messages[0]["role"], "user");
        assert!(
            messages[0]["content"]["text"]
                .as_str()
                .unwrap()
                .contains("test-server")
        );
    }

    #[tokio::test]
    async fn test_handle_prompts_get_unknown_prompt() {
        let server = create_test_server();
        let params = json!({
            "name": "nonexistent-prompt",
            "arguments": {}
        });

        let response = server
            .handle_prompts_get(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602); // Invalid params
        assert!(error.message.contains("nonexistent-prompt"));
    }

    #[tokio::test]
    async fn test_handle_prompts_get_missing_params() {
        let server = create_test_server();
        let response = server.handle_prompts_get(Some(json!(1)), None).await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    #[tokio::test]
    async fn test_initialize_includes_prompts_capability() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), None)
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["capabilities"]["prompts"].is_object());
    }

    // ============== Additional Initialize Tests ==============

    #[tokio::test]
    async fn test_initialize_with_null_id() {
        let server = create_test_server();
        let response = server.handle_initialize(None, None, None).await;

        assert!(response.error.is_none());
        // G-3: `route_incoming_message` now drops id-less messages, so the
        // stdio path can no longer reach this handler with `id: None`. The
        // handler must still emit a spec-legal `"id": null` for direct
        // callers (HTTP, tests).
        let serialized = serde_json::to_value(&response).unwrap();
        assert!(serialized.as_object().unwrap().contains_key("id"));
        assert!(serialized["id"].is_null());
    }

    #[tokio::test]
    async fn test_initialize_with_string_id() {
        let server = create_test_server();
        let response = server
            .handle_initialize(Some(json!("request-1")), None, None)
            .await;

        assert!(response.error.is_none());
        assert_eq!(response.id, Some(json!("request-1")));
    }

    #[tokio::test]
    async fn test_initialize_includes_resources_capability() {
        let server = create_test_server();
        let response = server.handle_initialize(Some(json!(1)), None, None).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["capabilities"]["resources"].is_object());
    }

    #[tokio::test]
    async fn test_initialize_multiple_times() {
        let server = create_test_server();

        let response1 = server.handle_initialize(Some(json!(1)), None, None).await;
        let response2 = server.handle_initialize(Some(json!(2)), None, None).await;

        // Both should succeed (no state prevents re-initialization)
        assert!(response1.error.is_none());
        assert!(response2.error.is_none());
    }

    #[tokio::test]
    async fn test_initialize_invalid_params_still_succeeds() {
        let server = create_test_server();
        let params = json!({
            "invalid": "params",
            "completely": "wrong"
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), None)
            .await;

        // Should still succeed (params are optional/best-effort)
        assert!(response.error.is_none());
        // With no recoverable protocolVersion, we advertise our own latest.
        let result = response.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn test_initialize_recovers_protocol_version_from_malformed_params() {
        let server = create_test_server();
        // `clientInfo` is missing, so `InitializeParams` deserialization
        // fails outright — the whole `params` object used to be discarded in
        // a `debug!`, silently downgrading the session to our latest version.
        let params = json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "elicitation": {} }
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), None)
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(
            result["protocolVersion"], "2025-06-18",
            "a supported protocolVersion must survive a failed typed parse"
        );
    }

    #[tokio::test]
    async fn test_initialize_unsupported_protocol_version_falls_forward() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "1999-01-01",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0.0.1" }
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), None)
            .await;

        // Spec: fall forward to our latest, do NOT return -32602.
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn test_initialize_recovers_capabilities_when_only_client_version_missing() {
        // Fix-round follow-up to G-18: the original fix only recovered
        // `protocolVersion` off the raw Value. `ClientInfo.version` had no
        // serde default, so a client that omits ONLY `clientInfo.version`
        // still failed the typed deserialize and still lost `capabilities`
        // and `clientInfo` entirely — including `capabilities.elicitation`,
        // which the destructive-tool gate depends on
        // (`require_elicitation_on_destructive` defaults to true).
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        let params = json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "elicitation": {} },
            "clientInfo": { "name": "test-client" }
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), Some(&session_ctx))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["protocolVersion"], "2025-06-18");
        assert!(
            session_ctx.caps.supports_elicitation(),
            "omitting only clientInfo.version must not drop capabilities.elicitation"
        );
    }

    // ============== Additional Tools Tests ==============

    #[tokio::test]
    async fn test_tools_list_with_null_id() {
        let server = create_test_server();
        let response = server.handle_tools_list(None, None).await;

        assert!(response.error.is_none());
        // G-3: id-less messages never reach here from stdio any more; the
        // response must still serialize `"id": null` rather than omit it.
        let serialized = serde_json::to_value(&response).unwrap();
        assert!(serialized.as_object().unwrap().contains_key("id"));
        assert!(serialized["id"].is_null());
    }

    #[tokio::test]
    async fn test_tools_list_multiple_times() {
        let server = create_test_server();

        let response1 = server.handle_tools_list(Some(json!(1)), None).await;
        let response2 = server.handle_tools_list(Some(json!(2)), None).await;

        assert!(response1.error.is_none());
        assert!(response2.error.is_none());

        // Results should be identical
        assert_eq!(response1.result, response2.result);
    }

    #[tokio::test]
    async fn test_tools_call_with_null_arguments() {
        let server = create_test_server();
        let params = json!({
            "name": "ssh_status",
            "arguments": null
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        // Should succeed (null arguments treated as empty)
        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_tools_call_empty_name() {
        let server = create_test_server();
        let params = json!({
            "name": "",
            "arguments": {}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        // Empty name should result in tool not found. Since G-22, that is a
        // JSON-RPC -32602 error, not an isError tool result. -32602 alone
        // doesn't separate "reached the registry as an unknown tool" from
        // an earlier param-shape rejection (also -32602) — the message
        // must say "Unknown tool" to prove it took the registry path.
        let error = response.error.expect("empty name must be -32602");
        assert_eq!(error.code, -32602);
        assert!(
            error.message.contains("Unknown tool"),
            "must reach the registry as an unknown tool, not an earlier param rejection, got: {}",
            error.message
        );
    }

    // ============== Additional Prompts Tests ==============

    #[tokio::test]
    async fn test_prompts_get_deploy() {
        let server = create_test_server();
        let params = json!({
            "name": "deploy",
            "arguments": {
                "host": "prod-server",
                "service": "my-app"
            }
        });

        let response = server
            .handle_prompts_get(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let messages = result["messages"].as_array().unwrap();
        assert!(!messages.is_empty());
    }

    #[tokio::test]
    async fn test_prompts_get_security_audit() {
        let server = create_test_server();
        let params = json!({
            "name": "security-audit",
            "arguments": {
                "host": "server1"
            }
        });

        let response = server
            .handle_prompts_get(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_prompts_get_invalid_params_structure() {
        let server = create_test_server();
        let params = json!([1, 2, 3]); // Array instead of object

        let response = server
            .handle_prompts_get(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
    }

    // ============== Resources Tests ==============

    #[tokio::test]
    async fn test_resources_list_returns_array() {
        let server = create_test_server();
        let response = server.handle_resources_list(Some(json!(1))).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["resources"].is_array());
    }

    #[tokio::test]
    async fn test_resources_read_missing_params() {
        let server = create_test_server();
        let response = server.handle_resources_read(Some(json!(1)), None).await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    #[tokio::test]
    async fn test_resources_read_invalid_uri() {
        let server = create_test_server();
        let params = json!({
            "uri": "invalid://not-a-resource"
        });

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        // Should return error for unknown resource type
        assert!(response.error.is_some());
    }

    // ============== Request Handling Tests ==============

    #[tokio::test]
    async fn test_handle_request_with_null_id() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: "ping".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
        // G-3: `handle_request` is a raw dispatch entry point and still
        // answers. The filtering happens one layer up, in
        // `route_incoming_message` — see
        // `test_route_incoming_message_drops_unhandled_notification`.
        let serialized = serde_json::to_value(&response).unwrap();
        assert!(serialized.as_object().unwrap().contains_key("id"));
        assert!(serialized["id"].is_null());
    }

    // ============== Notification Routing (G-3) ==============

    #[test]
    fn test_route_incoming_message_drops_unhandled_notification() {
        // JSON-RPC 2.0 §4.1: a Notification is a Request without `id` and
        // the server MUST NOT reply to it. `notifications/progress` is the
        // reachable case — a client reports progress against a
        // server-issued progressToken and we used to answer it with a
        // Response carrying no id at all.
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);

        let message = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: Some("notifications/progress".to_string()),
            params: Some(json!({ "progressToken": "tok-1", "progress": 1 })),
            result: None,
            error: None,
        };

        let routed = McpServer::route_incoming_message(message, &session_ctx);
        assert!(
            routed.is_none(),
            "a JSON-RPC notification must not be dispatched as a request"
        );
    }

    #[test]
    fn test_route_incoming_message_drops_unknown_method_notification() {
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);

        let message = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: Some("notifications/something/we/do/not/know".to_string()),
            params: None,
            result: None,
            error: None,
        };

        assert!(McpServer::route_incoming_message(message, &session_ctx).is_none());
    }

    #[test]
    fn test_route_incoming_message_keeps_request_with_id() {
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);

        let message = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(7)),
            method: Some("ping".to_string()),
            params: None,
            result: None,
            error: None,
        };

        let routed =
            McpServer::route_incoming_message(message, &session_ctx).expect("request must route");
        assert_eq!(routed.method, "ping");
        assert_eq!(routed.id, Some(json!(7)));
    }

    // ============== Cancelled-request suppression (G-17) ==============

    #[test]
    fn test_cancelled_response_is_not_written_back() {
        // MCP: after receiving `notifications/cancelled`, the receiver
        // SHOULD NOT send a result or an error for that request id — the
        // client has already released it. We still BUILD the -32800
        // envelope (HTTP has no cancellation notification path and needs a
        // terminal answer); the stdio session just doesn't write it.
        let cancelled = JsonRpcResponse::error(Some(json!(1)), JsonRpcError::cancelled(None));
        assert!(!McpServer::should_send_response(&cancelled));
    }

    #[test]
    fn test_non_cancelled_responses_are_written_back() {
        let failed = JsonRpcResponse::error(Some(json!(2)), JsonRpcError::internal_error("boom"));
        assert!(McpServer::should_send_response(&failed));

        let bad_params =
            JsonRpcResponse::error(Some(json!(3)), JsonRpcError::invalid_params("nope"));
        assert!(McpServer::should_send_response(&bad_params));

        let ok = JsonRpcResponse::success(Some(json!(4)), json!({}));
        assert!(McpServer::should_send_response(&ok));
    }

    #[test]
    fn test_should_write_back_requires_cancel_token_confirmation() {
        // Fix-round hardening: `should_send_response` alone keys on the
        // error CODE, which is correct today only because the sole
        // producer of `CANCELLED_ERROR_CODE` is a per-request token fired
        // by `notifications/cancelled`. `should_write_back` adds the
        // second half of that assumption as an explicit, checked
        // precondition — a future -32800 producer unrelated to a real
        // cancellation must not be silently suppressed.
        let cancelled = JsonRpcResponse::error(Some(json!(1)), JsonRpcError::cancelled(None));
        assert!(
            McpServer::should_write_back(&cancelled, false),
            "must write back: the token was never actually cancelled"
        );
        assert!(
            !McpServer::should_write_back(&cancelled, true),
            "must suppress: this is a genuine cancellation"
        );

        let ok = JsonRpcResponse::success(Some(json!(2)), json!({}));
        assert!(McpServer::should_write_back(&ok, true));
        assert!(McpServer::should_write_back(&ok, false));
    }

    #[tokio::test]
    async fn test_handle_request_tools_list() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(99)),
            method: "tools/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
        assert_eq!(response.id, Some(json!(99)));
    }

    #[tokio::test]
    async fn test_handle_request_prompts_list() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(100)),
            method: "prompts/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_handle_request_resources_list() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(101)),
            method: "resources/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
    }

    // ============== Server Creation Tests ==============

    #[test]
    fn test_server_creation_with_default_config() {
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

        let (server, audit_task) = McpServer::new(config);

        // Server should be created
        assert!(!server.initialized.load(std::sync::atomic::Ordering::SeqCst));

        // Audit task might be None if audit is disabled by default
        drop(audit_task);
    }

    #[tokio::test]
    async fn test_server_initialized_flag() {
        let server = create_test_server();

        // Initially not initialized
        assert!(!server.initialized.load(std::sync::atomic::Ordering::SeqCst));

        // After initialize call
        server.handle_initialize(Some(json!(1)), None, None).await;

        // Should be initialized
        assert!(server.initialized.load(std::sync::atomic::Ordering::SeqCst));
    }

    // ============== Edge Cases ==============

    #[tokio::test]
    async fn test_handle_request_empty_method() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: String::new(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32601); // Method not found
    }

    #[tokio::test]
    async fn test_handle_request_unicode_method() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "方法/调用".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_some());
    }

    // ============== Task Tests (MCP 2025-11-25+) ==============

    #[tokio::test]
    async fn test_initialize_includes_tasks_capability() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), None)
            .await;

        let result = response.result.unwrap();
        assert!(result["capabilities"]["tasks"].is_object());
        assert!(result["capabilities"]["tasks"]["list"].is_object());
        assert!(result["capabilities"]["tasks"]["cancel"].is_object());
        assert!(result["capabilities"]["tasks"]["requests"]["tools"]["call"].is_object());
    }

    /// NOT a mirror of dispatch, despite appearances: production never calls
    /// `task_support()` to build the listing — three independent hardcoded
    /// literals do — so this only proves the listing and the helper agree.
    /// Under COORDINATED drift, `definitions()` and `task_support()` both
    /// moved to "optional", it goes green while the server still answers
    /// `-32601`. `meta_tools::tests::task_support_is_coherent_with_dispatch`
    /// is the test that pins ground truth against `handle_tools_call`; do not
    /// delete it as "a redundant assertion" (audit D-F5, 2026-08-20).
    #[tokio::test]
    async fn test_tools_list_includes_execution_field() {
        let server = create_test_server();
        let response = server.handle_tools_list(Some(json!(1)), None).await;

        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();

        for tool in tools {
            let name = tool["name"].as_str().expect("tool name");
            // G-21/G-14/G-19 (audit 2026-08-19): every tool in `tools/list`
            // (including `mcp_call_tool`, listed in both modes since it is
            // dispatchable in both) must declare a real `execution.taskSupport`
            // that agrees with what `handle_tools_call` actually does with a
            // `task` object for that name: "forbidden" for the three meta-tools
            // (dispatched ahead of the task branch), "optional" everywhere else.
            assert_eq!(
                tool["execution"]["taskSupport"],
                super::super::meta_tools::task_support(name),
                "Tool {name} execution.taskSupport disagrees with dispatch"
            );
        }
    }

    #[tokio::test]
    async fn test_tools_call_without_task_field_is_synchronous() {
        let server = create_test_server();
        let params = json!({
            "name": "ssh_status",
            "arguments": {}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        // Synchronous: should return content directly (not CreateTaskResult)
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["content"].is_array());
    }

    #[tokio::test]
    async fn test_tools_call_with_task_field_returns_create_task_result() {
        let server = create_test_server();
        let params = json!({
            "name": "ssh_status",
            "arguments": {},
            "task": {"ttl": 30000}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // Should have task field with taskId and status
        assert!(result["task"]["taskId"].is_string());
        assert_eq!(result["task"]["status"], "working");
        assert!(result["task"]["createdAt"].is_string());
        assert!(result["task"]["pollInterval"].is_number());
    }

    #[tokio::test]
    async fn test_tools_call_with_task_emits_status_working_notification() {
        // SEP-1686: every status transition (including non-existent → working at
        // creation) MUST emit `notifications/tasks/status` so clients can track
        // the task lifecycle without polling.
        let server = create_test_server();
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        let params = json!({
            "name": "ssh_status",
            "arguments": {},
            "task": {"ttl": 30000}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session_ctx))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let task_id = result["task"]["taskId"]
            .as_str()
            .expect("response should carry task.taskId")
            .to_string();

        // The creation notification is emitted synchronously before the response
        // is built, so it MUST already be queued. Drain anything on the channel
        // and look for the working notification specifically — the spawned
        // worker may also race in a terminal-status notification.
        let mut found_working = false;
        while let Ok(Some(msg)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await
        {
            if let WriterMessage::Notification(n) = msg
                && n.method == "notifications/tasks/status"
            {
                let params = n.params.expect("tasks/status should carry params");
                if params["taskId"] == task_id.as_str() && params["status"] == "working" {
                    found_working = true;
                    break;
                }
            }
        }

        assert!(
            found_working,
            "expected `notifications/tasks/status` with status=\"working\" and taskId={task_id}"
        );
    }

    #[tokio::test]
    async fn test_tools_call_async_unknown_tool() {
        let server = create_test_server();
        let params = json!({
            "name": "nonexistent_tool",
            "arguments": {},
            "task": {}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;

        // Task-augmented path must agree with the synchronous one: -32602,
        // not a CreateTaskResult and not an isError envelope.
        let error = response
            .error
            .expect("an unknown tool must be a JSON-RPC error on the task path too");
        assert_eq!(error.code, -32602);
        assert!(error.message.contains("nonexistent_tool"));
    }

    #[tokio::test]
    async fn test_tasks_get_returns_status() {
        let server = create_test_server();
        // Create a task via tools/call
        let call_params = json!({
            "name": "ssh_status",
            "arguments": {},
            "task": {"ttl": 60000}
        });
        let call_response = server
            .handle_tools_call(Some(json!(1)), Some(call_params), None, None)
            .await;
        let task_id = call_response.result.unwrap()["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_string();

        // Poll the task
        let get_params = json!({"taskId": task_id});
        // Small delay to let the worker potentially finish
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let response = server
            .handle_tasks_get(Some(json!(2)), Some(get_params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["taskId"], task_id);
        // Status could be working or completed at this point
        assert!(result["status"].is_string());
    }

    #[tokio::test]
    async fn test_tasks_get_nonexistent() {
        let server = create_test_server();
        let params = json!({"taskId": "nonexistent-id"});

        let response = server.handle_tasks_get(Some(json!(1)), Some(params)).await;

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_tasks_cancel() {
        let server = create_test_server();
        // Create a task
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["status"], "cancelled");
    }

    #[tokio::test]
    async fn test_tasks_cancel_nonexistent() {
        let server = create_test_server();
        let params = json!({"taskId": "no-such-task"});

        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn test_tasks_list_empty() {
        let server = create_test_server();

        let response = server.handle_tasks_list(Some(json!(1)), None).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["tasks"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_tasks_list_with_tasks() {
        let server = create_test_server();
        server.task_store.create_task(Some(60_000)).await.unwrap();
        server.task_store.create_task(Some(60_000)).await.unwrap();

        let response = server.handle_tasks_list(Some(json!(1)), None).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["tasks"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_tasks_list_invalid_cursor_returns_invalid_params() {
        let server = create_test_server();
        let params = json!({ "cursor": "no-such-task-id" });

        let response = server.handle_tasks_list(Some(json!(1)), Some(params)).await;

        let error = response
            .error
            .expect("an unknown tasks/list cursor must be a JSON-RPC error");
        assert_eq!(error.code, -32602);
        assert!(
            error.message.contains("no-such-task-id"),
            "error must name the offending cursor, got: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn test_tools_list_non_numeric_cursor_returns_invalid_params() {
        let server = create_test_server();
        let params = json!({ "cursor": "not-a-number" });

        let response = server
            .handle_tools_list(Some(json!(1)), Some(&params))
            .await;

        let error = response
            .error
            .expect("a non-numeric tools/list cursor must be a JSON-RPC error");
        assert_eq!(error.code, -32602);
        assert!(
            error.message.contains("not-a-number"),
            "error must name the offending cursor, got: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn test_tasks_result_waits_for_completion() {
        let server = create_test_server();
        let params = json!({
            "name": "ssh_status",
            "arguments": {},
            "task": {"ttl": 60000}
        });

        let call_response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, None)
            .await;
        let task_id = call_response.result.unwrap()["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_string();

        // tasks/result blocks until terminal
        let result_params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_result(Some(json!(2)), Some(result_params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // Should have _meta with related-task
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
            task_id
        );
        // Should have content from the tool execution
        assert!(result["content"].is_array());
    }

    #[tokio::test]
    async fn test_tasks_result_nonexistent() {
        let server = create_test_server();
        let params = json!({"taskId": "no-such-task"});

        let response = server
            .handle_tasks_result(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn test_tasks_cancel_already_completed_returns_error() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();
        server
            .task_store
            .complete_task(
                &task_id,
                json!({"content": [{"type": "text", "text": "done"}]}),
            )
            .await;

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
        let err = response.error.unwrap();
        assert_eq!(err.code, -32602);
    }

    #[tokio::test]
    async fn test_tasks_cancel_already_cancelled_returns_error() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();
        server.task_store.cancel_task(&task_id).await.unwrap();

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn test_tasks_get_on_completed_task() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();
        server
            .task_store
            .complete_task(
                &task_id,
                json!({"content": [{"type": "text", "text": "ok"}]}),
            )
            .await;

        let params = json!({"taskId": task_id});
        let response = server.handle_tasks_get(Some(json!(1)), Some(params)).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["status"], "completed");
        assert_eq!(result["taskId"], task_id);
    }

    /// G-23 (audit 2026-08-19): `cancel_task` stores no result, so
    /// `wait_for_result` returns `None` and the handler answered "Task not
    /// found" — while `tasks/get` and `tasks/list` both still returned the same
    /// task. Wording fix only; storing a terminal result for cancelled tasks is
    /// out of scope for 2.2.0.
    ///
    /// D-F3 (audit 2026-08-20): the message was built with `{:?}` on a
    /// `TaskStatus` carrying `#[serde(rename_all = "lowercase")]`, so this
    /// endpoint said `Cancelled` while `tasks/get` said `cancelled` for the
    /// same task — and the terminal state was reachable only by string-matching
    /// English. Both spellings were asserted in this one test, fourteen lines
    /// apart.
    #[tokio::test]
    async fn test_tasks_result_on_cancelled_task() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();
        server.task_store.cancel_task(&task_id).await.unwrap();

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_result(Some(json!(1)), Some(params))
            .await;

        let error = response.error.expect("cancelled tasks store no result");
        assert!(
            !error.message.contains("Task not found"),
            "misleading message: {}",
            error.message
        );
        // The wire spelling, not Rust's. Anchored on the substitution site:
        // the trailing "(cancelled tasks record none)" parenthetical contains
        // the lowercase word regardless, so a bare `contains("cancelled")`
        // would pass even with `{:?}`.
        assert!(
            error.message.contains("terminal state cancelled"),
            "message must name the terminal state in its wire spelling: {}",
            error.message
        );
        assert!(
            !error.message.contains("Cancelled"),
            "Rust Debug casing must not reach the wire: {}",
            error.message
        );

        // Machine-readable: no client should have to parse the prose above.
        let data = error
            .data
            .expect("a terminal-state tasks/result error must carry data");
        assert_eq!(data["taskId"], json!(task_id));
        assert_eq!(data["status"], json!("cancelled"));

        // The two endpoints must agree: tasks/get still reports the task.
        let get = server
            .handle_tasks_get(Some(json!(2)), Some(json!({"taskId": task_id})))
            .await;
        assert_eq!(get.result.expect("task info")["status"], "cancelled");
    }

    #[tokio::test]
    async fn test_tasks_result_unknown_id_still_says_not_found() {
        let server = create_test_server();
        let response = server
            .handle_tasks_result(Some(json!(1)), Some(json!({"taskId": "no-such-task"})))
            .await;

        let error = response.error.expect("unknown task is an error");
        assert!(
            error.message.contains("Task not found"),
            "got: {}",
            error.message
        );
    }

    /// G-1 (audit 2026-08-19): a `tasks/result` poll whose budget elapses
    /// must answer with the task's CURRENT status. Returning "Task not
    /// found" would tell the client its running task had vanished, and
    /// returning nothing at all is what used to park the request forever.
    #[tokio::test]
    async fn test_tasks_result_times_out_with_current_status() {
        // 10ms poll interval => 300ms wait budget.
        let limits = LimitsConfig {
            task_poll_interval_ms: 10,
            ..LimitsConfig::default()
        };
        let server = create_test_server_with_limits(limits);

        // A task nobody will ever complete.
        let (task_id, _cancel) = server.task_store.create_task(Some(60_000)).await.unwrap();

        let started = Instant::now();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server.handle_tasks_result(Some(json!(1)), Some(json!({ "taskId": task_id }))),
        )
        .await
        .expect("tasks/result must not park forever");

        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "poll should end after ~300ms, took {:?}",
            started.elapsed()
        );
        assert!(
            response.error.is_none(),
            "a timed-out poll is not an error: {:?}",
            response.error
        );
        let result = response.result.unwrap();
        assert_eq!(result["taskId"], task_id);
        assert_eq!(result["status"], "working");
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
            task_id
        );
    }

    /// G-9 (audit 2026-08-19): a task-augmented `tools/call` must be
    /// governed by `limits.max_concurrent_commands` like any other command.
    /// The enclosing request drops its permit as soon as it returns the
    /// `CreateTaskResult`, so the worker has to take its own — otherwise the
    /// real ceiling is `max_tasks` (50), and 50 concurrent SSH connections
    /// walk straight into sshd's `MaxStartups` 10:30:100.
    #[tokio::test]
    async fn task_augmented_call_waits_for_a_concurrency_permit() {
        let server = create_test_server();
        let available = server.concurrent_limit.available_permits();
        assert_eq!(available, 5, "fixture must keep the default limit");

        // Hold every permit: no command may run.
        let permits = Arc::clone(&server.concurrent_limit)
            .acquire_many_owned(u32::try_from(available).unwrap())
            .await
            .unwrap();

        let params = json!({
            "name": "ssh_status",
            "arguments": {},
            "task": {"ttl": 60000}
        });
        // If the permit were acquired BEFORE the `tokio::spawn` (i.e. still
        // in the dispatch path, the exact regression this test guards
        // against), this call would block forever on `acquire_owned()`
        // while we hold every permit above — `handle_tools_call` awaits
        // `handle_tools_call_async` directly (see call site around
        // `handle_tools_call`), it is never spawned itself. Wrap it in a
        // timeout so that misplacement fails as a readable assertion
        // instead of hanging the test (and CI) forever.
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server.handle_tools_call(Some(json!(1)), Some(params), None, None),
        )
        .await
        .expect(
            "handle_tools_call never returned — the concurrency permit is \
             likely being acquired before tokio::spawn (in the dispatch \
             path) instead of inside the spawned worker, so the enclosing \
             request itself blocked on the permits this test is holding",
        );
        let task_id = response.result.unwrap()["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_string();

        // The worker must be parked on the semaphore, not running.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let info = server.task_store.get_task(&task_id).await.unwrap();
        assert_eq!(
            info.status,
            crate::ports::protocol::TaskStatus::Working,
            "task worker ran while every concurrency permit was held"
        );

        // Release the permits: the worker must then run to a terminal state.
        drop(permits);
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let info = server.task_store.get_task(&task_id).await.unwrap();
            if info.status != crate::ports::protocol::TaskStatus::Working {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "task never ran after the permits were released"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // The worker's own permit must be released once it reaches a
        // terminal state — otherwise "the worker holds it for the whole
        // TTL" would pass this test silently.
        assert_eq!(
            server.concurrent_limit.available_permits(),
            5,
            "worker did not release its concurrency permit on completion"
        );
    }

    #[tokio::test]
    async fn test_tasks_result_on_already_completed() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();
        server
            .task_store
            .complete_task(
                &task_id,
                json!({"content": [{"type": "text", "text": "result data"}]}),
            )
            .await;

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_result(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
            task_id
        );
        assert!(result["content"].is_array());
    }

    #[tokio::test]
    async fn test_tasks_get_missing_params() {
        let server = create_test_server();

        let response = server.handle_tasks_get(Some(json!(1)), None).await;

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_tasks_cancel_missing_params() {
        let server = create_test_server();

        let response = server.handle_tasks_cancel(Some(json!(1)), None).await;

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_tasks_result_missing_params() {
        let server = create_test_server();

        let response = server.handle_tasks_result(Some(json!(1)), None).await;

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_handle_request_tasks_result_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/result".to_string(),
            params: Some(json!({"taskId": "nonexistent"})),
        };

        let response = server.handle_request(request).await;

        // Should be dispatched (not method_not_found)
        assert!(response.error.is_some());
        assert_ne!(response.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn test_handle_request_tasks_get_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/get".to_string(),
            params: Some(json!({"taskId": "nonexistent"})),
        };

        let response = server.handle_request(request).await;

        // Should be dispatched (not method_not_found)
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602); // Invalid params (task not found)
    }

    #[tokio::test]
    async fn test_handle_request_tasks_list_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        // Should succeed with empty tasks list
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["tasks"].is_array());
    }

    #[tokio::test]
    async fn test_handle_request_tasks_cancel_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/cancel".to_string(),
            params: Some(json!({"taskId": "nonexistent"})),
        };

        let response = server.handle_request(request).await;

        // Should be dispatched (not method_not_found)
        assert!(response.error.is_some());
        assert_ne!(response.error.unwrap().code, -32601);
    }

    // ============== Resources List/Read Tests ==============

    #[tokio::test]
    async fn test_resources_list_contains_expected_resources() {
        let server = create_test_server();
        let response = server.handle_resources_list(Some(json!(1))).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let resources = result["resources"].as_array().unwrap();

        // With no hosts configured, history://recent and health://server are present
        let uris: Vec<&str> = resources
            .iter()
            .map(|r| r["uri"].as_str().unwrap())
            .collect();
        assert!(uris.contains(&"history://recent"));
        assert!(uris.contains(&"health://server"));
    }

    #[tokio::test]
    async fn test_resources_list_resources_have_required_fields() {
        let server = create_test_server();
        let response = server.handle_resources_list(Some(json!(1))).await;

        let result = response.result.unwrap();
        let resources = result["resources"].as_array().unwrap();

        for resource in resources {
            assert!(resource["uri"].is_string(), "Resource missing uri");
            assert!(resource["name"].is_string(), "Resource missing name");
        }
    }

    #[tokio::test]
    async fn test_resources_list_with_null_id() {
        let server = create_test_server();
        let response = server.handle_resources_list(None).await;

        assert!(response.error.is_none());
        // G-3: `"id": null` must be present, not omitted.
        let serialized = serde_json::to_value(&response).unwrap();
        assert!(serialized.as_object().unwrap().contains_key("id"));
        assert!(serialized["id"].is_null());
    }

    #[tokio::test]
    async fn test_resources_read_valid_history_uri() {
        let server = create_test_server();
        let params = json!({ "uri": "history://recent" });

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["contents"].is_array());
    }

    #[tokio::test]
    async fn test_resources_read_valid_health_uri() {
        let server = create_test_server();
        let params = json!({ "uri": "health://server" });

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["contents"].is_array());
        let contents = result["contents"].as_array().unwrap();
        assert!(!contents.is_empty());
    }

    /// G-7 (audit 2026-08-19): asking for a scheme the server does not serve
    /// is a caller mistake (-32602 Invalid params), not a server malfunction
    /// (-32603 Internal error). Real execution failures keep -32603.
    #[tokio::test]
    async fn test_resources_read_unsupported_scheme() {
        let server = create_test_server();
        let params = json!({ "uri": "ftp://server/file" });

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert!(error.message.contains("ftp"));
        assert_eq!(
            error.code, -32602,
            "an unroutable scheme is Invalid params, not Internal error"
        );
    }

    /// The malformed-URI path shares the same `McpInvalidRequest` variant and
    /// must also report -32602.
    #[tokio::test]
    async fn test_resources_read_malformed_uri_is_invalid_params() {
        let server = create_test_server();
        let params = json!({ "uri": "health://wrong-target" });

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        let error = response.error.expect("health://wrong-target must fail");
        assert_eq!(error.code, -32602, "message was: {}", error.message);
    }

    /// Fix round 1 (audit 2026-08-19, task 33 follow-up): `UnknownHost` is a
    /// caller mistake exactly like a malformed URI, but was falling through
    /// to the catch-all `-32603` arm because it isn't `McpInvalidRequest`.
    #[tokio::test]
    async fn test_resources_read_unknown_host_is_invalid_params() {
        let server = create_test_server();
        let params = json!({ "uri": "file://nosuchhost/etc/passwd" });

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        let error = response.error.expect("unknown host must fail");
        assert_eq!(error.code, -32602, "message was: {}", error.message);
        assert!(error.message.contains("nosuchhost"), "{}", error.message);
    }

    /// Fix round 1 (audit 2026-08-19, task 33 follow-up): a rate limit is
    /// NOT the caller's fault — the request was well-formed and should be
    /// retried — so it must stay `-32603`, not fall into the `-32602` arm
    /// the way it did when the resource handlers built it as
    /// `McpInvalidRequest`. Exhausts a 1-token-per-second bucket with two
    /// back-to-back calls; the second must be rejected by the limiter.
    #[tokio::test]
    async fn test_resources_read_rate_limit_is_internal_error() {
        let mut config = test_config();
        config.limits = LimitsConfig {
            rate_limit_per_second: 1,
            ..LimitsConfig::default()
        };
        // Permissive so the "cat" command clears command validation and the
        // handler actually reaches the rate-limit check on both calls,
        // rather than failing earlier every time on "not in whitelist".
        config.security = SecurityConfig {
            mode: crate::config::SecurityMode::Permissive,
            ..SecurityConfig::default()
        };
        config.hosts.insert(
            "prod".to_string(),
            crate::config::HostConfig {
                hostname: "test.example.com".to_string(),
                port: 22,
                user: "tester".to_string(),
                auth: crate::config::AuthConfig::Agent,
                description: None,
                host_key_verification: crate::config::HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: crate::config::OsType::default(),
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
        let (server, _audit_task) = McpServer::new(config);

        let params = json!({ "uri": "file://prod/etc/hosts" });

        // First call consumes the single token; whatever it returns (success
        // or an execution failure) is irrelevant to this test.
        let _ = server
            .handle_resources_read(Some(json!(1)), Some(params.clone()))
            .await;

        // Second call must hit the exhausted bucket.
        let response = server
            .handle_resources_read(Some(json!(2)), Some(params))
            .await;

        let error = response.error.expect("exhausted rate limit must fail");
        assert_eq!(
            error.code, -32603,
            "a rate limit is not a caller mistake, message was: {}",
            error.message
        );
        assert!(
            error.message.contains("Rate limit"),
            "expected a rate-limit message, got: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn test_resources_read_invalid_params_structure() {
        let server = create_test_server();
        let params = json!([1, 2, 3]); // Array instead of object

        let response = server
            .handle_resources_read(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    // ============== Resource Templates Tests ==============

    #[test]
    fn test_resource_templates_list_empty_hosts() {
        let server = create_test_server();
        let response = server.handle_resource_templates_list(Some(json!(1)));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let templates = result["resourceTemplates"].as_array().unwrap();
        // No hosts configured, so no templates
        assert!(templates.is_empty());
    }

    #[test]
    fn test_resource_templates_list_with_null_id() {
        let server = create_test_server();
        let response = server.handle_resource_templates_list(None);

        assert!(response.error.is_none());
        // G-3: `"id": null` must be present, not omitted.
        let serialized = serde_json::to_value(&response).unwrap();
        assert!(serialized.as_object().unwrap().contains_key("id"));
        assert!(serialized["id"].is_null());
    }

    /// Build a server whose config has exactly one host, so the
    /// per-host resource templates are non-empty.
    fn create_test_server_with_host(alias: &str) -> McpServer {
        let mut config = test_config();
        config.hosts.insert(
            alias.to_string(),
            crate::config::HostConfig {
                hostname: "test.example.com".to_string(),
                port: 22,
                user: "tester".to_string(),
                auth: crate::config::AuthConfig::Agent,
                description: None,
                host_key_verification: crate::config::HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: crate::config::OsType::default(),
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
        let (server, _audit_task) = McpServer::new(config);
        server
    }

    /// G-7 (audit 2026-08-19): the only published template was
    /// `ssh://{host}/{path}`, and no handler answers the `ssh` scheme — every
    /// expansion of the advertised template failed. Templates must be derived
    /// from the handlers that actually exist.
    ///
    /// MINOR (fix round 1, audit 2026-08-19): the original version of this
    /// test only checked scheme membership and an expansion-variable
    /// substring — it never proved a published template actually
    /// *resolves*. It now also expands the `file://` template for a
    /// concrete path and routes it through the real `resources/read`
    /// handler, proving the URI is recognized and dispatched rather than
    /// rejected as unroutable — the exact failure the phantom `ssh://`
    /// template produced 100% of the time before G-7. Also switched the
    /// expected expansion variable from `{path}` to `{+path}`: `{path}` is
    /// RFC 6570 *simple* expansion, which percent-encodes `/`, so a
    /// conformant expander would turn a nested path into something
    /// `parse_file_uri`/`parse_log_uri` cannot route; `{+path}` (*reserved*
    /// expansion) passes `/` through unencoded.
    #[tokio::test]
    async fn test_published_resource_templates_all_have_a_handler() {
        let server = create_test_server_with_host("prod");
        let response = server.handle_resource_templates_list(Some(json!(1)));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let templates = result["resourceTemplates"].as_array().unwrap();
        assert!(
            !templates.is_empty(),
            "one configured host must yield at least one template"
        );

        let schemes = server.resource_registry.schemes();
        for template in templates {
            let uri_template = template["uriTemplate"].as_str().unwrap();
            let scheme = uri_template.split("://").next().unwrap();
            assert!(
                schemes.contains(&scheme),
                "published template {uri_template} uses scheme '{scheme}' \
                 which no registered handler answers (registered: {schemes:?})"
            );
            assert_ne!(
                scheme, "ssh",
                "the phantom ssh:// template must not come back"
            );
            assert!(
                uri_template.contains("{+path}"),
                "a template must use RFC 6570 reserved expansion so a \
                 nested path round-trips: {uri_template}"
            );
        }

        let published: Vec<&str> = templates
            .iter()
            .map(|t| t["uriTemplate"].as_str().unwrap())
            .collect();
        assert!(
            published.contains(&"file://prod/{+path}"),
            "the file handler is template-based and must be published, got {published:?}"
        );
        assert!(
            published.contains(&"log://prod/{+path}"),
            "the log handler is template-based and must be published, got {published:?}"
        );

        // Prove the published `file://` template actually resolves: expand
        // it for a concrete path and route it through the real
        // `resources/read` handler. There is no real SSH backend in this
        // test, so the call still fails -- but it must fail for a
        // DIFFERENT reason than the phantom `ssh://` template did
        // (`-32602`, "unroutable scheme"). Any other failure proves the URI
        // was recognized and dispatched to the file handler, which is what
        // "the template resolves" means.
        let read_response = server
            .handle_resources_read(
                Some(json!(2)),
                Some(json!({ "uri": "file://prod/etc/hosts" })),
            )
            .await;
        let error = read_response
            .error
            .expect("no real SSH backend in this test, so the read itself must fail");
        assert_ne!(
            error.code, -32602,
            "a -32602 here would mean the URI was rejected as unroutable, \
             exactly like the old phantom ssh:// template -- got: {}",
            error.message
        );
    }

    // ============== Resource Subscribe/Unsubscribe Tests ==============

    /// IMPORTANT (fix round 1 of the 2026-08-19 audit corrections, task 31
    /// follow-up): `handle_initialize` now advertises
    /// `resources.subscribe: false` (G-6) because nothing in this crate
    /// ever emits `notifications/resources/updated` — but this handler kept
    /// handing out a `subscriptionId` anyway, promising a notification the
    /// handshake had just disclaimed. `resources/subscribe` must refuse
    /// every call with `-32601 Method not found`, matching what a client
    /// should expect from a capability the server does not advertise, and
    /// must write nothing into the per-session map (there is nothing left
    /// to unsubscribe from later).
    ///
    /// Before: pinned that a valid subscribe call succeeds and lands in the
    /// per-session `resource_subs` map (FIND-036). Now: pins that it is
    /// unconditionally refused and the map stays empty — real coverage of
    /// the opposite behavior, not a relaxed version of the old assertion.
    #[tokio::test]
    async fn test_resource_subscribe_always_returns_method_not_found() {
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        let params = json!({ "uri": "health://server" });

        let response =
            McpServer::handle_resource_subscribe(Some(json!(1)), Some(params), Some(&session_ctx));

        let error = response.error.expect("subscribe must be refused");
        assert_eq!(error.code, -32601);
        assert!(error.message.contains("resources/subscribe"));
        let subs = session_ctx.resource_subs.read().await;
        assert!(
            subs.is_empty(),
            "a refused subscribe must not write a subscription id anyone could later unsubscribe"
        );
    }

    /// Before: pinned that a MISSING `uri` param specifically produces
    /// `-32602 Invalid params`, i.e. that param validation ran. Now: the
    /// capability gate fires before any param is even looked at, so a
    /// missing `uri` gets the same `-32601` as a well-formed call — pinning
    /// that the refusal is unconditional, not parameter-dependent.
    #[tokio::test]
    async fn test_resource_subscribe_missing_uri_still_refused_as_method_not_found() {
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        let params = json!({});

        let response =
            McpServer::handle_resource_subscribe(Some(json!(1)), Some(params), Some(&session_ctx));

        let error = response.error.expect("subscribe must be refused");
        assert_eq!(error.code, -32601);
    }

    /// `resources/unsubscribe` is refused with the same -32601 as
    /// `resources/subscribe` (F9). The pair must agree: the handshake
    /// disclaims `resources.subscribe`, so neither half of the
    /// subscription protocol exists, and a client probing for one must not
    /// be told that cancelling works while creating does not.
    ///
    /// The session is seeded with a subscription anyway, so this test also
    /// proves the refusal is UNCONDITIONAL rather than an accident of the
    /// map being empty — and that the entry is left untouched rather than
    /// silently removed by a handler that claims not to exist.
    #[tokio::test]
    async fn test_resource_unsubscribe_is_refused_like_subscribe() {
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        session_ctx
            .resource_subs
            .write()
            .await
            .insert("health://server".to_string(), vec!["sub-1".to_string()]);

        let unsub_params = json!({ "uri": "health://server" });
        let response = McpServer::handle_resource_unsubscribe(
            Some(json!(2)),
            Some(unsub_params),
            Some(&session_ctx),
        );

        let error = response
            .error
            .expect("unsubscribe must be refused while the capability is disclaimed");
        assert_eq!(error.code, -32601);
        assert!(
            error.message.contains("resources/unsubscribe"),
            "the refusal must name the method the client called, not its sibling: {}",
            error.message
        );

        // The seeded entry survives: a method that does not exist must not
        // have had a side effect.
        let subs = session_ctx.resource_subs.read().await;
        assert!(
            subs.contains_key("health://server"),
            "a refused unsubscribe must not mutate the session map"
        );
    }

    #[tokio::test]
    async fn test_resource_subscribe_without_session_rejected() {
        // Still refused without a session -- now unconditionally, via the
        // same -32601 capability gate rather than a session-specific check.
        let params = json!({ "uri": "health://server" });
        let response = McpServer::handle_resource_subscribe(Some(json!(1)), Some(params), None);
        let error = response.error.expect("subscribe must be refused");
        assert_eq!(error.code, -32601);
    }

    // ============== subscriptions/listen Tests (2026-07-28) ==============

    #[tokio::test]
    async fn test_subscriptions_listen_registers_and_acknowledges() {
        let server = create_test_server();
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        let params = json!({
            "notifications": {
                "toolsListChanged": true,
                "resourceSubscriptions": ["history://recent", "ssh://prod/etc/passwd"]
            }
        });

        let response = server
            .handle_subscriptions_listen(Some(json!(1)), Some(params), Some(&session_ctx))
            .await;

        assert!(response.error.is_none());
        let sub_id = response.result.expect("result")["subscriptionId"]
            .as_u64()
            .expect("subscriptionId is a number");
        assert_eq!(server.subscriptions.len(), 1);

        // The ack is a NOTIFICATION on the session channel, and echoes
        // only the URIs this server can actually serve (no ssh:// handler
        // exists, so that URI must be dropped from the echo).
        match rx.try_recv().expect("ack notification must be sent") {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/subscriptions/acknowledged");
                let params = n.params.expect("params present");
                assert_eq!(
                    params["_meta"][crate::mcp::protocol::META_SUBSCRIPTION_ID],
                    json!(sub_id)
                );
                assert_eq!(params["notifications"]["toolsListChanged"], json!(true));
                assert_eq!(
                    params["notifications"]["resourceSubscriptions"],
                    json!(["history://recent"])
                );
            }
            _ => panic!("expected a Notification"),
        }
    }

    #[tokio::test]
    async fn test_subscriptions_listen_requires_notifications_member() {
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);

        let response = server
            .handle_subscriptions_listen(Some(json!(1)), Some(json!({})), Some(&session_ctx))
            .await;

        assert_eq!(response.error.expect("error").code, -32602);
    }

    #[tokio::test]
    async fn test_subscriptions_listen_without_session_is_refused() {
        let server = create_test_server();
        let response = server
            .handle_subscriptions_listen(
                Some(json!(1)),
                Some(json!({ "notifications": { "toolsListChanged": true } })),
                None,
            )
            .await;
        assert_eq!(response.error.expect("error").code, -32600);
        assert!(server.subscriptions.is_empty());
    }

    #[tokio::test]
    async fn test_subscriptions_listen_is_routed_by_method_name() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "subscriptions/listen".to_string(),
            params: Some(json!({ "notifications": { "toolsListChanged": true } })),
        };

        // The session-less public entry point refuses it — but with
        // -32600, proving the method is routed rather than unknown.
        let error = server
            .handle_request(request)
            .await
            .error
            .expect("session-less listen is refused");
        assert_eq!(error.code, -32600, "method must be routed, not unknown");
    }

    /// MCP 2026-07-28: a server MUST NOT deliver a notification type that
    /// no live subscription requested. Before this, `spawn_config_watcher`
    /// fanned `tools/list_changed` + `resources/list_changed` out to every
    /// live session regardless of what (if anything) it had subscribed to.
    #[tokio::test]
    async fn test_list_changed_reaches_only_subscribers() {
        let server = create_test_server();
        let (tx_sub, mut rx_sub) = mpsc::channel::<WriterMessage>(8);
        let (tx_silent, mut rx_silent) = mpsc::channel::<WriterMessage>(8);
        let session_sub = SessionContext::new(tx_sub);
        // A live session that never sent subscriptions/listen.
        let _session_silent = SessionContext::new(tx_silent);

        server
            .handle_subscriptions_listen(
                Some(json!(1)),
                Some(json!({ "notifications": { "toolsListChanged": true } })),
                Some(&session_sub),
            )
            .await;
        // Drain the acknowledgement so the next recv is the broadcast.
        let _ack = rx_sub.try_recv().expect("ack notification");

        assert_eq!(
            server
                .subscriptions
                .publish_topic(NotificationTopic::ToolsListChanged),
            1
        );

        match rx_sub.try_recv().expect("subscriber receives its topic") {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/tools/list_changed");
            }
            _ => panic!("expected a Notification"),
        }
        assert!(
            rx_silent.try_recv().is_err(),
            "a session that never sent subscriptions/listen MUST receive nothing"
        );

        // A topic nobody subscribed to reaches nobody at all.
        assert_eq!(
            server
                .subscriptions
                .publish_topic(NotificationTopic::ResourcesListChanged),
            0
        );
        assert!(
            rx_sub.try_recv().is_err(),
            "a tools-only subscriber MUST NOT receive resources/list_changed"
        );
    }

    /// The config watcher is the only server-wide `list_changed` producer.
    /// It must build without touching a fanout, and must be a no-op when
    /// nothing is subscribed.
    #[tokio::test]
    async fn test_config_reload_publishes_through_the_subscription_registry() {
        let server = create_test_server();
        assert!(server.subscriptions.is_empty());
        assert_eq!(
            server
                .subscriptions
                .publish_topic(NotificationTopic::ToolsListChanged),
            0,
            "a reload with zero subscriptions delivers zero notifications"
        );
    }

    // ============== Completions Tests ==============

    #[test]
    fn test_completions_complete_missing_params() {
        let server = create_test_server();
        let response = server.handle_completions_complete(Some(json!(1)), None);

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    #[test]
    fn test_completions_complete_invalid_params() {
        let server = create_test_server();
        let params = json!({ "invalid": "structure" });
        let response = server.handle_completions_complete(Some(json!(1)), Some(params));

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    #[test]
    fn test_completions_complete_prompt_ref() {
        let server = create_test_server();
        let params = json!({
            "ref": {
                "type": "ref/prompt",
                "name": "system-health"
            },
            "argument": {
                "name": "host",
                "value": ""
            }
        });

        let response = server.handle_completions_complete(Some(json!(1)), Some(params));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["completion"].is_object());
        assert!(result["completion"]["values"].is_array());
        assert!(result["completion"]["total"].is_number());
    }

    #[test]
    fn test_completions_complete_resource_ref() {
        let server = create_test_server();
        let params = json!({
            "ref": {
                "type": "ref/resource",
                "uri": "ssh://server/{path}"
            },
            "argument": {
                "name": "path",
                "value": "/etc"
            }
        });

        let response = server.handle_completions_complete(Some(json!(1)), Some(params));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["completion"]["values"].is_array());
    }

    // ============== Logging Tests ==============

    #[test]
    fn test_logging_set_level_missing_params() {
        let server = create_test_server();
        let response = server.handle_logging_set_level(Some(json!(1)), None, None);

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[test]
    fn test_logging_set_level_invalid_params() {
        let server = create_test_server();
        let params = json!({ "level": "nonexistent" });
        let response = server.handle_logging_set_level(Some(json!(1)), Some(params), None);

        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[test]
    fn test_logging_set_level_debug() {
        let server = create_test_server();
        let params = json!({ "level": "debug" });
        let response = server.handle_logging_set_level(Some(json!(1)), Some(params), None);

        assert!(response.error.is_none());
        assert_eq!(server.log_level.load(Ordering::Relaxed), 0); // debug = 0
    }

    #[test]
    fn test_logging_set_level_error() {
        let server = create_test_server();
        let params = json!({ "level": "error" });
        let response = server.handle_logging_set_level(Some(json!(1)), Some(params), None);

        assert!(response.error.is_none());
        assert_eq!(server.log_level.load(Ordering::Relaxed), 4); // error = 4
    }

    // ============== Tools List Pagination Tests ==============

    #[tokio::test]
    async fn test_tools_list_with_cursor_paginates() {
        let server = create_test_server();

        // First page with cursor "0"
        let params = json!({ "cursor": "0" });
        let response = server
            .handle_tools_list(Some(json!(1)), Some(&params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 50); // page_size = 50
        assert!(result["nextCursor"].is_string()); // more pages available
    }

    #[tokio::test]
    async fn test_tools_list_cursor_past_end_returns_empty() {
        let server = create_test_server();

        // Cursor way past the end
        let params = json!({ "cursor": "999999" });
        let response = server
            .handle_tools_list(Some(json!(1)), Some(&params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.is_empty());
    }

    /// D-F7 (audit 2026-08-20): `"18446744073709551615"` parses cleanly to
    /// `usize::MAX`, so the cursor guard let it through and `start + page_size`
    /// overflowed BEFORE `.min(len)` clamped it — a panic in debug builds, and
    /// in release a silent wrap to 49 that the `start < len` guard happened to
    /// turn into an empty page. `saturating_add` makes both profiles agree with
    /// `test_tools_list_cursor_past_end_returns_empty`.
    #[tokio::test]
    async fn test_tools_list_cursor_usize_max_does_not_overflow() {
        let server = create_test_server();

        let params = json!({ "cursor": usize::MAX.to_string() });
        let response = server
            .handle_tools_list(Some(json!(1)), Some(&params))
            .await;

        assert!(response.error.is_none(), "got: {:?}", response.error);
        let result = response.result.unwrap();
        assert!(result["tools"].as_array().unwrap().is_empty());
        assert!(result["nextCursor"].is_null());
    }

    #[tokio::test]
    async fn test_tools_list_no_cursor_returns_all() {
        let server = create_test_server();

        let response = server.handle_tools_list(Some(json!(1)), None).await;
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();

        // Without cursor, all tools are returned (>50)
        assert!(tools.len() > 50);
        // And no nextCursor
        assert!(result.get("nextCursor").is_none() || result["nextCursor"].is_null());
    }

    #[tokio::test]
    async fn test_tools_list_filter_by_group() {
        let server = create_test_server();

        let params = json!({ "group": "docker" });
        let response = server
            .handle_tools_list(Some(json!(1)), Some(&params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
        for tool in tools {
            let name = tool["name"].as_str().unwrap();
            assert!(
                name.starts_with("ssh_docker"),
                "Expected docker tool, got {name}"
            );
        }
    }

    #[tokio::test]
    async fn test_tools_list_filter_read_only() {
        let server = create_test_server();

        let params = json!({ "readOnlyHint": true });
        let response = server
            .handle_tools_list(Some(json!(1)), Some(&params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
        for tool in tools {
            let read_only = tool["annotations"]["readOnlyHint"]
                .as_bool()
                .unwrap_or(false);
            assert!(read_only, "Tool {} not read-only", tool["name"]);
        }
    }

    #[tokio::test]
    async fn test_tools_list_filter_destructive() {
        let server = create_test_server();

        let params = json!({ "destructiveHint": true });
        let response = server
            .handle_tools_list(Some(json!(1)), Some(&params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        for tool in tools {
            let destructive = tool["annotations"]["destructiveHint"]
                .as_bool()
                .unwrap_or(false);
            assert!(destructive, "Tool {} not destructive", tool["name"]);
        }
    }

    // ============== Request Routing Coverage ==============

    #[tokio::test]
    async fn test_handle_request_completions_complete_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "completions/complete".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        // Missing params -> invalid_params, not method_not_found
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_handle_request_completion_complete_singular_dispatch() {
        // The MCP 2025-06-18 schema names this method `completion/complete`
        // (SINGULAR). The installed Claude Code client sends only that
        // spelling, and it was answered with -32601 Method not found,
        // making `DefaultCompletionProvider` dead code over the wire.
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "completion/complete".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(
            error.code, -32602,
            "missing params must be invalid_params, not method_not_found"
        );
    }

    #[tokio::test]
    async fn test_handle_request_completion_complete_singular_returns_values() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "completion/complete".to_string(),
            // `environment` is a static-list argument (`complete_from_list`
            // in `DefaultCompletionProvider`), not `host` — `test_config()`
            // sets `hosts: HashMap::new()`, so a `host` argument here would
            // legitimately return an empty array regardless of whether
            // dispatch reached the real provider at all, which is exactly
            // the false-positive `result["completion"]["values"].is_array()`
            // used to let through (an empty array also satisfies `is_array`
            // and is what both the `try_read` fallback and
            // `unwrap_or_default()` produce).
            params: Some(json!({
                "ref": { "type": "ref/prompt", "name": "diagnose_host" },
                "argument": { "name": "environment", "value": "" }
            })),
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none(), "error: {:?}", response.error);
        let result = response.result.unwrap();
        let values: Vec<&str> = result["completion"]["values"]
            .as_array()
            .unwrap_or_else(|| panic!("completion.values must be an array, got: {result}"))
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            values,
            vec!["dev", "staging", "production"],
            "completion/complete must return DefaultCompletionProvider's real \
             values, not an empty/fallback array; got: {result}"
        );
    }

    #[tokio::test]
    async fn test_handle_request_logging_set_level_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "logging/setLevel".to_string(),
            params: Some(json!({ "level": "info" })),
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_handle_request_resources_templates_list_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "resources/templates/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["resourceTemplates"].is_array());
    }

    #[tokio::test]
    async fn test_handle_request_resources_subscribe_dispatch() {
        // FIND-036 (audit 2026-05-09): `resources/subscribe` is a
        // per-session operation. Calling it through the legacy
        // session-less `handle_request` path now produces an error
        // rather than silently writing to a non-existent shared map.
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "resources/subscribe".to_string(),
            params: Some(json!({ "uri": "health://server" })),
        };

        let response = server.handle_request(request).await;

        assert!(
            response.error.is_some(),
            "session-less subscribe must be refused (FIND-036)"
        );
    }

    #[tokio::test]
    async fn test_handle_request_resources_unsubscribe_dispatch() {
        // F9 (2026-08-19 batch H re-review): the dispatch arm must carry the
        // refusal too, not just the handler. `resources.subscribe` is
        // disclaimed at the handshake, so BOTH halves of the subscription
        // pair answer method-not-found — this used to assert success while
        // its `resources/subscribe` sibling immediately above asserted an
        // error, which is exactly the contradiction F9 removes.
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "resources/unsubscribe".to_string(),
            params: Some(json!({ "uri": "health://server" })),
        };

        let response = server.handle_request(request).await;

        let error = response
            .error
            .expect("unsubscribe must be refused while the capability is disclaimed");
        assert_eq!(error.code, -32601);
    }

    #[tokio::test]
    async fn test_handle_request_resources_read_dispatch() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "resources/read".to_string(),
            params: Some(json!({ "uri": "history://recent" })),
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
    }

    // ============== Build Server Extensions Tests ==============

    #[tokio::test]
    async fn test_build_server_extensions_includes_tasks() {
        let server = create_test_server();
        let exts = server.build_server_extensions().await.unwrap();
        assert!(exts.contains_key("io.modelcontextprotocol/tasks"));
    }

    #[tokio::test]
    async fn test_build_server_extensions_includes_output_pagination() {
        let server = create_test_server();
        let exts = server.build_server_extensions().await.unwrap();
        assert!(exts.contains_key("com.bridge-mcp/output-pagination"));
    }

    #[tokio::test]
    async fn test_build_server_extensions_no_multi_host_with_zero_hosts() {
        let server = create_test_server();
        let exts = server.build_server_extensions().await.unwrap();
        // Zero hosts -> no multi-host extension
        assert!(!exts.contains_key("com.bridge-mcp/multi-host"));
    }

    // ============== Request Cancellation (MCP 2025-11-25) ==============

    #[test]
    fn test_active_requests_starts_empty() {
        let active = ActiveRequests::new();
        assert_eq!(active.len(), 0);
    }

    #[test]
    fn test_register_request_stores_token_in_map() {
        let active = ActiveRequests::new();
        let token = active.register("req-1".to_string());

        assert!(!token.is_cancelled(), "fresh token must not be cancelled");
        assert_eq!(active.len(), 1);
        assert!(active.contains("req-1"));
    }

    #[test]
    fn test_unregister_request_removes_from_map() {
        let active = ActiveRequests::new();
        let _ = active.register("req-2".to_string());
        active.unregister("req-2");
        assert_eq!(active.len(), 0);
    }

    #[test]
    fn test_unregister_unknown_request_is_noop() {
        let active = ActiveRequests::new();
        // Must not panic when the id is not present.
        active.unregister("never-existed");
    }

    #[test]
    fn test_cancel_request_fires_token_and_returns_true() {
        let active = ActiveRequests::new();
        let token = active.register("req-3".to_string());

        let cancelled = active.cancel("req-3");

        assert!(cancelled);
        assert!(
            token.is_cancelled(),
            "token must be cancelled after cancel_request"
        );
        // Map entry should be removed as part of cancel.
        assert_eq!(active.len(), 0);
    }

    #[test]
    fn test_cancel_unknown_request_returns_false() {
        let active = ActiveRequests::new();
        assert!(!active.cancel("unknown"));
    }

    #[test]
    fn test_cancel_request_removes_entry_to_prevent_double_cancel() {
        let active = ActiveRequests::new();
        let _ = active.register("req-4".to_string());

        // First cancel fires and removes.
        assert!(active.cancel("req-4"));
        // Second cancel finds nothing.
        assert!(!active.cancel("req-4"));
    }

    /// FIND-038: a cancel notification arriving on session B must NOT
    /// touch session A's in-flight requests, even if it carries A's id.
    #[test]
    fn test_cancel_does_not_cross_sessions() {
        let session_a = ActiveRequests::new();
        let session_b = ActiveRequests::new();

        // Session A registers an in-flight request id "42".
        let token_a = session_a.register("42".to_string());

        // Session B receives notifications/cancelled { requestId: "42" }.
        // The handler runs against B's local map only.
        McpServer::handle_cancellation_notification(
            &session_b,
            Some(&json!({ "requestId": "42", "reason": "cross-session attack" })),
        );

        assert!(
            !token_a.is_cancelled(),
            "session B must not be able to cancel session A's request"
        );
        assert!(
            session_a.contains("42"),
            "session A's map must still contain its request"
        );
        assert_eq!(
            session_b.len(),
            0,
            "session B's map remains empty (no matching id locally)"
        );
    }

    /// End-to-end: verifies that `handle_request_with_cancel` propagates
    /// the token into the `ToolContext` so that `tools/call` sees a
    /// cancellable context. Uses the public `handle_tools_call` path with
    /// an unknown tool (which does no async SSH work) to avoid needing a
    /// mock executor — the test focuses on the wiring, not the cancel
    /// mechanics (which are covered by `test_cancel_request_*`).
    #[tokio::test]
    async fn test_handle_request_with_cancel_tools_call_routes_token() {
        let server = create_test_server();
        let token = tokio_util::sync::CancellationToken::new();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!("req-with-token")),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "nonexistent_tool_xyz",
                "arguments": { "host": "no-such-host" }
            })),
        };

        // Must not panic, and must produce a response (unknown tool error
        // or similar). The key assertion is that the wiring compiles and
        // runs; deeper verification lives in the full integration test
        // added in commit 6.
        let response = server
            .handle_request_with_cancel(request, Some(token), None)
            .await;
        assert!(response.result.is_some() || response.error.is_some());
    }

    /// Verifies that the public `handle_request` wrapper still works
    /// without a cancel token — required for HTTP transport and tests.
    #[tokio::test]
    async fn test_handle_request_wrapper_passes_none_cancel_token() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!("wrap-1")),
            method: "tools/list".to_string(),
            params: None,
        };
        let response = server.handle_request(request).await;
        assert!(response.error.is_none());
    }

    // ============== notifications/cancelled handler ==============

    #[test]
    fn test_handle_cancellation_notification_fires_token_for_known_id() {
        let active = ActiveRequests::new();
        let token = active.register("req-42".to_string());
        assert!(!token.is_cancelled());

        let params = json!({ "requestId": "req-42", "reason": "user abort" });
        McpServer::handle_cancellation_notification(&active, Some(&params));

        assert!(token.is_cancelled(), "token must fire after notification");
    }

    #[test]
    fn test_handle_cancellation_notification_ignores_unknown_id() {
        let active = ActiveRequests::new();
        // No panic, no observable side effect.
        let params = json!({ "requestId": "never-registered" });
        McpServer::handle_cancellation_notification(&active, Some(&params));
    }

    #[test]
    fn test_handle_cancellation_notification_ignores_missing_request_id() {
        let active = ActiveRequests::new();
        // Malformed notification (no requestId) must be silently ignored
        // per MCP spec.
        let params = json!({ "reason": "nothing specific" });
        McpServer::handle_cancellation_notification(&active, Some(&params));
    }

    #[test]
    fn test_handle_cancellation_notification_accepts_numeric_request_id() {
        // JSON-RPC allows numeric IDs; the normalization to String must
        // match what register stores for the raw ::Number case.
        let active = ActiveRequests::new();
        // The spawn path in run() uses `other.to_string()` for non-string
        // ids, which yields "7" for Value::Number(7). Test that the
        // notification handler applies the same normalization.
        let token = active.register("7".to_string());

        let params = json!({ "requestId": 7 });
        McpServer::handle_cancellation_notification(&active, Some(&params));

        assert!(token.is_cancelled());
    }

    #[test]
    fn test_plan_command_from_args_extracts_command_field() {
        let args = serde_json::json!({ "host": "prod", "command": "rm -rf /tmp/x" });
        let cmd = super::plan_command_from_args(Some(&args));
        assert_eq!(cmd.as_deref(), Some("rm -rf /tmp/x"));
    }

    #[test]
    fn test_plan_command_from_args_none_when_absent() {
        let args = serde_json::json!({ "host": "prod" });
        assert!(super::plan_command_from_args(Some(&args)).is_none());
        assert!(super::plan_command_from_args(None).is_none());
    }

    #[tokio::test]
    async fn test_initialize_server_info_meta_carries_build_rev() {
        let server = create_test_server();
        let params = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        });

        let response = server
            .handle_initialize(Some(json!(1)), Some(params), None)
            .await;

        let result = response.result.unwrap();
        let build = &result["serverInfo"]["_meta"]["io.github.muchiny/build"];
        assert!(
            build.is_object(),
            "serverInfo._meta must carry build provenance, got: {}",
            result["serverInfo"]
        );
        assert_eq!(build["rev"], BUILD_REV);
        assert_eq!(build["version"], SERVER_VERSION);
    }

    /// Confirms the NON-mutation half of the dispatch-chokepoint contract:
    /// when `handle_request_with_cancel` scopes a request's `_meta` envelope
    /// onto a session clone (Task 3), the ORIGINAL `SessionContext` the
    /// caller holds is left untouched — `request_meta` stays `None` and its
    /// capability reads keep falling back to `caps` alone.
    ///
    /// This does NOT prove the scoped clone actually carries the envelope
    /// to downstream handlers — a regression that dropped
    /// `session.map(|s| s.with_request_meta(...))` entirely would still
    /// pass this test, since `session` is `&SessionContext` and the
    /// original can never be mutated through it either way. That positive
    /// half is covered by `test_tool_context_capability_flags_come_from_request_meta`
    /// (unit-level) and end-to-end by the seam tests in tasks 4-6, which
    /// drive a real `_meta`-bearing request through full dispatch and
    /// assert on behaviour that only the scoped clone can produce.
    #[tokio::test]
    async fn test_dispatch_with_meta_leaves_original_session_unmutated() {
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tools/list".to_string(),
            params: Some(json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "ExampleClient",
                        "version": "1.0.0"
                    },
                    "io.modelcontextprotocol/clientCapabilities": { "elicitation": {} }
                }
            })),
        };

        let response = server
            .handle_request_with_cancel(request, None, Some(&session_ctx))
            .await;
        assert!(response.error.is_none());

        // The session-level bundle is untouched by the request-level parse.
        assert!(session_ctx.request_meta.is_none());
        assert!(!session_ctx.supports_elicitation());
    }

    #[tokio::test]
    async fn test_tool_context_capability_flags_come_from_request_meta() {
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let base = SessionContext::new(tx);
        // No `initialize` ever ran.
        assert!(!base.caps.supports_elicitation());
        assert!(!base.caps.supports_sampling());

        let params = json!({
            "_meta": {
                "io.modelcontextprotocol/clientCapabilities": {
                    "elicitation": {},
                    "sampling": {}
                }
            }
        });
        let scoped = base.with_request_meta(RequestMeta::from_params(Some(&params)));

        let ctx = server.create_tool_context(None, None, Some(&scoped)).await;
        assert!(ctx.client_supports_elicitation);
        assert!(ctx.client_supports_sampling);
    }

    /// THE compatibility-seam test for 3.0.0.
    ///
    /// No `initialize` ever happens — a Modern (2026-07-28) client's very
    /// first message is `tools/call`, and the only place it declares
    /// elicitation support is the per-request `_meta` envelope. The
    /// fail-closed destructive gate (`server.rs:451`) must honour that
    /// declaration, otherwise every `destructive_hint: true` tool starts
    /// refusing the moment the handshake is deleted.
    #[tokio::test]
    async fn test_destructive_gate_honours_elicitation_from_request_meta_only() {
        let mut config = test_config();
        config.security.require_elicitation_on_destructive = true;
        let (server, _audit_task) = McpServer::new(config);

        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        // Proof of the premise: no handshake ran, so the session flags are
        // all false and only the envelope can grant the capability.
        assert!(!session_ctx.caps.supports_elicitation());

        // Fake Modern client: wait for the server's `elicitation/create`,
        // then decline it. Reaching this point at all proves the capability
        // check passed on the strength of `_meta` alone.
        let pending = Arc::clone(&session_ctx.pending);
        let fake_client = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let WriterMessage::Request(req) = msg
                    && req.method == "elicitation/create"
                {
                    let id = req.id.as_str().unwrap_or_default().to_string();
                    pending.resolve(&id, ClientResponse::Success(json!({ "action": "decline" })));
                    return true;
                }
            }
            false
        });

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "ssh_cron_remove",
                "arguments": { "host": "prod", "name": "backup" },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "ExampleClient",
                        "version": "1.0.0"
                    },
                    "io.modelcontextprotocol/clientCapabilities": { "elicitation": {} }
                }
            })),
        };

        let response = server
            .handle_request_with_cancel(request, None, Some(&session_ctx))
            .await;

        let elicited = tokio::time::timeout(std::time::Duration::from_secs(5), fake_client)
            .await
            .expect(
                "timed out waiting for elicitation/create — the gate ignored the per-request _meta envelope",
            )
            .unwrap();
        assert!(
            elicited,
            "server never sent elicitation/create — the gate ignored the per-request _meta envelope"
        );

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            !text.contains("does not support elicitation"),
            "gate rejected on capability instead of eliciting: {text}"
        );
        assert!(
            text.contains("User declined execution of destructive tool"),
            "unexpected error text: {text}"
        );
    }

    /// The fail-closed half: a request with NO envelope and no handshake
    /// must still be refused. Without this, the test above could pass by
    /// the gate having been disabled rather than by the seam working.
    #[tokio::test]
    async fn test_destructive_gate_still_refuses_without_meta_or_handshake() {
        let mut config = test_config();
        config.security.require_elicitation_on_destructive = true;
        let (server, _audit_task) = McpServer::new(config);

        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "ssh_cron_remove",
                "arguments": { "host": "prod", "name": "backup" }
            })),
        };

        let response = server
            .handle_request_with_cancel(request, None, Some(&session_ctx))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("does not support elicitation"),
            "unexpected error text: {text}"
        );
    }

    /// Legacy era: `initialize` declared elicitation, subsequent requests
    /// carry no `_meta`. The fallback must keep working until the handshake
    /// is removed in a later 3.0.0 task.
    #[tokio::test]
    async fn test_destructive_gate_falls_back_to_initialize_when_no_meta() {
        let mut config = test_config();
        config.security.require_elicitation_on_destructive = true;
        let (server, _audit_task) = McpServer::new(config);

        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);

        // Legacy handshake declares elicitation.
        let init = server
            .handle_initialize(
                Some(json!(0)),
                Some(json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "elicitation": {} },
                    "clientInfo": { "name": "LegacyClient", "version": "0.9.0" }
                })),
                Some(&session_ctx),
            )
            .await;
        assert!(init.error.is_none());
        assert!(session_ctx.caps.supports_elicitation());

        let pending = Arc::clone(&session_ctx.pending);
        let fake_client = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let WriterMessage::Request(req) = msg
                    && req.method == "elicitation/create"
                {
                    let id = req.id.as_str().unwrap_or_default().to_string();
                    pending.resolve(&id, ClientResponse::Success(json!({ "action": "decline" })));
                    return true;
                }
            }
            false
        });

        // No `_meta` anywhere on this request.
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "ssh_cron_remove",
                "arguments": { "host": "prod", "name": "backup" }
            })),
        };

        let response = server
            .handle_request_with_cancel(request, None, Some(&session_ctx))
            .await;

        let elicited = tokio::time::timeout(std::time::Duration::from_secs(5), fake_client)
            .await
            .expect("timed out waiting for elicitation/create — legacy fallback broken")
            .unwrap();
        assert!(
            elicited,
            "legacy fallback broken: no elicitation/create was sent"
        );
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("User declined execution of destructive tool"),
            "unexpected error text: {text}"
        );
    }

    /// Precedence: an explicit empty `clientCapabilities` in the request
    /// envelope is an authoritative denial and beats a stale handshake flag.
    #[tokio::test]
    async fn test_request_meta_empty_capabilities_overrides_initialize() {
        let mut config = test_config();
        config.security.require_elicitation_on_destructive = true;
        let (server, _audit_task) = McpServer::new(config);

        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        session_ctx.caps.set_supports_elicitation(true);

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "ssh_cron_remove",
                "arguments": { "host": "prod", "name": "backup" },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            })),
        };

        let response = server
            .handle_request_with_cancel(request, None, Some(&session_ctx))
            .await;

        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("does not support elicitation"),
            "per-request denial did not override the handshake flag: {text}"
        );
    }

    #[tokio::test]
    async fn test_client_overrides_resolve_from_request_meta_client_info() {
        use crate::config::{ClientOverride, MatchMode};

        let mut config = test_config();
        config.limits.max_output_chars = 40_000;
        config.limits.client_overrides = vec![ClientOverride {
            name_contains: "modernclient".to_string(),
            match_mode: MatchMode::Exact,
            max_output_chars: Some(1234),
        }];
        let (server, _audit_task) = McpServer::new(config);

        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let base = SessionContext::new(tx);
        // No handshake: `runtime_max_output` was never written.
        assert!(base.runtime_max_output.read().await.is_none());

        let params = json!({
            "_meta": {
                "io.modelcontextprotocol/clientInfo": {
                    "name": "ModernClient",
                    "version": "1.0.0"
                }
            }
        });
        let scoped = base.with_request_meta(RequestMeta::from_params(Some(&params)));

        let ctx = server.create_tool_context(None, None, Some(&scoped)).await;
        assert_eq!(ctx.config.limits.max_output_chars, 1234);
    }

    #[tokio::test]
    async fn test_runtime_override_beats_request_meta_client_profile() {
        use crate::config::{ClientOverride, MatchMode};

        let mut config = test_config();
        config.limits.max_output_chars = 40_000;
        config.limits.client_overrides = vec![ClientOverride {
            name_contains: "modernclient".to_string(),
            match_mode: MatchMode::Exact,
            max_output_chars: Some(1234),
        }];
        let (server, _audit_task) = McpServer::new(config);

        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let base = SessionContext::new(tx);
        // Explicit operator action (`ssh_config_set`) wins over the profile.
        *base.runtime_max_output.write().await = Some(9999);

        let params = json!({
            "_meta": {
                "io.modelcontextprotocol/clientInfo": {
                    "name": "ModernClient",
                    "version": "1.0.0"
                }
            }
        });
        let scoped = base.with_request_meta(RequestMeta::from_params(Some(&params)));

        let ctx = server.create_tool_context(None, None, Some(&scoped)).await;
        assert_eq!(ctx.config.limits.max_output_chars, 9999);
    }

    #[tokio::test]
    async fn test_no_client_info_leaves_max_output_at_the_yaml_default() {
        use crate::config::{ClientOverride, MatchMode};

        let mut config = test_config();
        config.limits.max_output_chars = 40_000;
        config.limits.client_overrides = vec![ClientOverride {
            name_contains: "modernclient".to_string(),
            match_mode: MatchMode::Exact,
            max_output_chars: Some(1234),
        }];
        let (server, _audit_task) = McpServer::new(config);

        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);

        let ctx = server
            .create_tool_context(None, None, Some(&session_ctx))
            .await;
        assert_eq!(ctx.config.limits.max_output_chars, 40_000);
    }
}
