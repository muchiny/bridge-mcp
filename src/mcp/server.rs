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
use crate::domain::{ExecuteCommandUseCase, OutputCache, TaskStore, TunnelManager};
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
use super::session_context::{NotificationFanout, SessionContext};
use super::transport::{Session, Transport, stdio::StdioTransport};

use super::history::CommandHistory;
use super::prompt_registry::{PromptRegistry, create_default_prompt_registry};
use super::protocol::{
    ClientInfo, CompletionRef, CompletionResult, CompletionsCapability, CompletionsCompleteParams,
    CompletionsCompleteResult, CreateTaskResult, Icon, InitializeParams, InitializeResult,
    JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, LogLevel,
    LoggingCapability, LoggingSetLevelParams, PROTOCOL_VERSION, PromptsCapability,
    PromptsGetParams, PromptsGetResult, PromptsListResult, ResourcesCapability,
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
    /// Server-wide fanout registry of live session writer channels.
    ///
    /// Used by the config watcher (and any other server-wide event
    /// source) to broadcast `list_changed` notifications to ALL live
    /// sessions. Per-session direct delivery (progress, elicitation,
    /// sampling, logging) goes through [`SessionContext::notification_tx`]
    /// instead — the per-session tx is the only correct routing for
    /// messages addressed to one specific client.
    ///
    /// FIND-034 (audit 2026-05-09) replaced the previous single
    /// last-writer-wins `notification_tx` slot with this fanout
    /// registry plus per-session `SessionContext` senders.
    notification_fanout: NotificationFanout,
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
        self.0.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Snapshot of currently-registered request ids. Test helper.
    #[cfg(test)]
    fn contains(&self, id: &str) -> bool {
        self.0.lock().map(|m| m.contains_key(id)).unwrap_or(false)
    }
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
        let sanitizer = Arc::new(Sanitizer::from_config_with_legacy(
            &config.security.sanitize,
            &config.security.sanitize_patterns,
        ));

        // Create audit logger (async with background writer task)
        // Vuln 3 (audit 2026-05-09): wire a sanitizer so `event.command` is
        // masked before tracing emission AND before file write — the audit
        // log used to leak MYSQL_PWD/PGPASSWORD/Bearer tokens/webhook URLs.
        let sanitizer_for_audit =
            crate::security::Sanitizer::from_config(&config.security.sanitize);
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
            notification_fanout: NotificationFanout::new(),
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
        if !session.caps.supports_elicitation() {
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
                if s.len() > 300 {
                    format!("{}… (truncated)", &s[..300])
                } else {
                    s
                }
            },
        );

        let requester = Arc::new(super::client_requester::ClientRequester::new(
            tx,
            pending,
            std::time::Duration::from_secs(120),
        ));
        let elicitation = super::elicitation::ElicitationService::new(requester);
        elicitation.set_supported(true);

        match elicitation.confirm_destructive(tool_name, &summary).await {
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

        // Apply per-session runtime override to the snapshot so handlers
        // see THIS session's effective value (FIND-033 audit 2026-05-09).
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
        ctx.client_supports_elicitation = session.is_some_and(|s| s.caps.supports_elicitation());
        ctx.client_supports_sampling = session.is_some_and(|s| s.caps.supports_sampling());
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

        info!("MCP SSH Bridge server starting...");

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

    /// Spawn the three per-server cleanup tasks (session manager, task
    /// store, output cache) and return their join handles so the serve
    /// loop can abort them on shutdown.
    fn spawn_cleanup_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let cleanup_sm = Arc::clone(&self.session_manager);
        let sm_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_sm.cleanup().await;
            }
        });

        let cleanup_ts = Arc::clone(&self.task_store);
        let ts_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_ts.cleanup().await;
            }
        });

        let cleanup_oc = Arc::clone(&self.output_cache);
        let oc_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_oc.cleanup().await;
            }
        });

        let cleanup_cp = Arc::clone(&self.connection_pool);
        let cp_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_cp.cleanup().await;
            }
        });

        vec![sm_handle, ts_handle, oc_handle, cp_handle]
    }

    /// Start a config file watcher that broadcasts `list_changed`
    /// notifications on reload.
    ///
    /// FIND-034 (audit 2026-05-09): the previous topology read a single
    /// global `notification_tx` slot at callback time, so the broadcast
    /// reached only the most recently registered session. The watcher
    /// now uses [`NotificationFanout::broadcast`], which fans the
    /// notifications out to every live session's per-session sender.
    fn spawn_config_watcher(&self, path: &Path) -> Option<ConfigWatcher> {
        let fanout = self.notification_fanout.clone();
        let on_reload: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            fanout.broadcast(&WriterMessage::Notification(
                JsonRpcNotification::tools_list_changed(),
            ));
            fanout.broadcast(&WriterMessage::Notification(
                JsonRpcNotification::resources_list_changed(),
            ));
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

        // Register this session's tx with the server-wide fanout so the
        // config watcher (and any other broadcaster) reaches us. The
        // returned guard removes the registration on drop — including
        // panics — so dead senders never accumulate (FIND-034).
        let fanout_guard = self.notification_fanout.register(tx.clone());

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
                    let Some(request) = self.route_incoming_message(message, &session_ctx).await
                    else {
                        continue;
                    };

                    // Acquire permit (blocks if at concurrency limit)
                    let Ok(permit) = self.concurrent_limit.clone().acquire_owned().await else {
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
                            let _ = tx.send(WriterMessage::Response(Box::new(response))).await;
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

        // The fanout guard removes our tx from the broadcast registry on
        // drop (end of this function), so the config watcher stops
        // trying to send into a dead channel without us touching any
        // shared state here.

        // Signal writer to stop and wait for it. Then explicitly drop
        // the fanout guard so the session's tx is removed from the
        // broadcast registry — the lexical drop at end-of-scope would
        // do this too, but being explicit documents the contract.
        drop(tx);
        let _ = writer_handle.await;
        drop(fanout_guard);
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
    async fn route_incoming_message(
        &self,
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
            self.handle_roots_changed(session).await;
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
            self.handle_initialized_notification(session).await;
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

    /// Fetch roots from the client after initialization.
    ///
    /// Uses the SESSION-LOCAL pending-requests map so a `roots/list`
    /// response coming back from the client is resolved against this
    /// session only (Vuln 8 audit 2026-05-09). The fetched roots are
    /// stored on the session-local roots slot (FIND-037 audit
    /// 2026-05-09): a different client's `roots/list` response cannot
    /// overwrite this session's roots.
    async fn fetch_roots(&self, session: &SessionContext) {
        if !session.caps.supports_roots() {
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
    async fn handle_roots_changed(&self, session: &SessionContext) {
        info!("Client roots changed, re-fetching");
        self.fetch_roots(session).await;
    }

    /// Handle `notifications/initialized` — fetch client roots if supported.
    /// No response is emitted (per JSON-RPC 2.0 notification semantics).
    async fn handle_initialized_notification(&self, session: &SessionContext) {
        info!("Client sent notifications/initialized; fetching roots");
        self.fetch_roots(session).await;
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
    /// supplied. Use [`Self::serve`] / [`Self::serve_session`] for full
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

        match request.method.as_str() {
            "initialize" => self.handle_initialize(id, request.params, session).await,
            "tools/list" => self.handle_tools_list(id, request.params.as_ref()),
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
            "completions/complete" => self.handle_completions_complete(id, request.params),
            "logging/setLevel" => self.handle_logging_set_level(id, request.params, session),
            "resources/templates/list" => self.handle_resource_templates_list(id),
            "resources/subscribe" => {
                self.handle_resource_subscribe(id, request.params, session)
                    .await
            }
            "resources/unsubscribe" => {
                self.handle_resource_unsubscribe(id, request.params, session)
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
                    debug!(error = %e, "Could not parse initialize params (continuing anyway)");
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
                    subscribe: true,
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
                website_url: Some("https://github.com/muchini/bridge-mcp".to_string()),
                icons: Some(vec![Icon {
                    src: SERVER_ICON_URL.to_string(),
                    mime_type: Some("image/svg+xml".to_string()),
                    sizes: Some(vec!["any".to_string()]),
                    theme: None,
                }]),
            },
            instructions: Some(instructions),
        };

        JsonRpcResponse::success_or_serialize_error(id, &result)
    }

    fn handle_tools_list(&self, id: Option<Value>, params: Option<&Value>) -> JsonRpcResponse {
        use super::registry::tool_group;

        let page_size = 50;

        // Filtering by annotation hints and tool group
        let filter_read_only = params
            .and_then(|p| p.get("readOnlyHint"))
            .and_then(Value::as_bool);
        let filter_destructive = params
            .and_then(|p| p.get("destructiveHint"))
            .and_then(Value::as_bool);
        let filter_group = params.and_then(|p| p.get("group")).and_then(|v| v.as_str());

        let mut all_tools = self.registry.list_tools();
        // Surface the progressive-discovery meta-tools alongside the registry
        // so clients can find them via `tools/list`. They stay at the front
        // so a client paging through the list sees them immediately.
        let mut meta_defs = super::meta_tools::definitions();
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
            let start = cursor_val.parse::<usize>().unwrap_or(0);
            let end = (start + page_size).min(all_tools.len());
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

        let call_params: ToolCallParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        info!(tool = %call_params.name, "Tool call");

        // Progressive-discovery meta-tools are dispatched before the registry
        // so they can inspect the registry itself. They are read-only and
        // argument-validated locally, so they skip the elicitation gate and
        // the task/progress plumbing.
        if super::meta_tools::is_meta_tool(&call_params.name) {
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

                // Cancellation gets a proper JSON-RPC error with MCP's
                // `-32800` "Request Cancelled" code so clients can tell it
                // apart from a plain tool failure. All other errors stay in
                // the tool-result envelope for backward compatibility.
                if matches!(e, crate::error::BridgeError::Cancelled) {
                    return JsonRpcResponse::error(id, JsonRpcError::cancelled(None));
                }

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
        // Get the handler first to validate the tool exists
        let Some(handler) = self.registry.get(&tool_name) else {
            let error_result = ToolCallResult::error(format!("Unknown tool: {tool_name}"));
            return JsonRpcResponse::success_or_serialize_error(id, &error_result);
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
                JsonRpcResponse::error(id, JsonRpcError::internal_error(e.to_string()))
            }
        }
    }

    // =========================================================================
    // Resource template & subscription handlers
    // =========================================================================

    fn handle_resource_templates_list(&self, id: Option<Value>) -> JsonRpcResponse {
        use super::protocol::ResourceTemplate;

        let Ok(config) = self.config.try_read() else {
            return JsonRpcResponse::success(id, json!({ "resourceTemplates": [] }));
        };
        let templates: Vec<ResourceTemplate> = config
            .hosts
            .keys()
            .map(|host| ResourceTemplate {
                uri_template: format!("ssh://{host}/{{path}}"),
                name: format!("{host} file access"),
                description: Some(format!("Access files on {host} via SSH")),
                mime_type: None,
            })
            .collect();

        JsonRpcResponse::success_or_serialize_error(id, &json!({ "resourceTemplates": templates }))
    }

    /// Subscribe to resource notifications.
    ///
    /// FIND-036 (audit 2026-05-09): subscriptions are now per-session.
    /// The previous server-wide `HashMap<String, Vec<String>>` keyed on
    /// URI alone leaked sub-ids across clients — two clients subscribing
    /// to the same URI shared the Vec, and one client's `unsubscribe`
    /// could remove the other's entries. Each session now has its own
    /// map, so there is no cross-session interference.
    async fn handle_resource_subscribe(
        &self,
        id: Option<Value>,
        params: Option<Value>,
        session: Option<&SessionContext>,
    ) -> JsonRpcResponse {
        let uri = params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if uri.is_empty() {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("uri is required"));
        }
        let Some(session) = session else {
            // Without a session there's no per-session subscription map
            // to write into. Subscriptions are only meaningful in a live
            // session anyway.
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_request("resources/subscribe requires an active MCP session"),
            );
        };
        let sub_id = uuid::Uuid::new_v4().to_string();
        {
            let mut subs = session.resource_subs.write().await;
            subs.entry(uri.to_string())
                .or_default()
                .push(sub_id.clone());
        }
        JsonRpcResponse::success(id, json!({"subscriptionId": sub_id}))
    }

    /// Unsubscribe from resource notifications.
    ///
    /// FIND-036 (audit 2026-05-09): operates on this session's map only.
    async fn handle_resource_unsubscribe(
        &self,
        id: Option<Value>,
        params: Option<Value>,
        session: Option<&SessionContext>,
    ) -> JsonRpcResponse {
        let uri = params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !uri.is_empty()
            && let Some(session) = session
        {
            let mut subs = session.resource_subs.write().await;
            subs.remove(uri);
        }
        JsonRpcResponse::success(id, json!({}))
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

        // Block until the task reaches a terminal state
        match self
            .task_store
            .wait_for_result(&result_params.task_id)
            .await
        {
            Some(result) => {
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
            None => JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params(format!("Task not found: {}", result_params.task_id)),
            ),
        }
    }

    async fn handle_tasks_list(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        let list_params: TaskListParams = params
            .and_then(|p| serde_json::from_value(p).ok())
            .unwrap_or(TaskListParams { cursor: None });

        let (tasks, next_cursor) = self
            .task_store
            .list_tasks(list_params.cursor.as_deref(), 20)
            .await;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, HttpTransportConfig, LimitsConfig, SecurityConfig, SessionConfig,
        SshConfigDiscovery, ToolGroupsConfig,
    };
    use serde_json::json;
    use std::collections::HashMap;

    fn create_test_server() -> McpServer {
        // Tests in this module exercise the full handler inventory
        // (pagination, group filters, etc.). FIND-024 changed the
        // default profile to a minimal 8-group set, so we explicitly
        // opt every group in for the test fixture. Production code paths
        // continue to use whatever the operator put in `tool_groups`.
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: crate::mcp::registry::all_enabled_tool_groups_config_for_test(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };
        let (server, _audit_task) = McpServer::new(config);
        server
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

    #[test]
    fn test_handle_tools_list_returns_all_registered_tools() {
        let server = create_test_server();

        let response = server.handle_tools_list(Some(json!(1)), None);

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

    #[test]
    fn test_handle_tools_list_tools_have_required_fields() {
        let server = create_test_server();

        let response = server.handle_tools_list(Some(json!(1)), None);

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

        // Unknown tool returns success with error content (MCP spec)
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["isError"].as_bool().unwrap_or(false));
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
            audit: AuditConfig::default(),
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
        let response = server.handle_tools_list(Some(json!(1)), None);
        let tools = response.result.unwrap()["tools"]
            .as_array()
            .cloned()
            .unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&super::super::meta_tools::LIST_TOOL_GROUPS));
        assert!(names.contains(&super::super::meta_tools::SEARCH_TOOLS));
        assert!(names.contains(&super::super::meta_tools::DESCRIBE_TOOL));
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
        let list_response = server.handle_tools_list(Some(json!(1)), None);
        let first_real = list_response.result.unwrap()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|t| {
                let name = t["name"].as_str()?.to_string();
                (!super::super::meta_tools::is_meta_tool(&name)).then_some(name)
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
        let server = create_test_server();
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
        let routed = server.route_incoming_message(message, &session_ctx).await;

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
        // `fetch_roots` awaits the (never-arriving) client response, so we
        // drive `route_incoming_message` in a background task and just verify
        // the outbound `roots/list` shows up on tx.
        let server = Arc::new(create_test_server());
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

        let server_bg = Arc::clone(&server);
        let session_ctx_bg = session_ctx.clone();
        let route_handle = tokio::spawn(async move {
            server_bg
                .route_incoming_message(message, &session_ctx_bg)
                .await
        });

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

        route_handle.abort();
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
        assert!(response.id.is_none());
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
    }

    // ============== Additional Tools Tests ==============

    #[test]
    fn test_tools_list_with_null_id() {
        let server = create_test_server();
        let response = server.handle_tools_list(None, None);

        assert!(response.error.is_none());
        assert!(response.id.is_none());
    }

    #[test]
    fn test_tools_list_multiple_times() {
        let server = create_test_server();

        let response1 = server.handle_tools_list(Some(json!(1)), None);
        let response2 = server.handle_tools_list(Some(json!(2)), None);

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

        // Empty name should result in tool not found
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["isError"].as_bool().unwrap_or(false));
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
        assert!(response.id.is_none());
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
            audit: AuditConfig::default(),
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

    #[test]
    fn test_tools_list_includes_execution_field() {
        let server = create_test_server();
        let response = server.handle_tools_list(Some(json!(1)), None);

        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();

        for tool in tools {
            assert_eq!(
                tool["execution"]["taskSupport"], "optional",
                "Tool {} missing execution.taskSupport",
                tool["name"]
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

        // Unknown tool should return error content, not CreateTaskResult
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["isError"].as_bool().unwrap_or(false));
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

    #[tokio::test]
    async fn test_tasks_result_on_cancelled_task() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task(Some(60_000)).await.unwrap();
        server.task_store.cancel_task(&task_id).await.unwrap();

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_result(Some(json!(1)), Some(params))
            .await;

        // Cancelled tasks have no stored result — handler returns error
        assert!(response.error.is_some());
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
        assert!(response.id.is_none());
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
        assert!(response.id.is_none());
    }

    // ============== Resource Subscribe/Unsubscribe Tests ==============

    #[tokio::test]
    async fn test_resource_subscribe_valid() {
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        let params = json!({ "uri": "health://server" });

        let response = server
            .handle_resource_subscribe(Some(json!(1)), Some(params), Some(&session_ctx))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["subscriptionId"].is_string());
        // The subscription must land in THIS session's per-session map
        // (FIND-036) — verify it's there.
        let subs = session_ctx.resource_subs.read().await;
        assert!(subs.contains_key("health://server"));
    }

    #[tokio::test]
    async fn test_resource_subscribe_missing_uri() {
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        let params = json!({});

        let response = server
            .handle_resource_subscribe(Some(json!(1)), Some(params), Some(&session_ctx))
            .await;

        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
    }

    #[tokio::test]
    async fn test_resource_unsubscribe() {
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        // First subscribe
        let sub_params = json!({ "uri": "health://server" });
        server
            .handle_resource_subscribe(Some(json!(1)), Some(sub_params), Some(&session_ctx))
            .await;

        // Then unsubscribe
        let unsub_params = json!({ "uri": "health://server" });
        let response = server
            .handle_resource_unsubscribe(Some(json!(2)), Some(unsub_params), Some(&session_ctx))
            .await;

        assert!(response.error.is_none());
        // Map must now be empty for that URI (FIND-036).
        let subs = session_ctx.resource_subs.read().await;
        assert!(!subs.contains_key("health://server"));
    }

    #[tokio::test]
    async fn test_resource_subscribe_without_session_rejected() {
        // FIND-036: subscription is per-session and meaningless without
        // a live session. Calls from non-MCP code paths must be refused
        // rather than silently forced through a non-existent global map.
        let server = create_test_server();
        let params = json!({ "uri": "health://server" });
        let response = server
            .handle_resource_subscribe(Some(json!(1)), Some(params), None)
            .await;
        assert!(response.error.is_some());
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

    #[test]
    fn test_tools_list_with_cursor_paginates() {
        let server = create_test_server();

        // First page with cursor "0"
        let params = json!({ "cursor": "0" });
        let response = server.handle_tools_list(Some(json!(1)), Some(&params));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 50); // page_size = 50
        assert!(result["nextCursor"].is_string()); // more pages available
    }

    #[test]
    fn test_tools_list_cursor_past_end_returns_empty() {
        let server = create_test_server();

        // Cursor way past the end
        let params = json!({ "cursor": "999999" });
        let response = server.handle_tools_list(Some(json!(1)), Some(&params));

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn test_tools_list_no_cursor_returns_all() {
        let server = create_test_server();

        let response = server.handle_tools_list(Some(json!(1)), None);
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();

        // Without cursor, all tools are returned (>50)
        assert!(tools.len() > 50);
        // And no nextCursor
        assert!(result.get("nextCursor").is_none() || result["nextCursor"].is_null());
    }

    #[test]
    fn test_tools_list_filter_by_group() {
        let server = create_test_server();

        let params = json!({ "group": "docker" });
        let response = server.handle_tools_list(Some(json!(1)), Some(&params));

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

    #[test]
    fn test_tools_list_filter_read_only() {
        let server = create_test_server();

        let params = json!({ "readOnlyHint": true });
        let response = server.handle_tools_list(Some(json!(1)), Some(&params));

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

    #[test]
    fn test_tools_list_filter_destructive() {
        let server = create_test_server();

        let params = json!({ "destructiveHint": true });
        let response = server.handle_tools_list(Some(json!(1)), Some(&params));

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
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "resources/unsubscribe".to_string(),
            params: Some(json!({ "uri": "health://server" })),
        };

        let response = server.handle_request(request).await;

        assert!(response.error.is_none());
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
}
