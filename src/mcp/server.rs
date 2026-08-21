use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

use serde_json::{Value, json};
use tokio::sync::{RwLock, Semaphore, mpsc};
use tokio::task::JoinSet;
use tracing::{Instrument, debug, error, info, warn};

use crate::config::{Config, ConfigWatcher};
use crate::domain::output_truncator::truncate_chars;
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
use super::request_meta::RequestMeta;
use super::session_context::SessionContext;
use super::subscriptions::{NotificationTopic, SubscriptionRegistry, SubscriptionsListenParams};
use super::transport::{Session, Transport, stdio::StdioTransport};

use super::history::CommandHistory;
use super::prompt_registry::{PromptRegistry, create_default_prompt_registry};
use super::protocol::{
    BUILD_META_KEY, BUILD_REV, CANCELLED_ERROR_CODE, CacheScope, CompletionRef, CompletionResult,
    CompletionsCapability, CompletionsCompleteParams, CompletionsCompleteResult, DISCOVER_TTL_MS,
    DetailedTask, DiscoverMeta, DiscoverResult, DiscoverResultType, Icon, JsonRpcError,
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, LogLevel, LoggingCapability,
    LoggingSetLevelParams, PROTOCOL_VERSION, PromptsCapability, PromptsGetParams, PromptsGetResult,
    PromptsListResult, ResourcesCapability, ResourcesListResult, ResourcesReadParams,
    ResourcesReadResult, SERVER_ICON_URL, SERVER_NAME, SERVER_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
    ServerCapabilities, ServerInfo, TaskCancelParams, TaskGetParams, TaskNotificationParams,
    TaskStatus, TaskUpdateParams, ToolCallParams, ToolCallResult, ToolContent, ToolsCapability,
    ToolsListResult, WriterMessage,
};
use super::registry::{ToolRegistry, create_filtered_registry};
use super::resource_registry::{ResourceRegistry, create_default_resource_registry};

/// The parts of the opening-handshake payload that are identical for the
/// Legacy `initialize` response and the Modern `server/discover` response.
///
/// `server/discover` wraps these three values and adds `resultType`,
/// `supportedVersions`, `ttlMs` and `cacheScope` on top; `initialize` wraps
/// them with a negotiated `protocolVersion`. Keeping the assembly in one place
/// means a capability added here reaches both without a second edit.
struct DiscoveryPayload {
    capabilities: ServerCapabilities,
    server_info: ServerInfo,
    instructions: String,
}

/// MCP Server that communicates over stdio
/// How often the resource-update watch loop looks for changes.
///
/// `history://` is change-detected exactly, through the monotonic
/// revision counter on `CommandHistory`. Every other published resource
/// scheme is backed by the REMOTE host — `metrics://`, `services://` and
/// `health://` shell out on each read, `file://` and `log://` read remote
/// paths — so this process has no change feed for them and must not
/// pretend to. For those, a tick means "poll again", not "it changed".
/// That is deliberate: the alternative is either advertising
/// `subscribe: true` with nothing behind it, or opening an inotify
/// channel per subscribed path over SSH, which the bridge does not do.
const RESOURCE_WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Decide which subscribed URIs get `notifications/resources/updated` on
/// one tick of the watch loop.
///
/// Split out of the loop so the decision is unit-testable without waiting
/// 30 s of wall clock.
fn resource_update_tick(uris: &[String], history_changed: bool) -> Vec<String> {
    uris.iter()
        .filter(|uri| history_changed || !uri.starts_with("history://"))
        .cloned()
        .collect()
}

/// Run ONE tick of the resource-update watch loop: read the live
/// subscriptions, decide what changed, publish, and advance
/// `last_revision`.
///
/// Extracted out of the spawned loop in
/// [`McpServer::spawn_resource_update_watch`] because that loop could not
/// be driven from a test. With a 30 s `RESOURCE_WATCH_INTERVAL` the
/// interval's first tick fires immediately but with zero subscriptions,
/// so it takes the `continue`, and the second tick is a wall-clock
/// interval away. The tick-to-publish wiring was therefore covered only
/// by hand-composed calls: gutting `publish_resource_updated` inside the
/// loop body left the whole suite green (measured at commit `3f7c2fa`,
/// 9112 passed / 0 failed), so the call could have been deleted by a
/// later refactor with nothing to notice.
///
/// Returns how many notifications were actually delivered, so a test can
/// assert on the wiring itself rather than on the loop merely being
/// alive.
fn watch_once(
    subscriptions: &SubscriptionRegistry,
    history: &CommandHistory,
    last_revision: &mut u64,
) -> usize {
    let uris = subscriptions.subscribed_resource_uris();
    if uris.is_empty() {
        return 0;
    }
    let revision = history.revision();
    let history_changed = revision != *last_revision;
    *last_revision = revision;
    resource_update_tick(&uris, history_changed)
        .iter()
        .map(|uri| subscriptions.publish_resource_updated(uri))
        .sum()
}

/// What `subscriptions/listen` decided, for the dispatch layer to act on.
///
/// MCP 2026-07-28 gives `subscriptions/listen` **no immediate result**.
/// The server acknowledges with a notification, keeps the request `id`
/// alive for the lifetime of the subscription, and answers it only at
/// graceful teardown ("it SHOULD respond to the original
/// `subscriptions/listen` request with an empty result before closing the
/// stream"). Returning a result at registration time would do two wrong
/// things at once: close a request that must stay open, and invent a
/// `{"subscriptionId": N}` shape the spec does not define.
///
/// So the handler yields an intention and each transport honours it. This
/// lives at the shared dispatch chokepoint deliberately — stdio and HTTP
/// both go through it, so neither has to re-derive the rule, and neither
/// can drift from the other.
pub(crate) enum ListenOutcome {
    /// Registered. The request `id` stays open and unanswered; the
    /// teardown response belongs to the stream owner, not to this handler.
    Streaming {
        /// Byte-for-byte the JSON-RPC `id` of the listen request.
        subscription_id: Value,
    },
    /// Refused before any subscription existed. The transport writes this
    /// response immediately, exactly as for any other rejected request.
    Rejected(Box<JsonRpcResponse>),
}

impl ListenOutcome {
    /// Build a [`ListenOutcome::Rejected`] carrying `error` for `id`.
    fn rejected(id: Option<Value>, error: JsonRpcError) -> Self {
        Self::Rejected(Box::new(JsonRpcResponse::error(id, error)))
    }
}

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
    concurrent_limit: Arc<Semaphore>,
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
            concurrent_limit,
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

        // Spawn cleanup tasks (global, shared across sessions), plus the
        // resource-update watch loop that feeds
        // `notifications/resources/updated` to live subscriptions.
        let cleanup_handles = self.spawn_global_tasks();

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

    /// Assemble every process-global background task: the cleanup loops
    /// plus the resource-update watch.
    ///
    /// Split out of [`Self::serve`] so the composition is drivable from a
    /// test. `serve()` needs a transport and an accept loop, so nothing
    /// could assert that the watch handle really joins the vec shutdown
    /// aborts — deleting the `push` reddened nothing.
    fn spawn_global_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = self.spawn_cleanup_tasks();
        handles.push(self.spawn_resource_update_watch());
        handles
    }

    /// Spawn the resource-update watch loop.
    ///
    /// Deliberately NOT part of [`Self::spawn_cleanup_tasks`]: that
    /// function's contract (and its test) is "one loop per expiring
    /// resource", and this loop expires nothing. It is appended to the
    /// same handle vec in `serve()` so shutdown aborts it too.
    ///
    /// The loop does no work at all while nobody is subscribed, and emits
    /// nothing for `history://` while the bridge is idle.
    fn spawn_resource_update_watch(&self) -> tokio::task::JoinHandle<()> {
        let subscriptions = self.subscriptions.clone();
        let history = Arc::clone(&self.history);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(RESOURCE_WATCH_INTERVAL);
            let mut last_revision = history.revision();
            loop {
                interval.tick().await;
                watch_once(&subscriptions, &history, &mut last_revision);
            }
        })
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
    /// BEFORE it spawns the handler — so N parked `tasks/result` long polls
    /// (N = the limit, 5 by default) meant the client's next message was
    /// never read at all. Measured: N=4 still answered `ping`; N=5 answered
    /// neither `ping` nor `tasks/cancel` — the one request that could have
    /// released the parked polls — and was still dead after 208 s.
    ///
    /// `tasks/result` was deleted in 3.0.0, so that exact scenario is no
    /// longer reachable; the measurement is recorded as the historical
    /// reason the exemption exists, not as a description of any method
    /// this server still dispatches. The exemption itself still earns its
    /// keep: task WORKERS legitimately hold all N permits during normal
    /// operation, and the control plane must stay answerable through it.
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
                            let Some(response) = server
                                .handle_request_with_cancel(
                                    request,
                                    cancel_token,
                                    Some(&session_ctx_for_task),
                                )
                                .await
                            else {
                                // A live `subscriptions/listen`: MCP
                                // 2026-07-28 requires the request `id` to
                                // stay alive for the lifetime of the
                                // subscription and to be answered only at
                                // graceful teardown, so nothing is written
                                // now. The id is deliberately left
                                // registered in `active_requests` too —
                                // unregistering it is exactly the "keep the
                                // id alive" rule inverted, and keeping it
                                // is what lets `notifications/cancelled`
                                // close the subscription.
                                drop(permit);
                                return;
                            };
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
    /// The `tasks/*` methods a client may only use after declaring the
    /// extension ON THE REQUEST.
    ///
    /// Named methods, never the `tasks/` PREFIX. `tasks/list` and
    /// `tasks/result` were deleted in 3.0.0 and must keep answering `-32601`
    /// to everyone: a prefix gate would tell a non-declaring client to declare
    /// a capability that would not make those methods exist. The prefix is
    /// right for `is_concurrency_exempt`, which is about scheduling; it is
    /// wrong here, where the answer has to distinguish "you may not" from
    /// "there is no such thing".
    const TASK_METHODS_REQUIRING_EXTENSION: [&'static str; 3] =
        ["tasks/get", "tasks/update", "tasks/cancel"];

    pub async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let id = request.id.clone();
        self.handle_request_with_cancel(request, None, None)
            .await
            .unwrap_or_else(|| {
                // Only `subscriptions/listen` yields no response, and only
                // once it has actually registered — which needs a session.
                // This entry point passes `None`, so listen is refused with
                // -32600 long before that point and this arm is dead TODAY.
                //
                // IT DOES NOT STAY DEAD. Task 66 gives the HTTP transport a
                // real session precisely so `subscriptions/listen` works
                // there; the moment it lands, this arm becomes live for any
                // caller that reaches listen through this signature.
                //
                // So it MUST stay an error and MUST NOT become a fabricated
                // success. Returning a synthesized `result` here would
                // silently reintroduce the exact defect this refactor
                // removed — an immediate answer to a request the spec says
                // must stay open until graceful teardown. A caller that
                // needs a live subscription has to go through a path that
                // can honour `ListenOutcome::Streaming`, not through here.
                // No `unreachable!()`: panicking a third-party transport is
                // worse than answering it honestly.
                JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_request(
                        "subscriptions/listen requires a session-aware transport",
                    ),
                )
            })
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
    ///
    /// Returns `None` for the one method that has no immediate response:
    /// a successful `subscriptions/listen` keeps its request `id` open for
    /// the lifetime of the subscription (see [`ListenOutcome`]).
    pub(crate) async fn handle_request_with_cancel(
        &self,
        request: JsonRpcRequest,
        cancel_token: Option<tokio_util::sync::CancellationToken>,
        session: Option<&SessionContext>,
    ) -> Option<JsonRpcResponse> {
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

        // The tasks extension is gated per REQUEST: "Servers MUST return this
        // error for non-declaring clients issuing `tasks/get`,
        // `tasks/update`, and `tasks/cancel` requests", and "Servers MUST NOT
        // infer capabilities from prior requests" — so a declaration made on
        // an earlier request, or at a handshake, grants nothing here.
        //
        // Ahead of the match, so that a `tasks/*` method cannot be added below
        // without meeting this list.
        if Self::TASK_METHODS_REQUIRING_EXTENSION.contains(&request.method.as_str())
            && !Self::request_declares_tasks_extension(session)
        {
            return Some(JsonRpcResponse::error(
                id,
                JsonRpcError::missing_required_client_capability(&json!({
                    "extensions": { super::protocol::extensions::TASKS: {} }
                })),
            ));
        }

        // `subscriptions/listen` is the only method with no immediate
        // result, so it is dispatched before the response-returning match
        // rather than inside it. Handling it here — at the shared
        // chokepoint — fixes stdio and any future streaming transport at
        // once, instead of leaving each transport to re-derive the rule.
        if request.method == "subscriptions/listen" {
            return match self
                .handle_subscriptions_listen(id, request.params, session)
                .await
            {
                ListenOutcome::Rejected(response) => Some(*response),
                ListenOutcome::Streaming { subscription_id } => {
                    debug!(
                        subscription_id = %subscription_id,
                        "subscriptions/listen registered; holding its request id open until teardown"
                    );
                    None
                }
            };
        }

        Some(match request.method.as_str() {
            "server/discover" => self.handle_discover(id).await,
            "initialize" => Self::handle_initialize(id, request.params.as_ref()),
            "tools/list" => self.handle_tools_list(id, request.params.as_ref()).await,
            "tools/call" => {
                self.handle_tools_call(id, request.params, cancel_token, session)
                    .await
            }
            "prompts/list" => self.handle_prompts_list(id),
            "prompts/get" => self.handle_prompts_get(id, request.params).await,
            "resources/list" => self.handle_resources_list(id).await,
            "resources/read" => self.handle_resources_read(id, request.params).await,
            // No `tasks/result` and no `tasks/list` arm: MCP 2026-07-28 has
            // neither method. `tasks/result`'s payload is inlined into the
            // `tasks/get` below; `tasks/list` was removed deliberately, so
            // that a server cannot leak one caller's task ids to another
            // (spec 5.15, cross-caller correlation). Both names now fall
            // through to -32601 like any other unknown method.
            "tasks/get" => self.handle_tasks_get(id, request.params).await,
            "tasks/update" => self.handle_tasks_update(id, request.params).await,
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
            "ping" => JsonRpcResponse::success(id, json!({})),
            _ => {
                error!(method = %request.method, "Unknown method");
                JsonRpcResponse::error(id, JsonRpcError::method_not_found(&request.method))
            }
        })
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

    /// Assemble the shared handshake payload: capabilities, server identity,
    /// and the dynamic instructions string.
    ///
    /// Every field here is a verbatim move out of `handle_initialize`,
    /// including `server_info.meta` (build provenance via
    /// `build_provenance_meta()`) — the plan this was written against
    /// omitted that field from its literal, but `handle_initialize` has
    /// unconditionally populated it since before this cluster started, and
    /// `test_server_discover_full_wire_shape` pins it. Sole caller:
    /// `handle_discover`. It was shared with `handle_initialize` until that
    /// arm stopped building a payload at all and became a bare `-32022`.
    async fn build_discovery_payload(&self) -> DiscoveryPayload {
        let instructions = {
            let config = self.config.read().await;
            instructions::build_instructions(&config, self.registry.len())
        };

        DiscoveryPayload {
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: true }),
                prompts: Some(PromptsCapability { list_changed: true }),
                resources: Some(ResourcesCapability {
                    // G-6 (audit 2026-08-19) set this to `false` because
                    // nothing in the crate emitted
                    // `notifications/resources/updated`, and left a standing
                    // instruction: "flip this back to `true` in the same
                    // commit that adds the emitter". That emitter exists now
                    // — `spawn_resource_update_watch` polls at
                    // `RESOURCE_WATCH_INTERVAL` and publishes through
                    // `SubscriptionRegistry` — so the flag is honest again.
                    //
                    // The per-URI `resources/subscribe` RPC is gone with it
                    // (MCP 2026-07-28: "It replaces the former
                    // `resources/subscribe` RPC"); a client now asks for
                    // updates through `subscriptions/listen`'s
                    // `resourceSubscriptions`. The capability flag survives
                    // that folding: it says whether resource-update
                    // notifications exist at all, not which method opens
                    // them.
                    subscribe: true,
                    list_changed: true,
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
            instructions,
        }
    }

    /// Handle `server/discover` (MCP 2026-07-28) — the Modern entry point.
    ///
    /// Unlike `initialize` this is a plain request with no follow-up
    /// notification and no connection-scoped state: nothing here writes to the
    /// server. Client identity, client capabilities and the per-request
    /// protocol version all arrive in each request's `_meta` envelope instead,
    /// which is why `params` is not read here.
    ///
    /// `cacheScope: "public"` is correct **only while this server has no
    /// per-caller authorization**. Every caller gets byte-identical
    /// capabilities, tool inventory and instructions, because group enablement
    /// comes from `config.tool_groups` (global, process-wide) and never from
    /// who is asking — which is also what 2026-07-28 requires of list
    /// endpoints. `rbac.enabled: true` is rejected at config load
    /// (`src/config/loader.rs:226`) precisely because nothing in the request
    /// path enforces it. The day RBAC becomes real and `tools/list` starts
    /// varying by caller, this value MUST become session-scoped and the
    /// tripwire test `test_cache_scope_is_public_only_while_rbac_is_dead`
    /// will fail to remind you.
    async fn handle_discover(&self, id: Option<Value>) -> JsonRpcResponse {
        let payload = self.build_discovery_payload().await;

        let result = DiscoverResult {
            result_type: DiscoverResultType::Complete,
            supported_versions: SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .map(|v| (*v).to_string())
                .collect(),
            capabilities: payload.capabilities,
            meta: Some(DiscoverMeta {
                server_info: payload.server_info,
            }),
            instructions: Some(payload.instructions),
            ttl_ms: DISCOVER_TTL_MS,
            cache_scope: CacheScope::Public,
        };

        JsonRpcResponse::success_or_serialize_error(id, &result)
    }

    /// Handle the Legacy `initialize` handshake.
    ///
    /// bridge-mcp 3.0.0 speaks MCP 2026-07-28 only, where `initialize` and
    /// `notifications/initialized` no longer exist — `server/discover` opens
    /// the connection instead (see `handle_discover`).
    ///
    /// The arm is kept, rather than falling through to `-32601 Method not
    /// found`, because a Legacy client cannot fall *forward* on its own. The
    /// spec's compatibility contract is a client-side probe
    /// (`/specification/2026-07-28/basic/transports/stdio`, "Backward
    /// Compatibility"): *"Clients supporting both modern and legacy MCP
    /// versions should probe using `server/discover` before sending other
    /// requests. If the server returns a discovery result, it is modern and
    /// the client should select a mutually supported version. If the server
    /// returns a specific modern protocol error, it is modern but requires a
    /// different version. If the server returns other errors or fails to
    /// respond, it is treated as a legacy server, and the client should fall
    /// back to the `initialize` handshake."*
    ///
    /// The server-side rule is on `/specification/2026-07-28/basic/versioning`:
    /// *"A server that supports only modern versions **SHOULD** name the
    /// protocol versions it supports in any error it returns to an
    /// `initialize` request, on any transport: legacy clients have no
    /// fall-forward mechanism, and this message may be the only diagnostic
    /// they can surface to users."* The SHOULD constrains what the error must
    /// *contain*, not which code it carries; `data.supported` is that naming,
    /// in machine-readable form.
    ///
    /// **Which code is transport-dependent, and this function is only correct
    /// for stdio.** The compatibility matrix leaves the stdio code
    /// implementation-defined (a Legacy `initialize` is both an unknown method
    /// and missing its `_meta` fields, i.e. `-32601` and `-32602` both apply),
    /// so `-32022` is a free and strictly more informative choice. Over
    /// Streamable HTTP the code is *pinned* elsewhere: a Legacy `initialize`
    /// POST carries no `Mcp-Method` header, so Server Validation makes
    /// `400` + `-32020 HeaderMismatch` a MUST, and answering `-32022` there
    /// would violate it. That check is Task 66's `check_modern_headers`, which
    /// rejects the request before dispatch ever reaches this arm — until it
    /// lands, the HTTP path answers `-32022` and is non-conformant.
    ///
    /// The requested version is read straight off the raw `Value` rather than
    /// through `InitializeParams`, so a payload that fails deserialization —
    /// missing `clientInfo`, missing `capabilities` — still echoes back what
    /// the client asked for. Nothing here mutates server or session state.
    fn handle_initialize(id: Option<Value>, params: Option<&Value>) -> JsonRpcResponse {
        let requested = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str)
            .unwrap_or_default();

        warn!(
            requested_version = requested,
            "Legacy `initialize` rejected; this server speaks {PROTOCOL_VERSION} only \
             (use server/discover)"
        );

        JsonRpcResponse::error(id, JsonRpcError::unsupported_protocol_version(requested))
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

        // Server-elected task. MCP 2026-07-28 deleted `params.task`: "The
        // server is the sole decider; clients do not signal task preference on
        // the request itself." The policy lives in `task_policy`.
        //
        // BOTH conditions are required, and the second is a MUST NOT, not a
        // courtesy: "A server MUST NOT return `CreateTaskResult` to a client
        // that did not include the extension capability on its request,
        // regardless of prior declarations." A non-declaring client asking for
        // a long-running tool gets the ordinary synchronous answer — the same
        // one it got before this release — never a handle it cannot poll.
        //
        // MCP Tasks have their own cancellation via `tasks/cancel`; we don't
        // propagate the request-level `cancel_token` here because the task
        // lives beyond the enclosing request.
        if super::task_policy::is_long_running(&call_params.name)
            && Self::request_declares_tasks_extension(session)
        {
            // The progress token is deliberately NOT forwarded: it is not
            // part of this call's signature at all. See the context built
            // below.
            return self
                .handle_tools_call_async(call_params.name, call_params.arguments, id, session)
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

    /// Whether THIS request declared the tasks extension.
    ///
    /// Reads `request_meta` and nothing else. There is deliberately no
    /// `SessionContext::supports_tasks_extension()` alongside
    /// `supports_elicitation()` / `supports_sampling()` / `supports_roots()`:
    /// those three fall back to the connection handshake when the request
    /// declares nothing, and for the tasks extension that fallback is
    /// forbidden — "regardless of prior declarations", and "Servers MUST NOT
    /// infer capabilities from prior requests". An accessor built on the
    /// neighbouring pattern would be a capability cache wearing the right
    /// clothes.
    ///
    /// A session with no `request_meta` at all (the non-MCP internal call
    /// path) declares nothing, so it is `false` — never a handle.
    fn request_declares_tasks_extension(session: Option<&SessionContext>) -> bool {
        session
            .and_then(|s| s.request_meta.as_ref())
            .is_some_and(|meta| meta.declares_extension(super::protocol::extensions::TASKS))
    }

    /// Handle a server-elected task: create the task, spawn a background
    /// worker, and return the flat task handle immediately.
    #[allow(clippy::too_many_lines)]
    async fn handle_tools_call_async(
        &self,
        tool_name: String,
        arguments: Option<Value>,
        id: Option<Value>,
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
        // `None`: the server picks the TTL unilaterally (spec 5.9). The
        // client used to propose one through `params.task.ttl` and the store
        // capped it; there is no client proposal left to cap.
        let Some((task_id, cancel_token)) = self.task_store.create_task().await else {
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

        // Emit `notifications/tasks` for the initial non-existent → working
        // transition. The worker emits the matching terminal notification.
        // A `working` task has no payload to carry.
        if let Some(tx) = task_notification_tx.as_ref() {
            let params = TaskNotificationParams::new(task_info.clone(), None);
            let msg = WriterMessage::Notification(JsonRpcNotification::task_notification(&params));
            let _ = tx.try_send(msg);
        }

        // Propagate the task's cancel_token into the ToolContext so the
        // handler can do clean shutdown (e.g. evicting the SSH connection
        // from the pool) when the task is cancelled via `tasks/cancel`.
        // `None` for the progress token, and the parameter no longer reaches
        // this function at all: "`notifications/progress` and
        // `notifications/message` notifications MUST NOT be sent on the
        // `subscriptions/listen` stream for a task, and are not supported on
        // tasks in general in this specification."
        //
        // Structure, not vigilance: `ToolContext::progress_reporter` hands a
        // handler `None` when the token is absent, so a promoted tool CANNOT
        // report progress even if it asks. Progress for a task lives in
        // `statusMessage` instead. This matters most for the tool most likely
        // to join the promotion list after the MRTR item closes —
        // `ssh_runbook_execute` is one of the four handlers that do call
        // `progress_reporter`.
        let ctx = self
            .create_tool_context(Some(cancel_token.clone()), None, session)
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

            // Store the result and send notification.
            //
            // The `failed`/`completed` boundary is a MUST that is easy to
            // implement backwards, and 2025-11-25 said the OPPOSITE of what
            // 2026-07-28 says: "The `failed` status MUST NOT be used to
            // represent non-JSON-RPC errors, such as a tool result that
            // completed with `isError: true`. Errors within the context of a
            // protocol method result MUST use the `completed` status with the
            // error details in the `result` field."
            //
            // The rule that makes each arm decidable: `tasks/get` "returns
            // exactly what the underlying request would have returned". So
            // this match mirrors the SYNCHRONOUS path arm for arm — whatever
            // `handle_tools_call` answers with an isError envelope is
            // `completed` here, and only what it answers with a JSON-RPC error
            // is `failed`.
            let (info, payload) = match result {
                Ok(tool_result) => {
                    let tool_result = tool_result.without_apps();
                    let result_value =
                        serde_json::to_value(&tool_result).unwrap_or_else(|e| json!({
                            "content": [{"type": "text", "text": format!("Serialization error: {e}")}],
                            "isError": true,
                        }));
                    (
                        task_store
                            .complete_task(&task_id, result_value.clone())
                            .await,
                        Some(result_value),
                    )
                }
                // Cancellation is the one arm the synchronous path answers
                // with a JSON-RPC error (`-32800`), so it is the one arm that
                // is `failed` — and `error` then carries that error OBJECT,
                // not a tool result. `McpUnknownTool`, the other JSON-RPC arm
                // over there, cannot occur here: the handler was resolved
                // before the spawn.
                Err(crate::error::BridgeError::Cancelled) => {
                    let error_value = serde_json::to_value(JsonRpcError::cancelled(None))
                        .unwrap_or_else(|_| {
                            json!({
                                "code": CANCELLED_ERROR_CODE,
                                "message": "Request cancelled by client",
                            })
                        });
                    (
                        task_store
                            .fail_task(
                                &task_id,
                                "Task was cancelled during execution.",
                                error_value.clone(),
                            )
                            .await,
                        Some(error_value),
                    )
                }
                // A tool that ran and failed. The synchronous path returns
                // this as a successful result carrying `isError: true`, so the
                // task is COMPLETED. An operator filtering on
                // `status == "failed"` will no longer see these; the probe is
                // `result.isError == true`.
                Err(e) => {
                    let error_result = ToolCallResult::error(e.to_string());
                    let result_value =
                        serde_json::to_value(&error_result).unwrap_or_else(|e| json!({
                            "content": [{"type": "text", "text": format!("Serialization error: {e}")}],
                            "isError": true,
                        }));
                    (
                        task_store
                            .complete_task(&task_id, result_value.clone())
                            .await,
                        Some(result_value),
                    )
                }
            };

            // Send the terminal notification (best-effort) on the per-session
            // tx so it reaches the originating client only.
            //
            // It carries the PAYLOAD, not just the status: "The notification
            // includes the full task object, allowing clients to access the
            // complete task state and final results without polling the
            // `tasks/get` method." A notification a client must follow with a
            // poll would be a notification that saved nobody anything.
            if let Some(info) = info
                && let Some(tx) = task_notification_tx.as_ref()
            {
                let params = TaskNotificationParams::new(info, payload);
                let msg =
                    WriterMessage::Notification(JsonRpcNotification::task_notification(&params));
                let _ = tx.try_send(msg);
            }
        });

        // Return the task handle immediately. `resultType: "task"` is the
        // MUST that lets a client tell this apart from a standard
        // `ToolCallResult`; it says nothing about progress, which lives in
        // `status`. The client polls `tasks/get`.
        //
        // The handle is FLAT: `taskId`/`status`/`ttlMs` sit at the root of
        // `result`, not under a nested `task` object.
        let create_result = DetailedTask::handle(task_info);
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
    /// Registers this session's opt-in filter under the JSON-RPC `id` of
    /// the request, and emits the
    /// `notifications/subscriptions/acknowledged` notification carrying
    /// the subset the server actually honours.
    ///
    /// Returns an intention, never an immediate `JsonRpcResponse`. An
    /// earlier revision answered right away with `{"subscriptionId": N}`,
    /// justified by "the spec leaves this open". It does not: §Graceful
    /// Closure resolves it explicitly — the server SHOULD answer the
    /// original request with an empty result *before closing the stream*,
    /// and "a conformant server must keep the request `id` alive for the
    /// lifetime of the subscription and answer it at teardown". The
    /// teardown result has a defined shape (`resultType: "complete"` plus
    /// `_meta["io.modelcontextprotocol/subscriptionId"]`) which
    /// `{"subscriptionId": N}` was not.
    ///
    /// The G-1 long-poll worry does not apply either: nothing parks here.
    /// The handler returns immediately; only the request `id` stays
    /// unanswered, held by the transport rather than by a blocked task.
    /// SPEC: verify against
    /// <https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions>
    async fn handle_subscriptions_listen(
        &self,
        id: Option<Value>,
        params: Option<Value>,
        session: Option<&SessionContext>,
    ) -> ListenOutcome {
        let Some(session) = session else {
            return ListenOutcome::rejected(
                id,
                JsonRpcError::invalid_request(
                    "subscriptions/listen requires an active MCP session",
                ),
            );
        };
        // The subscription id IS the request id, so a listen without one
        // has nowhere to correlate its notifications and cannot be honoured.
        let Some(subscription_id) = id.clone() else {
            return ListenOutcome::rejected(
                id,
                JsonRpcError::invalid_request(
                    "subscriptions/listen requires a JSON-RPC id: the subscription is identified by it",
                ),
            );
        };
        let Some(params) = params else {
            return ListenOutcome::rejected(
                id,
                JsonRpcError::invalid_params("subscriptions/listen requires params.notifications"),
            );
        };
        let listen: SubscriptionsListenParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return ListenOutcome::rejected(
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

        let ack_filter = match serde_json::to_value(&filter) {
            Ok(v) => v,
            Err(e) => {
                return ListenOutcome::rejected(
                    id,
                    JsonRpcError::internal_error(format!("Serialization error: {e}")),
                );
            }
        };

        self.subscriptions.register(
            subscription_id.clone(),
            filter.clone(),
            session.notification_tx.clone(),
        );

        // MUST be the first message on the subscription, and MUST precede
        // any notification delivered because of it.
        let _ = session
            .notification_tx
            .send(WriterMessage::Notification(
                JsonRpcNotification::subscriptions_acknowledged(&subscription_id, &ack_filter),
            ))
            .await;

        ListenOutcome::Streaming { subscription_id }
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

    /// Point-in-time snapshot of a task — the ONLY way to read one.
    ///
    /// Never blocks. MCP 2026-07-28 deleted `tasks/result` and folded its
    /// payload in here: the answer carries the status AND, at a terminal
    /// status, the stored `result` (completed) or `error` (failed), inlined
    /// flat alongside the task fields.
    ///
    /// `resultType` is `"complete"` on every answer, whatever the status —
    /// it names the result SHAPE, not the progress. A `working` snapshot is
    /// still a complete `tasks/get` result.
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

        // Unknown or TTL-evicted id is -32602. This is also where eviction
        // surfaces: as an error from a non-blocking call, never as a hang.
        let Some(info) = self.task_store.get_task(&get_params.task_id).await else {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params(format!("Task not found: {}", get_params.task_id)),
            );
        };

        let status = info.status;
        let snapshot = DetailedTask::snapshot(info);
        let snapshot = match status {
            // `result` MUST be present on a completed task. `get_result`
            // returning None here would mean the store completed a task
            // without storing anything, which `complete_task` cannot do.
            TaskStatus::Completed => match self.task_store.get_result(&get_params.task_id).await {
                Some(result) => snapshot.with_result(result),
                None => snapshot,
            },
            TaskStatus::Failed => match self.task_store.get_result(&get_params.task_id).await {
                Some(error) => snapshot.with_error(error),
                None => snapshot,
            },
            // `working` carries no payload; `cancelled` carries none either
            // — `CancelledTask` extends `Task` with no `result` field, so
            // inventing one would be an extension of our own.
            TaskStatus::Working | TaskStatus::InputRequired | TaskStatus::Cancelled => snapshot,
        };

        JsonRpcResponse::success_or_serialize_error(id, &snapshot)
    }

    /// `tasks/update` — deliver `inputResponses` for a task waiting on input.
    ///
    /// A no-op acknowledgement, and conformant as one. bridge-mcp never enters
    /// `input_required`: no tool suspends mid-execution to elicit, and the
    /// destructive-confirmation gate resolves on the ORIGINAL `tools/call`
    /// through core multi-round-trip, before any task exists — which is what
    /// the spec prescribes ("a server that needs client input _before_
    /// returning a `CreateTaskResult` uses the multi round-trip request flow
    /// on the original request").
    ///
    /// So this server never issues an `inputRequest`, so no key a client sends
    /// can be outstanding, and the spec says what to do with those: "A server
    /// SHOULD ignore any `inputResponses` responses mapped to a key that is
    /// not currently outstanding for the task — including keys that were never
    /// issued". Ignoring all of them is that rule at its limit.
    ///
    /// It exists rather than answering `-32601` because the extension
    /// declaration promises the method: advertising a capability whose methods
    /// the server then refuses is worse than the no-op.
    async fn handle_tasks_update(
        &self,
        id: Option<Value>,
        params: Option<Value>,
    ) -> JsonRpcResponse {
        let Some(params) = params else {
            return JsonRpcResponse::error(id, JsonRpcError::invalid_params("Missing params"));
        };

        let update_params: TaskUpdateParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(format!("Invalid params: {e}")),
                );
            }
        };

        // "Servers SHOULD return a JSON-RPC error if the `taskId` does not
        // correspond to a known task." Checked before the ack, so the no-op
        // does not silently absorb a typo'd or TTL-evicted id.
        if self
            .task_store
            .get_task(&update_params.task_id)
            .await
            .is_none()
        {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params(format!("Task not found: {}", update_params.task_id)),
            );
        }

        // "On success, the server MUST acknowledge the request with an empty
        // result", and "The `resultType` field MUST be set to `"complete"` on
        // `UpdateTaskResult`".
        JsonRpcResponse::success(id, json!({ "resultType": "complete" }))
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

        // "On success, the server MUST acknowledge the request with an empty
        // result", and `CancelTaskResult = Result` — so the ack carries the
        // discriminator and nothing else. It deliberately does NOT echo the
        // task: a client reading a status here would be reading a value the
        // spec calls eventually consistent, and `tasks/get` is where status
        // lives.
        //
        // Only an unknown id is an error ("Servers SHOULD return a JSON-RPC
        // error if the `taskId` does not correspond to a known task"). An
        // already-terminal task is acknowledged like any other: cancellation
        // is cooperative, and the client "MAY delete all state associated with
        // the task as soon as it sends a cancellation", so it cannot know the
        // work had already finished.
        if self
            .task_store
            .cancel_task(&cancel_params.task_id)
            .await
            .is_none()
        {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params(format!("Task not found: {}", cancel_params.task_id)),
            );
        }

        JsonRpcResponse::success(id, json!({ "resultType": "complete" }))
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

    /// A session whose CURRENT request declares the tasks extension.
    ///
    /// Goes through `with_request_meta(RequestMeta::from_params(..))`, which
    /// is exactly what `handle_request_with_cancel` does at the chokepoint —
    /// so a test using this exercises the real capability seam instead of a
    /// flag set by hand. Nothing here touches `session.caps`: the handshake
    /// must not be able to grant this extension.
    /// Params carrying the tasks-extension declaration the way a Modern
    /// client sends it: inside this request's own `_meta`.
    ///
    /// Dispatcher-level tests must put it HERE rather than on the session,
    /// because the chokepoint replaces the session's `request_meta` with
    /// whatever it parses from the request it is handling. That is the whole
    /// point of a per-request capability, and it makes these tests exercise
    /// the real seam end to end.
    fn params_declaring_tasks(mut params: Value) -> Value {
        params["_meta"] = json!({
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": { "io.modelcontextprotocol/tasks": {} }
            }
        });
        params
    }

    fn session_declaring_tasks() -> (SessionContext, mpsc::Receiver<WriterMessage>) {
        let (tx, rx) = mpsc::channel::<WriterMessage>(64);
        let params = json!({
            "_meta": {
                "io.modelcontextprotocol/clientCapabilities": {
                    "extensions": { "io.modelcontextprotocol/tasks": {} }
                }
            }
        });
        let session =
            SessionContext::new(tx).with_request_meta(RequestMeta::from_params(Some(&params)));
        (session, rx)
    }

    fn create_test_server() -> McpServer {
        let (server, _audit_task) = McpServer::new(test_config());
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
    /// `tasks/result` used to be a long poll that took a permit from
    /// `limits.max_concurrent_commands` (default 5) INSIDE the reader loop,
    /// so N parked polls froze the entire session: the loop blocks on
    /// `acquire_owned()` before it spawns the handler, so the client's next
    /// message is never read. The audit measured the boundary exactly —
    /// N=4 still answered `ping`, N=5 answered neither `ping` nor
    /// `tasks/cancel` (the one call that could have released the polls),
    /// and it was still dead 208 s later.
    ///
    /// 3.0.0 deletes the long poll — and then the method: MCP 2026-07-28 has
    /// no `tasks/result` at all, and `tasks/get` is a non-blocking snapshot.
    /// The original reproduction (many never-completing tasks, each held open
    /// by a blocking poll) can no longer be built.
    ///
    /// The exemption this guards, `is_concurrency_exempt`, survives both
    /// changes and is still load-bearing — it keys on the method PREFIX, so
    /// what needs proving is that `ping` and `tasks/*` never reach
    /// `acquire_owned()` at all. That matters more now, not less: task
    /// workers legitimately hold every permit during normal operation, so a
    /// full semaphore is the busy state, not a fault. This re-anchors the
    /// original shape onto the surviving method — N `tasks/get` polls at and
    /// past the concurrency limit (5), with every permit held by an entirely
    /// separate mechanism, plus a `ping`. All must still answer.
    ///
    /// This is the ONLY execution coverage of `is_concurrency_exempt`;
    /// deleting it would leave the exemption pinned by nothing.
    #[tokio::test]
    async fn control_plane_survives_a_full_concurrency_semaphore() {
        let server = Arc::new(create_test_server());
        assert_eq!(
            server.concurrent_limit.available_permits(),
            5,
            "fixture must keep the default max_concurrent_commands"
        );

        // Hold every permit: no ordinary (non-exempt) command may run.
        let permits = Arc::clone(&server.concurrent_limit)
            .acquire_many_owned(5)
            .await
            .unwrap();

        // 6 tasks, one past the 5-permit limit — the same "at and past"
        // shape the original `parked_polls` table walked.
        let mut task_ids = Vec::new();
        for _ in 0..6 {
            let (task_id, _cancel) = server.task_store.create_task().await.unwrap();
            task_ids.push(task_id);
        }

        let (session, client_tx, mut server_rx) = in_memory_session();
        let serve = tokio::spawn(Arc::clone(&server).serve_session(session));

        let mut expected_ids: std::collections::HashSet<Option<Value>> =
            std::collections::HashSet::new();
        for (i, task_id) in task_ids.iter().enumerate() {
            let id = i64::try_from(i).unwrap();
            client_tx
                .send(client_request(
                    id,
                    "tasks/get",
                    // The envelope is not decoration here: `tasks/get` is
                    // capability-gated per request, so without it these polls
                    // would be answered with `-32021` and the test would be
                    // measuring the gate instead of the semaphore.
                    Some(json!({
                        "taskId": task_id,
                        "_meta": {
                            "io.modelcontextprotocol/clientCapabilities": {
                                "extensions": { "io.modelcontextprotocol/tasks": {} }
                            }
                        }
                    })),
                ))
                .unwrap();
            expected_ids.insert(Some(json!(id)));
        }
        client_tx.send(client_request(9999, "ping", None)).unwrap();
        expected_ids.insert(Some(json!(9999)));

        let mut answered = std::collections::HashSet::new();
        while answered.len() < expected_ids.len() {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(3), server_rx.recv())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "session froze with every concurrency permit held: only answered \
                         {answered:?} of {expected_ids:?} so far"
                    )
                })
                .expect("session writer channel closed");

            match msg {
                WriterMessage::Response(response) => {
                    assert!(response.error.is_none(), "unexpected error: {response:?}");
                    answered.insert(response.id.clone());
                }
                _ => panic!("expected a response, got a notification or a batch"),
            }
        }

        assert_eq!(
            answered, expected_ids,
            "every tasks/get poll and the ping must all be answered despite every \
             concurrency permit being held"
        );

        drop(permits);
        serve.abort();
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

    /// 2026-07-28 has no handshake, so the server holds no "initialized"
    /// state. This test is a grep-in-a-test: if someone reintroduces a
    /// connection-scoped readiness flag, it fails and points them at
    /// `server/discover`, which is stateless by construction.
    ///
    /// It searches only the PRODUCTION half of the file. Do not "simplify"
    /// this back to `src.contains(...)`: the needle also occurs in this
    /// test's own assertion, so searching the whole file matches itself and
    /// the test can never pass — which is exactly how it was first written.
    /// Splitting beats escaping the literal because it also survives a future
    /// test that mentions the field name in passing.
    ///
    /// `expect` rather than a lenient fallback: if the anchor ever stops
    /// matching, this must fail loudly on the anchor instead of silently
    /// widening the search back to the whole file.
    #[test]
    fn test_server_holds_no_handshake_state() {
        let src = include_str!("server.rs");
        let (production, _tests) = src
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("anchor `#[cfg(test)]\\nmod tests {` not found; fix this test's split");
        assert!(
            !production.contains("initialized: AtomicBool"),
            "McpServer regained an `initialized` flag; 2026-07-28 has no handshake \
             and server/discover must stay stateless"
        );
    }

    /// G-6 (audit 2026-08-19) forced `resources.subscribe: false` because
    /// nothing in the crate emitted `notifications/resources/updated`, and
    /// left a standing instruction to flip it back in the same commit that
    /// adds the emitter. `spawn_resource_update_watch` is that emitter.
    ///
    /// The flag on its own would be satisfied by a server that simply
    /// started lying again, so this also pins the producer it advertises:
    /// a subscribed URI really does get published.
    ///
    /// Re-pointed from `handle_initialize` to `server/discover` in the 3.0.0
    /// integration merge. The handshake is gone; the JSON path is unchanged,
    /// so the assertion survives the move verbatim.
    #[tokio::test]
    async fn test_resources_capability_advertises_subscribe() {
        let server = create_test_server();
        let response = server.handle_discover(Some(json!(1))).await;

        assert!(response.error.is_none());
        let result = response.result.expect("server/discover result");

        assert_eq!(
            result["capabilities"]["resources"]["subscribe"],
            json!(true),
            "a real emitter exists, so the flag is honest again"
        );
        assert_eq!(
            result["capabilities"]["resources"]["listChanged"],
            json!(true),
            "listChanged IS honored (config reload broadcasts \
             resources_list_changed) and must stay advertised"
        );

        // The producer the flag promises, exercised end to end.
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        server
            .handle_subscriptions_listen(
                Some(json!(2)),
                Some(json!({
                    "notifications": { "resourceSubscriptions": ["history://recent"] }
                })),
                Some(&session_ctx),
            )
            .await;
        let _ack = rx.try_recv().expect("ack notification");
        server.history.record_success("host", "uptime", 0, 5);
        let mut last_revision: u64 = 0;
        assert_eq!(
            watch_once(&server.subscriptions, &server.history, &mut last_revision),
            1,
            "resources.subscribe: true must be backed by a producer that fires"
        );
    }

    /// A Legacy client that still opens with `initialize` gets `-32022` with
    /// the supported-version list — not `-32601`, and not a fake handshake.
    ///
    /// The arm exists at all because of the 2026-07-28 client-side probe
    /// (`/specification/2026-07-28/basic/transports/stdio`, "Backward
    /// Compatibility"): a dual-era client sends `server/discover` first, and
    /// reads "discovery result = modern", "specific modern protocol error =
    /// modern but wrong version", "anything else = legacy". A Legacy-only
    /// client never probes; `-32022` is the only response that tells it which
    /// revision would have worked.
    #[tokio::test]
    async fn test_legacy_initialize_returns_unsupported_protocol_version() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: Some(json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {"elicitation": {}},
                "clientInfo": {"name": "legacy-client", "version": "1.0.0"}
            })),
        };

        let response = server.handle_request(request).await;

        assert!(response.result.is_none(), "initialize must not succeed");
        let error = response.error.expect("initialize must return an error");
        assert_eq!(error.code, -32022);
        assert_eq!(error.message, "Unsupported protocol version");

        let data = error.data.expect("data payload");
        assert_eq!(data["supported"], json!(["2026-07-28"]));
        assert_eq!(data["requested"], json!("2025-11-25"));
    }

    /// Malformed `initialize` params must not change the answer. The handler
    /// reads `protocolVersion` straight off the raw `Value`, so a payload that
    /// would fail `InitializeParams` deserialization still round-trips the
    /// requested version back to the client.
    #[tokio::test]
    async fn test_legacy_initialize_malformed_params_still_echoes_version() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: "initialize".to_string(),
            // No clientInfo, no capabilities — `InitializeParams` cannot parse
            // this, but `protocolVersion` is still right there.
            params: Some(json!({"protocolVersion": "2024-11-05"})),
        };

        let response = server.handle_request(request).await;

        let error = response.error.expect("initialize must return an error");
        assert_eq!(error.code, -32022);
        assert_eq!(error.data.unwrap()["requested"], json!("2024-11-05"));
    }

    /// No params at all: still `-32022`, with an empty `requested`.
    #[tokio::test]
    async fn test_legacy_initialize_without_params() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(3)),
            method: "initialize".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        let error = response.error.expect("initialize must return an error");
        assert_eq!(error.code, -32022);
        assert_eq!(error.data.unwrap()["requested"], json!(""));
    }

    /// `initialize` must mutate nothing. Before 3.0.0 it wrote three
    /// `SessionCapabilities` `AtomicBool`s, the per-session
    /// `runtime_max_output` slot, and a server-wide `client_info` — a Legacy
    /// client could therefore hand itself elicitation rights through a
    /// handshake this server no longer honors.
    ///
    /// Only the capability flags are asserted here because they are all that
    /// still exists to assert. `McpServer::client_info` was deleted once this
    /// arm stopped writing it: Modern carries `clientInfo` per request in the
    /// `_meta` envelope (`RequestMeta::client_info`), so a server-wide "the
    /// client" is meaningless for a stateless server serving concurrent
    /// sessions. That guarantee is now structural — there is no field left to
    /// record an identity into — which is stronger than this test was.
    #[tokio::test]
    async fn test_legacy_initialize_mutates_no_handshake_state() {
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session = SessionContext::new(tx);

        assert!(!session.caps.supports_elicitation());
        assert!(!session.caps.supports_roots());
        assert!(!session.caps.supports_sampling());

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(4)),
            method: "initialize".to_string(),
            params: Some(json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "elicitation": {},
                    "sampling": {},
                    "roots": {"listChanged": true}
                },
                "clientInfo": {"name": "legacy-client", "version": "1.0.0"}
            })),
        };

        let response = server
            .handle_request_with_cancel(request, None, Some(&session))
            .await
            .expect("only subscriptions/listen answers nothing");

        assert_eq!(response.error.expect("must error").code, -32022);
        assert!(
            !session.caps.supports_elicitation(),
            "a rejected handshake granted elicitation"
        );
        assert!(
            !session.caps.supports_roots(),
            "a rejected handshake granted roots"
        );
        assert!(
            !session.caps.supports_sampling(),
            "a rejected handshake granted sampling"
        );
    }

    /// Full wire shape of `server/discover`, asserted against a literal.
    ///
    /// Source: MCP 2026-07-28 `/specification/2026-07-28/server/discover`.
    /// Note `serverInfo` is NOT a sibling of `capabilities` any more — it moved
    /// inside `result._meta` under the reverse-DNS key
    /// `io.modelcontextprotocol/serverInfo`. A client that still reads
    /// `result.serverInfo` gets `null`.
    ///
    /// `serverInfo` itself carries a nested `_meta` with build provenance
    /// (`build_provenance_meta()`, keyed by `BUILD_META_KEY`) — the plan this
    /// was written against omitted that field from its literal, the same gap
    /// `test_handshake_payload_is_byte_identical` (Task 12) already had to
    /// close. `build_discovery_payload` populates it unconditionally.
    ///
    /// There is deliberately NO `capabilities.tasks` here, and its absence is
    /// load-bearing rather than an omission. Tasks are an EXTENSION in
    /// 2026-07-28, declared under `capabilities.extensions` keyed by
    /// `io.modelcontextprotocol/tasks` — which this literal does assert, two
    /// keys below. The 2025-11-25 core block (`list`/`cancel`/`requests`)
    /// could not be declared here even if we wanted to: `tasks/list` no longer
    /// exists, and per-request support is not something a server announces.
    /// Restoring it would re-advertise two methods the server does not serve.
    #[tokio::test]
    async fn test_server_discover_full_wire_shape() {
        let server = create_test_server();
        let response = server.handle_discover(Some(json!("discover-1"))).await;

        assert!(response.error.is_none(), "server/discover must not error");
        assert_eq!(response.id, Some(json!("discover-1")));
        let result = response
            .result
            .expect("server/discover must return a result");

        let expected_instructions = {
            let config = server.config.read().await;
            instructions::build_instructions(&config, server.registry.len())
        };

        assert_eq!(
            result,
            json!({
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {
                    "tools": {"listChanged": true},
                    "prompts": {"listChanged": true},
                    "resources": {"subscribe": true, "listChanged": true},
                    "completions": {},
                    "logging": {},
                    "extensions": {
                        "io.modelcontextprotocol/tasks": {},
                        "com.bridge-mcp/output-pagination": {}
                    }
                },
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                        "description": "Secure SSH bridge for remote server management via MCP",
                        "websiteUrl": "https://github.com/muchiny/bridge-mcp",
                        "icons": [{
                            "src": SERVER_ICON_URL,
                            "mimeType": "image/svg+xml",
                            "sizes": ["any"]
                        }],
                        "_meta": {
                            "io.github.muchiny/build": {
                                "rev": BUILD_REV,
                                "version": SERVER_VERSION
                            }
                        }
                    }
                },
                "instructions": expected_instructions,
                "ttlMs": 3_600_000,
                "cacheScope": "public"
            })
        );
    }

    /// Tripwire: `cacheScope: "public"` is only sound while this server has no
    /// per-caller authorization.
    ///
    /// "public" means the discovery result — capabilities, tool inventory,
    /// instructions — may be cached and replayed to any caller. That holds
    /// today because group enablement lives in `config.tool_groups`
    /// (process-wide) and `rbac.enabled: true` is rejected at config load
    /// (`src/config/loader.rs:226`) since nothing in the request path enforces
    /// it. 2026-07-28 in fact *requires* list endpoints not to vary per
    /// connection, so this is the conformant shape.
    ///
    /// When RBAC becomes real — when `RbacConfig::default().enabled` can be
    /// true, or when the loader stops rejecting it — this test fails, and
    /// `handle_discover` must switch to a session-scoped cache scope before it
    /// can pass again. Do not silence it by editing the assertion.
    ///
    /// Both preconditions are checked by BEHAVIOUR, not by grepping
    /// `loader.rs` for the shape of its `if`. A source-text guard passes on a
    /// rejection that has been refactored into something that no longer
    /// rejects, which is precisely the state it exists to catch. This is also
    /// the only test in the tree that exercises the load-time refusal at all.
    #[tokio::test]
    async fn test_cache_scope_is_public_only_while_rbac_is_dead() {
        assert!(
            !crate::security::rbac::RbacConfig::default().enabled,
            "RBAC default flipped to enabled: server/discover's cacheScope must \
             stop being \"public\" — a cached discovery result would replay one \
             caller's capabilities to another"
        );

        // Second, independent encoding of the same precondition: an operator
        // who asks for RBAC must still be refused at config load.
        let yaml = "\
hosts:
  test:
    hostname: \"10.0.0.1\"
    user: testuser
    auth:
      type: agent
security:
  mode: permissive
rbac:
  enabled: true
";
        let config_file = tempfile::NamedTempFile::new().expect("create temp config");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(config_file.path(), std::fs::Permissions::from_mode(0o600))
                .expect("tighten temp config permissions");
        }
        std::fs::write(config_file.path(), yaml).expect("write temp config");

        let err = crate::config::load_config(config_file.path()).expect_err(
            "`rbac.enabled: true` loaded successfully: per-caller authorization may now \
             be live, so server/discover's cacheScope can no longer be \"public\"",
        );
        assert!(
            matches!(
                &err,
                crate::error::BridgeError::ConfigInvalid { field, .. } if field == "rbac.enabled"
            ),
            "`rbac.enabled: true` was rejected for the wrong reason ({err}); the \
             load-time RBAC refusal that makes cacheScope \"public\" honest is gone"
        );

        let server = create_test_server();
        let result = server
            .handle_discover(Some(json!(1)))
            .await
            .result
            .expect("server/discover must return a result");
        assert_eq!(result["cacheScope"], "public");
    }

    /// `server/discover` must be reachable through the public dispatcher, not
    /// just as a direct method call.
    #[tokio::test]
    async fn test_server_discover_is_routed() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(7)),
            method: "server/discover".to_string(),
            params: Some(json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "ExampleClient",
                        "version": "1.0.0"
                    },
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            })),
        };

        let response = server.handle_request(request).await;

        assert!(
            response.error.is_none(),
            "server/discover fell through to -32601: {:?}",
            response.error
        );
        assert_eq!(response.result.unwrap()["resultType"], "complete");
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

    /// Supersedes `test_task_through_call_tool_is_accepted`, which asked for
    /// the task with `params.task` through the dispatcher.
    ///
    /// The dispatcher rewrites `params.name` to the INNER tool before the
    /// promotion check runs, so promotion keys on the tool that will actually
    /// execute — the same rule the dispatcher's own comment demands of any
    /// future RBAC enforcement, for the same reason: a decision keyed on the
    /// outer name (`mcp_call_tool`) would be steerable by wrapping.
    ///
    /// The negative half is what makes it a test of the KEY rather than of
    /// the dispatcher: the same wrapper around a tool that is not on the list
    /// must stay synchronous.
    #[tokio::test]
    async fn promotion_keys_on_the_inner_tool_of_mcp_call_tool() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();

        let promoted = json!({
            "name": super::super::meta_tools::CALL_TOOL,
            "arguments": {
                "name": "ssh_ansible_playbook",
                "arguments": {"host": "nowhere", "playbook": "site.yml"}
            }
        });
        let response = server
            .handle_tools_call(Some(json!(1)), Some(promoted), None, Some(&session))
            .await;
        assert!(response.error.is_none(), "{:?}", response.error);
        let result = response.result.expect("task handle");
        assert_eq!(result["resultType"], "task");
        assert_eq!(result["status"], "working");

        let plain = json!({
            "name": super::super::meta_tools::CALL_TOOL,
            "arguments": {"name": "ssh_status", "arguments": {}}
        });
        let response = server
            .handle_tools_call(Some(json!(2)), Some(plain), None, Some(&session))
            .await;
        let result = response.result.expect("synchronous result");
        assert!(
            result.get("resultType").is_none(),
            "an unlisted inner tool must not be promoted: {result}"
        );
        assert!(result["content"].is_array());
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

        // Server should be created with its full tool inventory reachable.
        assert!(!server.registry.is_empty(), "registry came up empty");

        // Audit task might be None if audit is disabled by default
        drop(audit_task);
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

    /// Inverts `test_tools_list_includes_execution_field`, which required
    /// every tool to CARRY `execution.taskSupport`.
    ///
    /// MCP 2026-07-28 removed per-tool task gating entirely: the server is the
    /// sole decider, per request, and no client may signal a task preference,
    /// so there is nothing for a per-tool declaration to gate. The pair of
    /// audit tests that guarded the field — including
    /// `task_support_is_coherent_with_dispatch`, annotated "do not delete it
    /// as a redundant assertion" (D-F5) — are not overruled: they policed the
    /// agreement between an advertisement and a dispatch rule, and BOTH sides
    /// of that agreement are gone. What replaces them is this tripwire, which
    /// guards the removal instead of the value.
    ///
    /// It sweeps the whole listing rather than sampling: the field was fed by
    /// three independent hardcoded literals plus the registry, so a partial
    /// removal is the realistic failure, and it would be invisible to a test
    /// that checked one tool.
    #[tokio::test]
    async fn tools_list_never_advertises_task_support() {
        let server = create_test_server();
        let response = server.handle_tools_list(Some(json!(1)), None).await;

        let result = response.result.unwrap();
        let tools = result["tools"].as_array().expect("a tools array");
        assert!(!tools.is_empty(), "an empty listing would pass vacuously");

        for tool in tools {
            let name = tool["name"].as_str().expect("tool name");
            assert!(
                tool.get("execution").is_none(),
                "tool {name} still advertises an `execution` object: {tool}"
            );
            // Belt and braces on the KEY, not just its container: a future
            // `taskSupport` hoisted to the tool root, or nested under some
            // other object, would slip past the check above.
            assert!(
                !tool.to_string().contains("taskSupport"),
                "tool {name} still mentions taskSupport somewhere: {tool}"
            );
        }
    }

    /// D8: the destructive-op elicitation gate MUST resolve BEFORE a task
    /// exists. Creating the task first and asking for confirmation afterwards
    /// is the flow the spec says cannot be implemented without reading the
    /// multi-round-trip page first — the named MRTR debt.
    ///
    /// **This ordering is not observable at runtime today, and saying so is
    /// worth more than a test that appears to prove it.**
    /// `check_destructive_elicitation` fires only for `destructive_hint:
    /// true`, and `long_running_tools_are_never_destructive` forbids exactly
    /// those from the promotion list — so no single call can reach both the
    /// gate and the task branch. A runtime test would have to assert that two
    /// things happen in order when one of them never happens, and it would sit
    /// green forever whatever the order.
    ///
    /// The two meet the day the MRTR item closes and a destructive tool joins
    /// `LONG_RUNNING_TOOLS` — which is exactly when a silent reordering would
    /// ship the forbidden flow. So the order is pinned now, as source text,
    /// while the code is still correct. A source-text guard is the weakest
    /// kind of test; it is still stronger than the runtime test that cannot
    /// be written.
    #[test]
    fn the_elicitation_gate_precedes_the_task_branch() {
        let src = include_str!("server.rs");

        // Scope 1 — the production half. `include_str!` pulls in THIS test,
        // whose own assertion arguments are the two literals searched for
        // below; scanning the whole file would make the guard match itself and
        // pass (or fail) for reasons having nothing to do with the code it
        // polices. `expect`, never a fallback to the whole file: a missing
        // boundary is a broken guard and must say which it is.
        let (production, _) = src.split_once("#[cfg(test)]\nmod tests {").expect(
            "the `#[cfg(test)] mod tests {` boundary must exist for this guard to scope itself",
        );

        // Scope 2 — ONE function. `check_destructive_elicitation` is also
        // DEFINED earlier in the file, so a file-wide index comparison would
        // be comparing that definition against the branch and would pass no
        // matter how `handle_tools_call` itself is ordered.
        let from_fn = production
            .find("async fn handle_tools_call(")
            .expect("handle_tools_call must exist");
        let body = &production[from_fn..];
        let to_next_fn = body
            .find("\n    async fn handle_tools_call_async(")
            .expect("handle_tools_call_async must follow handle_tools_call");
        let body = &body[..to_next_fn];

        let gate = body
            .find(".check_destructive_elicitation(")
            .expect("the destructive-op gate must run inside handle_tools_call");
        let promotion = body
            .find("task_policy::is_long_running(")
            .expect("the promotion decision must be made inside handle_tools_call");

        assert!(
            gate < promotion,
            "the destructive-op elicitation gate must resolve BEFORE the task branch: a task \
             created first and confirmed afterwards is the MRTR flow this release cannot ship"
        );
    }

    /// A tool that is not on the promotion list is answered synchronously —
    /// even for a client that declared the extension. Declaring it is
    /// permission, not a request: "The client declaring the extension
    /// capability does not suggest that it requires a `CreateTaskResult` in
    /// response to that request."
    #[tokio::test]
    async fn an_unlisted_tool_is_answered_synchronously() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();
        let params = json!({
            "name": "ssh_status",
            "arguments": {}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(result["content"].is_array());
        assert!(
            result.get("resultType").is_none(),
            "a synchronous answer carries no task discriminator: {result}"
        );
    }

    /// Supersedes `test_tools_call_with_task_field_returns_create_task_result`.
    /// Same subject — the shape of the handle — on the trigger that replaced
    /// `params.task`, and on the 2026-07-28 field names.
    #[tokio::test]
    async fn a_promoted_call_returns_a_flat_task_handle() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();
        let params = json!({
            "name": "ssh_ansible_playbook",
            "arguments": {"host": "nowhere", "playbook": "site.yml"}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // FLAT and discriminated: `resultType: "task"` is the MUST that tells
        // a client this is a handle and not a `CallToolResult`.
        assert_eq!(result["resultType"], "task");
        assert!(result["taskId"].is_string());
        assert_eq!(result["status"], "working");
        assert!(result["createdAt"].is_string());
        assert!(result["ttlMs"].is_number());
        assert!(result["pollIntervalMs"].is_number());
        assert!(
            result.get("task").is_none(),
            "the enclosing `task` object is the 2025-11-25 shape: {result}"
        );
    }

    /// The MUST NOT, and the reason the promotion is a conjunction rather
    /// than a lookup: "A server MUST NOT return `CreateTaskResult` to a client
    /// that did not include the extension capability on its request, regardless
    /// of prior declarations."
    ///
    /// The two assertions are not redundant. `error.is_none()` alone would
    /// pass for a server that answered with a handle; `content.is_array()`
    /// alone would pass for one that answered with an isError envelope. What
    /// has to be true is that this client got the ordinary result it would
    /// have got before the extension existed.
    #[tokio::test]
    async fn a_long_running_tool_stays_synchronous_for_a_non_declaring_client() {
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        // A session with NO envelope on this request: the non-declaring case.
        let session = SessionContext::new(tx);
        let params = json!({
            "name": "ssh_ansible_playbook",
            "arguments": {"host": "nowhere", "playbook": "site.yml"}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert!(
            result.get("resultType").is_none(),
            "a non-declaring client must never receive a task handle: {result}"
        );
        assert!(result.get("taskId").is_none(), "{result}");
        assert!(result["content"].is_array(), "{result}");
    }

    /// Every status transition (including non-existent → working at creation)
    /// emits a task notification, so a subscribed client can track the
    /// lifecycle without polling.
    ///
    /// The method is `notifications/tasks` — 2025-11-25 spelled it
    /// `notifications/tasks/status`.
    #[tokio::test]
    async fn a_promoted_call_emits_the_working_status_notification() {
        let server = create_test_server();
        let (session_ctx, mut rx) = session_declaring_tasks();
        let params = json!({
            "name": "ssh_ansible_playbook",
            "arguments": {"host": "nowhere", "playbook": "site.yml"}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session_ctx))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let task_id = result["taskId"]
            .as_str()
            .expect("response should carry a flat taskId")
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
                && n.method == "notifications/tasks"
            {
                let params = n.params.expect("a task notification carries params");
                if params["taskId"] == task_id.as_str() && params["status"] == "working" {
                    found_working = true;
                    break;
                }
            }
        }

        assert!(
            found_working,
            "expected `notifications/tasks` with status=\"working\" and taskId={task_id}"
        );
    }

    /// Supersedes `test_tools_call_async_unknown_tool`, which reached the task
    /// path with `params.task` on a name that never existed.
    ///
    /// That exact shape is now unreachable — the promotion list holds only
    /// registered names, and `long_running_tools_are_never_destructive`
    /// enforces it. The reachable form is the divergence between the two:
    /// a listed tool whose GROUP the operator disabled. The task path must
    /// then agree with the synchronous one — `-32602`, not a handle to a task
    /// that can never run, and not an isError envelope.
    #[tokio::test]
    async fn a_listed_tool_from_a_disabled_group_is_invalid_params_not_a_task() {
        let mut config = test_config();
        config
            .tool_groups
            .groups
            .insert("ansible".to_string(), false);
        let (server, _audit_task) = McpServer::new(config);
        let (session, _rx) = session_declaring_tasks();

        let params = json!({
            "name": "ssh_ansible_playbook",
            "arguments": {"host": "nowhere", "playbook": "site.yml"}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session))
            .await;

        let error = response
            .error
            .expect("a tool that is not registered must be a JSON-RPC error");
        assert_eq!(error.code, -32602);
        assert!(error.message.contains("ssh_ansible_playbook"));
    }

    #[tokio::test]
    async fn test_tasks_get_returns_status() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();
        // Create a task the only way a client can now: call a listed tool
        // while declaring the extension.
        let call_params = json!({
            "name": "ssh_ansible_playbook",
            "arguments": {"host": "nowhere", "playbook": "site.yml"}
        });
        let call_response = server
            .handle_tools_call(Some(json!(1)), Some(call_params), None, Some(&session))
            .await;
        let task_id = call_response.result.unwrap()["taskId"]
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
        let (task_id, _) = server.task_store.create_task().await.unwrap();

        let params = json!({"taskId": task_id});
        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(params))
            .await;

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        // EMPTY ack plus the discriminator, and nothing else: `CancelTaskResult
        // = Result`. The pre-3.0.0 handler echoed the whole `TaskInfo`, which
        // invited clients to read a status the spec calls eventually
        // consistent from the one response that cannot carry a fresh one.
        assert_eq!(result["resultType"], "complete");
        assert!(result.get("taskId").is_none(), "{result}");
        assert!(result.get("status").is_none(), "{result}");
        assert_eq!(
            result.as_object().map(serde_json::Map::len),
            Some(1),
            "the ack carries exactly one key: {result}"
        );

        // The intent still took effect where it belongs.
        assert_eq!(
            server.task_store.get_task(&task_id).await.unwrap().status,
            crate::ports::protocol::TaskStatus::Cancelled
        );
    }

    #[tokio::test]
    async fn test_tasks_cancel_nonexistent() {
        let server = create_test_server();
        let params = json!({"taskId": "no-such-task"});

        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(params))
            .await;

        // The only case that is still an error, now that a terminal task is
        // acknowledged. `assert_eq!` on the code: `is_some()` would keep
        // passing if every cancel started erroring again.
        let error = response.error.expect("an unknown taskId is an error");
        assert_eq!(error.code, -32602);
        assert!(error.message.contains("no-such-task"), "{}", error.message);
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
    async fn tasks_get_polls_until_terminal() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();
        let params = json!({
            "name": "ssh_ansible_playbook",
            "arguments": {"host": "nowhere", "playbook": "site.yml"}
        });

        let call_response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session))
            .await;
        // FLAT: taskId at the root of `result`, no nested `task` object.
        let task_id = call_response.result.unwrap()["taskId"]
            .as_str()
            .unwrap()
            .to_string();

        // Each call answers immediately; the CLIENT loops, not the server.
        let mut terminal = json!(null);
        for _ in 0..200 {
            let response = server
                .handle_tasks_get(Some(json!(2)), Some(json!({"taskId": task_id})))
                .await;
            assert!(response.error.is_none());
            let body = response.result.unwrap();
            // "complete" on EVERY turn, including while still `working`:
            // the discriminator names the shape, `status` names the
            // progress. Asserting it inside the loop is what makes the two
            // axes independently observable.
            assert_eq!(body["resultType"], "complete");
            assert_eq!(body["taskId"], task_id.as_str());
            if body["status"] != "working" {
                terminal = body;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert!(
            terminal["status"].is_string(),
            "worker never reached a terminal state within 2s"
        );
        assert_eq!(terminal["resultType"], "complete");
        // `related-task` is gone: it was emitted only by `tasks/result`.
        assert!(terminal.get("_meta").is_none());

        // The payload folded in from the deleted `tasks/result` — and the
        // correspondence the five `tasks/get` MUSTs demand: a completed task
        // carries `result`, a failed one carries `error`, and never both.
        //
        // The tool here cannot reach a real host, so today it lands on the
        // `failed` branch. Asserting the CORRESPONDENCE rather than one
        // outcome is what lets this test survive the `isError` inversion
        // (which moves this very call to `completed`) without being rewritten
        // — and still catch a payload that disagrees with its own status.
        match terminal["status"].as_str().unwrap() {
            "completed" => {
                assert!(terminal["result"]["content"].is_array(), "{terminal}");
                assert!(terminal.get("error").is_none(), "{terminal}");
            }
            "failed" => {
                assert!(!terminal["error"].is_null(), "{terminal}");
                assert!(terminal.get("result").is_none(), "{terminal}");
            }
            other => panic!("unexpected terminal status {other}: {terminal}"),
        }
    }

    /// Spec 5.13, the MUST that 2025-11-25 stated backwards: a tool that ran
    /// and returned an error is a COMPLETION carrying `isError: true`, never
    /// `status: "failed"`. `failed` is reserved for JSON-RPC faults.
    ///
    /// The decision rule is that `tasks/get` "returns exactly what the
    /// underlying request would have returned" — and the synchronous path
    /// answers this very input with an isError envelope, not an error. The
    /// tool here cannot reach its host, so the handler errors: the exact
    /// input that produced `failed` before this release.
    #[tokio::test]
    async fn a_tool_error_completes_the_task_and_never_fails_it() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();
        let params = json!({
            "name": "ssh_ansible_playbook",
            "arguments": {"host": "nowhere", "playbook": "site.yml"}
        });
        let call = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session))
            .await;
        let task_id = call.result.unwrap()["taskId"].as_str().unwrap().to_string();

        let mut body = json!(null);
        for _ in 0..200 {
            let response = server
                .handle_tasks_get(Some(json!(2)), Some(json!({"taskId": task_id})))
                .await;
            let snapshot = response.result.expect("tasks/get always answers");
            if snapshot["status"] != "working" {
                body = snapshot;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert_eq!(
            body["status"], "completed",
            "a tool error is a completion, not a failure: {body}"
        );
        // Value AND placement. The error details belong in `result`, where a
        // client reads a `CallToolResult`; `error` is reserved for a JSON-RPC
        // error object, and a task carrying both would satisfy a test written
        // without the negation.
        assert_eq!(body["result"]["isError"], true, "{body}");
        assert!(body["result"]["content"].is_array(), "{body}");
        assert!(body.get("error").is_none(), "{body}");
        // The human-readable half. An operator who filtered on
        // `status == "failed"` sees nothing now; this field is what is left
        // to read, so it must not claim success.
        assert_eq!(body["statusMessage"], "Task completed with a tool error.");
    }

    /// The terminal notification carries the PAYLOAD, not just the status:
    /// "The notification includes the full task object, allowing clients to
    /// access the complete task state and final results without polling the
    /// `tasks/get` method."
    ///
    /// Without the payload assertion this test would pass for a notification
    /// that merely says "done" — which is the version that saves a subscribed
    /// client nothing, since it would still have to poll for the result.
    #[tokio::test]
    async fn the_terminal_task_notification_carries_the_full_result() {
        let server = create_test_server();
        let (session, mut rx) = session_declaring_tasks();
        let params = json!({
            "name": "ssh_ansible_playbook",
            "arguments": {"host": "nowhere", "playbook": "site.yml"}
        });

        let response = server
            .handle_tools_call(Some(json!(1)), Some(params), None, Some(&session))
            .await;
        let task_id = response.result.unwrap()["taskId"]
            .as_str()
            .unwrap()
            .to_string();

        let mut terminal = None;
        while let Ok(Some(msg)) =
            tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await
        {
            if let WriterMessage::Notification(n) = msg {
                // MUST NOT, spec 5.14: progress is not supported on tasks at
                // all. This cannot fire today — none of the four promoted
                // tools calls `progress_reporter` — so it is a TRIPWIRE, not
                // proof. The guarantee itself is structural: the progress
                // token is not a parameter of `handle_tools_call_async`, and
                // `ToolContext::progress_reporter` returns `None` without one.
                // The tripwire is aimed at `ssh_runbook_execute`, which does
                // report progress and is the first candidate to join the list
                // once the MRTR item closes.
                assert_ne!(
                    n.method, "notifications/progress",
                    "progress MUST NOT be sent for a task"
                );
                if n.method == "notifications/tasks" {
                    let params = n.params.expect("params");
                    if params["taskId"] == task_id.as_str() && params["status"] != "working" {
                        terminal = Some(params);
                        break;
                    }
                }
            }
        }

        let terminal = terminal.expect("no terminal `notifications/tasks` arrived");
        assert_eq!(terminal["status"], "completed", "{terminal}");
        assert_eq!(terminal["result"]["isError"], true, "{terminal}");
        assert!(terminal["result"]["content"].is_array(), "{terminal}");
        // Flat, and no result discriminator on a notification.
        assert_eq!(terminal["taskId"], task_id.as_str());
        assert!(terminal.get("resultType").is_none(), "{terminal}");
    }

    #[tokio::test]
    async fn tasks_get_never_blocks_on_a_working_task() {
        // MCP 2026-07-28: `tasks/get` is a point-in-time snapshot and never
        // blocks. The pre-3.0.0 `tasks/result` parked here until the task
        // went terminal, which is the G-1 freeze (issue #131). The timeout
        // is the executable half of that guarantee — the `include_str!`
        // guard in `task_store.rs` only pins a NAME.
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task().await.unwrap();

        let response = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            server.handle_tasks_get(Some(json!(1)), Some(json!({"taskId": task_id}))),
        )
        .await
        .expect("tasks/get must not block on a working task");

        assert!(response.error.is_none());
        let body = response.result.unwrap();
        // The pair that proves the two axes are distinct: the discriminator
        // says "complete" (this IS the standard result shape) while the task
        // status says "working". Conflating them was the pre-3.0.0 error
        // that invented a `ResultType::Working`.
        assert_eq!(body["resultType"], "complete");
        assert_eq!(body["status"], "working");
        assert_eq!(body["taskId"], task_id.as_str());
        // A non-terminal task carries neither payload field.
        assert!(body.get("result").is_none());
        assert!(body.get("error").is_none());
    }

    #[tokio::test]
    /// Supersedes `test_tasks_cancel_already_completed_returns_error`.
    ///
    /// This is the race the spec names: the work finished before the
    /// cancellation arrived. The client cannot have known — it is told it may
    /// delete its state the moment it sends the request — so the answer is an
    /// ack, not an error.
    ///
    /// The `tasks/get` assertion is the half that matters: acknowledging must
    /// not mean overwriting. A completed task that reports `cancelled`
    /// afterwards would tell an operator the work never ran.
    async fn tasks_cancel_on_a_completed_task_is_acknowledged_not_refused() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task().await.unwrap();
        server
            .task_store
            .complete_task(
                &task_id,
                json!({"content": [{"type": "text", "text": "done"}]}),
            )
            .await;

        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(json!({"taskId": task_id})))
            .await;

        assert!(response.error.is_none(), "{:?}", response.error);
        assert_eq!(response.result.unwrap()["resultType"], "complete");

        let snapshot = server
            .handle_tasks_get(Some(json!(2)), Some(json!({"taskId": task_id})))
            .await
            .result
            .expect("the task is still readable");
        assert_eq!(
            snapshot["status"], "completed",
            "a late cancellation must not rewrite a finished task: {snapshot}"
        );
        assert!(snapshot["result"]["content"].is_array(), "{snapshot}");
    }

    #[tokio::test]
    /// Supersedes `test_tasks_cancel_already_cancelled_returns_error`. A
    /// client that deleted its state and re-sent cannot be punished for it.
    async fn tasks_cancel_is_idempotent() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task().await.unwrap();
        server.task_store.cancel_task(&task_id).await.unwrap();

        let response = server
            .handle_tasks_cancel(Some(json!(1)), Some(json!({"taskId": task_id})))
            .await;

        assert!(response.error.is_none(), "{:?}", response.error);
        assert_eq!(response.result.unwrap()["resultType"], "complete");
        assert_eq!(
            server.task_store.get_task(&task_id).await.unwrap().status,
            crate::ports::protocol::TaskStatus::Cancelled
        );
    }

    #[tokio::test]
    async fn test_tasks_get_on_completed_task() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task().await.unwrap();
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

    /// Supersedes `test_tasks_result_on_cancelled_task`.
    ///
    /// The G-23 / D-F3 audit guards it carried protected `tasks/result`'s
    /// "terminal state without a stored result" error path — its wire-spelled
    /// status text and its machine-readable `data`. That path is unreachable
    /// in 3.0.0: it belonged to a method that no longer exists. The guard is
    /// not reverted, it is rendered moot — `tasks/get` never had to synthesize
    /// a result for a cancelled task. It returns the snapshot, with
    /// `status: "cancelled"` and no `result` key, which is exactly
    /// `CancelledTask` (`extends Task`, no `result` field).
    #[tokio::test]
    async fn tasks_get_on_cancelled_carries_no_result() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task().await.unwrap();
        server.task_store.cancel_task(&task_id).await.unwrap();

        let response = server
            .handle_tasks_get(Some(json!(1)), Some(json!({"taskId": task_id})))
            .await;

        // A cancelled task is reported, not errored on.
        assert!(response.error.is_none());
        let body = response.result.expect("cancelled task is still readable");
        assert_eq!(body["resultType"], "complete");
        // The wire spelling, lowercase double-l — never Rust's `Cancelled`.
        assert_eq!(body["status"], "cancelled");
        assert_eq!(body["taskId"], task_id.as_str());
        // The half that carries the guarantee: no invented payload.
        assert!(
            body.get("result").is_none(),
            "CancelledTask has no `result` field"
        );
        assert!(body.get("error").is_none());
    }

    #[tokio::test]
    async fn tasks_get_unknown_id_still_says_not_found() {
        let server = create_test_server();
        let response = server
            .handle_tasks_get(Some(json!(1)), Some(json!({"taskId": "no-such-task"})))
            .await;

        let error = response.error.expect("unknown task is an error");
        assert_eq!(error.code, -32602);
        assert!(
            error.message.contains("Task not found"),
            "got: {}",
            error.message
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

        let (session, _rx) = session_declaring_tasks();
        let params = json!({
            "name": "ssh_ansible_playbook",
            "arguments": {"host": "nowhere", "playbook": "site.yml"}
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
            server.handle_tools_call(Some(json!(1)), Some(params), None, Some(&session)),
        )
        .await
        .expect(
            "handle_tools_call never returned — the concurrency permit is \
             likely being acquired before tokio::spawn (in the dispatch \
             path) instead of inside the spawned worker, so the enclosing \
             request itself blocked on the permits this test is holding",
        );
        let task_id = response.result.unwrap()["taskId"]
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
    async fn tasks_get_on_completed_inlines_the_result() {
        let server = create_test_server();
        let (task_id, _) = server.task_store.create_task().await.unwrap();
        server
            .task_store
            .complete_task(
                &task_id,
                json!({"content": [{"type": "text", "text": "result data"}]}),
            )
            .await;

        let response = server
            .handle_tasks_get(Some(json!(1)), Some(json!({"taskId": task_id})))
            .await;

        assert!(response.error.is_none());
        let body = response.result.unwrap();
        assert_eq!(body["resultType"], "complete");
        assert_eq!(body["status"], "completed");
        // Named key AND shape. `assert!(response.error.is_none())` alone
        // survives both deleting the line that populates `result` and
        // renaming the key; these two assertions survive neither.
        assert!(body["result"]["content"].is_array());
        assert_eq!(body["result"]["content"][0]["text"], "result data");
        // The completed task carries no `error` — the two payload fields are
        // mutually exclusive, and a lazy implementation setting both would
        // pass a test written without this negation.
        assert!(body.get("error").is_none());
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

    /// Replaces `test_handle_request_tasks_result_dispatch`, which asserted
    /// the exact opposite (`assert_ne!(code, -32601)`).
    ///
    /// `assert_eq!` on the code, not `error.is_some()`: an `is_some()` test
    /// stays green if the method still exists and merely fails for some
    /// other reason — here, "Task not found" for the nonexistent id — which
    /// is precisely the failure mode this test has to catch.
    #[tokio::test]
    async fn tasks_result_is_no_longer_a_method() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/result".to_string(),
            params: Some(json!({"taskId": "nonexistent"})),
        };

        let response = server.handle_request(request).await;

        assert_eq!(
            response.error.expect("tasks/result must not dispatch").code,
            -32601,
            "MCP 2026-07-28 has no tasks/result method"
        );
    }

    /// The POSITIVE half of the capability gate: with the extension declared
    /// on the request, `tasks/get` reaches its handler and answers on the
    /// merits — here `-32602` for an id that does not exist.
    ///
    /// Without this, a gate that refused EVERY request would satisfy all
    /// three refusal tests below and look perfectly conformant.
    #[tokio::test]
    async fn test_handle_request_tasks_get_dispatch() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/get".to_string(),
            params: Some(params_declaring_tasks(json!({"taskId": "nonexistent"}))),
        };

        let response = server
            .handle_request_with_cancel(request, None, Some(&session))
            .await
            .expect("only subscriptions/listen answers nothing");

        let error = response.error.expect("unknown task is an error");
        assert_eq!(
            error.code, -32602,
            "a declaring client must be answered on the merits, not gated: {error:?}"
        );
    }

    /// Replaces `test_handle_request_tasks_list_dispatch`, which asserted the
    /// exact opposite (a successful empty listing).
    ///
    /// `assert_eq!` on the code rather than `error.is_some()`: `tasks/list`
    /// required no params, so a surviving handler answers SUCCESSFULLY here.
    /// A test written as `is_some()` would fail for the right reason today
    /// and pass for the wrong one the moment anyone restored the arm.
    #[tokio::test]
    async fn tasks_list_is_no_longer_a_method() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request).await;

        assert_eq!(
            response.error.expect("tasks/list must not dispatch").code,
            -32601,
            "MCP 2026-07-28 removed tasks/list deliberately"
        );
    }

    /// Same positive half for `tasks/cancel`.
    ///
    /// The old body asserted `assert_ne!(code, -32601)`, which kept passing
    /// once the gate landed — `-32021` is not `-32601` either, so it was green
    /// while proving nothing about dispatch. `assert_eq!` on the code it
    /// should actually receive is what makes it a test again.
    #[tokio::test]
    async fn test_handle_request_tasks_cancel_dispatch() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/cancel".to_string(),
            params: Some(params_declaring_tasks(json!({"taskId": "nonexistent"}))),
        };

        let response = server
            .handle_request_with_cancel(request, None, Some(&session))
            .await
            .expect("only subscriptions/listen answers nothing");

        let error = response.error.expect("unknown task is an error");
        assert_eq!(error.code, -32602, "{error:?}");
    }

    /// The NEGATIVE half, on all three gated methods at once.
    ///
    /// `data.requiredCapabilities` is asserted LITERALLY, not merely present:
    /// its whole purpose is to tell a client what to declare in order to
    /// retry, so an invented shape would be as useless as an absent one while
    /// passing any presence check.
    #[tokio::test]
    async fn the_three_task_methods_reject_a_non_declaring_client_with_32021() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();
        // A real task, so the refusal cannot be mistaken for "not found".
        let (task_id, _) = server.task_store.create_task().await.unwrap();

        for method in ["tasks/get", "tasks/update", "tasks/cancel"] {
            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(json!(1)),
                method: method.to_string(),
                // No `_meta`: this request declares nothing, whatever any
                // earlier request or handshake may have said.
                params: Some(json!({ "taskId": task_id })),
            };

            let response = server
                .handle_request_with_cancel(request, None, Some(&session))
                .await
                .expect("only subscriptions/listen answers nothing");

            let error = response
                .error
                .unwrap_or_else(|| panic!("{method} must be refused for a non-declaring client"));
            assert_eq!(error.code, -32021, "{method}: {error:?}");

            let data = error
                .data
                .unwrap_or_else(|| panic!("{method}: -32021 must carry requiredCapabilities"));
            assert_eq!(
                data,
                json!({
                    "requiredCapabilities": {
                        "extensions": { "io.modelcontextprotocol/tasks": {} }
                    }
                }),
                "{method}: the payload must name what to declare, exactly"
            );
        }

        // And the task is untouched: a refused request must not have run.
        assert_eq!(
            server.task_store.get_task(&task_id).await.unwrap().status,
            crate::ports::protocol::TaskStatus::Working
        );
    }

    /// A deleted method stays deleted for everyone. This is why the gate lists
    /// three method NAMES instead of matching the `tasks/` prefix: a prefix
    /// gate would answer `-32021` here, telling a client to declare a
    /// capability that would not bring `tasks/list` back.
    #[tokio::test]
    async fn a_deleted_task_method_is_32601_not_32021_for_a_non_declaring_client() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();

        for method in ["tasks/list", "tasks/result"] {
            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(json!(1)),
                method: method.to_string(),
                params: Some(json!({"taskId": "whatever"})),
            };

            let response = server
                .handle_request_with_cancel(request, None, Some(&session))
                .await
                .expect("only subscriptions/listen answers nothing");

            assert_eq!(
                response.error.expect("deleted method").code,
                -32601,
                "{method} does not exist; the answer must say so, not blame a capability"
            );
        }
    }

    /// `tasks/update` acks with the discriminator and nothing else, and its
    /// `inputResponses` are ignored rather than rejected — this server never
    /// issues an `inputRequest`, so no key a client sends can be outstanding.
    #[tokio::test]
    async fn tasks_update_acknowledges_and_ignores_input_responses() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();
        let (task_id, _) = server.task_store.create_task().await.unwrap();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/update".to_string(),
            params: Some(params_declaring_tasks(json!({
                "taskId": task_id,
                "inputResponses": {
                    "never-issued": { "action": "accept", "content": { "input": "Luca" } }
                }
            }))),
        };

        let response = server
            .handle_request_with_cancel(request, None, Some(&session))
            .await
            .expect("only subscriptions/listen answers nothing");

        assert!(response.error.is_none(), "{:?}", response.error);
        let result = response.result.expect("an ack");
        assert_eq!(result["resultType"], "complete");
        assert_eq!(
            result.as_object().map(serde_json::Map::len),
            Some(1),
            "UpdateTaskResult is an empty acknowledgement: {result}"
        );

        // A no-op is a no-op: the task must be exactly where it was.
        let info = server.task_store.get_task(&task_id).await.unwrap();
        assert_eq!(info.status, crate::ports::protocol::TaskStatus::Working);
    }

    /// An unknown id is still an error, so the no-op cannot silently absorb a
    /// typo'd or TTL-evicted task.
    #[tokio::test]
    async fn tasks_update_on_an_unknown_task_is_invalid_params() {
        let server = create_test_server();
        let (session, _rx) = session_declaring_tasks();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tasks/update".to_string(),
            params: Some(params_declaring_tasks(json!({
                "taskId": "no-such-task",
                "inputResponses": {}
            }))),
        };

        let response = server
            .handle_request_with_cancel(request, None, Some(&session))
            .await
            .expect("only subscriptions/listen answers nothing");

        let error = response.error.expect("unknown taskId is an error");
        assert_eq!(error.code, -32602);
        assert!(error.message.contains("no-such-task"), "{}", error.message);
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

    // ====== Legacy resources/subscribe retirement (2026-07-28) ======

    /// MCP 2026-07-28 on `subscriptions/listen`: "It replaces the former
    /// `resources/subscribe` RPC and the HTTP GET endpoint." The pair must
    /// be GONE from the dispatch table, not merely stubbed — 2.2.0 kept two
    /// handlers answering `-32601` from live routing arms, which is a
    /// different thing from a method the server does not know.
    ///
    /// The `-32601` half is an ABSENCE assertion, and an absence is
    /// satisfied by a server that deleted subscriptions outright exactly as
    /// well as by one that migrated them. The rest of this test is its
    /// positive twin: the replacement really does register and acknowledge.
    #[tokio::test]
    async fn test_legacy_resource_subscribe_pair_is_gone() {
        let server = create_test_server();
        for method in ["resources/subscribe", "resources/unsubscribe"] {
            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(json!(1)),
                method: method.to_string(),
                params: Some(json!({ "uri": "history://recent" })),
            };
            let error = server
                .handle_request(request)
                .await
                .error
                .unwrap_or_else(|| panic!("{method} must no longer be routed"));
            assert_eq!(
                error.code, -32601,
                "{method} folded into subscriptions/listen"
            );
            assert!(
                error.message.contains(method),
                "the unknown-method refusal names the method: {}",
                error.message
            );
        }

        // Positive twin: the URI those two methods used to carry now
        // reaches the registry through the replacement.
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        let outcome = server
            .handle_subscriptions_listen(
                Some(json!(7)),
                Some(json!({
                    "notifications": { "resourceSubscriptions": ["history://recent"] }
                })),
                Some(&session_ctx),
            )
            .await;
        assert!(
            matches!(outcome, ListenOutcome::Streaming { .. }),
            "subscriptions/listen must be a live replacement, not another hole"
        );
        match rx.try_recv().expect("acknowledgement notification") {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/subscriptions/acknowledged");
            }
            _ => panic!("expected a Notification"),
        }
        assert_eq!(
            server.subscriptions.subscribed_resource_uris(),
            vec!["history://recent".to_string()],
            "the subscription the retired RPC used to create now lives here"
        );
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

        let outcome = server
            .handle_subscriptions_listen(Some(json!(1)), Some(params), Some(&session_ctx))
            .await;

        // MCP 2026-07-28: there is NO immediate result. The request id
        // stays open until graceful teardown, and the subscription id is
        // the request id itself — never a server-minted counter.
        let sub_id = match outcome {
            ListenOutcome::Streaming { subscription_id } => subscription_id,
            ListenOutcome::Rejected(r) => {
                panic!("listen must register, got rejection: {:?}", r.error)
            }
        };
        assert_eq!(
            sub_id,
            json!(1),
            "the subscription id MUST be the JSON-RPC id of the listen request"
        );
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
                    sub_id,
                    "the ack must correlate on the request id"
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

    /// `RequestId = string | number`. A string id must survive verbatim:
    /// the old implementation minted its own `u64`, which could not have
    /// represented this id at all, and no test caught it because the suite
    /// only asserted "subscriptionId is *a* number".
    #[tokio::test]
    async fn test_subscription_id_is_the_request_id_even_when_a_string() {
        let server = create_test_server();
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);

        let outcome = server
            .handle_subscriptions_listen(
                Some(json!("listen-7f3a")),
                Some(json!({ "notifications": { "toolsListChanged": true } })),
                Some(&session_ctx),
            )
            .await;

        let ListenOutcome::Streaming { subscription_id } = outcome else {
            panic!("listen must register");
        };
        assert_eq!(subscription_id, json!("listen-7f3a"));

        match rx.try_recv().expect("ack notification") {
            WriterMessage::Notification(n) => {
                let params = n.params.expect("params present");
                assert_eq!(
                    params["_meta"][crate::mcp::protocol::META_SUBSCRIPTION_ID],
                    json!("listen-7f3a")
                );
            }
            _ => panic!("expected a Notification"),
        }
    }

    /// Two concurrent subscriptions keep their own request ids — proof the
    /// registry stores what it was given rather than a counter of its own.
    #[tokio::test]
    async fn test_concurrent_listens_keep_their_own_request_ids() {
        let server = create_test_server();
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(16);
        let session_ctx = SessionContext::new(tx);

        for id in [json!(41), json!("second")] {
            let outcome = server
                .handle_subscriptions_listen(
                    Some(id.clone()),
                    Some(json!({ "notifications": { "toolsListChanged": true } })),
                    Some(&session_ctx),
                )
                .await;
            let ListenOutcome::Streaming { subscription_id } = outcome else {
                panic!("listen must register");
            };
            assert_eq!(subscription_id, id);
            let _ack = rx.try_recv().expect("ack notification");
        }

        assert_eq!(server.subscriptions.len(), 2);
        assert_eq!(
            server
                .subscriptions
                .publish_topic(NotificationTopic::ToolsListChanged),
            2
        );

        let mut seen = Vec::new();
        while let Ok(WriterMessage::Notification(n)) = rx.try_recv() {
            let params = n.params.expect("params present");
            seen.push(params["_meta"][crate::mcp::protocol::META_SUBSCRIPTION_ID].clone());
        }
        assert!(seen.contains(&json!(41)), "numeric id must be delivered");
        assert!(
            seen.contains(&json!("second")),
            "string id must be delivered"
        );
    }

    /// The subscription id IS the request id, so a listen carrying no id
    /// has nothing to correlate on and must be refused rather than
    /// silently given a fabricated one.
    #[tokio::test]
    async fn test_subscriptions_listen_without_an_id_is_refused() {
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);

        let outcome = server
            .handle_subscriptions_listen(
                None,
                Some(json!({ "notifications": { "toolsListChanged": true } })),
                Some(&session_ctx),
            )
            .await;

        let ListenOutcome::Rejected(response) = outcome else {
            panic!("an id-less listen must be rejected");
        };
        assert_eq!(response.error.expect("error").code, -32600);
        assert!(server.subscriptions.is_empty());
    }

    #[tokio::test]
    async fn test_subscriptions_listen_requires_notifications_member() {
        let server = create_test_server();
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);

        let outcome = server
            .handle_subscriptions_listen(Some(json!(1)), Some(json!({})), Some(&session_ctx))
            .await;

        let ListenOutcome::Rejected(response) = outcome else {
            panic!("malformed params must be rejected, not registered");
        };
        assert_eq!(response.error.expect("error").code, -32602);
        assert!(server.subscriptions.is_empty());
    }

    #[tokio::test]
    async fn test_subscriptions_listen_without_session_is_refused() {
        let server = create_test_server();
        let outcome = server
            .handle_subscriptions_listen(
                Some(json!(1)),
                Some(json!({ "notifications": { "toolsListChanged": true } })),
                None,
            )
            .await;
        let ListenOutcome::Rejected(response) = outcome else {
            panic!("a session-less listen must be rejected");
        };
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

    // ============== resources/updated Watch Tests ==============

    #[test]
    fn test_resource_update_tick_skips_history_when_unchanged() {
        let uris = vec![
            "history://recent".to_string(),
            "health://server".to_string(),
        ];
        assert_eq!(
            resource_update_tick(&uris, false),
            vec!["health://server".to_string()],
            "history:// is change-detected and must stay silent when idle"
        );
        assert_eq!(
            resource_update_tick(&uris, true),
            vec![
                "history://recent".to_string(),
                "health://server".to_string()
            ]
        );
    }

    #[test]
    fn test_resource_update_tick_with_no_subscriptions_is_empty() {
        assert!(resource_update_tick(&[], true).is_empty());
    }

    #[tokio::test]
    async fn test_resource_update_emits_only_to_subscribers_of_that_uri() {
        let server = create_test_server();
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        server
            .handle_subscriptions_listen(
                Some(json!(1)),
                Some(json!({
                    "notifications": { "resourceSubscriptions": ["history://recent"] }
                })),
                Some(&session_ctx),
            )
            .await;
        let _ack = rx.try_recv().expect("ack notification");

        let uris = server.subscriptions.subscribed_resource_uris();
        assert_eq!(uris, vec!["history://recent".to_string()]);

        // Idle bridge: the tick emits nothing at all.
        assert!(resource_update_tick(&uris, false).is_empty());
        assert!(rx.try_recv().is_err());

        // A recorded command bumps the revision, so the tick emits.
        server.history.record_success("host", "uptime", 0, 5);
        for uri in resource_update_tick(&uris, true) {
            server.subscriptions.publish_resource_updated(&uri);
        }
        match rx
            .try_recv()
            .expect("subscriber receives resources/updated")
        {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/resources/updated");
                assert_eq!(n.params.expect("params")["uri"], "history://recent");
            }
            _ => panic!("expected a Notification"),
        }

        // A URI nobody subscribed to reaches nobody.
        assert_eq!(
            server
                .subscriptions
                .publish_resource_updated("health://server"),
            0
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_spawn_resource_update_watch_keeps_ticking() {
        let server = create_test_server();
        let handle = server.spawn_resource_update_watch();
        tokio::task::yield_now().await;
        assert!(
            !handle.is_finished(),
            "the watch loop exited immediately instead of ticking forever"
        );
        handle.abort();
    }

    /// `RESOURCE_WATCH_INTERVAL` is a published contract — the CHANGELOG
    /// and the `subscribe: true` capability both promise a 30 s poll for
    /// the remote-backed schemes — and nothing asserted it at `3f7c2fa`:
    /// changing the constant reddened nothing.
    #[test]
    fn test_resource_watch_interval_is_thirty_seconds() {
        assert_eq!(
            RESOURCE_WATCH_INTERVAL,
            std::time::Duration::from_secs(30),
            "the documented poll interval for remote-backed schemes"
        );
    }

    /// The tick-to-publish wiring, driven directly.
    ///
    /// `test_spawn_resource_update_watch_keeps_ticking` cannot cover it:
    /// it only asserts the task is alive after one `yield_now`, and the
    /// loop's first tick runs with zero subscriptions. Gutting
    /// `publish_resource_updated` inside the loop left the whole suite
    /// green at `3f7c2fa` (9112 passed / 0 failed). This is the test that
    /// reddens now.
    #[tokio::test]
    async fn test_watch_once_publishes_to_a_live_subscription() {
        let server = create_test_server();
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        server
            .handle_subscriptions_listen(
                Some(json!(1)),
                Some(json!({
                    "notifications": { "resourceSubscriptions": ["history://recent"] }
                })),
                Some(&session_ctx),
            )
            .await;
        // Drain the acknowledgement so anything after it can only be an
        // update produced by the tick.
        let _ack = rx.try_recv().expect("ack notification");

        let mut last_revision = server.history.revision();

        // Idle bridge: `history://` is change-detected, so a tick is silent.
        assert_eq!(
            watch_once(&server.subscriptions, &server.history, &mut last_revision),
            0,
            "an idle tick must publish nothing"
        );
        assert!(rx.try_recv().is_err());

        // A recorded command bumps the revision; the next tick publishes.
        server.history.record_success("host", "uptime", 0, 5);
        assert_eq!(
            watch_once(&server.subscriptions, &server.history, &mut last_revision),
            1,
            "the tick must reach the subscriber via publish_resource_updated"
        );
        match rx
            .try_recv()
            .expect("subscriber receives resources/updated")
        {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/resources/updated");
                assert_eq!(n.params.expect("params")["uri"], "history://recent");
            }
            _ => panic!("expected a Notification"),
        }

        // The revision is consumed: with no new command the tick is silent
        // again, which is what keeps an idle bridge quiet.
        assert_eq!(
            watch_once(&server.subscriptions, &server.history, &mut last_revision),
            0,
            "last_revision must be advanced by the tick that published"
        );
        assert!(rx.try_recv().is_err());
    }

    /// The SPAWNED task really calls the wiring, not just `watch_once` in
    /// isolation. Paused time is what makes a 30 s interval observable:
    /// once every task is idle the runtime advances the clock to the next
    /// timer, so the second tick happens without 30 s of wall clock.
    #[tokio::test(start_paused = true)]
    async fn test_spawn_resource_update_watch_publishes_on_its_interval() {
        let server = create_test_server();
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        server
            .handle_subscriptions_listen(
                Some(json!(1)),
                Some(json!({
                    "notifications": { "resourceSubscriptions": ["history://recent"] }
                })),
                Some(&session_ctx),
            )
            .await;
        let _ack = rx.try_recv().expect("ack notification");

        let handle = server.spawn_resource_update_watch();

        // The interval's first tick fires immediately, against the revision
        // the task captured at spawn: nothing changed, so it is silent.
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "an idle bridge must not emit on the first tick"
        );

        // Now change history. The next tick must publish.
        server.history.record_success("host", "uptime", 0, 5);
        let msg = tokio::time::timeout(RESOURCE_WATCH_INTERVAL * 4, rx.recv())
            .await
            .expect("the watch loop must publish within a few intervals")
            .expect("the writer channel stays open");
        match msg {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/resources/updated");
                assert_eq!(n.params.expect("params")["uri"], "history://recent");
            }
            _ => panic!("expected a Notification"),
        }
        handle.abort();
    }

    /// Shutdown in `serve()` is `for h in cleanup_handles { h.abort(); }`,
    /// so the watch loop is both STARTED and STOPPED only if it sits in
    /// that vec. Neither half was asserted at `3f7c2fa` — deleting the
    /// `push` left the suite green. A length assertion alone would be
    /// satisfied by any fifth task, so this drives a real notification out
    /// of the vec and then proves aborting it silences the bridge.
    ///
    /// Subscribes to `health://server` rather than `history://recent` on
    /// purpose: remote-backed schemes are published on EVERY tick, so this
    /// test does not depend on whether the spawned task happened to sample
    /// the history revision before or after a `record_success` call. The
    /// change-detection path has its own tests.
    #[tokio::test(start_paused = true)]
    async fn test_spawn_global_tasks_starts_and_stops_the_resource_watch() {
        let server = create_test_server();
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        server
            .handle_subscriptions_listen(
                Some(json!(1)),
                Some(json!({
                    "notifications": { "resourceSubscriptions": ["health://server"] }
                })),
                Some(&session_ctx),
            )
            .await;
        let _ack = rx.try_recv().expect("ack notification");
        assert_eq!(
            server.subscriptions.subscribed_resource_uris(),
            vec!["health://server".to_string()],
            "the scheme must survive the servable-scheme filter"
        );

        let handles = server.spawn_global_tasks();
        assert_eq!(
            handles.len(),
            5,
            "four cleanup loops plus the resource-update watch"
        );

        let msg = tokio::time::timeout(RESOURCE_WATCH_INTERVAL * 4, rx.recv())
            .await
            .expect("the watch loop must be one of the spawned handles")
            .expect("the writer channel stays open");
        match msg {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/resources/updated");
                assert_eq!(n.params.expect("params")["uri"], "health://server");
            }
            _ => panic!("expected a Notification"),
        }

        // Exactly what `serve()` does to this vec on shutdown.
        for h in handles {
            h.abort();
        }
        while rx.try_recv().is_ok() {}
        assert!(
            tokio::time::timeout(RESOURCE_WATCH_INTERVAL * 4, rx.recv())
                .await
                .is_err(),
            "an aborted watch must stop publishing"
        );
    }

    /// The dispatch chokepoint must produce NO response for an accepted
    /// `subscriptions/listen` — this is the decision point, and `None` is
    /// what tells every transport to keep the request `id` open.
    #[tokio::test]
    async fn test_dispatch_yields_no_response_for_an_accepted_listen() {
        let server = create_test_server();
        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "subscriptions/listen".to_string(),
            params: Some(json!({ "notifications": { "toolsListChanged": true } })),
        };

        let response = server
            .handle_request_with_cancel(request, None, Some(&session_ctx))
            .await;

        assert!(
            response.is_none(),
            "an accepted listen must yield no response; a Some(..) here is an \
             immediate answer to a request that must stay open"
        );
        // The acknowledgement is a NOTIFICATION and still goes out.
        match rx.try_recv().expect("ack notification") {
            WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/subscriptions/acknowledged");
            }
            _ => panic!("expected a Notification, not a Response"),
        }
    }

    /// End-to-end over a real `serve_session`: not one byte of JSON-RPC
    /// *response* may be written back for an accepted `subscriptions/listen`.
    ///
    /// Driven through the in-memory transport rather than asserted on the
    /// handler's return value, because the guarantee is about what reaches
    /// the wire. A later `ping` is the sequencing device: once its response
    /// has come back, the session has demonstrably processed past the
    /// listen, so a missing listen response is a real absence, not a race.
    #[tokio::test]
    async fn test_accepted_listen_writes_no_response_to_the_transport() {
        let server = Arc::new(create_test_server());
        let (session, client_tx, mut server_rx) = in_memory_session();
        let serve = tokio::spawn(Arc::clone(&server).serve_session(session));

        client_tx
            .send(client_request(
                1,
                "subscriptions/listen",
                Some(json!({ "notifications": { "toolsListChanged": true } })),
            ))
            .unwrap();
        client_tx.send(client_request(2, "ping", None)).unwrap();

        // Every read is bounded. An unbounded `recv().await` would hang
        // forever here rather than fail: `serve_session` keeps the reader
        // alive while `client_tx` lives, so "no more messages" never
        // arrives as a channel close.
        let mut saw_ack = false;
        let mut saw_ping_response = false;
        while !saw_ping_response {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(3), server_rx.recv())
                .await
                .expect("session went silent before answering the ping")
                .expect("session writer channel closed");
            match msg {
                WriterMessage::Response(r) => {
                    // Both representations: the raw JSON-RPC id is a
                    // number, but this codebase also carries a normalized
                    // `String` form of it (`rid_cleanup`), and a response
                    // leaking through either one is the same violation.
                    assert!(
                        r.id != Some(json!(1)) && r.id != Some(json!("1")),
                        "a response was written for the listen request; its id \
                         must stay open until graceful teardown"
                    );
                    if r.id == Some(json!(2)) {
                        saw_ping_response = true;
                    }
                }
                WriterMessage::Notification(n) => {
                    if n.method == "notifications/subscriptions/acknowledged" {
                        saw_ack = true;
                    }
                }
                WriterMessage::BatchResponse(_) => panic!("unexpected batch response"),
                // Server-initiated requests (elicitation, sampling) are
                // unrelated to this assertion; skip rather than panic so an
                // unrelated feature cannot fail this test spuriously.
                WriterMessage::Request(_) => {}
            }
        }

        assert!(
            saw_ack,
            "the acknowledgement notification must still be sent"
        );
        assert_eq!(server.subscriptions.len(), 1, "the listen must be live");

        // `abort()`, never `drop(client_tx)` + `serve.await`. Session
        // teardown awaits the writer task, and that task only ends on a
        // send ERROR -- `drop(tx)` cannot close the channel because
        // `session_ctx.notification_tx` and the `mcp_logger` tx outlive
        // it. `ChannelWriter::send` is infallible, so the writer would
        // never exit and the await would hang. Same pattern as the G-1
        // harness above, and the reason is the pre-existing teardown
        // defect recorded in the task 35 commit.
        serve.abort();
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
            .await
            .expect("only subscriptions/listen yields no response");
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
            .await
            .expect("only subscriptions/listen yields no response");
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
            .await
            .expect("only subscriptions/listen yields no response");

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
            .await
            .expect("only subscriptions/listen yields no response");

        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("does not support elicitation"),
            "unexpected error text: {text}"
        );
    }

    /// Not a Legacy-handshake test any more: task 15 deleted every
    /// production writer of `SessionCapabilities` (`handle_initialize` used
    /// to be the only one). What survives is a narrower but still-real
    /// invariant — when a request carries no `_meta` envelope at all, the
    /// destructive-elicitation gate falls back to `session.caps` rather than
    /// denying by default. Its sibling,
    /// `test_request_meta_empty_capabilities_overrides_initialize`, sends an
    /// explicit empty `clientCapabilities: {}` (`Some(false)`, which beats
    /// `caps`) — a different branch from the `None` case exercised here.
    ///
    /// Decision point for task 68: `SessionCapabilities` survives only if a
    /// production caller still writes to it. This test is why the answer is
    /// GO after this task — `session_ctx.caps.set_supports_elicitation(true)`
    /// below is set directly, because no production code path does it any
    /// more. A recon that ran task 68's writer-search before this task landed
    /// found STOP.
    #[tokio::test]
    async fn test_destructive_gate_falls_back_to_caps_when_no_meta() {
        let mut config = test_config();
        config.security.require_elicitation_on_destructive = true;
        let (server, _audit_task) = McpServer::new(config);

        let (tx, mut rx) = mpsc::channel::<WriterMessage>(8);
        let session_ctx = SessionContext::new(tx);
        session_ctx.caps.set_supports_elicitation(true);

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
            .await
            .expect("only subscriptions/listen yields no response");

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
            .await
            .expect("only subscriptions/listen yields no response");

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
