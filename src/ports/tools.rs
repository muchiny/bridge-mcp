//! Tool Handler Port
//!
//! This module defines the trait for MCP tool handlers,
//! enabling a plugin-like architecture where each tool
//! can be implemented independently.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::{RwLock, mpsc};

use super::protocol::ToolCallResult;
use crate::config::Config;
use crate::domain::CommandHistory;
use crate::domain::{ExecuteCommandUseCase, OutputCache, TunnelManager};
use crate::error::Result;
use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
use crate::ssh::SessionManager;

use super::executor_router::ExecutorRouter;

/// Lexically normalize a POSIX-style absolute path: collapse `.`, `..`,
/// and repeated `/` without touching the filesystem. Output stays
/// absolute (leading `/`). Used by `validate_root_scope` so a path
/// `/root/../etc/passwd` resolves to `/etc/passwd` before the prefix
/// check rather than after.
fn normalize_path_lexical(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {} // empty (leading/trailing/double slash) or current
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    if stack.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", stack.join("/"))
    }
}

/// Schema definition for a tool
#[derive(Debug, Clone)]
pub struct ToolSchema {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: &'static str,
}

/// Context provided to tool handlers during execution
///
/// This struct contains all the dependencies that tools might need
/// to execute their operations.
pub struct ToolContext {
    pub config: Arc<Config>,
    pub validator: Arc<CommandValidator>,
    pub sanitizer: Arc<Sanitizer>,
    pub audit_logger: Arc<AuditLogger>,
    pub history: Arc<CommandHistory>,
    pub connection_pool: Arc<ExecutorRouter>,
    pub execute_use_case: Arc<ExecuteCommandUseCase>,
    pub rate_limiter: Arc<RateLimiter>,
    pub session_manager: Arc<SessionManager>,
    pub tunnel_manager: Arc<TunnelManager>,
    pub output_cache: Option<Arc<OutputCache>>,
    /// Runtime override for `max_output_chars`, shared with `McpServer`.
    /// Written by `ssh_config_set` or auto-detected from MCP client info.
    pub runtime_max_output_chars: Option<Arc<RwLock<Option<usize>>>>,
    /// Client-declared workspace roots for path scoping.
    pub roots: Vec<crate::mcp::protocol::RootEntry>,
    /// Optional session recorder for compliance auditing.
    pub session_recorder: Option<Arc<crate::security::SessionRecorder>>,
    /// Optional metrics collector for token consumption analytics.
    pub metrics: Option<Arc<crate::metrics::Metrics>>,
    /// Cancellation token for the in-flight MCP request.
    ///
    /// When `Some`, long-running handlers (SSH exec, helm upgrade, ansible
    /// playbook...) should race the underlying work against
    /// `token.cancelled()` in a `tokio::select!` so that
    /// `notifications/cancelled` from the MCP client can interrupt them.
    ///
    /// `None` disables cancellation — the default for test contexts and any
    /// handler invoked outside an MCP request lifecycle.
    pub cancel_token: Option<tokio_util::sync::CancellationToken>,
    /// Per-session writer channel for server-initiated JSON-RPC messages
    /// (progress, elicitation, sampling, logging notifications).
    ///
    /// Tool handlers that need to initiate a server → client interaction
    /// ([`crate::mcp::protocol::WriterMessage::Notification`] for a progress
    /// update) send on this channel. It is `None` in
    /// test contexts and for handlers invoked outside a live MCP session.
    ///
    /// This replaces the legacy `McpServer::notification_tx` global slot
    /// with a per-session sender so that multi-session transports (the
    /// daemon Unix socket) route notifications back to the originating
    /// connection instead of racing against a shared last-writer-wins
    /// slot.
    pub notification_tx: Option<mpsc::Sender<crate::mcp::protocol::WriterMessage>>,
    /// Client-provided progress token for `notifications/progress`.
    ///
    /// Present when the MCP client passed a `_meta.progressToken` on the
    /// request. Handlers obtain a [`ProgressReporter`](crate::mcp::progress::ProgressReporter) via
    /// [`ToolContext::progress_reporter`] which couples this token with
    /// the per-session [`Self::notification_tx`]; long-running handlers
    /// (`ssh_exec_multi`, `ssh_metrics_multi`, `ssh_diagnose`, runbook
    /// engines, ansible runners…) should report incremental progress
    /// through that helper so the client UI can render real-time
    /// completion instead of a single black-box wait.
    ///
    /// `None` when the client did not request progress reporting.
    pub progress_token: Option<serde_json::Value>,
    /// Snapshot of `MCPServer::client_supports_elicitation` taken at the
    /// time the request was dispatched. When `false`, the
    /// The sampling helper short-circuits without sending a
    /// request — saves a network round-trip for clients that do not
    /// advertise the elicitation capability.
    pub client_supports_elicitation: bool,
    /// Snapshot of `MCPServer::client_supports_sampling` taken at the
    /// time the request was dispatched. When `false`, the
    /// [`Self::sample`] helper short-circuits without sending a
    /// `sampling/createMessage` request — handlers can still proceed
    /// with the raw output, just without the LLM-side summary.
    pub client_supports_sampling: bool,
    /// Per-session MCP logger for `notifications/message`.
    ///
    /// Handlers that want to surface step-level events to the client
    /// (`ssh_runbook_execute` per-step, `ssh_ansible_playbook` per-task,
    /// `ssh_security_audit` per-CVE…) can use this to emit structured
    /// log entries. The level is filtered server-side via the shared
    /// `log_level` atomic so messages below the client's chosen
    /// threshold are dropped without any wire traffic.
    ///
    /// `None` in test contexts and when the session has no notification
    /// channel attached. Callers should fall back to `tracing::*` for
    /// local diagnostics in that case.
    pub mcp_logger: Option<Arc<crate::mcp::logger::McpLogger>>,
}

impl ToolContext {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<Config>,
        validator: Arc<CommandValidator>,
        sanitizer: Arc<Sanitizer>,
        audit_logger: Arc<AuditLogger>,
        history: Arc<CommandHistory>,
        connection_pool: Arc<ExecutorRouter>,
        execute_use_case: Arc<ExecuteCommandUseCase>,
        rate_limiter: Arc<RateLimiter>,
        session_manager: Arc<SessionManager>,
    ) -> Self {
        Self {
            config,
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool,
            execute_use_case,
            rate_limiter,
            session_manager,
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    /// Build a [`ProgressReporter`](crate::mcp::progress::ProgressReporter) for the current request, or `None`
    /// when the client did not provide a `progressToken` or the session
    /// has no notification channel attached. `total` is the number of
    /// expected steps and enables percentage display on the client side
    /// — pass `None` for indeterminate progress.
    ///
    /// Designed to be called once at the top of long-running handlers:
    ///
    /// ```ignore
    /// let progress = ctx.progress_reporter(Some(args.hosts.len() as u64));
    /// for (i, host) in args.hosts.iter().enumerate() {
    ///     run_step(host).await?;
    ///     if let Some(p) = progress.as_ref() {
    ///         p.report((i + 1) as u64, Some(&format!("{host} done")));
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn progress_reporter(
        &self,
        total: Option<u64>,
    ) -> Option<crate::mcp::progress::ProgressReporter> {
        let token = self.progress_token.clone()?;
        let tx = self.notification_tx.clone()?;
        Some(crate::mcp::progress::ProgressReporter::new(
            token, tx, total,
        ))
    }

    /// Ask the MCP client's LLM to analyze the given content.
    ///
    /// **Always returns `Ok(None)`.** This is the "sampling is unavailable"
    /// path every caller already handles — it is what happened for any client
    /// that did not declare the `sampling` capability — so the thirteen
    /// handlers behind `summarize=true` return their raw data with no
    /// LLM-side summary, exactly as they already did for most clients.
    ///
    /// # Why it is not a Multi Round-Trip Request
    ///
    /// It used to send `sampling/createMessage` as a server-initiated JSON-RPC
    /// request and block on the reply, which 2026-07-28 removed: *"Servers MUST
    /// send server-to-client requests ... using the MRTR pattern. The previous
    /// pattern of server-initiated requests is no longer supported."* So the
    /// old shape had to go regardless.
    ///
    /// Converting it is a different job from converting the confirmation gate,
    /// and the difference is structural rather than a matter of effort. The
    /// gate runs BEFORE the tool does, so answering `input_required` and
    /// replaying the whole call on the retry costs nothing. `sample()` is
    /// called from the MIDDLE of `execute`, after the remote command has
    /// already run, on output that does not exist until it has. To return
    /// `input_required` from there, `ToolHandler::execute` would have to be
    /// able to express "I need input" in its return type — it returns
    /// `Result<ToolCallResult>` — and every retry would re-run the remote
    /// command, since the server keeps no state between round trips.
    ///
    /// That refactor is a deliberate piece of work with its own trade-off to
    /// weigh (a second remote execution per summary, or the command output
    /// carried inside `requestState`). Leaving a non-conformant request on the
    /// wire until it is done was not an option; leaving the seam documented is.
    ///
    /// # Errors
    ///
    /// Never. The signature keeps its `Result` so the callers do not change
    /// shape, and so restoring the round trip does not touch them again.
    #[expect(
        clippy::unused_async,
        reason = "signature preserved for the MRTR conversion; see the doc above"
    )]
    pub async fn sample(
        &self,
        _prompt: &str,
        _content: &str,
        _max_tokens: u32,
    ) -> Result<Option<String>> {
        Ok(None)
    }

    /// Check if a path is within the declared client roots.
    /// Returns Ok if no roots are declared (backward compatible) or if the
    /// lexically-normalized path is a descendant of a declared root.
    pub fn validate_root_scope(&self, path: &str) -> Result<()> {
        if self.roots.is_empty() {
            return Ok(());
        }
        let normalized = normalize_path_lexical(path);

        for root in &self.roots {
            let raw = root.uri.strip_prefix("file://").unwrap_or(&root.uri);
            let root_norm = normalize_path_lexical(raw);
            if root_norm == "/"
                || normalized == root_norm
                || normalized.starts_with(&format!("{root_norm}/"))
            {
                return Ok(());
            }
        }
        Err(crate::error::BridgeError::McpInvalidRequest(format!(
            "Path '{path}' is outside declared workspace roots"
        )))
    }
}

/// Trait for tool handlers
///
/// Each tool in the MCP server implements this trait, providing
/// a consistent interface for tool registration and execution.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not implement `ToolHandler`",
    label = "this type cannot be used as an MCP tool handler",
    note = "see src/mcp/tool_handlers/README.md for the handler pattern"
)]
#[async_trait]
pub trait ToolHandler: Send + Sync {
    /// Get the tool's name (used for routing)
    fn name(&self) -> &'static str;

    /// Get the tool's description
    fn description(&self) -> &'static str;

    /// Get the tool's input schema as a JSON string
    fn schema(&self) -> ToolSchema;

    /// Execute the tool with the given arguments
    ///
    /// # Arguments
    /// * `args` - The tool arguments as a JSON value
    /// * `ctx` - The execution context with dependencies
    ///
    /// # Returns
    /// The tool result, either success or error
    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult>;

    /// Declares the expected output format of this tool.
    ///
    /// Used by the registry to inject the appropriate data-reduction params
    /// (`jq_filter` for JSON, `columns` for tabular, both for auto)
    /// and by `StandardToolHandler` to apply the correct reduction pipeline.
    ///
    /// Custom handlers return `RawText` (default) — no params advertised.
    ///
    /// `RawText` is `#[default]` on `OutputKind`, so any cargo-mutants
    /// rewrite to `Default::default()` is behaviorally identical
    /// (equivalent mutant) — filtered via `exclude_re` in
    /// `.cargo/mutants.toml`.
    fn output_kind(&self) -> crate::domain::output_kind::OutputKind {
        crate::domain::output_kind::OutputKind::RawText
    }

    /// Declares the JSON Schema for this tool's `structuredContent`
    /// return value (MCP 2025-06-18+, JSON Schema 2020-12).
    ///
    /// Returning `Some(schema)` advertises the schema in `tools/list`
    /// under `outputSchema`; clients can then validate or strongly type
    /// the `structuredContent` a tool returns. The schema SHOULD include
    /// `"$schema": "https://json-schema.org/draft/2020-12/schema"`.
    ///
    /// Default `None` — the tool emits no typed output contract.
    fn output_schema(&self) -> Option<Value> {
        None
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub mod mock {
    use super::*;
    use crate::config::{
        AuditConfig, AuthConfig, Config, HostConfig, HostKeyVerification, HttpTransportConfig,
        LimitsConfig, OsType, SecurityConfig, SessionConfig, SshConfigDiscovery, ToolGroupsConfig,
    };
    use crate::domain::history::HistoryConfig;
    use crate::ports::ExecutorRouter;
    use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
    use crate::ssh::SessionManager;
    use std::collections::HashMap;

    /// Create a minimal test context with no hosts configured
    #[must_use]
    pub fn create_test_context() -> ToolContext {
        create_test_context_with_config(Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // Test fixture: AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log).
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
        })
    }

    /// Create a test context with a single host "server1" at 192.168.1.100
    #[must_use]
    pub fn create_test_context_with_host() -> ToolContext {
        let mut hosts = HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
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

        create_test_context_with_config(Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // Test fixture: AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log).
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
        })
    }

    /// Create a test context whose validator runs in [`SecurityMode::Standard`]
    /// with the given command whitelist, on top of the "server1" host.
    ///
    /// Used by handlers that take a free-form shell command and must therefore
    /// go through `validate()` (whitelist + blacklist) rather than the
    /// `validate_builtin()` path reserved for trusted command builders.
    #[must_use]
    pub fn create_test_context_with_whitelist(whitelist: &[&str]) -> ToolContext {
        let base = create_test_context_with_host();
        let mut config = (*base.config).clone();
        config.security.mode = crate::config::SecurityMode::Standard;
        config.security.whitelist = whitelist.iter().map(|s| (*s).to_string()).collect();
        create_test_context_with_config(config)
    }

    /// Create a test context with custom hosts
    #[must_use]
    #[allow(clippy::implicit_hasher)]
    pub fn create_test_context_with_hosts(hosts: HashMap<String, HostConfig>) -> ToolContext {
        create_test_context_with_config(Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // Test fixture: AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log).
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
        })
    }

    /// Create a test context with a pre-populated command history
    #[must_use]
    pub fn create_test_context_with_history(history: Arc<CommandHistory>) -> ToolContext {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            // Test fixture: AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log).
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

        let validator = Arc::new(CommandValidator::new(&SecurityConfig::default()));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());

        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::with_defaults()),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    /// Create a test context with a mock executor that blocks before returning.
    ///
    /// The mock SSH call sleeps for `delay` before returning `mock_output`.
    /// Used by cancellation tests to verify that a `CancellationToken`
    /// propagated via `ToolContext.cancel_token` races ahead of the sleep.
    #[must_use]
    #[allow(clippy::implicit_hasher)]
    pub fn create_test_context_with_blocking_mock_executor(
        hosts: HashMap<String, HostConfig>,
        mock_output: crate::ssh::CommandOutput,
        delay: std::time::Duration,
    ) -> ToolContext {
        let config = Config {
            hosts,
            ..Config::default()
        };

        let validator = Arc::new(CommandValidator::new(&SecurityConfig::default()));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::mock_with_delay(mock_output, delay)),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    /// Create a test context with a mock executor that returns pre-configured output.
    ///
    /// This enables testing the full `StandardToolHandler` pipeline (steps 7-18)
    /// without real SSH connections. The mock executor returns the given output
    /// for any `exec()` call.
    #[must_use]
    #[allow(clippy::implicit_hasher)]
    pub fn create_test_context_with_mock_executor(
        hosts: HashMap<String, HostConfig>,
        mock_output: crate::ssh::CommandOutput,
    ) -> ToolContext {
        let config = Config {
            hosts,
            ..Config::default()
        };

        let validator = Arc::new(CommandValidator::new(&SecurityConfig::default()));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::mock(mock_output)),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    /// Create a test context with a custom config
    #[must_use]
    pub fn create_test_context_with_config(config: Config) -> ToolContext {
        // Build the validator from the config that was actually passed in —
        // it used to be hardcoded to `SecurityConfig::default()`, so a test
        // context could never exercise a custom whitelist or security mode and
        // any assertion about `validate()` was vacuous.
        let validator = Arc::new(CommandValidator::new(&config.security));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::with_defaults()),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)), // Disabled for tests
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(uri: &str, name: Option<&str>) -> crate::mcp::protocol::RootEntry {
        crate::mcp::protocol::RootEntry {
            uri: uri.to_string(),
            name: name.map(String::from),
        }
    }

    #[test]
    fn test_validate_root_scope_no_roots_allows_any_path() {
        let ctx = mock::create_test_context();
        assert!(ctx.validate_root_scope("/any/path").is_ok());
    }

    #[test]
    fn test_progress_reporter_returns_none_without_token() {
        let ctx = mock::create_test_context();
        assert!(ctx.progress_reporter(Some(5)).is_none());
    }

    #[tokio::test]
    async fn test_mcp_logger_is_none_in_test_context() {
        let ctx = mock::create_test_context();
        assert!(ctx.mcp_logger.is_none());
    }

    #[tokio::test]
    async fn test_mcp_logger_emits_when_attached() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let level = Arc::new(std::sync::atomic::AtomicU8::new(
            crate::mcp::protocol::LogLevel::Debug.severity(),
        ));
        let mut ctx = mock::create_test_context();
        ctx.mcp_logger = Some(Arc::new(crate::mcp::logger::McpLogger::new(level, tx)));

        ctx.mcp_logger
            .as_ref()
            .unwrap()
            .info("ssh_runbook", "step 1/3 complete");

        let msg = rx.try_recv().expect("notification on channel");
        match msg {
            crate::mcp::protocol::WriterMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/message");
                let params = n.params.unwrap();
                assert_eq!(params["level"], "info");
                assert_eq!(params["logger"], "ssh_runbook");
                assert_eq!(params["data"], "step 1/3 complete");
            }
            crate::mcp::protocol::WriterMessage::Response(_) => {
                panic!("expected Notification")
            }
        }
    }

    #[tokio::test]
    async fn test_sample_returns_none_without_tx() {
        let ctx = mock::create_test_context();
        let result = ctx.sample("p", "c", 100).await.unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_progress_reporter_returns_none_with_token_but_no_tx() {
        let mut ctx = mock::create_test_context();
        ctx.progress_token = Some(serde_json::json!("tok-test"));
        assert!(ctx.progress_reporter(Some(3)).is_none());
    }

    #[test]
    fn test_progress_reporter_emits_when_token_and_tx_present() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut ctx = mock::create_test_context();
        ctx.notification_tx = Some(tx);
        ctx.progress_token = Some(serde_json::json!("tok-99"));

        let reporter = ctx.progress_reporter(Some(2)).expect("reporter built");
        reporter.report(1, Some("first"));
        reporter.report(2, Some("done"));

        // Two notifications must land on the channel.
        let m1 = rx.try_recv().expect("first notification");
        let m2 = rx.try_recv().expect("second notification");
        match (m1, m2) {
            (
                crate::mcp::protocol::WriterMessage::Notification(n1),
                crate::mcp::protocol::WriterMessage::Notification(n2),
            ) => {
                assert_eq!(n1.method, "notifications/progress");
                assert_eq!(n2.method, "notifications/progress");
                let p1 = n1.params.unwrap();
                let p2 = n2.params.unwrap();
                assert_eq!(p1["progressToken"], "tok-99");
                assert_eq!(p1["progress"], 1);
                assert_eq!(p1["total"], 2);
                assert_eq!(p2["progress"], 2);
            }
            _ => panic!("expected two progress notifications"),
        }
    }

    #[test]
    fn test_validate_root_scope_matching_file_uri_root() {
        let mut ctx = mock::create_test_context();
        ctx.roots = vec![root("file:///home/user/project", Some("project"))];
        assert!(
            ctx.validate_root_scope("/home/user/project/src/main.rs")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_root_scope_slash_root_allows_all() {
        let mut ctx = mock::create_test_context();
        ctx.roots = vec![root("/", None)];
        assert!(ctx.validate_root_scope("/anything").is_ok());
    }

    #[test]
    fn test_validate_root_scope_outside_root_rejected() {
        let mut ctx = mock::create_test_context();
        ctx.roots = vec![root("file:///home/user/project", None)];
        let err = ctx.validate_root_scope("/etc/passwd").unwrap_err();
        assert!(err.to_string().contains("outside declared workspace roots"));
    }

    #[test]
    fn test_validate_root_scope_rejects_prefix_collision() {
        let mut ctx = mock::create_test_context();
        ctx.roots = vec![root("file:///home/user/project", None)];
        // "/home/user/projectile" must NOT match root "/home/user/project"
        let err = ctx
            .validate_root_scope("/home/user/projectile/file.txt")
            .unwrap_err();
        assert!(err.to_string().contains("outside declared workspace roots"));
    }

    #[test]
    fn test_validate_root_scope_exact_match() {
        let mut ctx = mock::create_test_context();
        ctx.roots = vec![root("file:///home/user/project", None)];
        assert!(ctx.validate_root_scope("/home/user/project").is_ok());
    }

    #[tokio::test]
    async fn test_sample_returns_quickly_when_unsupported() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mut ctx = mock::create_test_context();
        ctx.notification_tx = Some(tx);
        // `sample()` no longer contacts the client at all — see its docs. The
        // short-circuit this test guards is now unconditional rather than
        // conditional on the capability, and the timeout is still the
        // assertion that matters: it must not wait on anything.
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            ctx.sample("p", "c", 100),
        )
        .await
        .expect("must short-circuit and return without contacting the client");
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn validate_root_scope_rejects_parent_traversal() {
        let mut ctx = mock::create_test_context();
        ctx.roots = vec![root("file:///srv/app", None)];
        assert!(
            ctx.validate_root_scope("/srv/app/../../etc/shadow")
                .is_err()
        );
        assert!(
            ctx.validate_root_scope("/srv/app/foo/../../../etc/passwd")
                .is_err()
        );
    }

    #[test]
    fn validate_root_scope_accepts_clean_descendant() {
        let mut ctx = mock::create_test_context();
        ctx.roots = vec![root("file:///srv/app", None)];
        assert!(ctx.validate_root_scope("/srv/app/data/foo.txt").is_ok());
        assert!(ctx.validate_root_scope("/srv/app/data/./foo.txt").is_ok());
    }

    #[test]
    fn validate_root_scope_no_roots_still_passes() {
        let ctx = mock::create_test_context();
        assert!(ctx.validate_root_scope("/anywhere").is_ok());
    }

    #[test]
    fn validate_root_scope_handles_root_with_trailing_slash() {
        let mut ctx = mock::create_test_context();
        ctx.roots = vec![root("file:///srv/app/", None)];
        assert!(ctx.validate_root_scope("/srv/app/data").is_ok());
        assert!(ctx.validate_root_scope("/srv/app").is_ok());
        assert!(ctx.validate_root_scope("/srv/applications").is_err());
    }
}
