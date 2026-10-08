//! SSH Session Create Tool Handler
//!
//! Creates a persistent interactive shell session on a remote host.

use std::time::Instant;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp::tool_handlers::utils::elapsed_ms;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_session_create` tool
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshSessionCreateArgs {
    host: String,
    timeout_seconds: Option<u64>,
}

/// SSH Session Create tool handler
#[mcp_tool(
    name = "ssh_session_create",
    group = "sessions",
    annotation = "mutating"
)]
pub struct SshSessionCreateHandler;

impl SshSessionCreateHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds for the initial connection (default: from config)",
                "minimum": 1,
                "maximum": 3600
            }
        },
        "required": ["host"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshSessionCreateHandler {
    fn name(&self) -> &'static str {
        "ssh_session_create"
    }

    fn description(&self) -> &'static str {
        "Create a persistent interactive shell session on a remote host. Returns a JSON object \
         with fields: id (session_id to pass to ssh_session_exec/ssh_session_close), host, cwd, \
         created_at_secs_ago. Unlike ssh_exec (one-shot, stateless), a session preserves working \
         directory and environment variables across all subsequent ssh_session_exec calls — use \
         this when commands depend on each other (e.g. 'cd /app' then 'make build'). Close with \
         ssh_session_close when done; list open sessions with ssh_session_list."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshSessionCreateArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        // Get host config
        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        // Check rate limit
        if ctx.rate_limiter.check(&args.host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{}'. Please wait before sending more requests.",
                args.host
            )));
        }

        info!(host = %args.host, "Creating persistent session");

        // Build limits with optional timeout override
        let mut limits = ctx.config.limits.clone();
        if let Some(timeout) = args.timeout_seconds {
            limits.command_timeout_seconds = timeout;
        }

        // Resolve jump host if configured
        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jump_config| (jump_name.as_str(), jump_config))
        });

        // Audited as a state change, not as a command: a persistent remote
        // shell is opened here and no process is run. Measured live before
        // this call existed, `ssh_session_create` + `ssh_session_close`
        // against a real host wrote ZERO audit lines.
        let started = Instant::now();
        let session_info = match ctx
            .session_manager
            .create(&args.host, host_config, &limits, jump_host)
            .await
        {
            Ok(info) => info,
            Err(e) => {
                ctx.execute_use_case.log_failure(
                    self.name(),
                    &args.host,
                    &format!("{} host={}", self.name(), args.host),
                    &e.to_string(),
                );
                return Err(e);
            }
        };

        ctx.execute_use_case.log_state_change(
            self.name(),
            &args.host,
            &format!("{} session_id={}", self.name(), session_info.id),
            elapsed_ms(started),
        );

        let json = serde_json::to_string(&session_info)
            .unwrap_or_else(|e| format!("Error serializing session info: {e}"));

        Ok(ToolCallResult::text(json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[test]
    fn test_schema() {
        let handler = SshSessionCreateHandler;
        assert_eq!(handler.name(), "ssh_session_create");
        assert_ne!(handler.description(), "");

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_session_create");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshSessionCreateHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshSessionCreateHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    /// This tool's audit line, read off the logger — the proof the other
    /// state tools have and this one did not. It was closed by a live
    /// measurement instead, which is a fact about one afternoon and not a
    /// guard: nothing stopped a later commit from deleting the call.
    ///
    /// **It is the failure line, because that is the one a fixture can
    /// reach.** `SessionManager::create` checks `max_sessions` *before* it
    /// opens anything, so `max_sessions: 0` refuses with no network I/O at
    /// all and the handler's `log_failure` runs. What it pins: that the
    /// handler writes exactly one line, that the line names the tool, the
    /// host and the operation the handler built, and that `log_failure`
    /// hard-codes `event_type: "ssh_exec"` even here — which is why
    /// `select(.event_type == "state_change")` does not find these seven
    /// tools' failures.
    ///
    /// **What it does not cover:** the `log_state_change` call on the success
    /// path, which is downstream of a real SSH handshake no fixture can
    /// supply. Its shape is pinned by
    /// `the_success_line_shape_this_tool_writes` below, from the sink's side.
    #[tokio::test]
    async fn a_refused_session_writes_one_line_naming_this_tool() {
        let handler = SshSessionCreateHandler;
        let mut ctx = crate::ports::mock::create_test_context_with_host();
        ctx.session_manager = std::sync::Arc::new(crate::ssh::SessionManager::new(
            crate::config::SessionConfig {
                max_sessions: 0,
                ..crate::config::SessionConfig::default()
            },
        ));

        let err = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .expect_err("max_sessions: 0 must refuse every creation");
        assert!(
            matches!(err, BridgeError::TooManySessions { .. }),
            "the refusal must come from the limit, not from the network: {err:?}"
        );

        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1, "expected exactly one event: {events:?}");
        assert_eq!(events[0].tool_name.as_deref(), Some("ssh_session_create"));
        assert_eq!(events[0].host, "server1");
        assert_eq!(events[0].command, "ssh_session_create host=server1");
        assert_eq!(
            events[0].event_type, "ssh_exec",
            "`log_failure` builds `AuditEvent::new`, which hard-codes this"
        );
        assert!(
            matches!(
                events[0].result,
                crate::security::CommandResult::Error { .. }
            ),
            "got {:?}",
            events[0].result
        );
    }

    /// The success line's shape, through the sink rather than through the
    /// handler — the use-case test's pattern, for the same reason it exists
    /// there: `log_state_change` is reachable here only behind a real SSH
    /// handshake.
    ///
    /// **This is a weaker guard than the test above and the difference
    /// matters.** It pins the line's fields and the operation's shape, built
    /// from `handler.name()` so a rename of the tool moves both ends at once.
    /// It cannot see the call being removed from `execute`: that remains
    /// proved by compilation and by the 2026-09 live run, and by nothing a
    /// test can assert.
    #[tokio::test]
    async fn the_success_line_shape_this_tool_writes() {
        let handler = SshSessionCreateHandler;
        let ctx = create_test_context();
        let session_id = "6a0f8a2e-0000-4000-8000-000000000000";

        ctx.execute_use_case.log_state_change(
            handler.name(),
            "server1",
            &format!("{} session_id={session_id}", handler.name()),
            7,
        );

        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1, "expected exactly one event: {events:?}");
        assert_eq!(events[0].tool_name.as_deref(), Some("ssh_session_create"));
        assert_eq!(events[0].event_type, "state_change");
        assert_eq!(events[0].host, "server1");
        assert_eq!(
            events[0].command,
            format!("ssh_session_create session_id={session_id}")
        );
        match events[0].result {
            crate::security::CommandResult::StateChanged { duration_ms } => {
                assert_eq!(duration_ms, 7, "the duration must survive the sink");
            }
            ref other => panic!("a state change must audit as StateChanged, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_arguments() {
        let handler = SshSessionCreateHandler;
        let ctx = create_test_context();

        let result = handler.execute(Some(json!({"wrong": "field"})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_timeout_bounds() {
        let handler = SshSessionCreateHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let timeout_prop = &schema_json["properties"]["timeout_seconds"];
        assert_eq!(timeout_prop["minimum"], 1);
        assert_eq!(timeout_prop["maximum"], 3600);
    }

    #[test]
    fn test_handler_description_content() {
        let handler = SshSessionCreateHandler;
        assert!(handler.description().contains("persistent"));
        assert!(handler.description().contains("session"));
        assert!(handler.description().contains("state"));
    }
}
