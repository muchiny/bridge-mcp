//! SSH Config Set Tool Handler
//!
//! Allows runtime modification of `max_output_chars` during a session.

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
use crate::security::NO_HOST;

#[derive(Debug, Deserialize)]
struct ConfigSetArgs {
    key: String,
    value: u64,
}

/// Handler for `ssh_config_set`
#[mcp_tool(name = "ssh_config_set", group = "config", annotation = "mutating")]
pub struct SshConfigSetHandler;

impl SshConfigSetHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "key": {
                "type": "string",
                "description": "The config key to set.",
                "enum": ["max_output_chars"]
            },
            "value": {
                "type": "integer",
                "description": "Integer value in characters for max_output_chars. Default is ~40000. Use 0 to disable truncation entirely. Recommended range: 10000-200000. Setting too small a value will cause most tool outputs to be truncated.",
                "minimum": 0
            }
        },
        "required": ["key", "value"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshConfigSetHandler {
    fn name(&self) -> &'static str {
        "ssh_config_set"
    }

    fn description(&self) -> &'static str {
        "Bridge-local: sets a runtime configuration limit for the MCP bridge session itself \
         — not a remote host (there is no host param). Currently supports 'max_output_chars' \
         to adjust the output truncation threshold. Changes take effect immediately for \
         subsequent tool calls. Use ssh_config_get to read current values before and after."
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
        let parsed: ConfigSetArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        match parsed.key.as_str() {
            "max_output_chars" => {
                let Some(ref handle) = ctx.runtime_max_output_chars else {
                    return Ok(ToolCallResult::error(
                        "Runtime config modification not available in this context",
                    ));
                };

                #[allow(clippy::cast_possible_truncation)]
                let new_value = parsed.value as usize;

                let started = Instant::now();
                *handle.write().await = Some(new_value);

                info!(
                    max_output_chars = new_value,
                    "Runtime max_output_chars updated"
                );

                // The ONE tool in the seven with no host of any kind: it
                // changes a limit of the bridge process, as its own
                // description says ("not a remote host (there is no host
                // param)"). `NO_HOST` is the crate's single convention for
                // that, and it is why the convention exists.
                ctx.execute_use_case.log_state_change(
                    self.name(),
                    NO_HOST,
                    &format!("{} key=max_output_chars value={new_value}", self.name()),
                    elapsed_ms(started),
                );

                Ok(ToolCallResult::text(format!(
                    "max_output_chars set to {new_value}. \
                     This will take effect on subsequent tool calls."
                )))
            }
            other => Ok(ToolCallResult::error(format!(
                "Unknown config key: '{other}'. Supported keys: max_output_chars"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;
    use crate::mcp::protocol::ToolContent;
    use crate::ports::mock::create_test_context;

    fn get_text_content(result: &ToolCallResult) -> &str {
        match &result.content[0] {
            ToolContent::Text { text } => text,
            _ => panic!("Expected Text content"),
        }
    }

    #[tokio::test]
    async fn test_config_set_max_output_chars() {
        let handler = SshConfigSetHandler;
        let mut ctx = create_test_context();
        let runtime_override = Arc::new(RwLock::new(None));
        ctx.runtime_max_output_chars = Some(Arc::clone(&runtime_override));

        let args = serde_json::json!({"key": "max_output_chars", "value": 80000});
        let result = handler.execute(Some(args), &ctx).await.unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("80000"));
        assert_eq!(*runtime_override.read().await, Some(80_000));
    }

    /// The only one of the seven state tools with no host at all: its line
    /// carries the `NO_HOST` sentinel, a real `event_type`, and no exit code.
    #[tokio::test]
    async fn setting_a_runtime_limit_writes_one_hostless_state_change() {
        let handler = SshConfigSetHandler;
        let mut ctx = create_test_context();
        ctx.runtime_max_output_chars = Some(Arc::new(RwLock::new(None)));

        let args = serde_json::json!({"key": "max_output_chars", "value": 80000});
        handler.execute(Some(args), &ctx).await.unwrap();

        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1, "the state change must leave a line");
        assert_eq!(events[0].tool_name.as_deref(), Some("ssh_config_set"));
        assert_eq!(events[0].event_type, "state_change");
        assert_eq!(events[0].host, crate::security::NO_HOST);
        assert_eq!(
            events[0].command,
            "ssh_config_set key=max_output_chars value=80000"
        );
        assert!(matches!(
            events[0].result,
            crate::security::CommandResult::StateChanged { .. }
        ));
    }

    /// An unknown key changes nothing, so it writes nothing: the audit trail
    /// records state CHANGES, not rejected requests.
    ///
    /// **Both halves are read**, and the first one was missing: this test
    /// asserted only the absence of the audit line while its name promised
    /// the state too. The handle is cloned the way
    /// `test_config_set_max_output_chars` clones it, so the runtime override
    /// is read back after the call instead of being taken on trust — a
    /// handler that wrote the limit and merely skipped the logging would have
    /// passed the old body.
    #[tokio::test]
    async fn a_rejected_key_changes_no_state_and_writes_no_line() {
        let handler = SshConfigSetHandler;
        let mut ctx = create_test_context();
        let runtime_override = Arc::new(RwLock::new(None));
        ctx.runtime_max_output_chars = Some(Arc::clone(&runtime_override));

        let args = serde_json::json!({"key": "unknown_key", "value": 100});
        handler.execute(Some(args), &ctx).await.unwrap();

        assert_eq!(
            *runtime_override.read().await,
            None,
            "a rejected key must leave the runtime limit untouched"
        );
        assert!(ctx.audit_logger.drain_for_test().is_empty());
    }

    #[tokio::test]
    async fn test_config_set_unknown_key() {
        let handler = SshConfigSetHandler;
        let mut ctx = create_test_context();
        ctx.runtime_max_output_chars = Some(Arc::new(RwLock::new(None)));

        let args = serde_json::json!({"key": "unknown_key", "value": 100});
        let result = handler.execute(Some(args), &ctx).await.unwrap();
        assert!(result.is_error.unwrap_or(false));
    }

    #[tokio::test]
    async fn test_config_set_no_runtime_handle() {
        let handler = SshConfigSetHandler;
        let ctx = create_test_context();

        let args = serde_json::json!({"key": "max_output_chars", "value": 50000});
        let result = handler.execute(Some(args), &ctx).await.unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("not available"));
    }

    #[tokio::test]
    async fn test_config_set_missing_args() {
        let handler = SshConfigSetHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshConfigSetHandler;
        assert_eq!(handler.name(), "ssh_config_set");
        assert_ne!(handler.description(), "");

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_config_set");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert_eq!(required.len(), 2);
    }
}
