//! SSH History Tool Handler
//!
//! Provides access to command execution history.

use std::fmt::Write;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_history` tool
#[derive(Debug, Deserialize)]
struct SshHistoryArgs {
    limit: Option<usize>,
    host: Option<String>,
}

/// SSH History tool handler
#[mcp_tool(name = "ssh_history", group = "core", annotation = "read_only")]
pub struct SshHistoryHandler;

impl SshHistoryHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of entries to return (default: 10)",
                "minimum": 1,
                "maximum": 100
            },
            "host": {
                "type": "string",
                "description": "Filter history by host (optional)"
            }
        },
        "required": []
    }"#;
}

#[async_trait]
impl ToolHandler for SshHistoryHandler {
    fn name(&self) -> &'static str {
        "ssh_history"
    }

    fn description(&self) -> &'static str {
        "Get recent command execution history. Returns metadata only (host, command text, exit \
         code, duration, timestamp) — not the full command output. Useful to review what was run, \
         verify success/failure, or find when a command last executed. Filter by host to narrow \
         results. To retrieve the full output of a past command, use ssh_output_fetch with the \
         output_id if one was captured at execution time."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let args: SshHistoryArgs = match args {
            Some(v) => serde_json::from_value(v)
                .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?,
            None => SshHistoryArgs {
                limit: None,
                host: None,
            },
        };

        let limit = args.limit.unwrap_or(10);

        let entries = args.host.as_ref().map_or_else(
            || ctx.history.recent(limit),
            |host| ctx.history.for_host(host, limit),
        );

        if entries.is_empty() {
            return Ok(ToolCallResult::text(
                "No command history available.".to_string(),
            ));
        }

        let mut result = String::new();
        let _ = writeln!(
            result,
            "Recent command history ({} entries):\n",
            entries.len()
        );

        for entry in entries {
            let timestamp = entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC");
            let status = if entry.success { "OK" } else { "FAIL" };
            let exit_code = entry.exit_code;
            let duration_ms = entry.duration_ms;

            let _ = writeln!(result, "[{timestamp}] {status}");
            let _ = writeln!(result, "  Host: {}", entry.host);
            let _ = writeln!(result, "  Command: {}", entry.command);
            let _ = writeln!(
                result,
                "  Exit code: {exit_code}, Duration: {duration_ms}ms\n"
            );
        }

        Ok(ToolCallResult::text(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::CommandHistory;
    use crate::mcp::history::HistoryConfig;
    use crate::mcp::protocol::ToolContent;
    use crate::ports::mock::create_test_context_with_history;
    use serde_json::json;
    use std::sync::Arc;

    fn get_text_content(result: &ToolCallResult) -> &str {
        match &result.content[0] {
            ToolContent::Text { text } => text,
            _ => panic!("Expected Text content"),
        }
    }

    #[tokio::test]
    async fn test_ssh_history_empty() {
        let handler = SshHistoryHandler;
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
        let ctx = create_test_context_with_history(history);

        let result = handler.execute(None, &ctx).await.unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("No command history available"));
    }

    #[tokio::test]
    async fn test_ssh_history_with_entries() {
        let handler = SshHistoryHandler;
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

        history.record_success("server1", "ls -la", 0, 100);
        history.record_success("server2", "pwd", 0, 50);
        history.record_failure("server1", "bad-cmd");

        let ctx = create_test_context_with_history(history);

        let result = handler.execute(None, &ctx).await.unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("3 entries"));
        assert!(text.contains("server1"));
        assert!(text.contains("server2"));
        assert!(text.contains("ls -la"));
        assert!(text.contains("pwd"));
        assert!(text.contains("OK"));
        assert!(text.contains("FAIL"));
    }

    #[tokio::test]
    async fn test_ssh_history_with_limit() {
        let handler = SshHistoryHandler;
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

        history.record_success("host", "cmd1", 0, 100);
        history.record_success("host", "cmd2", 0, 100);
        history.record_success("host", "cmd3", 0, 100);
        history.record_success("host", "cmd4", 0, 100);
        history.record_success("host", "cmd5", 0, 100);

        let ctx = create_test_context_with_history(history);

        let result = handler
            .execute(Some(json!({"limit": 2})), &ctx)
            .await
            .unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("2 entries"));
        // Most recent entries should be returned
        assert!(text.contains("cmd5"));
        assert!(text.contains("cmd4"));
        assert!(!text.contains("cmd1"));
    }

    #[tokio::test]
    async fn test_ssh_history_filter_by_host() {
        let handler = SshHistoryHandler;
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

        history.record_success("host1", "cmd1", 0, 100);
        history.record_success("host2", "cmd2", 0, 100);
        history.record_success("host1", "cmd3", 0, 100);
        history.record_success("host2", "cmd4", 0, 100);

        let ctx = create_test_context_with_history(history);

        let result = handler
            .execute(Some(json!({"host": "host1"})), &ctx)
            .await
            .unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("2 entries"));
        assert!(text.contains("cmd1"));
        assert!(text.contains("cmd3"));
        assert!(!text.contains("cmd2"));
        assert!(!text.contains("cmd4"));
    }

    #[tokio::test]
    async fn test_ssh_history_filter_by_nonexistent_host() {
        let handler = SshHistoryHandler;
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

        history.record_success("host1", "cmd1", 0, 100);

        let ctx = create_test_context_with_history(history);

        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await
            .unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("No command history available"));
    }

    #[test]
    fn test_schema() {
        let handler = SshHistoryHandler;
        assert_eq!(handler.name(), "ssh_history");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_history");
    }
}
