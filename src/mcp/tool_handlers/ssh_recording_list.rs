//! SSH Recording List Tool Handler
//!
//! Lists all recording sessions (active and completed).

use std::fmt::Write;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

#[mcp_tool(
    name = "ssh_recording_list",
    group = "recording",
    annotation = "read_only"
)]
#[derive(Default)]
pub struct SshRecordingListHandler;

impl SshRecordingListHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {},
        "required": []
    }"#;
}

#[async_trait]
impl ToolHandler for SshRecordingListHandler {
    fn name(&self) -> &'static str {
        "ssh_recording_list"
    }

    fn description(&self) -> &'static str {
        "List all session recordings — both active (in-memory, started with ssh_recording_start \
         and not yet stopped) and completed (.cast files on disk). Returns session IDs, hosts, \
         start timestamps, event counts, and file paths. Use the returned file_path with \
         ssh_recording_replay to review events or ssh_recording_verify to check hash-chain \
         integrity. Takes no parameters."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, _args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let recorder = ctx.session_recorder.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest("Session recording is not enabled".to_string())
        })?;

        let recordings = recorder
            .list_recordings()
            .map_err(BridgeError::McpInvalidRequest)?;

        if recordings.is_empty() {
            return Ok(ToolCallResult::text("No recordings found."));
        }

        let mut output = format!("Found {} recording(s):\n\n", recordings.len());

        for rec in &recordings {
            let status = if rec.ended_at.is_none() {
                "ACTIVE"
            } else {
                "completed"
            };
            let _ = write!(
                output,
                "  {} [{}]\n    Host: {} | Events: {} | Started: {}\n    File: {}\n\n",
                rec.id,
                status,
                rec.host,
                rec.event_count,
                rec.started_at.format("%Y-%m-%d %H:%M:%S UTC"),
                rec.file_path,
            );
        }

        Ok(ToolCallResult::text(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_schema() {
        let handler = SshRecordingListHandler;
        assert_eq!(handler.name(), "ssh_recording_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_recording_list");
    }

    #[tokio::test]
    async fn test_recording_not_enabled() {
        let handler = SshRecordingListHandler;
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }
}
