//! SSH Recording Replay Tool Handler
//!
//! Replays a recorded session, returning its events.

use std::fmt::Write;
use std::path::PathBuf;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::security::recording::SessionRecorder;

#[derive(Debug, Deserialize)]
struct Args {
    file_path: String,
    #[serde(default)]
    max_events: Option<usize>,
}

#[mcp_tool(
    name = "ssh_recording_replay",
    group = "recording",
    annotation = "read_only"
)]
#[derive(Default)]
pub struct SshRecordingReplayHandler;

impl SshRecordingReplayHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the .cast recording file (obtain via ssh_recording_list)"
            },
            "max_events": {
                "type": "integer",
                "description": "Maximum number of events to return (default: all)",
                "minimum": 1
            }
        },
        "required": ["file_path"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshRecordingReplayHandler {
    fn name(&self) -> &'static str {
        "ssh_recording_replay"
    }

    fn description(&self) -> &'static str {
        "Read and display events from a .cast recording file (asciinema v2 format). Returns the \
         session header (title, terminal size, timestamp) followed by all events with relative \
         timestamps; event types are 'i' (stdin input), 'o' (stdout/stderr output), and 'm' \
         (marker). Use ssh_recording_list to discover file paths. Use max_events to cap output \
         for large sessions. To verify integrity instead of replaying, use ssh_recording_verify."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, args: Option<Value>, _ctx: &ToolContext) -> Result<ToolCallResult> {
        let args: Args =
            serde_json::from_value(args.ok_or_else(|| BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            })?)
            .map_err(|e| BridgeError::McpInvalidRequest(format!("Invalid arguments: {e}")))?;

        let path = PathBuf::from(&args.file_path);
        let (header, events) =
            SessionRecorder::replay_recording(&path).map_err(BridgeError::McpInvalidRequest)?;

        let max = args.max_events.unwrap_or(events.len());
        let events_to_show = &events[..max.min(events.len())];

        let mut output = format!(
            "=== Recording: {} ===\n\
             Title: {}\n\
             Timestamp: {}\n\
             Terminal: {}x{}\n\
             Total events: {}\n\n",
            args.file_path,
            header.title.as_deref().unwrap_or("(none)"),
            header.timestamp,
            header.width,
            header.height,
            events.len(),
        );

        for event in events_to_show {
            let type_label = match event.event_type.as_str() {
                "i" => "INPUT ",
                "o" => "OUTPUT",
                "m" => "MARKER",
                _ => "OTHER ",
            };
            let _ = writeln!(
                output,
                "[{:>10.3}s] {} | {}",
                event.time,
                type_label,
                event.data.replace('\r', "").replace('\n', "\\n")
            );
        }

        if events_to_show.len() < events.len() {
            let _ = write!(
                output,
                "\n... ({} more events not shown)\n",
                events.len() - events_to_show.len()
            );
        }

        Ok(ToolCallResult::text(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRecordingReplayHandler;
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshRecordingReplayHandler;
        assert_eq!(handler.name(), "ssh_recording_replay");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("file_path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"file_path": "/tmp/rec.cast", "max_events": 10});
        let args: Args = serde_json::from_value(json).unwrap();
        assert_eq!(args.file_path, "/tmp/rec.cast");
        assert_eq!(args.max_events, Some(10));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"file_path": "/tmp/rec.cast"});
        let args: Args = serde_json::from_value(json).unwrap();
        assert!(args.max_events.is_none());
    }

    #[tokio::test]
    async fn test_nonexistent_file() {
        let handler = SshRecordingReplayHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"file_path": "/nonexistent/file.cast"})), &ctx)
            .await;
        assert!(result.is_err());
    }
}
