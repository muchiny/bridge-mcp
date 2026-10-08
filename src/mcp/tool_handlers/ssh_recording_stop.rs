//! SSH Recording Stop Tool Handler
//!
//! Stops an active session recording.

use std::time::Instant;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp::tool_handlers::utils::elapsed_ms;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::security::NO_HOST;

#[derive(Debug, Deserialize)]
struct Args {
    session_id: String,
}

#[mcp_tool(
    name = "ssh_recording_stop",
    group = "recording",
    annotation = "mutating"
)]
#[derive(Default)]
pub struct SshRecordingStopHandler;

impl SshRecordingStopHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "session_id": {
                "type": "string",
                "description": "Session ID returned by ssh_recording_start"
            }
        },
        "required": ["session_id"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshRecordingStopHandler {
    fn name(&self) -> &'static str {
        "ssh_recording_stop"
    }

    fn description(&self) -> &'static str {
        "Stop an active recording session started with ssh_recording_start. Requires the \
         session_id returned by ssh_recording_start; use ssh_recording_list to rediscover IDs \
         for in-flight sessions. Returns a summary with event count, host, file path, and \
         whether the HMAC-SHA256 hash chain is enabled. The .cast file path can then be passed \
         to ssh_recording_replay (to review events) or ssh_recording_verify (to check integrity)."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let args: Args =
            serde_json::from_value(args.ok_or_else(|| BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            })?)
            .map_err(|e| BridgeError::McpInvalidRequest(format!("Invalid arguments: {e}")))?;

        let recorder = ctx.session_recorder.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest("Session recording is not enabled".to_string())
        })?;

        // The host comes back on the `RecordingInfo` the recorder returns.
        // On the failure path the id matched no active recording, so there is
        // no host to name: `NO_HOST`.
        let operation = format!("ssh_recording_stop session_id={}", args.session_id);
        let started = Instant::now();
        let info = match recorder.stop_session(&args.session_id) {
            Ok(info) => info,
            Err(e) => {
                ctx.execute_use_case
                    .log_failure(self.name(), NO_HOST, &operation, &e);
                return Err(BridgeError::McpInvalidRequest(e));
            }
        };

        ctx.execute_use_case.log_state_change(
            self.name(),
            &info.host,
            &operation,
            elapsed_ms(started),
        );

        Ok(ToolCallResult::text(format!(
            "Recording stopped.\n\n\
             Session: {}\n\
             Host: {}\n\
             Events: {}\n\
             File: {}\n\
             Hash chain: {}",
            info.id,
            info.host,
            info.event_count,
            info.file_path,
            if info.hash_chain_enabled {
                "enabled"
            } else {
                "disabled"
            }
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::ports::mock::create_test_context;
    use crate::security::SessionRecorder;
    use serde_json::json;

    /// The other half of the compliance control plane: the recorded host
    /// comes back on the `RecordingInfo`, so the line names a real host and
    /// carries no exit code.
    #[tokio::test]
    async fn stopping_a_recording_is_audited_as_a_state_change() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = Arc::new(SessionRecorder::new(
            dir.path().to_path_buf(),
            false,
            Vec::new(),
            false,
        ));
        let session_id = recorder.start_session("raspberry", None).unwrap();

        let mut ctx = create_test_context();
        ctx.session_recorder = Some(Arc::clone(&recorder));

        let handler = SshRecordingStopHandler;
        handler
            .execute(Some(json!({"session_id": session_id.clone()})), &ctx)
            .await
            .unwrap();

        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tool_name.as_deref(), Some("ssh_recording_stop"));
        assert_eq!(events[0].event_type, "state_change");
        assert_eq!(events[0].host, "raspberry");
        assert_eq!(
            events[0].command,
            format!("ssh_recording_stop session_id={session_id}")
        );
        assert!(matches!(
            events[0].result,
            crate::security::CommandResult::StateChanged { .. }
        ));
    }

    /// An id that matches no active recording: still a line, with `NO_HOST`.
    #[tokio::test]
    async fn stopping_an_unknown_recording_is_audited_without_a_host() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = create_test_context();
        ctx.session_recorder = Some(Arc::new(SessionRecorder::new(
            dir.path().to_path_buf(),
            false,
            Vec::new(),
            false,
        )));

        let handler = SshRecordingStopHandler;
        let result = handler
            .execute(Some(json!({"session_id": "rec_nope_1"})), &ctx)
            .await;
        assert!(result.is_err());

        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host, NO_HOST);
        assert!(matches!(
            events[0].result,
            crate::security::CommandResult::Error { .. }
        ));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRecordingStopHandler;
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
        let handler = SshRecordingStopHandler;
        assert_eq!(handler.name(), "ssh_recording_stop");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("session_id")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"session_id": "rec_host1_20260321_120000"});
        let args: Args = serde_json::from_value(json).unwrap();
        assert_eq!(args.session_id, "rec_host1_20260321_120000");
    }

    #[tokio::test]
    async fn test_recording_not_enabled() {
        let handler = SshRecordingStopHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"session_id": "test"})), &ctx)
            .await;
        assert!(result.is_err());
    }
}
