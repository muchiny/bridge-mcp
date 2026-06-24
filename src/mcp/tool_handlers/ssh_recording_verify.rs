//! SSH Recording Verify Tool Handler
//!
//! Verifies the hash chain integrity of a recorded session.

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
    hash_key: Option<String>,
}

#[mcp_tool(
    name = "ssh_recording_verify",
    group = "recording",
    annotation = "read_only"
)]
#[derive(Default)]
pub struct SshRecordingVerifyHandler;

impl SshRecordingVerifyHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the .cast recording file to verify (obtain via ssh_recording_list)"
            },
            "hash_key": {
                "type": "string",
                "description": "HMAC-SHA256 key used when the recording was started. If omitted, falls back to the MCP_RECORDING_KEY environment variable on the bridge host. Must match the key configured at recording time."
            }
        },
        "required": ["file_path"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshRecordingVerifyHandler {
    fn name(&self) -> &'static str {
        "ssh_recording_verify"
    }

    fn description(&self) -> &'static str {
        "Verify the HMAC-SHA256 hash chain integrity of a .cast recording file. Detects if any \
         events have been tampered with, deleted, or reordered since the session was recorded. \
         Returns PASS/FAIL with the index of the first invalid event on failure. Only recordings \
         captured with hash_chain enabled can be fully verified; those without a chain report \
         PASS with 0 verified events. Use ssh_recording_list to discover file paths; use \
         ssh_recording_replay to review the actual event content."
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

        let key = args
            .hash_key
            .or_else(|| std::env::var("MCP_RECORDING_KEY").ok())
            .unwrap_or_default();

        let path = PathBuf::from(&args.file_path);
        let result = SessionRecorder::verify_recording(&path, key.as_bytes())
            .map_err(BridgeError::McpInvalidRequest)?;

        let output = if result.valid {
            if result.verified_events == 0 {
                format!(
                    "PASS - Recording has {} events (no hash chain present, cannot verify integrity).",
                    result.total_events
                )
            } else {
                format!(
                    "PASS - All {} events verified. Hash chain integrity confirmed.\n\
                     No tampering detected.",
                    result.verified_events
                )
            }
        } else {
            format!(
                "FAIL - Hash chain verification failed!\n\n\
                 Total events: {}\n\
                 Verified events: {}\n\
                 First invalid event: #{}\n\n\
                 WARNING: This recording may have been tampered with. \
                 Events at or after index {} cannot be trusted.",
                result.total_events,
                result.verified_events,
                result.first_invalid_index.unwrap_or(0),
                result.first_invalid_index.unwrap_or(0),
            )
        };

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
        let handler = SshRecordingVerifyHandler;
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
        let handler = SshRecordingVerifyHandler;
        assert_eq!(handler.name(), "ssh_recording_verify");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("file_path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"file_path": "/tmp/rec.cast", "hash_key": "secret"});
        let args: Args = serde_json::from_value(json).unwrap();
        assert_eq!(args.file_path, "/tmp/rec.cast");
        assert_eq!(args.hash_key, Some("secret".to_string()));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"file_path": "/tmp/rec.cast"});
        let args: Args = serde_json::from_value(json).unwrap();
        assert!(args.hash_key.is_none());
    }

    #[tokio::test]
    async fn test_nonexistent_file() {
        let handler = SshRecordingVerifyHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"file_path": "/nonexistent/file.cast"})), &ctx)
            .await;
        assert!(result.is_err());
    }
}
