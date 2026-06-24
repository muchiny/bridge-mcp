//! SSH Recording Start Tool Handler
//!
//! Starts a new session recording for compliance auditing.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

#[derive(Debug, Deserialize)]
struct Args {
    host: String,
    #[serde(default)]
    title: Option<String>,
}

#[mcp_tool(
    name = "ssh_recording_start",
    group = "recording",
    annotation = "mutating"
)]
#[derive(Default)]
pub struct SshRecordingStartHandler;

impl SshRecordingStartHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias (as defined in bridge config) to associate with this recording session; the same alias used by all other ssh_* tools"
            },
            "title": {
                "type": "string",
                "description": "Optional title/description for the recording"
            }
        },
        "required": ["host"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshRecordingStartHandler {
    fn name(&self) -> &'static str {
        "ssh_recording_start"
    }

    fn description(&self) -> &'static str {
        "Start recording all SSH commands and outputs for this host. Records in asciinema v2 \
         format with optional HMAC-SHA256 hash chain for tamper-proof compliance auditing \
         (SOC2, HIPAA, PCI-DSS). Returns a session_id — pass it to ssh_recording_stop to end \
         the session and get the .cast file path. Use ssh_recording_list to see all active and \
         completed sessions."
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

        // Verify host exists
        ctx.config
            .hosts
            .get(&args.host)
            .ok_or_else(|| BridgeError::UnknownHost {
                host: args.host.clone(),
            })?;

        let recorder = ctx.session_recorder.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest("Session recording is not enabled".to_string())
        })?;

        let session_id = recorder
            .start_session(&args.host, args.title.as_deref())
            .map_err(BridgeError::McpInvalidRequest)?;

        Ok(ToolCallResult::text(format!(
            "Recording started.\n\nSession ID: {session_id}\nHost: {}\n\n\
             Use ssh_recording_stop with this session_id to end the recording.",
            args.host
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRecordingStartHandler;
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
        let handler = SshRecordingStartHandler;
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

    #[test]
    fn test_schema() {
        let handler = SshRecordingStartHandler;
        assert_eq!(handler.name(), "ssh_recording_start");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_recording_start");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "title": "test session"});
        let args: Args = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.title, Some("test session".to_string()));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: Args = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.title.is_none());
    }
}
