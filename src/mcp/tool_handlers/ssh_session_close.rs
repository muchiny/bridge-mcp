//! SSH Session Close Tool Handler
//!
//! Closes a persistent shell session.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_session_close` tool
#[derive(Debug, Deserialize)]
struct SshSessionCloseArgs {
    session_id: String,
}

/// SSH Session Close tool handler
#[mcp_tool(
    name = "ssh_session_close",
    group = "sessions",
    annotation = "destructive"
)]
pub struct SshSessionCloseHandler;

impl SshSessionCloseHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "session_id": {
                "type": "string",
                "description": "The session ID to close (returned by ssh_session_create)"
            }
        },
        "required": ["session_id"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshSessionCloseHandler {
    fn name(&self) -> &'static str {
        "ssh_session_close"
    }

    fn description(&self) -> &'static str {
        "Close a persistent shell session and release its resources (SSH connection, server-side \
         shell process). Always call this after a multi-step workflow created with \
         ssh_session_create is finished to avoid resource leaks. Returns JSON: \
         {status: \"closed\", session_id}. Use ssh_session_list to look up the session_id if \
         you did not save it from ssh_session_create."
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
        let args: SshSessionCloseArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        info!(session_id = %args.session_id, "Closing session");

        ctx.session_manager.close(&args.session_id).await?;

        Ok(ToolCallResult::text(
            serde_json::json!({"status": "closed", "session_id": args.session_id}).to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[test]
    fn test_schema() {
        let handler = SshSessionCloseHandler;
        assert_eq!(handler.name(), "ssh_session_close");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_session_close");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("session_id")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshSessionCloseHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_session_not_found() {
        let handler = SshSessionCloseHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"session_id": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::SessionNotFound { session_id } => {
                assert_eq!(session_id, "nonexistent");
            }
            e => panic!("Expected SessionNotFound, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_arguments() {
        let handler = SshSessionCloseHandler;
        let ctx = create_test_context();

        let result = handler.execute(Some(json!({"wrong": "field"})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_json_valid() {
        let handler = SshSessionCloseHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("session_id"));
    }

    #[test]
    fn test_handler_description_content() {
        let handler = SshSessionCloseHandler;
        assert!(handler.description().contains("Close"));
        assert!(handler.description().contains("session"));
    }

    #[tokio::test]
    async fn test_empty_session_id() {
        let handler = SshSessionCloseHandler;
        let ctx = create_test_context();

        let result = handler.execute(Some(json!({"session_id": ""})), &ctx).await;
        assert!(result.is_err());
        // Empty session IDs should not be found
        match result.unwrap_err() {
            BridgeError::SessionNotFound { session_id } => {
                assert_eq!(session_id, "");
            }
            e => panic!("Expected SessionNotFound, got: {e:?}"),
        }
    }
}
