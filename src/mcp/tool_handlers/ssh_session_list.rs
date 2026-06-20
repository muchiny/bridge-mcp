//! SSH Session List Tool Handler
//!
//! Lists all active persistent shell sessions.

use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// SSH Session List tool handler
#[mcp_tool(
    name = "ssh_session_list",
    group = "sessions",
    annotation = "read_only"
)]
pub struct SshSessionListHandler;

impl SshSessionListHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {},
        "required": []
    }"#;
}

#[async_trait]
impl ToolHandler for SshSessionListHandler {
    fn name(&self) -> &'static str {
        "ssh_session_list"
    }

    fn description(&self) -> &'static str {
        "List all active persistent shell sessions. Returns a JSON array of session objects, \
         each with fields: id (session_id), host, cwd, created_at_secs_ago, \
         last_used_secs_ago. Use this to retrieve session_id values for ssh_session_exec or \
         ssh_session_close. Takes no parameters."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, _args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let sessions = ctx.session_manager.list().await;

        if sessions.is_empty() {
            return Ok(ToolCallResult::text("No active sessions."));
        }

        let json = serde_json::to_string(&sessions)
            .unwrap_or_else(|e| format!("Error serializing sessions: {e}"));

        Ok(ToolCallResult::text(json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::protocol::ToolContent;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[test]
    fn test_schema() {
        let handler = SshSessionListHandler;
        assert_eq!(handler.name(), "ssh_session_list");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_session_list");
    }

    #[test]
    fn test_schema_json_valid() {
        let handler = SshSessionListHandler;
        let schema = handler.schema();

        // Verify schema is valid JSON
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        assert!(schema_json["required"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_empty() {
        let handler = SshSessionListHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await.unwrap();
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("No active sessions"));
            }
            _ => panic!("Expected Text content"),
        }
    }

    #[tokio::test]
    async fn test_list_with_args_ignored() {
        // Handler should work even if unexpected args are provided
        let handler = SshSessionListHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"unexpected": "arg"})), &ctx)
            .await
            .unwrap();
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("No active sessions"));
            }
            _ => panic!("Expected Text content"),
        }
    }

    #[test]
    fn test_handler_description_content() {
        let handler = SshSessionListHandler;
        assert!(handler.description().contains("session"));
        assert!(handler.description().contains("List"));
    }
}
