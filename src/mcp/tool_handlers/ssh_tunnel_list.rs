//! SSH Tunnel List Tool Handler
//!
//! Lists all active SSH port forwarding tunnels.

use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// SSH Tunnel List tool handler
#[mcp_tool(name = "ssh_tunnel_list", group = "tunnels", annotation = "read_only")]
pub struct SshTunnelListHandler;

impl SshTunnelListHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {},
        "required": []
    }"#;
}

#[async_trait]
impl ToolHandler for SshTunnelListHandler {
    fn name(&self) -> &'static str {
        "ssh_tunnel_list"
    }

    fn description(&self) -> &'static str {
        "List all active SSH port forwarding tunnels managed by this bridge process. Returns a \
         JSON array of TunnelInfo objects with fields: id (tunnel_id for ssh_tunnel_close), host, \
         local_port, remote_host, remote_port, direction, age_seconds. Returns 'No active \
         tunnels.' when none exist. Call this before ssh_tunnel_create to avoid binding a port \
         that is already in use, and before ssh_tunnel_close to find the exact tunnel_id."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, _args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let tunnels = ctx.tunnel_manager.list().await;

        if tunnels.is_empty() {
            return Ok(ToolCallResult::text("No active tunnels."));
        }

        let json = serde_json::to_string(&tunnels)
            .unwrap_or_else(|e| format!("Error serializing tunnels: {e}"));

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
        let handler = SshTunnelListHandler;
        assert_eq!(handler.name(), "ssh_tunnel_list");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_tunnel_list");
    }

    #[test]
    fn test_schema_json_valid() {
        let handler = SshTunnelListHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        assert!(schema_json["required"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_empty() {
        let handler = SshTunnelListHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await.unwrap();
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("No active tunnels"));
            }
            _ => panic!("Expected Text content"),
        }
    }

    #[tokio::test]
    async fn test_list_with_args_ignored() {
        let handler = SshTunnelListHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"unexpected": "arg"})), &ctx)
            .await
            .unwrap();
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("No active tunnels"));
            }
            _ => panic!("Expected Text content"),
        }
    }

    #[tokio::test]
    async fn test_list_with_active_tunnel() {
        use crate::domain::{TunnelDirection, TunnelInfo};
        use std::time::Instant;

        let handler = SshTunnelListHandler;
        let ctx = create_test_context();

        // Register a tunnel
        let info = TunnelInfo {
            id: "test-tunnel-1".to_string(),
            host: "test-server".to_string(),
            local_port: 8080,
            remote_host: "localhost".to_string(),
            remote_port: 80,
            direction: TunnelDirection::Local,
            created_at: Instant::now(),
            age_seconds: 0,
        };
        let handle = tokio::spawn(async {});
        ctx.tunnel_manager.register(info, handle).await.unwrap();

        let result = handler.execute(None, &ctx).await.unwrap();
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("test-tunnel-1"));
                assert!(text.contains("test-server"));
                assert!(text.contains("8080"));
            }
            _ => panic!("Expected Text content"),
        }
    }

    #[test]
    fn test_handler_description_content() {
        let handler = SshTunnelListHandler;
        assert!(handler.description().contains("tunnel"));
        assert!(handler.description().contains("List"));
    }
}
