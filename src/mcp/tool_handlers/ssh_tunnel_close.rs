//! SSH Tunnel Close Tool Handler
//!
//! Closes an active SSH port forwarding tunnel.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_tunnel_close` tool
#[derive(Debug, Deserialize)]
struct SshTunnelCloseArgs {
    tunnel_id: String,
}

/// SSH Tunnel Close tool handler
#[mcp_tool(
    name = "ssh_tunnel_close",
    group = "tunnels",
    annotation = "destructive"
)]
pub struct SshTunnelCloseHandler;

impl SshTunnelCloseHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "tunnel_id": {
                "type": "string",
                "description": "The tunnel_id to close — format: tunnel-{host}-{local_port}-{remote_port}. Use ssh_tunnel_list to enumerate active IDs before closing."
            }
        },
        "required": ["tunnel_id"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshTunnelCloseHandler {
    fn name(&self) -> &'static str {
        "ssh_tunnel_close"
    }

    fn description(&self) -> &'static str {
        "Close an active SSH port forwarding tunnel by tunnel_id, abort its forwarding task, and \
         release the bound local port. Use ssh_tunnel_list to find the exact tunnel_id (format: \
         tunnel-{host}-{local_port}-{remote_port}). Returns the final TunnelInfo JSON on success. \
         Does NOT close the SSH connection to the host — only the port forwarding is stopped. \
         Returns an error if the tunnel_id is not found."
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
        let args: SshTunnelCloseArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        info!(tunnel_id = %args.tunnel_id, "Closing tunnel");

        let closed = ctx.tunnel_manager.close(&args.tunnel_id).await?;

        let json = serde_json::to_string(&closed)
            .unwrap_or_else(|e| format!("Error serializing tunnel info: {e}"));

        Ok(ToolCallResult::text(json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{TunnelDirection, TunnelInfo};
    use crate::ports::mock::create_test_context;
    use serde_json::json;
    use std::time::Instant;

    #[test]
    fn test_schema() {
        let handler = SshTunnelCloseHandler;
        assert_eq!(handler.name(), "ssh_tunnel_close");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_tunnel_close");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("tunnel_id")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTunnelCloseHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_tunnel_not_found() {
        let handler = SshTunnelCloseHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"tunnel_id": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::Tunnel { reason } => {
                assert!(reason.contains("not found"));
            }
            e => panic!("Expected Tunnel error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_close_existing_tunnel() {
        let handler = SshTunnelCloseHandler;
        let ctx = create_test_context();

        // Register a tunnel first
        let info = TunnelInfo {
            id: "test-close-1".to_string(),
            host: "test-server".to_string(),
            local_port: 9090,
            remote_host: "localhost".to_string(),
            remote_port: 3306,
            direction: TunnelDirection::Local,
            created_at: Instant::now(),
            age_seconds: 0,
        };
        let handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        });
        ctx.tunnel_manager.register(info, handle).await.unwrap();

        let result = handler
            .execute(Some(json!({"tunnel_id": "test-close-1"})), &ctx)
            .await
            .unwrap();

        assert!(!result.is_error.unwrap_or(false));

        // Verify tunnel is removed
        let tunnels = ctx.tunnel_manager.list().await;
        assert!(tunnels.is_empty());
    }

    #[tokio::test]
    async fn test_invalid_arguments() {
        let handler = SshTunnelCloseHandler;
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
        let handler = SshTunnelCloseHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("tunnel_id"));
    }

    #[test]
    fn test_handler_description_content() {
        let handler = SshTunnelCloseHandler;
        assert!(handler.description().contains("Close"));
        assert!(handler.description().contains("tunnel"));
    }
}
