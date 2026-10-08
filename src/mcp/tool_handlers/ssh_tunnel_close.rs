//! SSH Tunnel Close Tool Handler
//!
//! Closes an active SSH port forwarding tunnel.

use std::time::Instant;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp::tool_handlers::utils::elapsed_ms;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::security::NO_HOST;

/// Arguments for `ssh_tunnel_close` tool
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshTunnelCloseArgs {
    tunnel_id: String,
}

/// SSH Tunnel Close tool handler
// Closing a tunnel tears down a forwarded port — a non-idempotent
// cleanup, not a destructive host mutation. `destructive` wrongly
// triggered the elicitation guard on routine teardown (and disagreed
// with tests/annotation_audit.rs, which lists it as Mutating).
#[mcp_tool(name = "ssh_tunnel_close", group = "tunnels", annotation = "mutating")]
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

        // The host comes back with the closed tunnel — `TunnelManager::close`
        // returns the `TunnelInfo` it removed — so no prior lookup is needed.
        // On the failure path the id matched no tunnel, so no host was ever
        // resolved: `NO_HOST`.
        let operation = format!("ssh_tunnel_close tunnel_id={}", args.tunnel_id);
        let started = Instant::now();
        let closed = match ctx.tunnel_manager.close(&args.tunnel_id).await {
            Ok(closed) => closed,
            Err(e) => {
                ctx.execute_use_case
                    .log_failure(self.name(), NO_HOST, &operation, &e.to_string());
                return Err(e);
            }
        };

        ctx.execute_use_case.log_state_change(
            self.name(),
            &closed.host,
            &operation,
            elapsed_ms(started),
        );

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
        assert_ne!(handler.description(), "");

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
            tokio::time::sleep(std::time::Duration::from_mins(1)).await;
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

    /// The real host reaches the line, and no exit code does — nothing ran.
    /// The host comes back on the `TunnelInfo` the manager removed, which is
    /// why this tool needs no prior lookup and no synthetic host.
    #[tokio::test]
    async fn closing_a_tunnel_is_audited_as_a_state_change_on_its_real_host() {
        let handler = SshTunnelCloseHandler;
        let ctx = create_test_context();

        let info = TunnelInfo {
            id: "test-audit-1".to_string(),
            host: "test-server".to_string(),
            local_port: 9091,
            remote_host: "localhost".to_string(),
            remote_port: 3306,
            direction: TunnelDirection::Local,
            created_at: Instant::now(),
            age_seconds: 0,
        };
        let handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_mins(1)).await;
        });
        ctx.tunnel_manager.register(info, handle).await.unwrap();

        handler
            .execute(Some(json!({"tunnel_id": "test-audit-1"})), &ctx)
            .await
            .unwrap();

        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tool_name.as_deref(), Some("ssh_tunnel_close"));
        assert_eq!(events[0].event_type, "state_change");
        assert_eq!(
            events[0].host, "test-server",
            "a real alias, not the sentinel"
        );
        assert_eq!(events[0].command, "ssh_tunnel_close tunnel_id=test-audit-1");
        assert!(
            matches!(
                events[0].result,
                crate::security::CommandResult::StateChanged { .. }
            ),
            "got {:?}",
            events[0].result
        );
        // The history is a history of commands, and no command ran.
        assert_eq!(ctx.history.len(), 0);
    }

    /// An id that matches nothing: the line is still written, with `NO_HOST`,
    /// because no tunnel ever existed to read a host from.
    #[tokio::test]
    async fn closing_an_unknown_tunnel_is_audited_without_a_host() {
        let handler = SshTunnelCloseHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"tunnel_id": "nonexistent"})), &ctx)
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
