//! SSH Tunnel Create Tool Handler
//!
//! Creates a local port forwarding tunnel through an SSH connection.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::domain::{TunnelDirection, TunnelInfo};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp::tool_handlers::utils::connect_with_jump;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_tunnel_create` tool
#[derive(Debug, Deserialize)]
struct SshTunnelCreateArgs {
    host: String,
    local_port: u16,
    remote_host: Option<String>,
    remote_port: u16,
}

/// SSH Tunnel Create tool handler
#[mcp_tool(name = "ssh_tunnel_create", group = "tunnels", annotation = "mutating")]
pub struct SshTunnelCreateHandler;

impl SshTunnelCreateHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml — the SSH host to tunnel through (use ssh_status to list available hosts)"
            },
            "local_port": {
                "type": "integer",
                "description": "Local port to listen on (bound to 127.0.0.1 on the bridge host); fails immediately if already in use",
                "minimum": 1,
                "maximum": 65535
            },
            "remote_host": {
                "type": "string",
                "description": "Remote hostname or IP to forward to, resolved on the remote SSH host (default: localhost, i.e. the remote machine itself)",
                "default": "localhost"
            },
            "remote_port": {
                "type": "integer",
                "description": "Port number on remote_host to forward to (e.g. 3306 for MySQL, 5432 for PostgreSQL, 6379 for Redis)",
                "minimum": 1,
                "maximum": 65535
            }
        },
        "required": ["host", "local_port", "remote_port"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshTunnelCreateHandler {
    fn name(&self) -> &'static str {
        "ssh_tunnel_create"
    }

    fn description(&self) -> &'static str {
        "Create a LOCAL port forwarding tunnel through SSH (traffic sent to 127.0.0.1:local_port \
         on the bridge host is forwarded to remote_host:remote_port on the remote side). Binds \
         the local port to 127.0.0.1 only. Returns a TunnelInfo JSON object including a tunnel_id \
         (format: tunnel-{host}-{local_port}-{remote_port}) required by ssh_tunnel_close. Only \
         local-direction forwarding is supported — there is no remote forwarding option. Use \
         ssh_tunnel_list to inspect active tunnels before creating a duplicate."
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
        let args: SshTunnelCreateArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        let remote_host = args.remote_host.unwrap_or_else(|| "localhost".to_string());

        // Get host config
        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        // Check rate limit
        if ctx.rate_limiter.check(&args.host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{}'. Please wait before sending more requests.",
                args.host
            )));
        }

        // Bind the local TCP listener first (fail fast if port is in use)
        let listener = TcpListener::bind(("127.0.0.1", args.local_port))
            .await
            .map_err(|e| BridgeError::Tunnel {
                reason: format!("Failed to bind local port {}: {e}", args.local_port),
            })?;

        let actual_local_port = listener
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(args.local_port);

        info!(
            host = %args.host,
            local_port = actual_local_port,
            remote = %format!("{remote_host}:{}", args.remote_port),
            "Creating SSH tunnel"
        );

        // Create a dedicated SSH connection (not from pool, tunnels need persistent connections)
        let client =
            connect_with_jump(&args.host, host_config, &ctx.config.limits, &ctx.config).await?;

        let client = Arc::new(client);

        // Generate tunnel ID
        let tunnel_id = format!(
            "tunnel-{}-{}-{}",
            args.host, actual_local_port, args.remote_port
        );

        let tunnel_info = TunnelInfo {
            id: tunnel_id.clone(),
            host: args.host.clone(),
            local_port: actual_local_port,
            remote_host: remote_host.clone(),
            remote_port: args.remote_port,
            direction: TunnelDirection::Local,
            created_at: Instant::now(),
            age_seconds: 0,
        };

        // Spawn the forwarding task
        let fwd_client = Arc::clone(&client);
        let fwd_remote_host = remote_host.clone();
        let fwd_remote_port = args.remote_port;
        let fwd_tunnel_id = tunnel_id.clone();

        let handle = tokio::spawn(async move {
            loop {
                let (tcp_stream, peer_addr) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!(tunnel_id = %fwd_tunnel_id, error = %e, "Tunnel accept error");
                        break;
                    }
                };

                debug!(
                    tunnel_id = %fwd_tunnel_id,
                    peer = %peer_addr,
                    "Tunnel: new connection"
                );

                let conn_client = Arc::clone(&fwd_client);
                let conn_remote_host = fwd_remote_host.clone();

                tokio::spawn(async move {
                    if let Err(e) = conn_client
                        .forward_tcp_connection(tcp_stream, &conn_remote_host, fwd_remote_port)
                        .await
                    {
                        debug!(error = %e, "Tunnel connection ended");
                    }
                });
            }
        });

        // Register in the tunnel manager
        ctx.tunnel_manager
            .register(tunnel_info.clone(), handle)
            .await?;

        let json = serde_json::to_string(&tunnel_info)
            .unwrap_or_else(|e| format!("Error serializing tunnel info: {e}"));

        Ok(ToolCallResult::text(json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[test]
    fn test_schema() {
        let handler = SshTunnelCreateHandler;
        assert_eq!(handler.name(), "ssh_tunnel_create");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_tunnel_create");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("local_port")));
        assert!(required.contains(&json!("remote_port")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTunnelCreateHandler;
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
        let handler = SshTunnelCreateHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "local_port": 8080,
                    "remote_port": 80
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_arguments() {
        let handler = SshTunnelCreateHandler;
        let ctx = create_test_context();

        let result = handler.execute(Some(json!({"wrong": "field"})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_port_bounds() {
        let handler = SshTunnelCreateHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let local_port = &schema_json["properties"]["local_port"];
        assert_eq!(local_port["minimum"], 1);
        assert_eq!(local_port["maximum"], 65535);

        let remote_port = &schema_json["properties"]["remote_port"];
        assert_eq!(remote_port["minimum"], 1);
        assert_eq!(remote_port["maximum"], 65535);
    }

    #[test]
    fn test_handler_description_content() {
        let handler = SshTunnelCreateHandler;
        assert!(handler.description().contains("tunnel"));
        assert!(handler.description().contains("forwarding"));
    }
}
