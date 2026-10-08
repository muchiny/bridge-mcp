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
use crate::mcp::tool_handlers::utils::{connect_with_jump, elapsed_ms};
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::ssh::SshClient;

/// Arguments for `ssh_tunnel_create` tool
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

        // The clock for the audit event's `duration_ms` starts HERE, before
        // the first thing that can take any time, and runs to the end of the
        // registration below.
        //
        // It used to start after `connect_with_jump`, around
        // `TunnelManager::register` alone — a `Mutex` lock and a
        // `HashMap::insert`. Measured live, that reported
        // `{"StateChanged":{"duration_ms":0}}` for a tunnel creation that had
        // really opened an SSH connection: a number that looked like a
        // measurement without being one, which is the class of defect this
        // variant exists to avoid. The old comment pleaded that "the
        // connection path times itself" — true, and inoperative: that timing
        // lives in a `tracing` span field (`SshClient::connect`), so it goes
        // to stderr and never to `audit.path`.
        //
        // What it measures: the local bind, the SSH handshake (jump host
        // included), the spawn of the forwarding task, and the registration.
        // What it excludes, all of it local and before any state could
        // change: argument parsing, the host-config lookup and the
        // rate-limit check. What it is never reported for: anything but a
        // tunnel that exists. `started` is read in exactly one place,
        // `log_state_change` on the success path: a failed bind or a failed
        // connection return early and write no event at all, and a refused
        // registration writes a `CommandResult::Error` line, which has no
        // duration field to put it in. An earlier version of this comment
        // claimed the duration also appeared "beside a registration that was
        // refused" — it does not, and that sentence widened the scope of its
        // own measurement.
        let started = Instant::now();

        // Bind the local TCP listener first (fail fast if port is in use)
        let listener = TcpListener::bind(("127.0.0.1", args.local_port))
            .await
            .map_err(|e| BridgeError::Tunnel {
                reason: format!("Failed to bind local port {}: {e}", args.local_port),
            })?;

        let actual_local_port = listener.local_addr().map_or(args.local_port, |a| a.port());

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
        let handle = spawn_forwarding_task(
            listener,
            client,
            remote_host,
            args.remote_port,
            tunnel_id.clone(),
        );

        // `register` takes the handle BY VALUE and drops it when it refuses
        // (`max_tunnels` reached). Dropping a tokio `JoinHandle` detaches the
        // task, it does not cancel it — so before this, a refused
        // registration left the listener task running for the life of the
        // process, holding the bound local port and the only
        // `Arc<SshClient>`, for a tunnel that does not exist and that
        // `ssh_tunnel_close` cannot reach because it was never registered.
        // `abort_handle` survives the move into `register`, so the refusal
        // can cancel what it declined to own.
        let aborter = handle.abort_handle();

        // Register in the tunnel manager, then audit as a state change and
        // not as a command: a forwarded port is opened here and no process
        // runs on the host, so the event carries a duration and no exit code.
        let operation = format!("{} tunnel_id={tunnel_id}", self.name());
        ctx.tunnel_manager
            .register(tunnel_info.clone(), handle)
            .await
            .inspect_err(|e| {
                aborter.abort();
                ctx.execute_use_case.log_failure(
                    self.name(),
                    &args.host,
                    &operation,
                    &e.to_string(),
                );
            })?;

        ctx.execute_use_case.log_state_change(
            self.name(),
            &args.host,
            &operation,
            elapsed_ms(started),
        );

        let json = serde_json::to_string(&tunnel_info)
            .unwrap_or_else(|e| format!("Error serializing tunnel info: {e}"));

        Ok(ToolCallResult::text(json))
    }
}

/// Spawn the task that accepts on `listener` and forwards each connection
/// through `client`.
///
/// Extracted from `execute` for its length alone — the loop is unchanged.
///
/// The task **owns** the listener and the `Arc<SshClient>`, so the tunnel's
/// lifetime is the task's: cancelling it drops the future, which closes the
/// bound local port and releases that `Arc`. Two callers cancel it —
/// `TunnelManager::close`, through the handle it stored, and `execute`'s own
/// error path, through an `AbortHandle` taken before the move.
///
/// Dropping the handle *without* cancelling does **not** stop the task, which
/// is why that error path exists at all. And cancellation is not a close
/// receipt: the port is released when the runtime drops the future, not when
/// `abort` returns, and any per-connection subtask already spawned holds its
/// own `Arc` clone and is not cancelled with its parent.
fn spawn_forwarding_task(
    listener: TcpListener,
    client: Arc<SshClient>,
    remote_host: String,
    remote_port: u16,
    tunnel_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (tcp_stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(tunnel_id = %tunnel_id, error = %e, "Tunnel accept error");
                    break;
                }
            };

            debug!(tunnel_id = %tunnel_id, peer = %peer_addr, "Tunnel: new connection");

            let conn_client = Arc::clone(&client);
            let conn_remote_host = remote_host.clone();

            tokio::spawn(async move {
                if let Err(e) = conn_client
                    .forward_tcp_connection(tcp_stream, &conn_remote_host, remote_port)
                    .await
                {
                    debug!(error = %e, "Tunnel connection ended");
                }
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::TunnelManager;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    /// A refused registration must not leave the bound port behind.
    ///
    /// `TunnelManager::register` takes the `JoinHandle` by value and drops it
    /// when it refuses; dropping a tokio handle **detaches** the task, so the
    /// listener kept running and the local port kept being bound, for a
    /// tunnel that was never registered and that `ssh_tunnel_close` could
    /// therefore never reach. `execute` now takes an `AbortHandle` before the
    /// move and cancels on that path.
    ///
    /// This drives the mechanism rather than the handler: the handler reaches
    /// its `register` call only after a real SSH handshake, which no fixture
    /// can supply. Everything else here is real — a real `TcpListener` owned
    /// by a real spawned task, a real `TunnelManager` refusal (`max_tunnels:
    /// 0` refuses every call, since `len() >= 0`), and a real rebind on the
    /// same port as the assertion. Without the `abort()` the rebind fails,
    /// which is the whole point.
    #[tokio::test]
    async fn a_refused_registration_releases_the_bound_port() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let aborter = handle.abort_handle();

        // The port is held while the task lives: the premise, not the claim.
        assert!(
            TcpListener::bind(addr).await.is_err(),
            "the spawned task must hold {addr} for this test to mean anything"
        );

        let info = TunnelInfo {
            id: "tunnel-test-0-0".to_string(),
            host: "test-server".to_string(),
            local_port: addr.port(),
            remote_host: "localhost".to_string(),
            remote_port: 80,
            direction: TunnelDirection::Local,
            created_at: Instant::now(),
            age_seconds: 0,
        };
        let manager = TunnelManager::new(0);
        assert!(
            manager.register(info, handle).await.is_err(),
            "max_tunnels: 0 must refuse, and the handle is consumed by the call"
        );

        // What `execute`'s error path now does.
        aborter.abort();

        // `abort` is not a close receipt — the port is released when the
        // runtime drops the future. Wait for that, bounded, then rebind.
        for _ in 0..10_000 {
            if aborter.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            aborter.is_finished(),
            "the cancelled task never finished; the rest of this test cannot conclude"
        );
        assert!(
            TcpListener::bind(addr).await.is_ok(),
            "the refused registration must leave {addr} free"
        );
    }

    #[test]
    fn test_schema() {
        let handler = SshTunnelCreateHandler;
        assert_eq!(handler.name(), "ssh_tunnel_create");
        assert_ne!(handler.description(), "");

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

    #[test]
    fn test_args_deserialization() {
        let args: SshTunnelCreateArgs = serde_json::from_value(json!({
            "host": "prod",
            "local_port": 15432,
            "remote_host": "db.internal",
            "remote_port": 5432
        }))
        .unwrap();
        assert_eq!(args.host, "prod");
        assert_eq!(args.local_port, 15432);
        assert_eq!(args.remote_host.as_deref(), Some("db.internal"));
        assert_eq!(args.remote_port, 5432);
    }

    #[test]
    fn test_args_minimal_deserialization() {
        // remote_host omitted → None (execute() defaults it to "localhost")
        let args: SshTunnelCreateArgs = serde_json::from_value(json!({
            "host": "prod",
            "local_port": 16379,
            "remote_port": 6379
        }))
        .unwrap();
        assert_eq!(args.host, "prod");
        assert_eq!(args.local_port, 16379);
        assert!(args.remote_host.is_none());
        assert_eq!(args.remote_port, 6379);
    }

    #[test]
    fn test_args_debug() {
        let args: SshTunnelCreateArgs = serde_json::from_value(json!({
            "host": "prod",
            "local_port": 8080,
            "remote_port": 80
        }))
        .unwrap();
        let dbg = format!("{args:?}");
        assert!(dbg.contains("SshTunnelCreateArgs"));
        assert!(dbg.contains("prod"));
    }

    #[test]
    fn test_invalid_json_type() {
        // local_port as a string is not a valid u16
        let result: std::result::Result<SshTunnelCreateArgs, _> = serde_json::from_value(json!({
            "host": "prod",
            "local_port": "not-a-port",
            "remote_port": 80
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_args_port_overflow_rejected() {
        // 70000 exceeds u16::MAX, so deserialization into `remote_port: u16` fails
        let result: std::result::Result<SshTunnelCreateArgs, _> = serde_json::from_value(json!({
            "host": "prod",
            "local_port": 8080,
            "remote_port": 70000
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTunnelCreateHandler;
        let schema_json: serde_json::Value =
            serde_json::from_str(handler.schema().input_schema).unwrap();

        // remote_host is optional (absent from `required`) and documents a localhost default
        let required = schema_json["required"].as_array().unwrap();
        assert!(!required.contains(&json!("remote_host")));
        assert_eq!(
            schema_json["properties"]["remote_host"]["default"],
            json!("localhost")
        );
    }

    #[tokio::test]
    async fn test_execute_invalid_port_type() {
        // Through the execute() path, a bad port type surfaces as McpInvalidRequest
        let handler = SshTunnelCreateHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "prod",
                    "local_port": "bad",
                    "remote_port": 80
                })),
                &ctx,
            )
            .await;
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
