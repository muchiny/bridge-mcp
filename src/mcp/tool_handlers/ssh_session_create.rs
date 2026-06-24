//! SSH Session Create Tool Handler
//!
//! Creates a persistent interactive shell session on a remote host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for `ssh_session_create` tool
#[derive(Debug, Deserialize)]
struct SshSessionCreateArgs {
    host: String,
    timeout_seconds: Option<u64>,
}

/// SSH Session Create tool handler
#[mcp_tool(
    name = "ssh_session_create",
    group = "sessions",
    annotation = "mutating"
)]
pub struct SshSessionCreateHandler;

impl SshSessionCreateHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds for the initial connection (default: from config)",
                "minimum": 1,
                "maximum": 3600
            }
        },
        "required": ["host"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshSessionCreateHandler {
    fn name(&self) -> &'static str {
        "ssh_session_create"
    }

    fn description(&self) -> &'static str {
        "Create a persistent interactive shell session on a remote host. Returns a JSON object \
         with fields: id (session_id to pass to ssh_session_exec/ssh_session_close), host, cwd, \
         created_at_secs_ago. Unlike ssh_exec (one-shot, stateless), a session preserves working \
         directory and environment variables across all subsequent ssh_session_exec calls — use \
         this when commands depend on each other (e.g. 'cd /app' then 'make build'). Close with \
         ssh_session_close when done; list open sessions with ssh_session_list."
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
        let args: SshSessionCreateArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

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

        info!(host = %args.host, "Creating persistent session");

        // Build limits with optional timeout override
        let mut limits = ctx.config.limits.clone();
        if let Some(timeout) = args.timeout_seconds {
            limits.command_timeout_seconds = timeout;
        }

        // Resolve jump host if configured
        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jump_config| (jump_name.as_str(), jump_config))
        });

        let session_info = ctx
            .session_manager
            .create(&args.host, host_config, &limits, jump_host)
            .await?;

        let json = serde_json::to_string(&session_info)
            .unwrap_or_else(|e| format!("Error serializing session info: {e}"));

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
        let handler = SshSessionCreateHandler;
        assert_eq!(handler.name(), "ssh_session_create");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_session_create");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshSessionCreateHandler;
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
        let handler = SshSessionCreateHandler;
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

    #[tokio::test]
    async fn test_invalid_arguments() {
        let handler = SshSessionCreateHandler;
        let ctx = create_test_context();

        let result = handler.execute(Some(json!({"wrong": "field"})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_timeout_bounds() {
        let handler = SshSessionCreateHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let timeout_prop = &schema_json["properties"]["timeout_seconds"];
        assert_eq!(timeout_prop["minimum"], 1);
        assert_eq!(timeout_prop["maximum"], 3600);
    }

    #[test]
    fn test_handler_description_content() {
        let handler = SshSessionCreateHandler;
        assert!(handler.description().contains("persistent"));
        assert!(handler.description().contains("session"));
        assert!(handler.description().contains("state"));
    }
}
