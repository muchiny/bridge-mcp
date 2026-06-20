//! SSH Sync Tool Handler
//!
//! Synchronizes directories between local and remote hosts via SFTP.

use std::fmt::Write;
use std::path::Path;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::security::{AuditEvent, CommandResult as AuditCommandResult};

use super::utils::{connect_with_jump, validate_path};

/// Arguments for `ssh_sync` tool
#[derive(Debug, Deserialize)]
struct SshSyncArgs {
    host: String,
    source: String,
    destination: String,
    direction: String,
    #[serde(default)]
    exclude: Option<Vec<String>>,
}

/// SSH Sync tool handler
#[mcp_tool(name = "ssh_sync", group = "file_transfer", annotation = "mutating")]
pub struct SshSyncHandler;

impl SshSyncHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "source": {
                "type": "string",
                "description": "Source path (local path for upload, remote path for download)"
            },
            "destination": {
                "type": "string",
                "description": "Destination path (remote path for upload, local path for download)"
            },
            "direction": {
                "type": "string",
                "enum": ["upload", "download"],
                "description": "Transfer direction: 'upload' (local to remote) or 'download' (remote to local)"
            },
            "exclude": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Glob patterns to exclude from the transfer"
            }
        },
        "required": ["host", "source", "destination", "direction"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshSyncHandler {
    fn name(&self) -> &'static str {
        "ssh_sync"
    }

    fn description(&self) -> &'static str {
        "Synchronize entire directories between local and remote hosts via SFTP. Recursively \
         transfers directory trees with exclude patterns. Use direction 'upload' for local-to-remote, \
         'download' for remote-to-local. NOTE: this tool only copies — it never deletes files at \
         the destination that are absent from the source; it is an additive copy, not a true mirror. \
         For single files, prefer ssh_upload or ssh_download instead. Returns count of files transferred."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    #[expect(clippy::too_many_lines, clippy::cast_precision_loss)]
    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshSyncArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        // Validate direction
        if args.direction != "upload" && args.direction != "download" {
            return Err(BridgeError::McpInvalidRequest(format!(
                "Invalid direction: '{}'. Must be 'upload' or 'download'",
                args.direction
            )));
        }

        // Validate paths for traversal attacks
        validate_path(&args.source)?;
        validate_path(&args.destination)?;

        // Get host config
        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        // Check rate limit for this host
        if ctx.rate_limiter.check(&args.host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{}'. Please wait before sending more requests.",
                args.host
            )));
        }

        let exclude = args.exclude.unwrap_or_default();

        info!(
            host = %args.host,
            source = %args.source,
            destination = %args.destination,
            direction = %args.direction,
            exclude_count = exclude.len(),
            "Syncing directory via SFTP"
        );

        // Connect to host (via jump host if configured)
        let client =
            connect_with_jump(&args.host, host_config, &ctx.config.limits, &ctx.config).await?;

        // Create SFTP session
        let sftp = client.sftp_session().await?;

        // Perform the transfer
        let result = if args.direction == "upload" {
            sftp.upload_directory(Path::new(&args.source), &args.destination, &exclude)
                .await
        } else {
            sftp.download_directory(&args.source, Path::new(&args.destination), &exclude)
                .await
        };

        // Close SFTP session
        sftp.close().await.ok();

        // Log the result
        let direction_label = if args.direction == "upload" {
            "SFTP_SYNC_UPLOAD"
        } else {
            "SFTP_SYNC_DOWNLOAD"
        };

        match &result {
            Ok(transfer_result) => {
                ctx.audit_logger.log(AuditEvent::new(
                    &args.host,
                    &format!("{direction_label} {} -> {}", args.source, args.destination),
                    AuditCommandResult::Success {
                        exit_code: 0,
                        duration_ms: transfer_result.duration_ms,
                    },
                ));
            }
            Err(e) => {
                ctx.audit_logger.log(AuditEvent::new(
                    &args.host,
                    &format!("{direction_label} {} -> {}", args.source, args.destination),
                    AuditCommandResult::Error {
                        message: e.to_string(),
                    },
                ));
            }
        }

        let transfer_result = result?;

        // Format output
        let mut output = String::new();
        let _ = writeln!(output, "Directory sync completed:");
        let _ = writeln!(output, "  Host: {}", args.host);
        let _ = writeln!(output, "  Direction: {}", args.direction);
        let _ = writeln!(output, "  Source: {}", args.source);
        let _ = writeln!(output, "  Destination: {}", args.destination);
        let _ = writeln!(
            output,
            "  Files transferred: {}",
            transfer_result.files_transferred
        );
        let _ = writeln!(
            output,
            "  Bytes transferred: {}",
            transfer_result.bytes_transferred
        );
        let _ = writeln!(
            output,
            "  Directories created: {}",
            transfer_result.directories_created
        );
        let _ = writeln!(output, "  Duration: {}ms", transfer_result.duration_ms);
        if transfer_result.duration_ms > 0 {
            let speed = transfer_result.bytes_transferred as f64
                / transfer_result.duration_ms as f64
                * 1000.0
                / 1_000_000.0;
            let _ = writeln!(output, "  Speed: {speed:.2} MB/s");
        }
        if !transfer_result.errors.is_empty() {
            let _ = writeln!(output, "  Errors ({}):", transfer_result.errors.len());
            for error in &transfer_result.errors {
                let _ = writeln!(output, "    - {error}");
            }
        }

        Ok(ToolCallResult::text(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[test]
    fn test_schema() {
        let handler = SshSyncHandler;
        assert_eq!(handler.name(), "ssh_sync");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_sync");

        // Verify valid JSON
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("source")));
        assert!(required.contains(&json!("destination")));
        assert!(required.contains(&json!("direction")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshSyncHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshSyncHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "unknown_host",
                    "source": "/tmp/local_dir",
                    "destination": "/home/user/remote_dir",
                    "direction": "upload"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "unknown_host");
            }
            e => panic!("Expected UnknownHost error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_arguments() {
        let handler = SshSyncHandler;
        let ctx = create_test_context();

        // Missing required fields
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_direction() {
        let handler = SshSyncHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "unknown_host",
                    "source": "/tmp/local_dir",
                    "destination": "/home/user/remote_dir",
                    "direction": "sideways"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("Invalid direction"));
                assert!(msg.contains("sideways"));
            }
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[test]
    fn test_handler_description_content() {
        let handler = SshSyncHandler;
        assert!(handler.description().contains("Synchronize"));
        assert!(handler.description().contains("SFTP"));
        assert!(handler.description().contains("directory"));
    }
}
